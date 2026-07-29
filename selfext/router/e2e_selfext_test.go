package router

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/resolution"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// The router is part of the BYOK-pure surface of the public MIT mallcop repo,
// so its TEST layer must reach NO commercial billing internals.
// This deterministic collect→propose→route e2e drives the proposer through a
// library-pure fakeSession (below); the real commercial billing session over a
// live inference endpoint is out of scope here (the e2e proves ROUTING, not
// billing) and is covered with the commercial layer.

// goldenCollectJSON is a `mallcop collect --json` envelope: one high-count
// unmapped github repo.rename gap whose closed vocabulary includes config_change
// (a KnownEventTypes member on the mallcop side). This is the proposer's process
// boundary — the deterministic e2e decodes it exactly as the operator pipeline
// would.
const goldenCollectJSON = `{
  "schema_version": 1,
  "mapping_gaps": [
    {
      "source": "github",
      "raw_action": "repo.rename",
      "count": 5,
      "sample_event_ids": ["evt_a", "evt_b"],
      "suggested_vocabulary": ["config_change", "login", "push"]
    }
  ],
  "gap_candidates": []
}`

// ---- inline proposer harness (fake inference + fake session + spy gate) ----

type e2eFake struct {
	resp  proposer.MessagesResponse
	err   error
	calls int
}

func (f *e2eFake) Messages(_ context.Context, _ proposer.MessagesRequest) (proposer.MessagesResponse, error) {
	f.calls++
	return f.resp, f.err
}

type e2eGate struct {
	denyErr error
	records int
}

func (g *e2eGate) Authorize(context.Context, string, float64) error { return g.denyErr }
func (g *e2eGate) Record(string, float64, bool) error               { g.records++; return nil }
func (g *e2eGate) CapUSD() float64                                  { return 25.0 }

// fakeSession is a library-pure session.Session backing the proposer in this e2e:
// it wraps the e2eGate spend-cap surface, counts "mints" (a successful Authorize —
// the metered rail mints its run key iff the gate grants), wraps a denial in
// *session.RefusalError exactly as a commercial billing session does, and hands back a fixed
// (baseURL, key). No billing server, no run key, no ledger — the router e2e asserts
// ROUTING; the real commercial billing lifecycle is proven with the commercial
// layer.
type fakeSession struct {
	gate    *e2eGate
	baseURL string
	mints   int
}

var _ session.Session = (*fakeSession)(nil)

func (s *fakeSession) Authorize(ctx context.Context, estUSD float64) error {
	if err := s.gate.Authorize(ctx, "selfext-propose", estUSD); err != nil {
		return &session.RefusalError{Err: err}
	}
	s.mints++
	return nil
}

func (s *fakeSession) Credentials(context.Context) (string, string, error) {
	return s.baseURL, "mallcop-sk-fake-subkey", nil
}

func (s *fakeSession) Record(_ context.Context, success bool, _ float64) (float64, error) {
	_ = s.gate.Record("selfext-propose", 0.02, success)
	return 0.02, nil
}

func (s *fakeSession) Close() error { return nil }

// e2eSetup builds a proposer + router that SHARE one reject set (proving the
// shared anti-thrash), the proposer driven by a library-pure fakeSession.
func e2eSetup(t *testing.T, fake *e2eFake, gate *e2eGate) (*proposer.Proposer, *Router, *fakeSession) {
	t.Helper()
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}
	sess := &fakeSession{gate: gate, baseURL: "https://forge.fake.local"}
	p := &proposer.Proposer{
		Session:      sess,
		Fingerprints: rejects,
		NewClient:    func(_, _ string) proposer.InferenceClient { return fake },
		Lane:         "investigate",
		BudgetUSD:    2.0,
	}
	base := t.TempDir()
	r := &Router{
		KnownEventTypes: map[string]bool{"config_change": true, "login": true, "push": true},
		OverlayDir:      base + "/overlay",
		ArtifactDir:     base + "/oss",
		ProvenanceDir:   base + "/prov",
		Fingerprints:    rejects, // SHARED with the proposer
		GitSHA:          "gitsha-e2e",
		// This e2e predates the autonomy dial and asserts the
		// auto-apply-data behavior — see newRouter's comment in router_test.go.
		Autonomy: autonomy.SemiAutonomy,
	}
	return p, r, sess
}

func e2eMappingReply() proposer.MessagesResponse {
	return proposer.MessagesResponse{
		StopReason: "tool_use",
		Content: []proposer.ContentBlock{{
			Type: "tool_use", Name: "propose_mapping",
			Input: map[string]any{"source": "github", "raw_action": "repo.rename", "event_type": "config_change"},
		}},
	}
}

func decodeGap(t *testing.T) proposer.MappingGap {
	t.Helper()
	env, err := proposer.DecodeCollectEnvelope([]byte(goldenCollectJSON))
	if err != nil {
		t.Fatalf("DecodeCollectEnvelope: %v", err)
	}
	if env.SchemaVersion != 1 || len(env.MappingGaps) != 1 {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	return env.MappingGaps[0]
}

// TestE2E_CollectProposeRoute_TenantOverlay is the deterministic end-to-end proof
// of the happy path (TEST PLAN case i): golden collect JSON → proposer(FAKE
// inference) → router(STUB GREEN gate) → TenantOverlay + overlay written +
// provenance recorded.
func TestE2E_CollectProposeRoute_TenantOverlay(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)

	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}
	if fake.calls != 1 {
		t.Errorf("inference calls = %d, want 1", fake.calls)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("destination = %q, want tenant_overlay", dec.Destination)
	}
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("overlay not written correctly")
	}
	if provenanceCount(t, r.ProvenanceDir) != 1 {
		t.Errorf("provenance not recorded")
	}
}

// TestE2E_SemiDial_DataAutoAppliesEvidence is the e2e proof of
// the DATA half of the SEMI-autonomy contrast: the REAL proposer (FAKE
// inference client, real strict-parse) hands a real Proposal to the REAL
// Router.Route at Autonomy=SemiAutonomy (e2eSetup's default — see its
// comment), and the decision is captured and logged verbatim (Decision JSON +
// the actual overlay file bytes on disk) so the e2e report quotes the ENGINE's
// own output, not a re-derived expectation. Companion: engine_test.go's
// TestE2E_SemiDial_CodeWaitsEvidence proves the CODE half (Applied=false) on
// the same dial position.
func TestE2E_SemiDial_DataAutoAppliesEvidence(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)
	if r.Autonomy != autonomy.SemiAutonomy {
		t.Fatalf("harness precondition: r.Autonomy = %q, want semi", r.Autonomy)
	}

	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	decJSON, _ := json.MarshalIndent(dec, "", "  ")
	t.Logf("SEMI/DATA real Decision:\n%s", decJSON)

	if dec.Destination != DestTenantOverlay {
		t.Fatalf("SEMI/DATA: destination = %q, want tenant_overlay (auto-apply)", dec.Destination)
	}
	if dec.OverlayPath == "" {
		t.Fatalf("SEMI/DATA: OverlayPath empty — nothing auto-written")
	}
	raw, err := os.ReadFile(dec.OverlayPath)
	if err != nil {
		t.Fatalf("read overlay file %q: %v", dec.OverlayPath, err)
	}
	t.Logf("SEMI/DATA real overlay file %s contents:\n%s", dec.OverlayPath, raw)
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("overlay not auto-written correctly")
	}
	if dec.Provenance.Destination != string(DestTenantOverlay) {
		t.Errorf("provenance destination = %q, want tenant_overlay", dec.Provenance.Destination)
	}
}

// TestE2E_ConsentGatesOSS (case ii): the SAME clean widen stays overlay-only
// without consent, and additionally emits an OSS-PR artifact (never auto-merged)
// with consent.
func TestE2E_ConsentGatesOSS(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	p, r, _ := e2eSetup(t, fake, &e2eGate{})
	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil || !out.Proposed {
		t.Fatalf("Propose: %v out=%+v", err, out)
	}

	noConsent, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route(no consent): %v", err)
	}
	if noConsent.Destination != DestTenantOverlay || noConsent.ArtifactPath != "" {
		t.Fatalf("no-consent must be overlay-only, got %q artifact=%q", noConsent.Destination, noConsent.ArtifactPath)
	}

	withConsent, err := r.Route(*out.Proposal, greenGate(), true)
	if err != nil {
		t.Fatalf("Route(consent): %v", err)
	}
	if withConsent.Destination != DestOSSContribBack || withConsent.ArtifactPath == "" {
		t.Fatalf("consent must emit an OSS-PR artifact, got %q artifact=%q", withConsent.Destination, withConsent.ArtifactPath)
	}
}

// TestE2E_KnownRejectSkips (case v): a fingerprint already in the SHARED reject
// set short-circuits the proposer to Skipped with ZERO Authorize and ZERO
// inference — the proposer and router share one anti-thrash ledger.
func TestE2E_KnownRejectSkips(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{}
	p, r, sess := e2eSetup(t, fake, gate)
	gap := decodeGap(t)

	// Poison the gap via the router's shared reject set (as a Forbidden route
	// would), then the proposer must skip it.
	forbidden := proposer.Proposal{Kind: proposer.KindConsensusBypass, BypassReason: "narrowing", Fingerprint: mustFingerprint(t, p, gap)}
	if _, err := r.Route(forbidden, greenGate(), false); err != nil {
		t.Fatalf("Route(forbidden): %v", err)
	}

	out, err := p.Propose(context.Background(), gap)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Skipped {
		t.Fatalf("want Skipped on shared-reject fingerprint, got %+v", out)
	}
	if fake.calls != 0 || gate.records != 0 || sess.mints != 0 {
		t.Errorf("known-reject spent: inference=%d records=%d mint=%d", fake.calls, gate.records, sess.mints)
	}
}

// TestE2E_OverCapRefuses (case vi): a denying spend gate refuses the proposer
// before any run key exists — ZERO inference, ZERO mint.
func TestE2E_OverCapRefuses(t *testing.T) {
	fake := &e2eFake{resp: e2eMappingReply()}
	gate := &e2eGate{denyErr: errors.New("cap exceeded")}
	p, _, sess := e2eSetup(t, fake, gate)

	out, err := p.Propose(context.Background(), decodeGap(t))
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !out.Refused {
		t.Fatalf("want Refused, got %+v", out)
	}
	if fake.calls != 0 || sess.mints != 0 {
		t.Errorf("over-cap spent: inference=%d mint=%d", fake.calls, sess.mints)
	}
}

// mustFingerprint recovers the gap fingerprint the proposer would compute, by
// running one Propose against a fake that records nothing and reading the
// Outcome fingerprint. It uses a fresh proposer so it does not perturb the
// caller's ledgers.
func mustFingerprint(t *testing.T, _ *proposer.Proposer, gap proposer.MappingGap) string {
	t.Helper()
	// The proposer's mapping fingerprint is deterministic over (source, raw_action);
	// recover it via a throwaway Propose whose gate refuses (no spend, no mint).
	fake := &e2eFake{resp: e2eMappingReply()}
	throwaway, _, _ := e2eSetup(t, fake, &e2eGate{denyErr: errors.New("cap exceeded")})
	out, err := throwaway.Propose(context.Background(), gap)
	if err != nil {
		t.Fatalf("recover fingerprint: %v", err)
	}
	if out.Fingerprint == "" {
		t.Fatalf("no fingerprint recovered")
	}
	return out.Fingerprint
}

// ---- ground-source-truth harness for GapCandidate-driven proposals (mallcoppro-b42) ----
//
// The proof below seeds a REAL git-repo store (core/store), runs the REAL
// core/collect.DetectorGaps over it, and marshals the result through the
// ACTUAL `mallcop collect --json` wire envelope shape (duplicated here exactly
// as proposer.CollectEnvelope already duplicates it across the module
// boundary) before decoding it back with the production
// proposer.DecodeCollectEnvelope. This is deliberately NOT a hand-rolled
// golden GapCandidate JSON: an earlier attempt hard-coded DetectorFamily as
// "priv_escalation" (underscore) — a shape the real collector can never
// emit. core/collect.DetectorGaps derives DetectorFamily via familyFromSource,
// which only strips the "detector:" prefix off a finding Source
// ("detector:priv-escalation" -> "priv-escalation", HYPHEN — see
// core/collect/gaps.go). The hand-rolled golden happened to match the fake
// inference reply's echoed detector field, which hid a real bug: a genuine
// widen's overlay key never matched the family form the real tuning.yaml
// reader (core/detect/tuning.go, which expects "priv_escalation") expects.
// That mismatch is fixed at the write side (selfext/router/overlay.go's
// writeTuningOverlay, via detect.TuningKey); the tests below prove the fix
// against the REAL collector output, not a fabrication.

// gapWireEnvelope duplicates cli.collectReport's (unexported to this package)
// wire shape so the marshaled bytes are BYTE FOR BYTE what
// `mallcop collect --json` emits for a given []collect.GapCandidate — the same
// intentional module-boundary duplication proposer.CollectEnvelope already
// performs on the decode side.
type gapWireEnvelope struct {
	SchemaVersion int                    `json:"schema_version"`
	MappingGaps   []collect.MappingGap   `json:"mapping_gaps"`
	GapCandidates []collect.GapCandidate `json:"gap_candidates"`
}

// initGapTestRepo creates a real git repo with a seeded root commit, mirroring
// core/collect/collect_test.go's initRepo (duplicated here — that helper is
// unexported to the collect package's own _test.go and this package must not
// import core/collect from non-test code).
func initGapTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	return dir
}

// realGroundedGapCandidates seeds ONE real store carrying BOTH an operator
// override-FP and a consensus-dissent on the SAME real detector family
// ("priv-escalation" — detect.Detector.Name()/finding Source's form), runs the
// REAL core/collect.DetectorGaps over it, and crosses the wire exactly as the
// CLI does. Returns the two GapCandidates the real collector emitted, keyed by
// kind.
func realGroundedGapCandidates(t *testing.T) map[string]proposer.GapCandidate {
	t.Helper()
	st, err := store.Open(initGapTestRepo(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	// override_fp: the agent's stored decision on find-esc was "escalate"; an
	// operator suppress directive's verb ("resolve") disagrees — exactly what
	// core/collect.DetectorGaps case (b) surfaces.
	escalated := resolution.Resolution{
		FindingID: "find-esc", Action: "escalate", Reason: "clean escalate, no dissent",
		Actor: "mallory", Severity: "medium", Source: "detector:priv-escalation",
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	}
	if _, err := st.Append(store.KindResolutions, escalated); err != nil {
		t.Fatalf("append resolution: %v", err)
	}
	meta, err := json.Marshal(map[string]any{"finding_id": "find-esc", "verb": "resolve"})
	if err != nil {
		t.Fatalf("marshal directive meta: %v", err)
	}
	if _, err := st.Append(store.KindDirectives, store.Directive{
		Op: "suppress", Pattern: "detector:priv-escalation", Actor: "operator",
		Reason: "false positive on mallory", Meta: meta,
	}); err != nil {
		t.Fatalf("append directive: %v", err)
	}

	// dissent: a consensus committee did not agree on find-dis — the fanout
	// dissent marker in the resolution's Reason (core/collect/gaps.go case (c)).
	dissentRes := resolution.Resolution{
		FindingID: "find-dis", Action: "resolve",
		Reason: "deep panel majority RESOLVE (2 resolve / 1 escalate). Dissent (malicious) cited; confidence penalized 0.10.",
		Actor:  "dana", Severity: "medium", Source: "detector:priv-escalation",
		Timestamp: time.Unix(1_700_000_001, 0).UTC(),
	}
	if _, err := st.Append(store.KindResolutions, dissentRes); err != nil {
		t.Fatalf("append dissent resolution: %v", err)
	}

	gaps, err := collect.DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}
	if len(gaps) != 2 {
		t.Fatalf("harness precondition: want exactly 2 real gaps (override_fp + dissent), got %d: %+v", len(gaps), gaps)
	}

	raw, err := json.Marshal(gapWireEnvelope{SchemaVersion: 1, MappingGaps: []collect.MappingGap{}, GapCandidates: gaps})
	if err != nil {
		t.Fatalf("marshal wire envelope: %v", err)
	}
	env, err := proposer.DecodeCollectEnvelope(raw)
	if err != nil {
		t.Fatalf("DecodeCollectEnvelope: %v", err)
	}
	if len(env.GapCandidates) != 2 {
		t.Fatalf("decoded envelope: want 2 gap candidates, got %d", len(env.GapCandidates))
	}

	byKind := make(map[string]proposer.GapCandidate, 2)
	for _, g := range env.GapCandidates {
		byKind[g.Kind] = g
		// Ground-truth precondition: the REAL collector's family normalization
		// (familyFromSource) yields the detector-REGISTRY's kebab-case form,
		// NEVER the tuning.yaml snake_case form — this is exactly the mismatch
		// mallcoppro-b42 closes at the WRITE side, not by faking the source
		// shape here.
		if g.DetectorFamily != "priv-escalation" {
			t.Fatalf("harness precondition: want the real collector's hyphenated family, got %q", g.DetectorFamily)
		}
	}
	if _, ok := byKind["override_fp"]; !ok {
		t.Fatalf("harness precondition: no override_fp gap in %+v", env.GapCandidates)
	}
	if _, ok := byKind["dissent"]; !ok {
		t.Fatalf("harness precondition: no dissent gap in %+v", env.GapCandidates)
	}
	return byKind
}

// nonBuiltinGapTuningKeyword is a role/permission substring that carries NONE
// of priv-escalation's built-in elevated-keyword vocabulary (see
// core/detect/priv_escalation.go's builtinElevatedKeywords — "poweruser" is
// ALREADY built in and would make a widen assertion vacuous). Purpose-built so
// TestE2E_GapCandidateProposeRoute_TenantOverlay's "actually reweights the
// next scan" assertion proves something real.
const nonBuiltinGapTuningKeyword = "shadowops"

// gapTuningReplyFor returns the FAKE inference reply for a GapCandidate
// propose run: a conforming propose_tuning tool_use widening the gap's OWN
// detector family — echoed EXACTLY as the const-constrained tool schema
// requires (gapTuningTool pins "detector" to gap.DetectorFamily, so a
// conforming model reply for a REAL gap echoes the hyphenated
// "priv-escalation", never a hand-typed underscore form).
func gapTuningReplyFor(gap proposer.GapCandidate) proposer.MessagesResponse {
	return proposer.MessagesResponse{
		StopReason: "tool_use",
		Content: []proposer.ContentBlock{{
			Type: "tool_use", Name: "propose_tuning",
			Input: map[string]any{
				"detector":     gap.DetectorFamily,
				"key":          "extra_elevated_keywords",
				"added_values": []string{nonBuiltinGapTuningKeyword},
			},
		}},
	}
}

// shadowopsFixture returns one role_assignment event whose role carries
// nonBuiltinGapTuningKeyword and NOTHING from priv-escalation's built-in
// keyword vocabulary, plus a baseline that knows the actor (so the unrelated
// new-actor detector stays quiet and the before/after Detect() comparison
// isolates priv-escalation only) but no role grant (so priv-escalation itself
// is ungated) — the minimal fixture for the "did the widen actually reweight
// the scan" assertion.
func shadowopsFixture(t *testing.T) ([]event.Event, *baseline.Baseline) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"role_name": nonBuiltinGapTuningKeyword, "target_user": "victim"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	events := []event.Event{{
		ID: "gap-tuning-1", Source: "cloud", Type: "role_assignment",
		Actor: "shadow-actor", Timestamp: time.Unix(1_700_000_100, 0).UTC(),
		Payload: payload,
	}}
	return events, &baseline.Baseline{KnownActors: []string{"shadow-actor"}}
}

// TestE2E_GapCandidateProposeRoute_TenantOverlay is the deterministic offline
// end-to-end proof for mallcoppro-b42 (design §Gap B) — the sibling of
// TestE2E_CollectProposeRoute_TenantOverlay for the GapCandidate/tuning lane:
//
//	REAL store (real resolution + suppress directive) -> REAL
//	core/collect.DetectorGaps -> the real collect->proposer wire boundary ->
//	proposer.ProposeGap (FAKE inference, echoing the schema-pinned family) ->
//	router.Route (STUB GREEN gate) -> TenantOverlay: tuning.yaml widened,
//	LOADABLE by the real detector tuning reader, and PROVEN to reweight the
//	next scan.
//
// This is the wire runSelfextPropose (cli/selfext.go) drives: it iterates
// env.GapCandidates alongside env.MappingGaps, filtered to override_fp/dissent
// kinds, and routes each through this exact ProposeGap -> Route pipeline.
func TestE2E_GapCandidateProposeRoute_TenantOverlay(t *testing.T) {
	detect.ResetTuning()
	t.Cleanup(detect.ResetTuning)

	gap := realGroundedGapCandidates(t)["override_fp"]

	fake := &e2eFake{resp: gapTuningReplyFor(gap)}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)

	// A synthetic event that ONLY fires once the widen lands — proves the
	// before/after comparison below isn't vacuous.
	events, bl := shadowopsFixture(t)
	if before := detect.Detect(events, bl); len(before) != 0 {
		t.Fatalf("harness precondition: shadowops event already fires priv-escalation before any widen: %+v", before)
	}

	out, err := p.ProposeGap(context.Background(), gap)
	if err != nil {
		t.Fatalf("ProposeGap: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}
	if fake.calls != 1 {
		t.Errorf("inference calls = %d, want 1", fake.calls)
	}
	if out.Proposal.Kind != proposer.KindTuning {
		t.Fatalf("proposal kind = %q, want tuning", out.Proposal.Kind)
	}
	if out.Proposal.Severity != "medium" {
		t.Errorf("proposal severity = %q, want the gap's medium (structural provenance, non-critical so it can auto-route)", out.Proposal.Severity)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("destination = %q, want tenant_overlay", dec.Destination)
	}

	// REGRESSION (mallcoppro-b42, fix 2): the overlay key must be the
	// NORMALIZED "priv_escalation" (underscore) — the family-name mismatch
	// this item closes — never the raw "priv-escalation" (hyphen) the real
	// collector's GapCandidate.DetectorFamily carries.
	got := readTuning(t, dec.OverlayPath)["priv_escalation"]["extra_elevated_keywords"]
	if len(got) != 1 || got[0] != nonBuiltinGapTuningKeyword {
		t.Fatalf("tuning overlay = %+v, want [%s] under priv_escalation.extra_elevated_keywords", got, nonBuiltinGapTuningKeyword)
	}
	if provenanceCount(t, r.ProvenanceDir) != 1 {
		t.Errorf("provenance not recorded")
	}

	// REGRESSION (mallcoppro-b42, fix 1+2 combined): the written tuning.yaml
	// must be LOADABLE by the REAL detector tuning reader (previously a LOUD
	// parse error on the unnormalized hyphenated key), and must actually
	// reweight the next scan — not just sit as inert bytes on disk.
	loaded, err := detect.LoadTuningFile(dec.OverlayPath)
	if err != nil {
		t.Fatalf("core/detect.LoadTuningFile(%s): %v (a real widen must be loadable by the real reader)", dec.OverlayPath, err)
	}
	detect.ApplyTuning(loaded)
	after := detect.Detect(events, bl)
	if len(after) != 1 || after[0].Type != "priv-escalation" {
		t.Fatalf("widen did not reweight the next scan: Detect(after tuning) = %+v, want exactly one priv-escalation finding", after)
	}
}

// TestE2E_GapCandidateDissent_TenantOverlay proves the dissent kind takes the
// SAME DATA-lane path as override_fp — driven by the SAME real collector run
// on a genuinely SEPARATE finding whose resolution carries the real fanout
// dissent marker (not a Kind field mutated onto the override_fp gap's
// structural data).
func TestE2E_GapCandidateDissent_TenantOverlay(t *testing.T) {
	gap := realGroundedGapCandidates(t)["dissent"]

	fake := &e2eFake{resp: gapTuningReplyFor(gap)}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)

	out, err := p.ProposeGap(context.Background(), gap)
	if err != nil {
		t.Fatalf("ProposeGap: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("destination = %q, want tenant_overlay", dec.Destination)
	}
	if got := readTuning(t, dec.OverlayPath)["priv_escalation"]["extra_elevated_keywords"]; len(got) == 0 {
		t.Errorf("dissent widen not written under the normalized priv_escalation key, got %+v", got)
	}
}

// TestE2E_GapCandidateForbidsMappingShape proves R9 defense-in-depth on the
// GapCandidate lane: even if a non-conforming model reply used the
// (mapping-lane-only) propose_mapping tool, StrictParseGap refuses it — no
// tool exists on this lane that can smuggle anything but an additive widen.
func TestE2E_GapCandidateForbidsMappingShape(t *testing.T) {
	gap := realGroundedGapCandidates(t)["override_fp"]
	fake := &e2eFake{resp: e2eMappingReply()} // propose_mapping — wrong lane
	gate := &e2eGate{}
	p, _, _ := e2eSetup(t, fake, gate)

	out, err := p.ProposeGap(context.Background(), gap)
	if err != nil {
		t.Fatalf("ProposeGap: %v", err)
	}
	if !out.Rejected {
		t.Fatalf("want Rejected (propose_mapping is not offered on the gap-candidate lane), got %+v", out)
	}
}

// TestE2E_GapCandidateNetNewFamily_HumanGate exercises router.go's net-new-
// detector-family HUMAN-GATE branch (humanGateReason) driven by a REAL
// GapCandidate-sourced tuning proposal, so that branch is proven live on the
// lane this item wires up rather than only unit-tested against hand-typed
// proposals (router_test.go's TestRoute* cases). cli/selfext.go's real Router
// construction leaves KnownDetectorFamilies empty today (family-novelty is
// then simply not gated — see router.go's doc comment on the field); this
// test populates it explicitly to prove the gate itself still works whenever a
// caller DOES supply a known-family set.
func TestE2E_GapCandidateNetNewFamily_HumanGate(t *testing.T) {
	gap := realGroundedGapCandidates(t)["override_fp"]
	fake := &e2eFake{resp: gapTuningReplyFor(gap)}
	gate := &e2eGate{}
	p, r, _ := e2eSetup(t, fake, gate)
	// priv-escalation is deliberately ABSENT from the known set — net-new.
	r.KnownDetectorFamilies = map[string]bool{"config-drift": true, "unusual-login": true}

	out, err := p.ProposeGap(context.Background(), gap)
	if err != nil {
		t.Fatalf("ProposeGap: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("want Proposed, got %+v", out)
	}

	dec, err := r.Route(*out.Proposal, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("destination = %q, want human_gate (net-new detector family not in KnownDetectorFamilies)", dec.Destination)
	}
	if dec.OverlayPath != "" {
		t.Errorf("human-gate route must NOT write an overlay, got path %q", dec.OverlayPath)
	}
}
