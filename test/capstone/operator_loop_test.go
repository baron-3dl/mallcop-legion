//go:build capstone

// operator_loop_test.go — the END-TO-END CAPSTONE for the operator-integration
// epic (mallcoppro-84c / mallcoppro-b1b). It proves the WHOLE spine on ONE real
// git-backed store, with NO MOCKS except the metered inference reply (a canned
// propose_tuning tool_use — inference is not the seam under test):
//
//	sense  → OPERATOR MARKS A FALSE POSITIVE in chat, via the REAL
//	         core/investigate record_decision tool (Gap A), which commits a REAL
//	         store.Directive through the SAME store.Open+append seam a live chat
//	         turn uses.
//	persist → a REAL scan #2 over the SAME events does NOT refire the finding,
//	         because the REAL core/pipeline DirectiveDispatcher suppress consumer
//	         (Gap C) drops it.
//	train  → the REAL core/collect.DetectorGaps read of the store surfaces the
//	         operator's judgment as an override_fp GapCandidate (Gap B input),
//	         which the REAL selfext/proposer.ProposeGap (canned inference) turns
//	         into a REAL add-only KindTuning proposal, run through the REAL
//	         validate-proposal gate (a real `mallcop validate-proposal`
//	         subprocess over a jail worktree) + the REAL selfext/router — and the
//	         resulting tuning.yaml is LOADABLE by core/detect.LoadTuningFile (the
//	         mallcoppro-2c2 no-poison guarantee).
//
// This is the epic's acceptance proof: operator FP in chat → directive commits
// → next scan does not refire AND the same judgment trains the detector. Every
// numbered step below asserts against a REAL component; only the inference reply
// is canned.
//
// Build-tagged `capstone` (like the repo's `integration`/`e2e`/`docdemo`
// harnesses) so the heavy real-gate subprocess stays out of the default
// `go test ./...`; it runs explicitly via `go test -tags capstone
// ./test/capstone/...` (wired into CI as its own step).
package capstone

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/investigate"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"github.com/mallcop-app/mallcop/selfext/router"
	"github.com/mallcop-app/mallcop/selfext/sandbox"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// ---- canned inference (the ONE allowed mock) ---------------------------------

// cannedTuningClient is a proposer.InferenceClient that returns ONE
// propose_tuning tool_use widening the priv-escalation detector's additive
// extra_elevated_keywords list. Inference is not the seam under test; the reply
// still flows through the REAL StrictParseGap add-only gate, so a malformed
// canned reply would be rejected exactly as a live model's would be.
type cannedTuningClient struct {
	detectorFamily string
	addedValue     string
	calls          int
}

func (c *cannedTuningClient) Messages(_ context.Context, _ proposer.MessagesRequest) (proposer.MessagesResponse, error) {
	c.calls++
	return proposer.MessagesResponse{
		StopReason: "tool_use",
		Content: []proposer.ContentBlock{{
			Type: "tool_use",
			Name: "propose_tuning",
			Input: map[string]any{
				"detector":     c.detectorFamily,
				"key":          "extra_elevated_keywords",
				"added_values": []string{c.addedValue},
			},
		}},
	}, nil
}

// ---- helpers -----------------------------------------------------------------

// initRepo makes a temp dir a real git repo with a hermetic identity and a root
// commit — the same shape core/investigate's own tests use, so the git-backed
// store and record_decision behave exactly as in production.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "capstone"},
		{"config", "user.email", "capstone@example.com"},
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
		"GIT_AUTHOR_NAME=capstone", "GIT_AUTHOR_EMAIL=capstone@example.com",
		"GIT_COMMITTER_NAME=capstone", "GIT_COMMITTER_EMAIL=capstone@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	return dir
}

// repoRoot resolves the mallcop checkout root this test file lives in
// (test/capstone/operator_loop_test.go → ../..), the real target repo the
// validate-proposal gate runs against.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// buildRealMallcop builds the REAL `mallcop` binary from the checkout — the
// trusted validate-proposal gate, exactly as production resolves it from PATH.
// A checkout that fails to build is real signal (a hard failure), never a skip.
func buildRealMallcop(t *testing.T, src string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mallcop")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/mallcop in %s: %v\n%s", src, err, out)
	}
	return bin
}

// firingEvent crafts a role_assignment granting a NON-owner/NON-admin elevated
// role ("maintainer" → severity "high", so the downstream tuning proposal is
// not force-routed to human review on critical severity) to a fresh target. The
// actor is baseline-known so the new-actor detector stays quiet and we isolate
// the priv-escalation finding.
func firingEvent(t *testing.T, id, actor string) event.Event {
	t.Helper()
	payload, err := json.Marshal(map[string]string{
		"role_name":   "maintainer",
		"target_user": "victim",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      "role_assignment",
		Actor:     actor,
		Timestamp: time.Date(2026, 7, 29, 16, 8, 0, 0, time.UTC),
		Payload:   payload,
	}
}

// scanPrivEscalation runs the REAL detector layer over events and returns the
// priv-escalation finding (there must be exactly one for this fixture). This is
// scan #1 / scan #2's detection stage: pure, offline, inference-free.
func scanPrivEscalation(t *testing.T, events []event.Event, bl *baseline.Baseline) (finding.Finding, bool) {
	t.Helper()
	for _, f := range detect.Detect(events, bl) {
		if f.Type == "priv-escalation" {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// TestOperatorIntegrationLoop_EndToEnd is the epic capstone.
func TestOperatorIntegrationLoop_EndToEnd(t *testing.T) {
	ctx := context.Background()
	const actor = "cap-operator"

	// A real git-backed store in the customer's own repo (D1/D3): findings,
	// resolutions, and directives all land here, and record_decision writes
	// through the SAME store handle.
	dir := initRepo(t)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Baseline: actor is known (suppress new-actor) but the maintainer grant is
	// NOT in the actor's known roles, so priv-escalation fires.
	bl := &baseline.Baseline{
		KnownActors: []string{actor},
		ActorRoles:  map[string][]string{actor: {"viewer"}},
	}
	events := []event.Event{firingEvent(t, "pe-cap-1", actor)}

	// ---- STEP 1: SEED — a real finding that fires on scan #1 ------------------
	f1, ok := scanPrivEscalation(t, events, bl)
	if !ok {
		t.Fatalf("STEP 1: priv-escalation did not fire on scan #1")
	}
	if f1.Severity == "critical" {
		t.Fatalf("STEP 1: fixture must be non-critical (got %q) or the tuning proposal is force-gated on severity", f1.Severity)
	}
	if _, err := st.Append(store.KindFindings, f1); err != nil {
		t.Fatalf("STEP 1: append finding: %v", err)
	}
	// The committee ESCALATED this finding — the agent's stored decision. This
	// is what the operator's suppress will DISAGREE with, producing the
	// override_fp training signal in STEP 4.
	res := resolution.Resolution{
		FindingID:  f1.ID,
		Action:     "escalate",
		Reason:     "committee escalated: unexpected maintainer grant",
		Confidence: 0.8,
		Actor:      actor,
		Severity:   f1.Severity,
		Source:     f1.Source,
		Timestamp:  time.Now().UTC(),
	}
	if _, err := st.Append(store.KindResolutions, res); err != nil {
		t.Fatalf("STEP 1: append resolution: %v", err)
	}

	// ---- STEP 2: OPERATOR MARKS FP via the REAL record_decision tool ----------
	// Propose-only dial + confirm — the live-chat default: the tool commits
	// nothing until the operator's Apply re-issues with confirm=true.
	writeConfig(t, dir, config.AutonomyNon)
	opts := investigate.Options{Store: st, RepoRoot: dir}

	// (a) unconfirmed → nothing written.
	pre, err := investigate.ExecuteTool(opts, "record_decision", map[string]any{
		"op":         "suppress",
		"finding_id": f1.ID,
		"reason":     "known-good: platform automation grants maintainer here",
	})
	if err != nil {
		t.Fatalf("STEP 2a: record_decision (propose-only): %v", err)
	}
	if out, _ := pre.(investigate.RecordDecisionOutput); out.Applied {
		t.Fatalf("STEP 2a: propose-only dial must not commit; got Applied=true")
	}
	if dirs0, _ := st.LoadDirectives(); len(dirs0) != 0 {
		t.Fatalf("STEP 2a: propose-only left %d directive(s), want 0", len(dirs0))
	}

	// (b) operator Apply (confirm=true) → commits a REAL directive.
	post, err := investigate.ExecuteTool(opts, "record_decision", map[string]any{
		"op":         "suppress",
		"finding_id": f1.ID,
		"reason":     "known-good: platform automation grants maintainer here",
		"confirm":    true,
	})
	if err != nil {
		t.Fatalf("STEP 2b: record_decision (confirm): %v", err)
	}
	if out, _ := post.(investigate.RecordDecisionOutput); !out.Applied {
		t.Fatalf("STEP 2b: confirmed record_decision did not commit; got %+v", post)
	}

	// Ground truth: re-open a FRESH store handle and confirm the suppress
	// directive really landed on disk, carrying the finding id in Meta (the
	// dual-audience key the override_fp join needs).
	st2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("STEP 2: re-open store: %v", err)
	}
	dirs, err := st2.LoadDirectives()
	if err != nil {
		t.Fatalf("STEP 2: load directives: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("STEP 2: want 1 committed directive, got %d", len(dirs))
	}
	suppress := dirs[0]
	wantPattern := f1.Source + "/" + f1.Type + "/" + f1.Actor
	if suppress.Op != "suppress" || suppress.Pattern != wantPattern {
		t.Fatalf("STEP 2: directive = {Op:%q Pattern:%q}, want {suppress %q}", suppress.Op, suppress.Pattern, wantPattern)
	}
	var meta struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(suppress.Meta, &meta); err != nil {
		t.Fatalf("STEP 2: decode directive meta: %v", err)
	}
	if meta.FindingID != f1.ID {
		t.Fatalf("STEP 2: directive Meta.finding_id = %q, want %q (record_decision must anchor the suppress to its finding for the override_fp join)", meta.FindingID, f1.ID)
	}
	t.Logf("STEP 2 OK: committed suppress directive pattern=%q finding_id=%q", suppress.Pattern, meta.FindingID)

	// ---- STEP 3: NO REFIRE — real scan #2, real DirectiveDispatcher ----------
	f2, ok := scanPrivEscalation(t, events, bl)
	if !ok {
		t.Fatalf("STEP 3: precondition — priv-escalation must still fire pre-directive on scan #2")
	}
	dispatcher := pipeline.NewDirectiveDispatcher() // real suppress consumer
	kept := dispatcher.Apply([]finding.Finding{f2}, dirs)
	for _, f := range kept {
		if f.Type == "priv-escalation" && f.Actor == actor {
			t.Fatalf("STEP 3: finding refired — the suppress directive did not drop it via the DirectiveDispatcher")
		}
	}
	t.Logf("STEP 3 OK: scan #2 fired the finding, DirectiveDispatcher suppressed it (%d→%d)", 1, len(kept))

	// ---- STEP 4: JUDGMENT → override_fp GapCandidate (real collect) ----------
	gaps, err := collect.DetectorGaps(st2, nil)
	if err != nil {
		t.Fatalf("STEP 4: DetectorGaps: %v", err)
	}
	var overrideGap *collect.GapCandidate
	for i := range gaps {
		if gaps[i].Kind == collect.GapOverrideFP && contains(gaps[i].FindingIDs, f1.ID) {
			overrideGap = &gaps[i]
			break
		}
	}
	if overrideGap == nil {
		t.Fatalf("STEP 4: no override_fp GapCandidate for %s; got %d gap(s): %+v", f1.ID, len(gaps), gaps)
	}
	if overrideGap.DetectorFamily != "priv-escalation" {
		t.Fatalf("STEP 4: gap DetectorFamily = %q, want priv-escalation", overrideGap.DetectorFamily)
	}
	t.Logf("STEP 4 OK: override_fp GapCandidate emitted — human=%q vs agent=%q on %s",
		overrideGap.Evidence.HumanVerb, overrideGap.Evidence.AgentAction, overrideGap.DetectorFamily)

	// ---- STEP 5: PROPOSAL REFLECTS CORRECTION (real proposer/gate/router) -----
	// Cross the module boundary exactly as production does: core/collect emits
	// the gap as JSON (`mallcop collect --json`), selfext/proposer decodes it
	// (DecodeCollectEnvelope) into its own GapCandidate. This is the real seam,
	// not a struct copy — a field/tag drift between the two independently
	// maintained types would surface right here.
	gapCandidate := proposerGapFromCollect(t, *overrideGap)
	canned := &cannedTuningClient{detectorFamily: gapCandidate.DetectorFamily, addedValue: "cap-superadmin-role"}
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("STEP 5: LoadRejectSet: %v", err)
	}
	p := &proposer.Proposer{
		Session:      &session.BYOISession{BaseURL: "https://byok.local", Key: "byok-key"},
		Fingerprints: rejects,
		NewClient:    func(_, _ string) proposer.InferenceClient { return canned },
		Lane:         "investigate",
		BudgetUSD:    2.0,
	}
	out, err := p.ProposeGap(ctx, gapCandidate)
	if err != nil {
		t.Fatalf("STEP 5: ProposeGap: %v", err)
	}
	if !out.Proposed || out.Proposal == nil {
		t.Fatalf("STEP 5: gap did not produce a proposal; got %+v", out)
	}
	prop := *out.Proposal
	if prop.Kind != proposer.KindTuning || prop.Tuning == nil {
		t.Fatalf("STEP 5: proposal kind = %q (tuning=%v), want a KindTuning widen", prop.Kind, prop.Tuning)
	}
	if canned.calls != 1 {
		t.Fatalf("STEP 5: inference calls = %d, want exactly 1", canned.calls)
	}
	t.Logf("STEP 5 OK: KindTuning proposal — widen %s.%s += %v", prop.Tuning.Detector, prop.Tuning.Key, prop.Tuning.AddedValues)

	// Loadability (mallcoppro-2c2, no poison overlay): the REAL router write path
	// produces a tuning.yaml the REAL core/detect.LoadTuningFile accepts, with
	// the operator-driven widen present. This is the durable "the judgment
	// trained the detector" artifact — asserted independently of the gate
	// verdict so it holds on both the auto-apply and human-gate branches.
	overlayDir := t.TempDir()
	tuningPath, err := router.WriteOverlay(overlayDir, prop, nil)
	if err != nil {
		t.Fatalf("STEP 5: WriteOverlay (real router write path): %v", err)
	}
	loaded, err := detect.LoadTuningFile(tuningPath)
	if err != nil {
		t.Fatalf("STEP 5: LoadTuningFile rejected the router-written tuning.yaml (POISON OVERLAY): %v", err)
	}
	if !contains(loaded.PrivEscalation.ExtraElevatedKeywords, "cap-superadmin-role") {
		t.Fatalf("STEP 5: loadable tuning.yaml missing the operator-driven widen; got %+v", loaded.PrivEscalation)
	}
	t.Logf("STEP 5 OK: tuning.yaml at %s is LOADABLE by core/detect.LoadTuningFile with the widen applied", tuningPath)

	// Drive the proposal through the REAL validate-proposal gate + REAL router.
	// The gate is a real `mallcop validate-proposal` subprocess over a jail
	// worktree of this checkout — the exact production path cli/selfext.go's
	// proposeGateViaWorktree uses. A fresh, coverage-less widen is honestly
	// non-GREEN (the reference exams gain no covered case), so the REAL router
	// escalates it to a human — the correct outcome for a widen the gate cannot
	// certify. Whichever REAL outcome the gate yields, the router decision below
	// is genuine (no synthetic GateResult).
	src := repoRoot(t)
	bin := buildRealMallcop(t, src)
	gate := runRealGate(ctx, t, bin, src, prop)
	t.Logf("STEP 5: real gate verdict — Passed=%v CoveragePlus=%d NewFirings=%d NovelGap=%v",
		gate.Passed, gate.CoveragePlus, len(gate.NewFirings), gate.NovelGap)

	rt := &router.Router{
		KnownEventTypes: map[string]bool{},
		OverlayDir:      filepath.Join(t.TempDir(), "overlay"),
		ArtifactDir:     filepath.Join(t.TempDir(), "artifacts"),
		ProvenanceDir:   filepath.Join(t.TempDir(), "prov"),
		Fingerprints:    rejects,
		Autonomy:        "semi", // would auto-apply a GREEN widen; a non-GREEN one still escalates
	}
	dec, err := rt.Route(prop, gate, false)
	if err != nil {
		t.Fatalf("STEP 5: router.Route: %v", err)
	}
	switch dec.Destination {
	case router.DestTenantOverlay:
		// GREEN gate certified the widen: it auto-applied to the tenant overlay.
		if dec.OverlayPath == "" {
			t.Fatalf("STEP 5: tenant_overlay route wrote no overlay path")
		}
		if _, err := detect.LoadTuningFile(dec.OverlayPath); err != nil {
			t.Fatalf("STEP 5: auto-applied overlay is not loadable: %v", err)
		}
		t.Logf("STEP 5 OK: real gate GREEN → router auto-applied the widen to the tenant overlay")
	case router.DestHumanGate, router.DestPendingApproval:
		// Coverage-less widen: the real gate did not certify it, so the real
		// router correctly held it for a human. The judgment still trained the
		// detector via the loadable overlay proven above.
		t.Logf("STEP 5 OK: real gate non-GREEN → router held the coverage-less widen for human review (%s): %s",
			dec.Destination, dec.Reason)
	default:
		t.Fatalf("STEP 5: unexpected router destination %q (reason=%q)", dec.Destination, dec.Reason)
	}

	t.Log("CAPSTONE PROVEN: operator FP in chat → suppress directive commits → scan #2 does not refire → override_fp GapCandidate → real KindTuning proposal through the real gate+router, tuning.yaml loadable.")
}

// runRealGate applies the proposal's overlay to a jail worktree of src, commits
// it, and runs the REAL `mallcop validate-proposal` subprocess over base..HEAD —
// the exact production path (cli/selfext.go proposeGateViaWorktree). It returns
// the real GateResult; an operational failure of the gate itself is a hard
// failure (real signal), never a silently-swallowed skip.
func runRealGate(ctx context.Context, t *testing.T, bin, src string, prop proposer.Proposal) engine.GateResult {
	t.Helper()
	gctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()

	jail := &sandbox.Jail{TargetRepo: src, BaseRef: "HEAD"}
	wt, err := jail.Open(gctx)
	if err != nil {
		t.Fatalf("real gate: open jail worktree: %v", err)
	}
	defer func() { _ = wt.Close() }()

	if _, err := router.WriteOverlay(filepath.Join(wt.Dir, "detectors"), prop, nil); err != nil {
		t.Fatalf("real gate: apply overlay to worktree: %v", err)
	}
	if _, err := wt.CommitAuthored(gctx, "capstone: apply add-only tuning widen "+prop.Fingerprint); err != nil {
		t.Fatalf("real gate: commit overlay: %v", err)
	}
	gr, _, err := engine.RunValidateProposal(gctx, bin, wt.Dir, wt.BaseSHA, "")
	if err != nil {
		t.Fatalf("real gate: validate-proposal: %v", err)
	}
	return gr
}

// writeConfig writes a mallcop.yaml at dir with the given autonomy dial — the
// same config seam record_decision reads via config.LoadEffective.
func writeConfig(t *testing.T, dir, autonomy string) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Learning.Autonomy = autonomy
	if err := config.WriteConfig(filepath.Join(dir, config.ConfigFileName), cfg); err != nil {
		t.Fatalf("write mallcop.yaml: %v", err)
	}
}

// proposerGapFromCollect crosses the collect→proposer module boundary through
// the REAL `mallcop collect --json` envelope wire format: marshal the collect
// GapCandidate into a CollectEnvelope's gap_candidates array, then decode it
// with the proposer's own DecodeCollectEnvelope — the exact path production
// takes across the process boundary.
func proposerGapFromCollect(t *testing.T, g collect.GapCandidate) proposer.GapCandidate {
	t.Helper()
	gapJSON, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal collect gap: %v", err)
	}
	envelope := []byte(`{"schema_version":1,"mapping_gaps":[],"gap_candidates":[` + string(gapJSON) + `]}`)
	env, err := proposer.DecodeCollectEnvelope(envelope)
	if err != nil {
		t.Fatalf("DecodeCollectEnvelope: %v", err)
	}
	if len(env.GapCandidates) != 1 {
		t.Fatalf("decoded %d gap candidates, want 1", len(env.GapCandidates))
	}
	return env.GapCandidates[0]
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
