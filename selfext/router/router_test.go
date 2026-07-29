package router

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"gopkg.in/yaml.v3"
)

// greenGate is a STUBBED GateResult that GREEN-certifies a clean widen: it
// passed, added coverage (+1), and introduced no regression. No real gate is
// needed to unit-test the router's tiering.
func greenGate() engine.GateResult {
	return engine.GateResult{
		SchemaVersion: 1,
		Tier:          "free",
		Passed:        true,
		BaseSHA:       "basesha0",
		HeadSHA:       "headsha0",
		CoveragePlus:  1,
		NewFirings:    nil,
	}
}

// newRouter builds a Router with Autonomy explicitly SemiAutonomy: every
// pre-existing test in this file predates the autonomy dial
// and asserts the auto-apply-data behavior that was the ONLY behavior before
// the dial existed — "semi" is the tier that reproduces it exactly (data
// auto-applies; the dial's own matrix is proven separately by the
// TestRouteAutonomy* tests below, which set Autonomy explicitly per case).
func newRouter(t *testing.T) *Router {
	t.Helper()
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("LoadRejectSet: %v", err)
	}
	base := t.TempDir()
	return &Router{
		KnownEventTypes: map[string]bool{"config_change": true, "login": true, "push": true},
		OverlayDir:      filepath.Join(base, "overlay"),
		ArtifactDir:     filepath.Join(base, "oss"),
		ProvenanceDir:   filepath.Join(base, "prov"),
		Fingerprints:    rejects,
		GitSHA:          "gitsha0",
		Autonomy:        autonomy.SemiAutonomy,
	}
}

func mappingProposal(source, action, eventType string) proposer.Proposal {
	return proposer.Proposal{
		Kind:           proposer.KindMapping,
		Mapping:        &proposer.MappingProposal{Source: source, RawAction: action, EventType: eventType},
		Universal:      true,
		Fingerprint:    "fp" + source + action + eventType,
		SampleEventIDs: []string{"evt_1"},
		Model:          "investigate",
		Endpoint:       "https://forge.example.test",
	}
}

func readMappings(t *testing.T, path string) map[string]map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var doc map[string]map[string]string
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %q: %v", path, err)
	}
	return doc
}

// readTuning reads a tuning.yaml overlay written by WriteOverlay for a
// KindTuning proposal (detector -> extra_* key -> added values). Shared by the
// router unit tests and the GapCandidate e2e (e2e_selfext_test.go,
// mallcoppro-b42).
func readTuning(t *testing.T, path string) map[string]map[string][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var doc map[string]map[string][]string
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %q: %v", path, err)
	}
	return doc
}

func provenanceCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("readdir %q: %v", dir, err)
	}
	return len(entries)
}

// (i) valid mapping + GREEN coverage+1 gate -> TenantOverlay, overlay appended,
// provenance recorded.
func TestRouteValidMappingGreenToOverlay(t *testing.T) {
	r := newRouter(t)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("destination = %q, want tenant_overlay", dec.Destination)
	}
	doc := readMappings(t, dec.OverlayPath)
	if doc["github"]["repo.rename"] != "config_change" {
		t.Errorf("overlay = %+v, want github/repo.rename -> config_change", doc)
	}
	if provenanceCount(t, r.ProvenanceDir) != 1 {
		t.Errorf("provenance not recorded")
	}
}

// readSoleProvenance reads the single RoutedRecord JSON file expected in dir.
func readSoleProvenance(t *testing.T, dir string) RoutedRecord {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %q: %v", dir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("provenance dir %q: got %d entries, want 1", dir, len(entries))
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read %q: %v", entries[0].Name(), err)
	}
	var rec RoutedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("decode provenance JSON: %v", err)
	}
	return rec
}

// TestRouteEndpointRoundTripsInProvenance pins that the proposal's inference
// Endpoint (the session/inference base URL the propose call was billed to)
// flows through Route into the persisted RoutedRecord's "endpoint" JSON field
// — mirroring engine.Provenance.Endpoint, which the engine authoring lane
// already records (engine.go:157/335).
func TestRouteEndpointRoundTripsInProvenance(t *testing.T) {
	r := newRouter(t)
	prop := mappingProposal("github", "repo.rename", "config_change")
	if prop.Endpoint == "" {
		t.Fatal("test fixture: mappingProposal must set a non-empty Endpoint")
	}
	dec, err := r.Route(prop, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Provenance.Endpoint != prop.Endpoint {
		t.Errorf("Decision.Provenance.Endpoint = %q, want %q", dec.Provenance.Endpoint, prop.Endpoint)
	}
	rec := readSoleProvenance(t, r.ProvenanceDir)
	if rec.Endpoint != prop.Endpoint {
		t.Errorf("persisted provenance endpoint = %q, want %q (did not round-trip through JSON)", rec.Endpoint, prop.Endpoint)
	}
}

// (ii) consent=false universal -> stays TenantOverlay (never OSS).
func TestRouteConsentFalseUniversalStaysOverlay(t *testing.T) {
	r := newRouter(t)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("consent=false must stay tenant_overlay, got %q", dec.Destination)
	}
	if dec.ArtifactPath != "" {
		t.Errorf("OSS artifact emitted without consent: %q", dec.ArtifactPath)
	}
	if provenanceCount(t, r.ArtifactDir) != 0 {
		t.Errorf("OSS artifact dir non-empty without consent")
	}
}

// (ii) consent=true universal -> OSSContribBack: OSS-PR artifact emitted AND the
// tenant overlay is still written; no auto-merge.
func TestRouteConsentTrueUniversalToOSS(t *testing.T) {
	r := newRouter(t)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), true)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestOSSContribBack {
		t.Fatalf("consent=true universal must be oss_contrib_back, got %q", dec.Destination)
	}
	if dec.ArtifactPath == "" {
		t.Fatalf("no OSS-PR artifact emitted")
	}
	if _, err := os.Stat(dec.ArtifactPath); err != nil {
		t.Errorf("OSS artifact file missing: %v", err)
	}
	// The tenant overlay is STILL written (the fix is never withheld).
	if dec.OverlayPath == "" {
		t.Fatalf("overlay not written on OSS route")
	}
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("overlay not written on OSS route")
	}
}

// (iii) net-new event_type -> HumanGate.
func TestRouteNetNewTypeToHumanGate(t *testing.T) {
	r := newRouter(t)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "brand_new_type"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("net-new type must be human_gate, got %q", dec.Destination)
	}
	// No overlay written for a human-gated proposal.
	if _, err := os.Stat(filepath.Join(r.OverlayDir, learnedMappingsFile)); !os.IsNotExist(err) {
		t.Errorf("overlay written for a human-gated proposal")
	}
}

// (iii) critical severity -> HumanGate even for an otherwise-clean widen.
func TestRouteCriticalToHumanGate(t *testing.T) {
	r := newRouter(t)
	p := mappingProposal("github", "repo.rename", "config_change")
	p.Severity = "critical"
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("critical severity must be human_gate, got %q", dec.Destination)
	}
}

// (iii) committee-calibration knob (a tuning key that is NOT an additive extra_*
// list) -> HumanGate.
func TestRouteKnobToHumanGate(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "priv_escalation", Key: "confidence_threshold", AddedValues: []string{"0.9"}},
		Fingerprint: "fp-knob",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("calibration knob must be human_gate, got %q", dec.Destination)
	}
}

// A valid additive tuning delta on an existing family -> TenantOverlay, written
// into tuning.yaml.
func TestRouteAdditiveTuningToOverlay(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "priv_escalation", Key: "extra_elevated_keywords", AddedValues: []string{"poweruser"}},
		Universal:   true,
		Fingerprint: "fp-tune",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("additive tuning must be tenant_overlay, got %q", dec.Destination)
	}
	data, err := os.ReadFile(dec.OverlayPath)
	if err != nil {
		t.Fatalf("read tuning overlay: %v", err)
	}
	var doc map[string]map[string][]string
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse tuning overlay: %v", err)
	}
	got := doc["priv_escalation"]["extra_elevated_keywords"]
	if len(got) != 1 || got[0] != "poweruser" {
		t.Errorf("tuning overlay = %+v, want [poweruser]", got)
	}
}

// A valid additive tuning delta whose detector family IS in a non-empty
// KnownDetectorFamilies vocab -> TenantOverlay (wiring
// KnownDetectorFamilies must not regress the already-known-family case).
func TestRouteKnownFamilyTuningToOverlay(t *testing.T) {
	r := newRouter(t)
	r.KnownDetectorFamilies = map[string]bool{"priv_escalation": true, "unusual-login": true}
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "priv_escalation", Key: "extra_elevated_keywords", AddedValues: []string{"poweruser"}},
		Universal:   true,
		Fingerprint: "fp-tune-known-family",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("known-family additive tuning must be tenant_overlay, got %q", dec.Destination)
	}
}

// A valid additive tuning delta whose detector family is NOT in a non-empty
// KnownDetectorFamilies vocab -> HumanGate (net-new detector family).
func TestRouteNetNewFamilyTuningToHumanGate(t *testing.T) {
	r := newRouter(t)
	r.KnownDetectorFamilies = map[string]bool{"priv_escalation": true}
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "brand_new_family", Key: "extra_elevated_keywords", AddedValues: []string{"poweruser"}},
		Universal:   true,
		Fingerprint: "fp-tune-net-new-family",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("net-new detector family must be human_gate, got %q", dec.Destination)
	}
	// No overlay written for a human-gated proposal.
	if _, err := os.Stat(filepath.Join(r.OverlayDir, tuningFile)); !os.IsNotExist(err) {
		t.Errorf("overlay written for a human-gated net-new-family proposal")
	}
}

// (iv) a consensus-bypass shape -> Forbidden, fingerprint poisoned.
func TestRouteConsensusBypassForbidden(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:         proposer.KindConsensusBypass,
		BypassReason: "family-match force-escalate rule",
		Fingerprint:  "fp-bypass",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestForbidden {
		t.Fatalf("consensus-bypass must be forbidden, got %q", dec.Destination)
	}
	if !r.Fingerprints.Has("fp-bypass") {
		t.Errorf("forbidden fingerprint not poisoned")
	}
}

// owner suppression (tenant-scoped) -> TenantOverlay (NOT forbidden), and NEVER
// OSS even with consent.
func TestRouteOwnerSuppressToOverlayNeverOSS(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindOwnerSuppress,
		Owner:       &proposer.OwnerSuppression{FindingType: "detector:unusual-login", Scope: "tenant:acme"},
		Universal:   false,
		Fingerprint: "fp-suppress",
	}
	dec, err := r.Route(p, greenGate(), true) // consent=true must NOT push a suppression to OSS
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("owner suppression must be tenant_overlay, got %q", dec.Destination)
	}
	if dec.ArtifactPath != "" {
		t.Errorf("owner suppression was contributed to OSS: %q", dec.ArtifactPath)
	}
}

// a GLOBAL suppression is a consensus bypass -> Forbidden.
func TestRouteGlobalSuppressForbidden(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindOwnerSuppress,
		Owner:       &proposer.OwnerSuppression{FindingType: "detector:unusual-login", Scope: "global"},
		Fingerprint: "fp-globalsuppress",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestForbidden {
		t.Fatalf("global suppression must be forbidden, got %q", dec.Destination)
	}
}

// a non-GREEN gate (no coverage delta) escalates to a human rather than
// auto-applying.
func TestRouteNonGreenGateToHumanGate(t *testing.T) {
	r := newRouter(t)
	gate := greenGate()
	gate.CoveragePlus = 0 // no coverage added
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), gate, false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("non-green gate must be human_gate, got %q", dec.Destination)
	}
}

// a gate that introduced a regression (NewFirings non-empty) escalates to a
// human even though it passed.
func TestRouteRegressionGateToHumanGate(t *testing.T) {
	r := newRouter(t)
	gate := greenGate()
	gate.NewFirings = []string{"benign-twin-now-fires"}
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), gate, false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("regression gate must be human_gate, got %q", dec.Destination)
	}
}

// WriteOverlay is append-only: a duplicate key is idempotent, a RETARGET of an
// existing (source, action) is refused (mirrors guard.checkMappingWidenOnly).
func TestOverlayAppendOnlyRefusesRetarget(t *testing.T) {
	r := newRouter(t)
	known := r.KnownEventTypes

	path, err := WriteOverlay(r.OverlayDir, mappingProposal("github", "repo.rename", "config_change"), known)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	// Idempotent re-write of the SAME mapping is a no-op (no error).
	if _, err := WriteOverlay(r.OverlayDir, mappingProposal("github", "repo.rename", "config_change"), known); err != nil {
		t.Fatalf("idempotent rewrite errored: %v", err)
	}
	// RETARGET of the frozen key is refused.
	if _, err := WriteOverlay(r.OverlayDir, mappingProposal("github", "repo.rename", "push"), known); err == nil {
		t.Fatalf("retarget of a frozen mapping was allowed (widen-only violated)")
	}
	// The original target survives.
	if readMappings(t, path)["github"]["repo.rename"] != "config_change" {
		t.Errorf("frozen mapping was mutated")
	}
	// A NEW (source, action) key appends fine.
	if _, err := WriteOverlay(r.OverlayDir, mappingProposal("github", "repo.transfer", "config_change"), known); err != nil {
		t.Fatalf("append of a new key failed: %v", err)
	}
	if readMappings(t, path)["github"]["repo.transfer"] != "config_change" {
		t.Errorf("new key not appended")
	}
}

// ---- autonomy dial matrix --------------------------------
//
// Router.Autonomy (autonomy.Dial) decides ONLY whether an
// otherwise-clean widen auto-applies to the tenant overlay. Below: for EACH of
// the three dial positions, one test proving what the dial ALLOWS to
// auto-apply and one proving what it still REJECTS (never auto-applies) —
// exercising the real Route() decision path, not a stub of it.

// autonomyRouter is newRouter with an explicit dial, for the matrix below (it
// deliberately does NOT reuse newRouter's SemiAutonomy default).
func autonomyRouter(t *testing.T, dial autonomy.Dial) *Router {
	t.Helper()
	r := newRouter(t)
	r.Autonomy = dial
	return r
}

// --- non: propose-only. Nothing auto-applies. ---

// ALLOW (non): the pipeline still runs a clean widen to completion — it is
// ALLOWED to reach a terminal, provenance-recorded decision (PendingApproval),
// not an error and not silently dropped.
func TestRouteAutonomyNonAllowsQueuingForApproval(t *testing.T) {
	r := autonomyRouter(t, autonomy.NonAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestPendingApproval {
		t.Fatalf("autonomy=non clean widen: destination = %q, want pending_approval", dec.Destination)
	}
	if provenanceCount(t, r.ProvenanceDir) != 1 {
		t.Errorf("autonomy=non: decision not recorded in provenance")
	}
}

// REJECT (non): the SAME clean widen that would auto-write under semi/fully
// does NOT write the overlay — no side effect happens at all.
func TestRouteAutonomyNonRejectsAutoWrite(t *testing.T) {
	r := autonomyRouter(t, autonomy.NonAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.OverlayPath != "" {
		t.Fatalf("autonomy=non must not write an overlay, got OverlayPath=%q", dec.OverlayPath)
	}
	if _, err := os.Stat(filepath.Join(r.OverlayDir, learnedMappingsFile)); !os.IsNotExist(err) {
		t.Errorf("autonomy=non: overlay file exists on disk despite propose-only dial")
	}
}

// --- semi: DATA auto-applies. ---

// ALLOW (semi): a clean widen auto-writes the overlay with no human step.
func TestRouteAutonomySemiAllowsDataAutoApply(t *testing.T) {
	r := autonomyRouter(t, autonomy.SemiAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("autonomy=semi clean widen: destination = %q, want tenant_overlay", dec.Destination)
	}
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("autonomy=semi: overlay not auto-written")
	}
}

// REJECT (semi): the dial's auto-apply does NOT extend to a structurally
// HUMAN-GATE-worthy proposal (net-new event_type) — semi only widens what the
// existing HUMAN-GATE/FORBIDDEN checks already allow through.
func TestRouteAutonomySemiRejectsNetNewType(t *testing.T) {
	r := autonomyRouter(t, autonomy.SemiAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "brand_new_type"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("autonomy=semi net-new type: destination = %q, want human_gate", dec.Destination)
	}
	if dec.OverlayPath != "" {
		t.Errorf("autonomy=semi: overlay written for a human-gated net-new type")
	}
}

// --- fully: DATA and CODE both auto-apply (code lane: see engine_test.go). ---

// ALLOW (fully): a clean widen auto-writes the overlay, same as semi.
func TestRouteAutonomyFullyAllowsDataAutoApply(t *testing.T) {
	r := autonomyRouter(t, autonomy.FullyAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("autonomy=fully clean widen: destination = %q, want tenant_overlay", dec.Destination)
	}
	if readMappings(t, dec.OverlayPath)["github"]["repo.rename"] != "config_change" {
		t.Errorf("autonomy=fully: overlay not auto-written")
	}
}

// REJECT (fully): the HARD LINE — even at maximum autonomy, with explicit
// per-build consent and a universal widen, OSS contribute-back is STILL never
// auto-merged: an OSS-PR artifact is emitted for human/maintainer review, full
// stop (not operator-overridable by the dial).
func TestRouteAutonomyFullyStillRequiresHumanForOSS(t *testing.T) {
	r := autonomyRouter(t, autonomy.FullyAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), true /* consent=true */)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestOSSContribBack {
		t.Fatalf("autonomy=fully consented universal widen: destination = %q, want oss_contrib_back", dec.Destination)
	}
	if dec.ArtifactPath == "" {
		t.Fatalf("autonomy=fully: no OSS-PR artifact emitted for human review")
	}
	// The artifact is a REVIEWABLE file on disk, not a merge/push: proving no
	// merge happened is exactly proving it is still a plain artifact file.
	info, err := os.Stat(dec.ArtifactPath)
	if err != nil {
		t.Fatalf("OSS artifact missing: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("OSS artifact path is a directory, want a reviewable file")
	}
}

// ---- NovelGap forces human review (BOTH ruling, part B) ------
//
// GateResult.NovelGap mirrors the SAME dial-independent hard line already
// proven above for OSS contribute-back (TestRouteAutonomyFullyStillRequiresHumanForOSS):
// a signal the gate itself raises that MUST escalate to human review
// regardless of the autonomy dial. Below: one test proving NovelGap forces
// human_gate even at "fully" (the most permissive dial — the strongest
// possible proof it is never bypassed), and one contrast test proving a
// gate-GREEN, NON-novel-gap (reference-covered) widen auto-routes NORMALLY at
// "fully", so the NovelGap check is not silently over-firing on every widen.

// novelGapGate is greenGate() with NovelGap set — otherwise a certifying,
// GREEN, coverage+1, zero-regression gate result.
func novelGapGate(families ...string) engine.GateResult {
	g := greenGate()
	g.NovelGap = true
	g.NovelGapFamilies = families
	return g
}

// REJECT (fully): NovelGap forces human_gate even at maximum autonomy — the
// SAME dial-independent treatment OSS contribute-back gets, proven against
// the most permissive dial position for the strongest possible guarantee.
func TestRouteAutonomyFullyNovelGapForcesHumanGate(t *testing.T) {
	r := autonomyRouter(t, autonomy.FullyAutonomy)
	gate := novelGapGate("newsource-newfamily")
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), gate, false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("autonomy=fully NovelGap=true: destination = %q, want human_gate", dec.Destination)
	}
	if dec.OverlayPath != "" {
		t.Errorf("autonomy=fully NovelGap=true: overlay must NOT be written, got %q", dec.OverlayPath)
	}
}

// ALLOW (fully, contrast): a gate-GREEN widen with NovelGap==false (the
// reference corpus DOES have labeled must_fire coverage for the family — see
// mallcop core/selfgate's TestValidateProposal_CustomerTreeExamAcceptsPassingDetector_
// ReferenceCoveredFamilyIsNotNovelGap for the mallcop-side proof of this same
// contrast) auto-routes NORMALLY at "fully" — proving the NovelGap check does
// not over-reject every widen, only the ones the gate itself flags.
func TestRouteAutonomyFullyReferenceCoveredFamilyRoutesNormally(t *testing.T) {
	r := autonomyRouter(t, autonomy.FullyAutonomy)
	dec, err := r.Route(mappingProposal("github", "repo.rename", "config_change"), greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("autonomy=fully non-novel-gap clean widen: destination = %q, want tenant_overlay", dec.Destination)
	}
	if dec.OverlayPath == "" {
		t.Errorf("autonomy=fully non-novel-gap clean widen: overlay not written")
	}
}
