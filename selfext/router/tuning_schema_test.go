package router

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/selfext/proposer"
)

// mallcoppro-2c2 (SUBSUMES mallcoppro-f7f): a DATA-lane tuning proposal that
// passes every writer-side check (additive key on the closed enum, own-gap
// match) could still produce a tuning.yaml document core/detect/tuning.go's
// strict KnownFields decode HARD-REJECTS on the very next scan — two
// independent ways:
//
//  1. KEY dimension (=f7f): the proposer's additiveTuningKeys allow-list used
//     to advertise extra_admin_actions/extra_sensitive_actions — no field in
//     PrivEscalationTuning backs either one.
//  2. SECTION dimension: a widen for ANY detector family other than
//     priv-escalation (e.g. "unusual-login", a REAL registered detector, see
//     core/detect.frameworkDetectorNames) normalizes to a top-level tuning.yaml
//     section ("unusual_login") the loader's Tuning struct has no field for at
//     all — unknown section, same hard error.
//
// These tests prove BOTH dimensions now route to HUMAN-GATE (never write a
// poison overlay), that a genuine priv-escalation widen still lands and is
// LOADABLE by the real detect.LoadTuningFile (regression proof), and that the
// exported WriteOverlay itself (not just Router.Route's pre-check) refuses to
// write either poison shape — the belt-and-suspenders defense cli/selfext.go's
// proposeGateViaWorktree depends on, since it calls WriteOverlay directly,
// ahead of Router.Route ever running.

// tuningOverlayPath mirrors overlay.go's private path join, for tests that
// need to assert a file was (or was not) written without going through Route.
func tuningOverlayPath(dir string) string {
	return filepath.Join(dir, tuningFile)
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected %q to not exist, stat err = %v", path, err)
	}
}

// (1) SECTION dimension: "unusual-login" is a real, registered detector family
// (core/detect.frameworkDetectorNames) but has NO tuning.yaml section in the
// loader's schema (only priv_escalation exists). A widen with an otherwise
// perfectly valid additive key must route to HUMAN-GATE, not TenantOverlay —
// and MUST NOT write tuning.yaml at all (a partial/poison write is exactly
// what this item forbids).
func TestRouteTuningUnknownSectionRoutesToHumanGate(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "unusual-login", Key: "extra_elevated_keywords", AddedValues: []string{"shadowops"}},
		Universal:   true,
		Fingerprint: "fp-unknown-section",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("family with no loadable tuning section: destination = %q, want human_gate", dec.Destination)
	}
	if dec.OverlayPath != "" {
		t.Errorf("family with no loadable tuning section: OverlayPath = %q, want empty (never written)", dec.OverlayPath)
	}
	mustNotExist(t, tuningOverlayPath(r.OverlayDir))
}

// (2) KEY dimension (=f7f): a phantom key that was formerly advertised
// (extra_admin_actions) but backed by no loader field must ALSO route to
// HUMAN-GATE, not TenantOverlay, and must not write tuning.yaml.
func TestRouteTuningPhantomKeyRoutesToHumanGate(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "priv_escalation", Key: "extra_admin_actions", AddedValues: []string{"grant-admin"}},
		Universal:   true,
		Fingerprint: "fp-phantom-key",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestHumanGate {
		t.Fatalf("phantom tuning key: destination = %q, want human_gate", dec.Destination)
	}
	if dec.OverlayPath != "" {
		t.Errorf("phantom tuning key: OverlayPath = %q, want empty (never written)", dec.OverlayPath)
	}
	mustNotExist(t, tuningOverlayPath(r.OverlayDir))

	// Belt-and-suspenders proof: IsAdditiveTuningKey itself now rejects the
	// phantom key (the pruned allow-list, mallcoppro-2c2 fix (a)) — the
	// human-gate route above is not an accident of the schema check alone.
	if proposer.IsAdditiveTuningKey("extra_admin_actions") {
		t.Errorf("extra_admin_actions must no longer be an additive key (no PrivEscalationTuning field backs it)")
	}
	if proposer.IsAdditiveTuningKey("extra_sensitive_actions") {
		t.Errorf("extra_sensitive_actions must no longer be an additive key (no PrivEscalationTuning field backs it)")
	}
}

// (3) REGRESSION: a genuine priv-escalation widen with a real schema key still
// lands at TenantOverlay AND round-trips through the REAL core/detect
// loader (detect.LoadTuningFile), not just a generic yaml.Unmarshal — proving
// the fix did not collaterally break the one section/key combination that
// MUST keep working.
func TestRouteAdditiveTuningRoundTripsThroughRealLoader(t *testing.T) {
	r := newRouter(t)
	p := proposer.Proposal{
		Kind:        proposer.KindTuning,
		Tuning:      &proposer.TuningDelta{Detector: "priv-escalation", Key: "extra_elevated_action_keywords", AddedValues: []string{"grant-superuser"}},
		Universal:   true,
		Fingerprint: "fp-real-loader-roundtrip",
	}
	dec, err := r.Route(p, greenGate(), false)
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if dec.Destination != DestTenantOverlay {
		t.Fatalf("valid priv-escalation widen: destination = %q, want tenant_overlay", dec.Destination)
	}
	if dec.OverlayPath == "" {
		t.Fatalf("valid priv-escalation widen: overlay not written")
	}

	loaded, err := detect.LoadTuningFile(dec.OverlayPath)
	if err != nil {
		t.Fatalf("detect.LoadTuningFile(%s): %v (a real widen must be loadable by the real reader — this is the exact failure mode this item closes)", dec.OverlayPath, err)
	}
	got := loaded.PrivEscalation.ExtraElevatedActionKeywords
	if len(got) != 1 || got[0] != "grant-superuser" {
		t.Fatalf("loaded tuning PrivEscalation.ExtraElevatedActionKeywords = %+v, want [grant-superuser]", got)
	}
}

// (4) WriteOverlay defense-in-depth: cli/selfext.go's proposeGateViaWorktree
// calls the exported router.WriteOverlay DIRECTLY, ahead of Router.Route's own
// pre-check (it needs a written overlay to compute the gate result in the
// first place). WriteOverlay itself — not just Route's humanGateReason — must
// refuse to write either poison shape, or that path would still corrupt a
// (throwaway, but real-shaped) tuning.yaml.
func TestWriteOverlayRefusesUnknownSection(t *testing.T) {
	dir := t.TempDir()
	p := proposer.Proposal{
		Kind:   proposer.KindTuning,
		Tuning: &proposer.TuningDelta{Detector: "unusual-login", Key: "extra_elevated_keywords", AddedValues: []string{"shadowops"}},
	}
	if _, err := WriteOverlay(dir, p, nil); err == nil {
		t.Fatalf("WriteOverlay: want error for a family with no loadable tuning section, got nil")
	}
	mustNotExist(t, tuningOverlayPath(dir))
}

func TestWriteOverlayRefusesPhantomKey(t *testing.T) {
	dir := t.TempDir()
	// WriteOverlay is exported and called directly by cli/selfext.go's
	// proposeGateViaWorktree, ahead of Router.Route's own pre-check — this
	// proves writeTuningOverlay itself refuses a phantom key (defense in
	// depth), not merely that Router.Route happens to catch it first. It is
	// caught twice over now: the pruned proposer.IsAdditiveTuningKey allow-list
	// rejects it (fix (a)), and writeTuningOverlay's own
	// detect.KnownTuningKey schema check would independently reject it even
	// if some future caller constructed a TuningDelta bypassing the proposer
	// package's IsAdditiveTuningKey check entirely.
	p := proposer.Proposal{
		Kind:   proposer.KindTuning,
		Tuning: &proposer.TuningDelta{Detector: "priv-escalation", Key: "extra_elevated_keywords", AddedValues: []string{"poweruser"}},
	}
	// Sanity: this one IS valid and must succeed, proving the negative test
	// below isn't vacuous (a broken helper that always errors).
	if _, err := WriteOverlay(dir, p, nil); err != nil {
		t.Fatalf("WriteOverlay: valid priv-escalation widen must succeed, got %v", err)
	}

	badDir := t.TempDir()
	bad := proposer.Proposal{
		Kind:   proposer.KindTuning,
		Tuning: &proposer.TuningDelta{Detector: "priv-escalation", Key: "extra_admin_actions", AddedValues: []string{"grant-admin"}},
	}
	if _, err := WriteOverlay(badDir, bad, nil); err == nil {
		t.Fatalf("WriteOverlay: want error for phantom key extra_admin_actions, got nil")
	}
	mustNotExist(t, tuningOverlayPath(badDir))
}
