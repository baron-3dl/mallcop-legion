package pipeline

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

func mkFinding(id, source, ftype, actor string) finding.Finding {
	return finding.Finding{ID: id, Source: source, Type: ftype, Actor: actor}
}

// TestApplyDirectives_SuppressRemovesMatchAndLeavesOthers is the load-bearing
// proof: a suppress directive removes ONLY the matching finding; every other
// finding survives.
func TestApplyDirectives_SuppressRemovesMatchAndLeavesOthers(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
		mkFinding("f3", "detector:secrets-exposure", "secrets-exposure", "carol"),
	}
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}

	kept := applyDirectives(findings, directives)

	if len(kept) != 2 {
		t.Fatalf("expected 2 kept, got %d: %+v", len(kept), kept)
	}
	for _, f := range kept {
		if f.ID == "f1" {
			t.Fatalf("f1 should have been suppressed, but it survived")
		}
	}
	// The two non-matching findings must survive, in order.
	if kept[0].ID != "f2" || kept[1].ID != "f3" {
		t.Fatalf("survivors out of order or wrong: %+v", kept)
	}
}

func TestApplyDirectives_GlobMatchesActorWildcard(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:secrets-exposure", "secrets-exposure", "carol"),
		mkFinding("f3", "detector:new-actor", "new-actor", "bob"),
	}
	// '*' actor: suppress ALL secrets-exposure findings regardless of actor.
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/*"},
	}
	kept := applyDirectives(findings, directives)
	if len(kept) != 1 || kept[0].ID != "f3" {
		t.Fatalf("glob suppress wrong: %+v", kept)
	}
}

func TestApplyDirectives_PrefixPatternMatchesBySource(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	// One-segment pattern: source only — suppress everything from this detector.
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure"},
	}
	kept := applyDirectives(findings, directives)
	if len(kept) != 1 || kept[0].ID != "f2" {
		t.Fatalf("prefix suppress wrong: %+v", kept)
	}
}

func TestApplyDirectives_UnsuppressCancelsLaterWins(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
	}
	// Replay order is oldest-first: suppress then unsuppress => kept.
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
		{Op: "unsuppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	kept := applyDirectives(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("unsuppress should restore the finding, got %d kept", len(kept))
	}
}

// TestApplyDirectives_NonDropOpsAreNoops proves an Op with NO registered
// consumer never drops a finding. 'focus' has no consumer wired in this
// package yet (Gap C's attention weighting lands elsewhere), so it stays the
// no-op-verb characterization this test was written for. 'mute' USED to be
// in this list pre-mallcoppro-ae2 (documented vocabulary, no consumer); it
// is now implemented (core/pipeline/consumer_mute.go registers a drop
// consumer honoring Meta.expires_at) and is proven separately in
// consumer_mute_test.go — it is no longer a no-op and must not be asserted
// as one here.
func TestApplyDirectives_NonDropOpsAreNoops(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
	}
	directives := []store.Directive{
		{Op: "focus", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	kept := applyDirectives(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("focus must not drop findings, got %d kept", len(kept))
	}
}

func TestApplyDirectives_EmptyDirectivesKeepsAll(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	kept := applyDirectives(findings, nil)
	if len(kept) != 2 {
		t.Fatalf("nil directives must keep all, got %d", len(kept))
	}
}

func TestMatchPattern_EmptyPatternNeverMatches(t *testing.T) {
	f := mkFinding("f1", "s", "t", "a")
	if matchPattern("", f) {
		t.Fatal("empty pattern must not match")
	}
}

func TestMatchPattern_OverSpecifiedNeverMatches(t *testing.T) {
	f := mkFinding("f1", "s", "t", "a")
	if matchPattern("s/t/a/extra", f) {
		t.Fatal("over-specified pattern (>3 segments) must not match")
	}
}

func TestFindingKey_Shape(t *testing.T) {
	f := mkFinding("f1", "detector:new-actor", "new-actor", "bob")
	if got, want := findingKey(f), "detector:new-actor/new-actor/bob"; got != want {
		t.Fatalf("findingKey = %q, want %q", got, want)
	}
}
