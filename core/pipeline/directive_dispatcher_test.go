package pipeline

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestNewDirectiveDispatcher_SuppressDropsMatch proves the DROP path on the
// dispatcher's own Apply (not the applyDirectives wrapper): a suppress
// directive removes the matching finding.
func TestNewDirectiveDispatcher_SuppressDropsMatch(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	d := NewDirectiveDispatcher()
	kept := d.Apply(findings, directives)
	if len(kept) != 1 || kept[0].ID != "f2" {
		t.Fatalf("expected only f2 kept, got %+v", kept)
	}
}

// TestNewDirectiveDispatcher_NoMatchKeepsFinding proves the KEEP path: a
// finding that no directive matches survives untouched.
func TestNewDirectiveDispatcher_NoMatchKeepsFinding(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:new-actor", "new-actor", "bob"),
	}
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	d := NewDirectiveDispatcher()
	kept := d.Apply(findings, directives)
	if len(kept) != 1 || kept[0].ID != "f1" {
		t.Fatalf("expected f1 kept (no matching directive), got %+v", kept)
	}
}

// TestDirectiveDispatcher_UnregisteredOpIsNoop proves an Op with no
// registered consumer (e.g. "focus"/"mute" on the default dispatcher, which
// only registers suppress/unsuppress) matches but never drops — the registry
// contract other stages hook into without touching this file.
func TestDirectiveDispatcher_UnregisteredOpIsNoop(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
	}
	directives := []store.Directive{
		{Op: "focus", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	d := NewDirectiveDispatcher()
	kept := d.Apply(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("unregistered op must not drop, got %d kept", len(kept))
	}
}

// TestDirectiveDispatcher_Register_CustomOpCanDrop proves the extension
// point: a caller registers a new Op consumer (simulating a future mute-TTL
// or case-close consumer) and it participates in the same Apply loop as
// suppress/unsuppress, without editing directives.go.
func TestDirectiveDispatcher_Register_CustomOpCanDrop(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
	}
	directives := []store.Directive{
		{Op: "mute", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	d := NewDirectiveDispatcher()
	d.Register("mute", func(v *FindingVerdict, _ store.Directive, _ finding.Finding) {
		v.Suppressed = true
	})
	kept := d.Apply(findings, directives)
	if len(kept) != 1 || kept[0].ID != "f2" {
		t.Fatalf("registered mute consumer should have dropped f1, got %+v", kept)
	}
}

// TestDirectiveDispatcher_Register_Override proves re-registering an Op
// (e.g. tests overriding the default suppress consumer) replaces the prior
// consumer rather than stacking both.
func TestDirectiveDispatcher_Register_Override(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
	}
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
	}
	d := NewDirectiveDispatcher()
	d.Register("suppress", func(v *FindingVerdict, _ store.Directive, _ finding.Finding) {
		// override: never suppress
	})
	kept := d.Apply(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("overridden suppress consumer should not drop, got %d kept", len(kept))
	}
}

// TestApplyDirectives_MatchesDefaultDispatcher is a characterization check
// that the applyDirectives wrapper (used by pipeline.go and the pre-existing
// directives_test.go suite) produces exactly what NewDirectiveDispatcher().Apply
// produces — i.e. the refactor did not change the wrapper's wiring.
func TestApplyDirectives_MatchesDefaultDispatcher(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("f1", "detector:secrets-exposure", "secrets-exposure", "alice"),
		mkFinding("f2", "detector:new-actor", "new-actor", "bob"),
		mkFinding("f3", "detector:secrets-exposure", "secrets-exposure", "carol"),
	}
	directives := []store.Directive{
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/alice"},
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/carol"},
		{Op: "unsuppress", Pattern: "detector:secrets-exposure/secrets-exposure/carol"},
		{Op: "focus", Pattern: "detector:new-actor/new-actor/bob"},
	}
	want := applyDirectives(findings, directives)
	got := NewDirectiveDispatcher().Apply(findings, directives)
	if len(want) != len(got) {
		t.Fatalf("length mismatch: wrapper=%d dispatcher=%d", len(want), len(got))
	}
	for i := range want {
		if want[i].ID != got[i].ID {
			t.Fatalf("order/content mismatch at %d: wrapper=%s dispatcher=%s", i, want[i].ID, got[i].ID)
		}
	}
}
