package pipeline

import (
	"encoding/json"
	"testing"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// mkCaseFinding builds a finding.Finding carrying an Evidence blob with a
// "grantee" key — the same entityKeys core/cases.ExtractEntity reads — so
// findingCaseID resolves a real, non-empty Entity, exactly like the
// new-external-access detector's real output (core/detect/new_external_access.go).
func mkCaseFinding(t *testing.T, id, typ, actor, entity string) finding.Finding {
	t.Helper()
	evidence, err := json.Marshal(map[string]string{"grantee": entity})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return finding.Finding{ID: id, Source: "detector:new-external-access", Type: typ, Actor: actor, Evidence: evidence}
}

// caseIDFor computes the SAME CaseID findingCaseID/ApplySuppressCase would
// derive for a finding with this (type, actor, entity) — the test's own
// independent computation of the value a real console/CLI would read off a
// finding it showed the operator, so the directive fixture below is built
// exactly the way a real caller would build it (from the case ID, never a
// guessed string).
func caseIDFor(typ, actor, entity string) string {
	return cases.CaseID(cases.Key{Type: typ, Actor: actor, Entity: entity})
}

// TestApplySuppressCase_DropsOnlyNamedCase_SiblingEntitySurvives is the
// mallcoppro-419 load-bearing proof at the unit level: two findings share
// Type+Actor but differ ONLY by Entity (alice vs bob) — core/cases'
// TestCollapse_DistinctEntity_DistinctCases already proves these are
// distinct cases. A 'suppress-case' directive naming ONLY alice's case must
// drop alice's finding and leave bob's untouched. This is explicitly the
// point of the item, not an incidental property.
func TestApplySuppressCase_DropsOnlyNamedCase_SiblingEntitySurvives(t *testing.T) {
	alice := mkCaseFinding(t, "f-alice", "new-external-access", "admin", "alice")
	bob := mkCaseFinding(t, "f-bob", "new-external-access", "admin", "bob")
	findings := []finding.Finding{alice, bob}

	aliceCaseID := caseIDFor("new-external-access", "admin", "alice")
	bobCaseID := caseIDFor("new-external-access", "admin", "bob")
	if aliceCaseID == bobCaseID {
		t.Fatalf("test fixture invalid: alice and bob must hash to DIFFERENT case IDs, got %q for both", aliceCaseID)
	}

	directives := []store.Directive{
		{Op: "suppress-case", Pattern: aliceCaseID},
	}
	kept := ApplySuppressCase(findings, directives)

	if len(kept) != 1 {
		t.Fatalf("want 1 kept finding, got %d: %+v", len(kept), kept)
	}
	if kept[0].ID != "f-bob" {
		t.Fatalf("kept finding = %q, want f-bob (alice's case should have been suppressed, bob's sibling case must survive)", kept[0].ID)
	}
}

// TestApplySuppressCase_NoMatchingDirective_KeepsAll proves a directive
// naming some OTHER case ID (not present in the finding set) drops nothing.
func TestApplySuppressCase_NoMatchingDirective_KeepsAll(t *testing.T) {
	findings := []finding.Finding{
		mkCaseFinding(t, "f1", "new-external-access", "admin", "alice"),
	}
	directives := []store.Directive{
		{Op: "suppress-case", Pattern: "0123456789ab"}, // matches no real case here
	}
	kept := ApplySuppressCase(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("want 1 kept, got %d", len(kept))
	}
}

// TestApplySuppressCase_EmptyDirectives_ReturnsAllUnchanged mirrors
// applyDirectives' own nil/empty-directives contract.
func TestApplySuppressCase_EmptyDirectives_ReturnsAllUnchanged(t *testing.T) {
	findings := []finding.Finding{
		mkCaseFinding(t, "f1", "new-external-access", "admin", "alice"),
		mkCaseFinding(t, "f2", "new-external-access", "admin", "bob"),
	}
	kept := ApplySuppressCase(findings, nil)
	if len(kept) != 2 {
		t.Fatalf("nil directives must keep all, got %d", len(kept))
	}
}

// TestApplySuppressCase_OtherOpsWithMatchingPatternIgnored proves Op
// discrimination: a directive whose Pattern happens to equal a real case ID
// but whose Op is NOT "suppress-case" (e.g. the pre-existing "suppress",
// whose Pattern vocabulary is the source/type/actor triple, not a case ID)
// must never be treated as a case suppression here.
func TestApplySuppressCase_OtherOpsWithMatchingPatternIgnored(t *testing.T) {
	findings := []finding.Finding{
		mkCaseFinding(t, "f1", "new-external-access", "admin", "alice"),
	}
	aliceCaseID := caseIDFor("new-external-access", "admin", "alice")
	directives := []store.Directive{
		{Op: "suppress", Pattern: aliceCaseID}, // wrong op, coincidental pattern value
		{Op: "focus", Pattern: aliceCaseID},
		{Op: "mute", Pattern: aliceCaseID},
	}
	kept := ApplySuppressCase(findings, directives)
	if len(kept) != 1 {
		t.Fatalf("want 1 kept (no suppress-case op present), got %d", len(kept))
	}
}

// TestApplySuppressCase_ExistingSuppressOpUnaffected proves the pre-existing
// finding-key 'suppress' op (applyDirectives/matchPattern) is completely
// untouched by this file: composing applyDirectives with ApplySuppressCase
// over a mixed directive set drops exactly the findings each op targets,
// independently.
func TestApplySuppressCase_ExistingSuppressOpUnaffected(t *testing.T) {
	// f1/f2 share type+actor but differ by entity -> distinct cases.
	// f3 is an unrelated finding targeted by a classic finding-key suppress.
	f1 := mkCaseFinding(t, "f1", "new-external-access", "admin", "alice")
	f2 := mkCaseFinding(t, "f2", "new-external-access", "admin", "bob")
	f3 := finding.Finding{ID: "f3", Source: "detector:secrets-exposure", Type: "secrets-exposure", Actor: "carol"}
	findings := []finding.Finding{f1, f2, f3}

	aliceCaseID := caseIDFor("new-external-access", "admin", "alice")
	directives := []store.Directive{
		{Op: "suppress-case", Pattern: aliceCaseID},
		{Op: "suppress", Pattern: "detector:secrets-exposure/secrets-exposure/carol"},
	}

	// applyDirectives (the pre-existing finding-key path) and
	// ApplySuppressCase (this item's new path) compose exactly as
	// pipeline.go wires them: each filters independently.
	afterClassicSuppress := applyDirectives(findings, directives)
	kept := ApplySuppressCase(afterClassicSuppress, directives)

	if len(kept) != 1 {
		t.Fatalf("want 1 kept (only bob's sibling case survives both filters), got %d: %+v", len(kept), kept)
	}
	if kept[0].ID != "f2" {
		t.Fatalf("kept = %q, want f2 (bob)", kept[0].ID)
	}
}

// TestFindingCaseID_MatchesCasesPackageHash proves findingCaseID is not an
// independently re-derived clustering path (the exact drift bug
// core/cases.CaseID's own doc comment warns against) — it must produce
// byte-identical output to calling core/cases.CaseID directly.
func TestFindingCaseID_MatchesCasesPackageHash(t *testing.T) {
	f := mkCaseFinding(t, "f1", "new-external-access", "admin", "alice")
	want := cases.CaseID(cases.Key{Type: "new-external-access", Actor: "admin", Entity: "alice"})
	if got := findingCaseID(f); got != want {
		t.Fatalf("findingCaseID = %q, want %q (must match core/cases.CaseID exactly)", got, want)
	}
}
