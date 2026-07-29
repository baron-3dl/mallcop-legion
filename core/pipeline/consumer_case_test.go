package pipeline

import (
	"testing"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
)

func TestApplyCaseDirectives_CloseCase_TargetsPatternOnly(t *testing.T) {
	existing := []cases.Case{
		{CaseID: "case-a", Status: "recurring"},
		{CaseID: "case-b", Status: "recurring"},
	}
	directives := []store.Directive{
		{Op: "close-case", Pattern: "case-a"},
	}
	got := ApplyCaseDirectives(existing, directives)
	byID := make(map[string]cases.Case, len(got))
	for _, c := range got {
		byID[c.CaseID] = c
	}
	if byID["case-a"].Status != cases.StatusClosed {
		t.Errorf("case-a status = %q, want %q", byID["case-a"].Status, cases.StatusClosed)
	}
	if byID["case-b"].Status != "recurring" {
		t.Errorf("case-b status = %q, want unchanged %q", byID["case-b"].Status, "recurring")
	}
}

func TestApplyCaseDirectives_RecurrenceFine_SetsAged(t *testing.T) {
	existing := []cases.Case{{CaseID: "case-a", Status: "recurring"}}
	directives := []store.Directive{{Op: "recurrence-fine", Pattern: "case-a"}}
	got := ApplyCaseDirectives(existing, directives)
	if got[0].Status != cases.StatusAged {
		t.Errorf("status = %q, want %q", got[0].Status, cases.StatusAged)
	}
}

func TestApplyCaseDirectives_UnregisteredOp_NoOp(t *testing.T) {
	existing := []cases.Case{{CaseID: "case-a", Status: "recurring"}}
	directives := []store.Directive{{Op: "suppress", Pattern: "case-a"}}
	got := ApplyCaseDirectives(existing, directives)
	if got[0].Status != "recurring" {
		t.Errorf("status changed by an op with no case consumer: %q", got[0].Status)
	}
}

func TestApplyCaseDirectives_UnmatchedPattern_NoOp(t *testing.T) {
	existing := []cases.Case{{CaseID: "case-a", Status: "recurring"}}
	directives := []store.Directive{{Op: "close-case", Pattern: "case-zzz"}}
	got := ApplyCaseDirectives(existing, directives)
	if got[0].Status != "recurring" {
		t.Errorf("status changed for an unmatched pattern: %q", got[0].Status)
	}
}

func TestApplyCaseDirectives_ReplayOrder_LastWordWins(t *testing.T) {
	existing := []cases.Case{{CaseID: "case-a", Status: "recurring"}}
	directives := []store.Directive{
		{Op: "close-case", Pattern: "case-a"},
		{Op: "recurrence-fine", Pattern: "case-a"},
	}
	got := ApplyCaseDirectives(existing, directives)
	if got[0].Status != cases.StatusAged {
		t.Errorf("status = %q, want the LATER directive (%q) to win", got[0].Status, cases.StatusAged)
	}
}
