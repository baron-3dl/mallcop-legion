package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
)

// buildRecurringCase runs 2 force-push scans for the same actor so the store
// ends up with exactly 1 recurring case in cases.json, and returns
// (storePath, caseID). Reuses the fixtures cases_test.go already defines in
// this package (gitOopsEventWithID, writeKnownActorsBaseline).
func buildRecurringCase(t *testing.T) (storePath, caseID string) {
	t.Helper()
	dir := t.TempDir()
	storePath = filepath.Join(dir, "store")
	baselinePath := filepath.Join(dir, "baseline.json")
	writeKnownActorsBaseline(t, baselinePath, "dev")

	ids := []string{"g1", "g2"}
	stamps := []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"}
	for i, id := range ids {
		eventsPath := filepath.Join(dir, "events-"+id+".jsonl")
		writeFile(t, eventsPath, gitOopsEventWithID(id, stamps[i]))
		err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath, "--baseline", baselinePath})
		if !isFindingsError(err) {
			t.Fatalf("scan %d (%s): want findings sentinel, got %v", i+1, id, err)
		}
	}

	got := readCasesJSON(t, storePath)
	if len(got) != 1 {
		t.Fatalf("setup: want 1 case, got %d: %+v", len(got), got)
	}
	if got[0].Status != "recurring" {
		t.Fatalf("setup: want status recurring before the close-case directive, got %q", got[0].Status)
	}
	return storePath, got[0].CaseID
}

// TestRunCaseClose_DrivesCollapseToClosedState is the item's ENFORCEMENT
// test (mallcoppro-a1c): issuing `mallcop case close <id>` persists a
// close-case directive, and replaying it (via collapseCases, the same call
// site `mallcop scan` always makes) transitions the TARGETED case's status
// from "recurring" to "closed" on the real, git-backed case store —
// core/cases.Collapse's byID lookup, formerly stuck producing only
// "open"/"recurring", now reflects the close/age verb core/cases.SetStatus
// adds. A SECOND, unrelated case with no directive against it must be left
// alone — proves the consumer targets by case_id, not a blanket effect.
func TestRunCaseClose_DrivesCollapseToClosedState(t *testing.T) {
	storePath, caseID := buildRecurringCase(t)

	// A second, distinct case (different actor/entity) in the SAME store,
	// with no directive issued against it — the control case.
	otherEventsPath := filepath.Join(filepath.Dir(storePath), "events-other.jsonl")
	writeFile(t, otherEventsPath, externalAccessEvent("e1", "2026-01-01T02:00:00Z", "carol"))
	writeKnownActorsBaseline(t, filepath.Join(filepath.Dir(storePath), "baseline2.json"), "dev", "admin")
	if err := runScan([]string{"--store", storePath, "--connector", "file", "--events", otherEventsPath,
		"--baseline", filepath.Join(filepath.Dir(storePath), "baseline2.json")}); !isFindingsError(err) {
		t.Fatalf("control-case scan: want findings sentinel, got %v", err)
	}
	before := readCasesJSON(t, storePath)
	var otherCaseID string
	for _, c := range before {
		if c.CaseID != caseID {
			otherCaseID = c.CaseID
		}
	}
	if otherCaseID == "" {
		t.Fatalf("setup: expected a second, distinct case besides %s: %+v", caseID, before)
	}

	if err := runCase([]string{"close", caseID, "--store", storePath, "--reason", "handled", "--by", "baron"}); err != nil {
		t.Fatalf("runCase close: %v", err)
	}

	// Replaying the directive is what cli/scan.go's collapseCases call does
	// on every scan (mallcoppro-a1c's design: replay every call, not just
	// when new escalations land). Drive it directly with thisRun=0 (no new
	// findings this call) to prove the directive-only replay path — the
	// EXACT scenario a close-case issued between scans needs, since a case
	// that never recurs again must still end up closed.
	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := collapseCases(st, 0); err != nil {
		t.Fatalf("collapseCases replay: %v", err)
	}

	got := readCasesJSON(t, storePath)
	var target, other *cases.Case
	for i := range got {
		switch got[i].CaseID {
		case caseID:
			target = &got[i]
		case otherCaseID:
			other = &got[i]
		}
	}
	if target == nil {
		t.Fatalf("target case %s missing after replay: %+v", caseID, got)
	}
	if target.Status != cases.StatusClosed {
		t.Errorf("target case status = %q, want %q", target.Status, cases.StatusClosed)
	}
	if other == nil {
		t.Fatalf("control case %s missing after replay: %+v", otherCaseID, got)
	}
	if other.Status == cases.StatusClosed {
		t.Errorf("control case %s was closed too — close-case directive must target ONLY its Pattern case_id", otherCaseID)
	}
}

// TestRunCaseAge_DrivesCollapseToAgedState proves the 'age' verb
// (recurrence-fine directive) transitions a case to StatusAged, distinct
// from StatusClosed.
func TestRunCaseAge_DrivesCollapseToAgedState(t *testing.T) {
	storePath, caseID := buildRecurringCase(t)

	if err := runCase([]string{"age", caseID, "--store", storePath}); err != nil {
		t.Fatalf("runCase age: %v", err)
	}

	st, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := collapseCases(st, 0); err != nil {
		t.Fatalf("collapseCases replay: %v", err)
	}

	got := readCasesJSON(t, storePath)
	if len(got) != 1 || got[0].CaseID != caseID {
		t.Fatalf("want 1 case %s, got %+v", caseID, got)
	}
	if got[0].Status != cases.StatusAged {
		t.Errorf("status = %q, want %q", got[0].Status, cases.StatusAged)
	}
}

// TestRunCaseClose_UnknownCaseID_Errors proves the CLI validates the target
// case exists before persisting a directive for it (catches an
// operator typo rather than silently writing an inert directive).
func TestRunCaseClose_UnknownCaseID_Errors(t *testing.T) {
	storePath, _ := buildRecurringCase(t)

	err := runCase([]string{"close", "does-not-exist", "--store", storePath})
	if err == nil {
		t.Fatal("want error for an unknown case id, got nil")
	}
	if !strings.Contains(err.Error(), "no case with id") {
		t.Errorf("want 'no case with id' error, got: %v", err)
	}
}

// TestRunCaseClose_MissingStore_Errors covers the --store required-flag
// path, matching runFeedback's precedent.
func TestRunCaseClose_MissingStore_Errors(t *testing.T) {
	err := runCase([]string{"close", "abc123"})
	if err == nil {
		t.Fatal("want error for missing --store, got nil")
	}
}
