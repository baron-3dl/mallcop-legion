package cases

import "testing"

func TestSetStatus_TransitionsMatchingCaseOnly(t *testing.T) {
	existing := []Case{
		{CaseID: "a", Status: "recurring"},
		{CaseID: "b", Status: "open"},
	}
	got := SetStatus(existing, "a", StatusClosed)
	if got[0].Status != StatusClosed {
		t.Errorf("case a status = %q, want %q", got[0].Status, StatusClosed)
	}
	if got[1].Status != "open" {
		t.Errorf("case b status = %q, want unchanged %q", got[1].Status, "open")
	}
	// Pure: the input slice must not have been mutated in place.
	if existing[0].Status != "recurring" {
		t.Errorf("SetStatus mutated its input: existing[0].Status = %q, want unchanged %q", existing[0].Status, "recurring")
	}
}

func TestSetStatus_UnknownID_NoOp(t *testing.T) {
	existing := []Case{{CaseID: "a", Status: "open"}}
	got := SetStatus(existing, "does-not-exist", StatusClosed)
	if len(got) != 1 || got[0].Status != "open" {
		t.Errorf("unknown id changed state: got %+v", got)
	}
}

func TestSetStatus_Age(t *testing.T) {
	existing := []Case{{CaseID: "a", Status: "recurring"}}
	got := SetStatus(existing, "a", StatusAged)
	if got[0].Status != StatusAged {
		t.Errorf("status = %q, want %q", got[0].Status, StatusAged)
	}
}
