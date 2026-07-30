package cases

import (
	"strings"
	"testing"
)

func TestSummarize_EmptySet_ZeroCounts(t *testing.T) {
	s := Summarize(nil)
	if s.Open != 0 || s.Recurring != 0 || len(s.Lines) != 0 {
		t.Errorf("want zero-value Summary for an empty case set, got %+v", s)
	}
}

func TestSummarize_OpenAndRecurring_CountsSplitCorrectly(t *testing.T) {
	cs := []Case{
		{CaseID: "a", Key: Key{Type: "git-oops", Actor: "dev", Entity: ""}, Status: "open", Count: 1},
		{CaseID: "b", Key: Key{Type: "new-external-access", Actor: "admin", Entity: "alice"}, Status: "recurring", Count: 3},
	}
	s := Summarize(cs)
	if s.Open != 2 {
		t.Errorf("open = %d, want 2 (both open and recurring count as open)", s.Open)
	}
	if s.Recurring != 1 {
		t.Errorf("recurring = %d, want 1 (only the recurring-status case)", s.Recurring)
	}
	if len(s.Lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %v", len(s.Lines), s.Lines)
	}
}

// TestSummarize_ClosedAndAged_ExcludedFromOpenAndLines proves a case the
// operator has closed or aged (core/pipeline's CaseConsumer, mallcoppro-a1c)
// is excluded from BOTH the open/recurring counts and the per-case lines —
// status must not keep advertising a case the operator already dismissed.
func TestSummarize_ClosedAndAged_ExcludedFromOpenAndLines(t *testing.T) {
	cs := []Case{
		{CaseID: "a", Key: Key{Type: "git-oops", Actor: "dev", Entity: "closed-entity"}, Status: StatusClosed, Count: 1},
		{CaseID: "b", Key: Key{Type: "git-oops", Actor: "ops", Entity: "aged-entity"}, Status: StatusAged, Count: 5},
		{CaseID: "c", Key: Key{Type: "git-oops", Actor: "qa", Entity: "still-open-entity"}, Status: "open", Count: 1},
	}
	s := Summarize(cs)
	if s.Open != 1 {
		t.Errorf("open = %d, want 1 (closed/aged excluded)", s.Open)
	}
	if s.Recurring != 0 {
		t.Errorf("recurring = %d, want 0", s.Recurring)
	}
	if len(s.Lines) != 1 || !strings.Contains(s.Lines[0], "still-open-entity") {
		t.Fatalf("want exactly 1 line naming the still-open case, got %v", s.Lines)
	}
}

func TestFormatLine_EmptyEntity_ShowsPlaceholder(t *testing.T) {
	line := FormatLine(Case{Key: Key{Type: "git-oops", Actor: "dev", Entity: ""}, Count: 3, Status: "recurring"})
	if !strings.Contains(line, "entity=(no entity)") {
		t.Errorf("want a placeholder for an empty entity, got %q", line)
	}
	if !strings.Contains(line, "git-oops") || !strings.Contains(line, "count=3") || !strings.Contains(line, "status=recurring") {
		t.Errorf("want type/count/status all present, got %q", line)
	}
}

func TestHumanizeCadence(t *testing.T) {
	cases := []struct {
		secs float64
		want string
	}{
		{0, "no established cadence"},
		{-1, "no established cadence"},
		{30, "~30s"},
		{90, "~1m"},
		{3700, "~1h"},
		{200000, "~2d"},
	}
	for _, c := range cases {
		got := HumanizeCadence(c.secs)
		if got != c.want {
			t.Errorf("HumanizeCadence(%v) = %q, want %q", c.secs, got, c.want)
		}
	}
}
