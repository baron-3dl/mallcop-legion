package main

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// alice works 09-17 UTC; bob works 22-06 UTC (night shift).
var testBaseline = &baseline.Baseline{
	ActorHours: map[string][]int{
		"alice": {9, 10, 11, 12, 13, 14, 15, 16, 17},
		"bob":   {22, 23, 0, 1, 2, 3, 4, 5, 6},
	},
}

func makeEvent(id, actor string, hour int) event.Event {
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      "push",
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, hour, 0, 0, 0, time.UTC),
		Org:       "acme",
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name         string
		ev           event.Event
		wantFinding  bool
		wantSeverity string
	}{
		{
			name:        "alice during business hours",
			ev:          makeEvent("evt-a", "alice", 10),
			wantFinding: false,
		},
		{
			name:         "alice at 3am — unusual",
			ev:           makeEvent("evt-b", "alice", 3),
			wantFinding:  true,
			wantSeverity: "low",
		},
		{
			name:        "bob at midnight — normal",
			ev:          makeEvent("evt-c", "bob", 23),
			wantFinding: false,
		},
		{
			name:         "bob at 14:00 — unusual",
			ev:           makeEvent("evt-d", "bob", 14),
			wantFinding:  true,
			wantSeverity: "low",
		},
		{
			name:        "unknown actor carol — skipped (new-actor handles)",
			ev:          makeEvent("evt-e", "carol", 3),
			wantFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := evaluate(tc.ev, testBaseline)
			if tc.wantFinding && f == nil {
				t.Fatalf("expected a finding but got nil")
			}
			if !tc.wantFinding && f != nil {
				t.Fatalf("expected no finding but got: %+v", f)
			}
			if tc.wantFinding && f.Severity != tc.wantSeverity {
				t.Fatalf("severity: got %q want %q", f.Severity, tc.wantSeverity)
			}
		})
	}
}

func TestNoBaselineData(t *testing.T) {
	bl := &baseline.Baseline{} // no actor hours
	ev := makeEvent("evt-x", "alice", 3)
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected no finding when no baseline data, got: %+v", f)
	}
}

func TestGoldenFixture(t *testing.T) {
	bl, err := baseline.Load("testdata/baseline.json")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}

	eventsFile, err := os.Open("testdata/events.jsonl")
	if err != nil {
		t.Fatalf("open events: %v", err)
	}
	defer eventsFile.Close()

	goldenFile, err := os.Open("testdata/findings.golden.jsonl")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer goldenFile.Close()

	var got []finding.Finding
	scanner := bufio.NewScanner(eventsFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		f := evaluate(ev, bl)
		if f != nil {
			got = append(got, *f)
		}
	}

	var want []finding.Finding
	gScanner := bufio.NewScanner(goldenFile)
	for gScanner.Scan() {
		line := gScanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("unmarshal golden finding: %v", err)
		}
		want = append(want, f)
	}

	if len(got) != len(want) {
		t.Fatalf("finding count: got %d want %d", len(got), len(want))
	}

	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID {
			t.Errorf("[%d] ID: got %q want %q", i, g.ID, w.ID)
		}
		if g.Severity != w.Severity {
			t.Errorf("[%d] Severity: got %q want %q", i, g.Severity, w.Severity)
		}
		if g.Type != w.Type {
			t.Errorf("[%d] Type: got %q want %q", i, g.Type, w.Type)
		}
		if g.Actor != w.Actor {
			t.Errorf("[%d] Actor: got %q want %q", i, g.Actor, w.Actor)
		}
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
