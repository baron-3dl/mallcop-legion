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

var testBaseline = &baseline.Baseline{
	KnownActors: []string{"alice", "bob", "svc-ci"},
}

func makeEvent(id, actor, source, evType string) event.Event {
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
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
			name:        "known actor alice",
			ev:          makeEvent("evt-a", "alice", "github", "push"),
			wantFinding: false,
		},
		{
			name:        "known service account",
			ev:          makeEvent("evt-b", "svc-ci", "github", "workflow_run"),
			wantFinding: false,
		},
		{
			name:         "unknown actor charlie",
			ev:           makeEvent("evt-c", "charlie", "github", "push"),
			wantFinding:  true,
			wantSeverity: "medium",
		},
		{
			name:         "unknown actor external-bot",
			ev:           makeEvent("evt-d", "external-bot", "github", "issue_comment"),
			wantFinding:  true,
			wantSeverity: "medium",
		},
		{
			name:        "empty actor ignored",
			ev:          event.Event{ID: "evt-e", Source: "github", Type: "push", Actor: ""},
			wantFinding: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			emitted := make(map[string]bool)
			f := evaluate(tc.ev, testBaseline, emitted)
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

func TestDeduplicate(t *testing.T) {
	// Same new actor appearing twice should only produce one finding.
	emitted := make(map[string]bool)
	ev1 := makeEvent("evt-x1", "mallory", "github", "push")
	ev2 := makeEvent("evt-x2", "mallory", "github", "push")

	f1 := evaluate(ev1, testBaseline, emitted)
	f2 := evaluate(ev2, testBaseline, emitted)

	if f1 == nil {
		t.Fatal("expected finding for first event, got nil")
	}
	if f2 != nil {
		t.Fatalf("expected no finding for duplicate actor, got: %+v", f2)
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

	emitted := make(map[string]bool)
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
		f := evaluate(ev, bl, emitted)
		if f != nil {
			got = append(got, *f)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan events: %v", err)
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
	if err := gScanner.Err(); err != nil {
		t.Fatalf("scan golden: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("finding count: got %d want %d", len(got), len(want))
	}

	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID {
			t.Errorf("[%d] ID: got %q want %q", i, g.ID, w.ID)
		}
		if g.Source != w.Source {
			t.Errorf("[%d] Source: got %q want %q", i, g.Source, w.Source)
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
		if !g.Timestamp.Equal(w.Timestamp) {
			t.Errorf("[%d] Timestamp: got %v want %v", i, g.Timestamp, w.Timestamp)
		}
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
