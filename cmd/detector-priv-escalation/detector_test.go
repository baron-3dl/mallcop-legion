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
	ActorRoles: map[string][]string{
		"alice": {"write", "contributor"},
		"bob":   {"admin"},
	},
}

func makePrivEvent(id, actor, evType, roleName, permLevel, targetUser string) event.Event {
	payload, _ := json.Marshal(map[string]string{
		"role_name":        roleName,
		"permission_level": permLevel,
		"target_user":      targetUser,
	})
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   payload,
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
			name:        "non-escalation event ignored",
			ev:          makePrivEvent("evt-a", "alice", "push", "", "", ""),
			wantFinding: false,
		},
		{
			name:        "alice already has write role",
			ev:          makePrivEvent("evt-b", "alice", "role_assignment", "write", "", "carol"),
			wantFinding: false,
		},
		{
			name:         "alice granted owner — new escalation, critical",
			ev:           makePrivEvent("evt-c", "alice", "role_assignment", "owner", "", "dave"),
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "charlie granted admin via permission_change — critical",
			ev:           makePrivEvent("evt-d", "charlie", "permission_change", "", "admin", ""),
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:         "new user dave added as collaborator with maintainer",
			ev:           makePrivEvent("evt-e", "dave", "collaborator_added", "maintainer", "", "dave"),
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "admin_action always critical",
			ev:           makePrivEvent("evt-f", "eve", "admin_action", "", "", ""),
			wantFinding:  true,
			wantSeverity: "critical",
		},
		{
			name:        "bob already has admin role",
			ev:          makePrivEvent("evt-g", "bob", "role_assignment", "admin", "", ""),
			wantFinding: false,
		},
		{
			name:        "member_added with no elevated keywords — no finding",
			ev:          makePrivEvent("evt-h", "alice", "member_added", "reader", "", ""),
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

func TestDeduplication(t *testing.T) {
	emitted := make(map[string]bool)
	ev1 := makePrivEvent("evt-x1", "mallory", "role_assignment", "admin", "", "mallory")
	ev2 := makePrivEvent("evt-x2", "mallory", "role_assignment", "admin", "", "mallory")

	f1 := evaluate(ev1, testBaseline, emitted)
	f2 := evaluate(ev2, testBaseline, emitted)

	if f1 == nil {
		t.Fatal("expected finding for first event")
	}
	if f2 != nil {
		t.Fatalf("expected no finding for duplicate actor:role, got: %+v", f2)
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
		t.Fatalf("finding count: got %d want %d\ngot: %+v\nwant: %+v", len(got), len(want), got, want)
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
