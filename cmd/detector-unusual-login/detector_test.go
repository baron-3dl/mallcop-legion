package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

var testBaseline = &baseline.Baseline{
	KnownUsers: map[string]baseline.UserProfile{
		"alice": {
			KnownIPs:  []string{"1.2.3.4", "5.6.7.8"},
			KnownGeos: []string{"US"},
		},
		"bob": {
			KnownIPs:  []string{"9.10.11.12"},
			KnownGeos: []string{"GB", "US"},
		},
	},
}

func makeLoginEvent(id, actor, ip, geo string) event.Event {
	payload, _ := json.Marshal(map[string]string{"ip": ip, "geo": geo})
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      "login",
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
			// (a) known user, known IP → no finding
			name:        "known user known IP",
			ev:          makeLoginEvent("evt-a", "alice", "1.2.3.4", "US"),
			wantFinding: false,
		},
		{
			// (b) known user, new IP but known geo → low severity
			name:         "known user new IP known geo",
			ev:           makeLoginEvent("evt-b", "bob", "99.88.77.66", "GB"),
			wantFinding:  true,
			wantSeverity: "low",
		},
		{
			// (c) known user, new IP, unknown geo → high severity
			name:         "known user unknown geo",
			ev:           makeLoginEvent("evt-c", "alice", "200.100.50.25", "DE"),
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			// new user not in baseline → high severity
			name:         "new user",
			ev:           makeLoginEvent("evt-d", "charlie", "10.0.0.1", "CN"),
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			// non-login event → no finding
			name:        "non-login event ignored",
			ev:          event.Event{ID: "evt-e", Type: "push", Actor: "alice"},
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

func TestGoldenFixture(t *testing.T) {
	bl, err := baseline.Load("fixtures/baseline.json")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}

	eventsFile, err := os.Open("fixtures/events.jsonl")
	if err != nil {
		t.Fatalf("open events: %v", err)
	}
	defer eventsFile.Close()

	goldenFile, err := os.Open("fixtures/findings.golden.jsonl")
	if err != nil {
		t.Fatalf("open golden: %v", err)
	}
	defer goldenFile.Close()

	// Collect findings produced by the detector.
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
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan events: %v", err)
	}

	// Collect golden findings.
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
		// Compare evidence as normalized JSON.
		if !jsonEqual(g.Evidence, w.Evidence) {
			t.Errorf("[%d] Evidence: got %s want %s", i, g.Evidence, w.Evidence)
		}
	}
}

// jsonEqual compares two json.RawMessage values by normalizing to maps.
func jsonEqual(a, b json.RawMessage) bool {
	var am, bm map[string]interface{}
	if err := json.Unmarshal(a, &am); err != nil {
		return bytes.Equal(a, b)
	}
	if err := json.Unmarshal(b, &bm); err != nil {
		return false
	}
	ra, _ := json.Marshal(am)
	rb, _ := json.Marshal(bm)
	return string(ra) == string(rb)
}
