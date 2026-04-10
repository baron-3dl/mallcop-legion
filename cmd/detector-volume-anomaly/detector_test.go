package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

var testBaseline = &baseline.Baseline{
	FrequencyTables: map[string]int{
		"github:push":         10, // 3× = 30 threshold
		"github:pull_request": 20, // 3× = 60 threshold
		"github:login":        8,  // 3× = 24 threshold
		"github:rare_event":   3,  // below minBaselineCount — never fires
	},
}

func makeEvent(id, source, evType, actor string) event.Event {
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
		Org:       "acme",
	}
}

func makeEvents(source, evType, actor string, count int) []event.Event {
	events := make([]event.Event, count)
	for i := range events {
		events[i] = makeEvent(
			fmt.Sprintf("evt-%s-%d", evType, i),
			source, evType, actor,
		)
	}
	return events
}

func TestEvaluateAll_NoAnomaly(t *testing.T) {
	// 10 push events with baseline of 10 — ratio = 1.0, no finding.
	events := makeEvents("github", "push", "alice", 10)
	findings := evaluateAll(events, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestEvaluateAll_BelowThreshold(t *testing.T) {
	// 29 push events, threshold is 30 (3×10) — no finding.
	events := makeEvents("github", "push", "alice", 29)
	findings := evaluateAll(events, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestEvaluateAll_AboveThreshold(t *testing.T) {
	// 31 push events, threshold is 30 (3×10) — one finding.
	events := makeEvents("github", "push", "alice", 31)
	findings := evaluateAll(events, testBaseline)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
	if f.Type != "volume-anomaly" {
		t.Errorf("type: got %q want volume-anomaly", f.Type)
	}
}

func TestEvaluateAll_BelowMinBaseline(t *testing.T) {
	// rare_event has baseline of 3 (< minBaselineCount=5) — never fires.
	events := makeEvents("github", "rare_event", "alice", 100)
	findings := evaluateAll(events, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (below min baseline), got %d", len(findings))
	}
}

func TestEvaluateAll_NoBaselineEntry(t *testing.T) {
	// Event type with no baseline entry — skipped (zero baseline).
	events := makeEvents("github", "unknown_type", "alice", 100)
	findings := evaluateAll(events, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (no baseline entry), got %d", len(findings))
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

	var events []event.Event
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
		events = append(events, ev)
	}

	got := evaluateAll(events, bl)

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
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
