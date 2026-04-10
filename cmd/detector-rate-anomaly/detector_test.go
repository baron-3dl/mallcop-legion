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

func makeRateEvent(id, evType, actor, source string, payload map[string]interface{}) event.Event {
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 15, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   raw,
	}
}

func TestEvaluate_NonRateEvent(t *testing.T) {
	ev := makeRateEvent("evt-a", "login", "alice", "app", map[string]interface{}{})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected nil for non-rate event, got %+v", f)
	}
}

func TestEvaluate_NormalRate(t *testing.T) {
	ev := makeRateEvent("evt-b", "api_request", "alice", "app", map[string]interface{}{
		"request_count": 10,
		"endpoint":      "/api/v1/status",
	})
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{"app:api_request": 20},
	}
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected nil for normal rate, got %+v", f)
	}
}

func TestEvaluate_AbsoluteHighBurst(t *testing.T) {
	ev := makeRateEvent("evt-c", "api_burst", "attacker", "app", map[string]interface{}{
		"request_count": 2000,
		"endpoint":      "/api/v1/data",
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for high burst, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_AbsoluteMediumBurst(t *testing.T) {
	ev := makeRateEvent("evt-d", "api_request", "alice", "app", map[string]interface{}{
		"request_count": 300,
		"endpoint":      "/api/v1/reports",
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for medium burst, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_RateAnomalyHigh(t *testing.T) {
	// 100 requests vs baseline of 5 = 20x → high
	ev := makeRateEvent("evt-e", "api_request", "attacker", "app", map[string]interface{}{
		"request_count": 100,
		"endpoint":      "/api/v1/search",
	})
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{"app:api_request": 5},
	}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for high rate anomaly, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_RateAnomalyMedium(t *testing.T) {
	// 50 requests vs baseline of 8 = ~6x → medium
	ev := makeRateEvent("evt-f", "api_request", "bob", "app", map[string]interface{}{
		"request_count": 50,
		"endpoint":      "/api/v1/items",
	})
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{"app:api_request": 8},
	}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for medium rate anomaly, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_SensitiveEndpointRate(t *testing.T) {
	ev := makeRateEvent("evt-g", "api_request", "attacker", "app", map[string]interface{}{
		"request_count": 15,
		"endpoint":      "/admin/users",
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for sensitive endpoint access, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_SensitiveEndpointLowRate(t *testing.T) {
	// 5 requests to sensitive endpoint — below threshold, should not trigger.
	ev := makeRateEvent("evt-h", "api_request", "alice", "app", map[string]interface{}{
		"request_count": 5,
		"endpoint":      "/admin/dashboard",
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected nil for low rate on sensitive endpoint, got %+v", f)
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
		if f := evaluate(ev, bl); f != nil {
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
		if g.Reason != w.Reason {
			t.Errorf("[%d] Reason: got %q want %q", i, g.Reason, w.Reason)
		}
	}
}
