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

func makeEvent(id, evType, actor, source string, payload map[string]interface{}) event.Event {
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    source,
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 14, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   raw,
	}
}

func TestEvaluate_BenignDownload(t *testing.T) {
	ev := makeEvent("evt-a", "download", "alice", "s3", map[string]interface{}{
		"bytes_transferred": 1024 * 1024, // 1 MB
		"resource_count":    1,
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected nil for benign download, got %+v", f)
	}
}

func TestEvaluate_NonExfilEvent(t *testing.T) {
	ev := makeEvent("evt-b", "login", "alice", "github", map[string]interface{}{})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected nil for non-exfil event, got %+v", f)
	}
}

func TestEvaluate_HighVolumeTransfer(t *testing.T) {
	ev := makeEvent("evt-c", "bulk_export", "attacker", "s3", map[string]interface{}{
		"bytes_transferred": int64(600 * 1024 * 1024), // 600 MB
		"destination":       "https://evil.attacker.com",
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for high-volume transfer, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_MediumVolumeTransfer(t *testing.T) {
	ev := makeEvent("evt-d", "data_export", "bob", "s3", map[string]interface{}{
		"bytes_transferred": int64(150 * 1024 * 1024), // 150 MB
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for medium-volume transfer, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_BulkResourceAccessHigh(t *testing.T) {
	ev := makeEvent("evt-e", "list_objects", "attacker", "s3", map[string]interface{}{
		"resource_count": 250,
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for high bulk resource access, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_BulkResourceAccessMedium(t *testing.T) {
	ev := makeEvent("evt-f", "bulk_read", "alice", "s3", map[string]interface{}{
		"files_accessed": 25,
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for medium bulk resource access, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_FrequencyAnomalyHigh(t *testing.T) {
	// resource_count=10 is below bulk thresholds (20/100) so frequency rule fires.
	// 10 vs baseline of 1 = 10x → high severity.
	ev := makeEvent("evt-g", "object_get", "attacker", "s3", map[string]interface{}{
		"resource_count": 10,
	})
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{
			"s3:object_get": 1,
		},
	}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for high frequency anomaly, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
	}
}

func TestEvaluate_FrequencyAnomalyMedium(t *testing.T) {
	ev := makeEvent("evt-h", "file_download", "bob", "github", map[string]interface{}{
		"resource_count": 15, // 15 vs baseline of 4 = ~3.75x
	})
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{
			"github:file_download": 4,
		},
	}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for medium frequency anomaly, got nil")
	}
	if f.Severity != "medium" {
		t.Errorf("severity: got %q want medium", f.Severity)
	}
}

func TestEvaluate_FrequencyWithinBaseline(t *testing.T) {
	ev := makeEvent("evt-i", "file_download", "alice", "github", map[string]interface{}{
		"resource_count": 3,
	})
	bl := &baseline.Baseline{
		FrequencyTables: map[string]int{
			"github:file_download": 10,
		},
	}
	f := evaluate(ev, bl)
	if f != nil {
		t.Fatalf("expected nil for within-baseline frequency, got %+v", f)
	}
}

func TestEvaluate_RepoClone(t *testing.T) {
	ev := makeEvent("evt-j", "repo_clone", "attacker", "github", map[string]interface{}{
		"bytes_transferred": int64(800 * 1024 * 1024), // 800 MB repo clone
		"destination":       "attacker@evil.example.com",
	})
	bl := &baseline.Baseline{}
	f := evaluate(ev, bl)
	if f == nil {
		t.Fatal("expected finding for large repo clone, got nil")
	}
	if f.Severity != "high" {
		t.Errorf("severity: got %q want high", f.Severity)
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
