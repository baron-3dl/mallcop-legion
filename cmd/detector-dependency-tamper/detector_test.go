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

var testBaseline = &baseline.Baseline{}

func makeDepEvent(id, evType, actor string, payload map[string]interface{}) event.Event {
	raw, _ := json.Marshal(payload)
	return event.Event{
		ID:        id,
		Source:    "github",
		Type:      evType,
		Actor:     actor,
		Timestamp: time.Date(2026, 4, 10, 18, 0, 0, 0, time.UTC),
		Org:       "acme",
		Payload:   raw,
	}
}

func TestEvaluate_BenignDepUpdate(t *testing.T) {
	ev := makeDepEvent("evt-a", "dependency_update", "alice", map[string]interface{}{
		"package":     "lodash",
		"ecosystem":   "npm",
		"old_version": "4.17.20",
		"new_version": "4.17.21",
		"direct":      false,
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for benign dep update, got %d: %+v", len(findings), findings)
	}
}

func TestEvaluate_NonDepEvent(t *testing.T) {
	ev := event.Event{
		ID: "evt-b", Source: "github", Type: "push", Actor: "alice",
		Timestamp: time.Date(2026, 4, 10, 18, 0, 0, 0, time.UTC),
	}
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 for non-dep event, got %d", len(findings))
	}
}

func TestEvaluate_HashMismatch(t *testing.T) {
	ev := makeDepEvent("evt-c", "lock_file_change", "alice", map[string]interface{}{
		"package":       "express",
		"ecosystem":     "npm",
		"expected_hash": "sha256-abc123def456",
		"actual_hash":   "sha256-deadbeef1234",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for hash mismatch, got 0")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity: got %q want critical", findings[0].Severity)
	}
	if findings[0].Type != "dependency-tamper" {
		t.Errorf("type: got %q want dependency-tamper", findings[0].Type)
	}
}

func TestEvaluate_HashMatch(t *testing.T) {
	ev := makeDepEvent("evt-d", "lock_file_change", "alice", map[string]interface{}{
		"package":       "express",
		"ecosystem":     "npm",
		"expected_hash": "sha256-abc123def456",
		"actual_hash":   "sha256-abc123def456",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 for matching hashes, got %d", len(findings))
	}
}

func TestEvaluate_SuspiciousRegistry_HTTP(t *testing.T) {
	ev := makeDepEvent("evt-e", "package_install", "bob", map[string]interface{}{
		"package":   "some-package",
		"ecosystem": "npm",
		"registry":  "http://internal-mirror.evil.com/npm",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for HTTP registry, got 0")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity: got %q want critical", findings[0].Severity)
	}
}

func TestEvaluate_SuspiciousRegistry_Localhost(t *testing.T) {
	ev := makeDepEvent("evt-f", "package_install", "bob", map[string]interface{}{
		"package":   "my-package",
		"ecosystem": "pypi",
		"registry":  "https://localhost:8080/simple",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for localhost registry, got 0")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("severity: got %q want critical", findings[0].Severity)
	}
}

func TestEvaluate_TyposquattingPackage(t *testing.T) {
	ev := makeDepEvent("evt-g", "lock_file_change", "alice", map[string]interface{}{
		"ecosystem":      "npm",
		"added_packages": []string{"reqqests"},
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for typosquatting package, got 0")
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity: got %q want high", findings[0].Severity)
	}
}

func TestEvaluate_NewDirectDependency(t *testing.T) {
	ev := makeDepEvent("evt-h", "dependency_add", "alice", map[string]interface{}{
		"package":     "new-analytics-sdk",
		"ecosystem":   "npm",
		"new_version": "1.0.0",
		"direct":      true,
		"registry":    "https://registry.npmjs.org",
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for new direct dependency, got 0")
	}
	if findings[0].Severity != "medium" {
		t.Errorf("severity: got %q want medium", findings[0].Severity)
	}
}

func TestEvaluate_VersionDowngrade(t *testing.T) {
	ev := makeDepEvent("evt-i", "dependency_update", "bob", map[string]interface{}{
		"package":     "openssl",
		"ecosystem":   "go",
		"old_version": "3.0.1",
		"new_version": "1.1.0",
		"direct":      false,
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) == 0 {
		t.Fatal("expected findings for version downgrade, got 0")
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity: got %q want high", findings[0].Severity)
	}
}

func TestEvaluate_NewTransitiveDep_NotFlagged(t *testing.T) {
	// Transitive (not direct) additions without typosquatting should not trigger.
	ev := makeDepEvent("evt-j", "lock_file_change", "alice", map[string]interface{}{
		"ecosystem":      "npm",
		"added_packages": []string{"inherits", "once"},
	})
	findings := evaluate(ev, testBaseline)
	if len(findings) != 0 {
		t.Fatalf("expected 0 for benign transitive deps, got %d: %+v", len(findings), findings)
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
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event: %v", err)
		}
		got = append(got, evaluate(ev, bl)...)
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
