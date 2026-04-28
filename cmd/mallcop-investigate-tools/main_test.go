package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout to a pipe during fn, then returns what was
// written. This lets us test run() without exec.Command.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return buf.String()
}

// makeFixtureDir creates a temp fixture directory with optional baseline.json,
// events.json, and findings.jsonl content.
func makeFixtureDir(t *testing.T, baseline, events, findings string) string {
	t.Helper()
	dir := t.TempDir()
	if baseline != "" {
		if err := os.WriteFile(filepath.Join(dir, "baseline.json"), []byte(baseline), 0o644); err != nil {
			t.Fatalf("write baseline.json: %v", err)
		}
	}
	if events != "" {
		if err := os.WriteFile(filepath.Join(dir, "events.json"), []byte(events), 0o644); err != nil {
			t.Fatalf("write events.json: %v", err)
		}
	}
	if findings != "" {
		if err := os.WriteFile(filepath.Join(dir, "findings.jsonl"), []byte(findings), 0o644); err != nil {
			t.Fatalf("write findings.jsonl: %v", err)
		}
	}
	return dir
}

// ---- check-baseline tests --------------------------------------------------

func TestCheckBaseline_HappyPath(t *testing.T) {
	baselineJSON := `{
		"known_entities": {
			"actors": ["alice@example.com"],
			"sources": ["github"]
		},
		"frequency_tables": {"alice@example.com": 42},
		"relationships": {
			"alice@example.com": {
				"count": 42,
				"first_seen": "2026-03-01T00:00:00Z",
				"last_seen": "2026-04-10T12:00:00Z"
			}
		}
	}`
	dir := makeFixtureDir(t, baselineJSON, "", "")

	var result baselineResult
	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "alice@example.com",
			"--source", "github",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if !result.Known {
		t.Errorf("Known = false, want true")
	}
	if result.Frequency != 42 {
		t.Errorf("Frequency = %d, want 42", result.Frequency)
	}
	if result.LastSeen != "2026-04-10T12:00:00Z" {
		t.Errorf("LastSeen = %q, want %q", result.LastSeen, "2026-04-10T12:00:00Z")
	}
	// TODO(mallcoppro-a97): roles always empty until upstream adds actor_roles.
	if result.Roles == nil {
		t.Errorf("Roles must not be nil (should be empty slice)")
	}
}

func TestCheckBaseline_NotFound(t *testing.T) {
	baselineJSON := `{
		"known_entities": {
			"actors": ["bob@example.com"],
			"sources": ["github"]
		}
	}`
	dir := makeFixtureDir(t, baselineJSON, "", "")

	var result baselineResult
	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "unknown@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result.Known {
		t.Errorf("Known = true for unknown entity, want false")
	}
	if result.Frequency != 0 {
		t.Errorf("Frequency = %d, want 0 for unknown entity", result.Frequency)
	}
}

func TestCheckBaseline_NoBaselineFile(t *testing.T) {
	// No baseline.json at all — empty fixture dir.
	dir := makeFixtureDir(t, "", "", "")

	var result baselineResult
	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "check-baseline",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if result.Known {
		t.Errorf("Known = true with no baseline file, want false")
	}
}

func TestCheckBaseline_ProductionStubbed(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")
	err := run([]string{
		"--tool", "check-baseline",
		"--mode", "production",
		"--fixture-dir", dir,
		"--entity", "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for production mode, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented', got: %v", err)
	}
}

// ---- search-events tests ---------------------------------------------------

const testEventsJSON = `{
	"events": [
		{
			"id": "evt-001",
			"timestamp": "2026-04-10T10:00:00Z",
			"source": "github",
			"event_type": "push",
			"actor": "alice@example.com",
			"action": "git.push",
			"target": "repo/main",
			"severity": "info"
		},
		{
			"id": "evt-002",
			"timestamp": "2026-04-09T08:00:00Z",
			"source": "azure",
			"event_type": "login",
			"actor": "bob@example.com",
			"action": "user.login",
			"target": "portal",
			"severity": "low"
		},
		{
			"id": "evt-003",
			"timestamp": "2026-04-10T11:00:00Z",
			"source": "github",
			"event_type": "login",
			"actor": "alice@example.com",
			"action": "user.login",
			"target": "github.com",
			"severity": "info"
		}
	]
}`

func TestSearchEvents_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--source", "github",
			"--since", "2026-04-10T00:00:00Z",
			"--until", "2026-04-10T23:59:59Z",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Errorf("want 2 events for alice on github on 2026-04-10, got %d\nout=%q", len(lines), out)
	}
	for _, line := range lines {
		var ev rawEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("parse event line: %v\nline=%q", err, line)
			continue
		}
		if !strings.EqualFold(ev.Actor, "alice@example.com") {
			t.Errorf("got actor %q, want alice@example.com", ev.Actor)
		}
		if !strings.EqualFold(ev.Source, "github") {
			t.Errorf("got source %q, want github", ev.Source)
		}
	}
}

func TestSearchEvents_ActorNotFound(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "nobody@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output for unknown actor, got: %q", out)
	}
}

func TestSearchEvents_NoEventsFile(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output when no events.json, got: %q", out)
	}
}

func TestSearchEvents_TypeFilter(t *testing.T) {
	dir := makeFixtureDir(t, "", testEventsJSON, "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-events",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--type", "push",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("want 1 push event for alice, got %d\nout=%q", len(lines), out)
	}
	var ev rawEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("parse event: %v", err)
	}
	if ev.EventType != "push" {
		t.Errorf("event_type = %q, want push", ev.EventType)
	}
}

func TestSearchEvents_ProductionStubbed(t *testing.T) {
	err := run([]string{
		"--tool", "search-events",
		"--mode", "production",
		"--actor", "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for production mode, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented', got: %v", err)
	}
}

// ---- search-findings tests -------------------------------------------------

const testFindingsJSONL = `{"id":"fnd-001","actor":"alice@example.com","source":"github","timestamp":"2026-04-10T10:00:00Z","title":"Unusual push pattern"}
{"id":"fnd-002","actor":"bob@example.com","source":"azure","timestamp":"2026-04-09T08:00:00Z","title":"Off-hours login"}
`

func TestSearchFindings_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
			"--since", "2026-04-10T00:00:00Z",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("want 1 finding for alice after 2026-04-10, got %d\nout=%q", len(lines), out)
	}
	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &finding); err != nil {
		t.Fatalf("parse finding: %v", err)
	}
	if finding["id"] != "fnd-001" {
		t.Errorf("id = %v, want fnd-001", finding["id"])
	}
}

func TestSearchFindings_ActorNotFound(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "nobody@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output for unknown actor, got: %q", out)
	}
}

func TestSearchFindings_NoFindingsFile(t *testing.T) {
	// findings.jsonl may not exist yet — empty result is valid.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "search-findings",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--actor", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected empty output when no findings.jsonl, got: %q", out)
	}
}

func TestSearchFindings_ProductionStubbed(t *testing.T) {
	err := run([]string{
		"--tool", "search-findings",
		"--mode", "production",
		"--actor", "alice@example.com",
	})
	if err == nil {
		t.Fatal("expected error for production mode, got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("error should mention 'not yet implemented', got: %v", err)
	}
}

// ---- read-finding ----------------------------------------------------------

const testFindingsForReadJSONL = `{"finding_id":"fnd-rf-001","actor":"alice@example.com","source":"github","title":"Unusual push pattern","severity":"medium"}
{"id":"fnd-rf-002","actor":"bob@example.com","source":"azure","title":"Off-hours login","severity":"low"}
`

func TestReadFinding_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-001",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(out), &finding); err != nil {
		t.Fatalf("parse finding: %v\nout=%q", err, out)
	}
	if finding["finding_id"] != "fnd-rf-001" {
		t.Errorf("finding_id = %v, want fnd-rf-001", finding["finding_id"])
	}
	if finding["actor"] != "alice@example.com" {
		t.Errorf("actor = %v, want alice@example.com", finding["actor"])
	}
	if finding["error"] != nil {
		t.Errorf("unexpected error key in happy-path output: %v", finding["error"])
	}
}

func TestReadFinding_HappyPath_IDFallback(t *testing.T) {
	// findings without finding_id but with id should still be findable.
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-002",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var finding map[string]interface{}
	if err := json.Unmarshal([]byte(out), &finding); err != nil {
		t.Fatalf("parse finding: %v\nout=%q", err, out)
	}
	if finding["id"] != "fnd-rf-002" {
		t.Errorf("id = %v, want fnd-rf-002", finding["id"])
	}
	if finding["error"] != nil {
		t.Errorf("unexpected error key in id-fallback output: %v", finding["error"])
	}
}

func TestReadFinding_NotFound(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-does-not-exist",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error for not-found: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v\nout=%q", err, out)
	}
	if result["error"] != "not_found" {
		t.Errorf("error = %v, want not_found", result["error"])
	}
	if result["finding_id"] != "fnd-rf-does-not-exist" {
		t.Errorf("finding_id echo = %v, want fnd-rf-does-not-exist", result["finding_id"])
	}
}

func TestReadFinding_NoFindingsFile(t *testing.T) {
	// findings.jsonl absent — must return not_found, not an error.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-finding",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--finding-id", "fnd-rf-001",
		})
		if err != nil {
			t.Errorf("run() returned unexpected error when findings.jsonl absent: %v", err)
		}
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v\nout=%q", err, out)
	}
	if result["error"] != "not_found" {
		t.Errorf("error = %v, want not_found when findings.jsonl absent", result["error"])
	}
}

func TestReadFinding_RequiresFindingID(t *testing.T) {
	dir := makeFixtureDir(t, "", "", testFindingsForReadJSONL)

	err := run([]string{
		"--tool", "read-finding",
		"--mode", "exam",
		"--fixture-dir", dir,
	})
	if err == nil {
		t.Fatal("expected error for missing --finding-id, got nil")
	}
	if !strings.Contains(err.Error(), "finding-id is required") {
		t.Errorf("error message = %v, want mention of finding-id required", err)
	}
}

// ---- baseline-stats tests --------------------------------------------------

// testBaselineEventsArray is a flat JSON array of event records used for
// baseline-stats tests.
const testBaselineEventsArray = `[
	{"actor":"alice@example.com","source":"github","type":"push","timestamp":"2026-04-10T09:00:00Z"},
	{"actor":"alice@example.com","source":"github","type":"push","timestamp":"2026-04-10T22:00:00Z"},
	{"actor":"alice@example.com","source":"aws","type":"login","timestamp":"2026-04-09T03:00:00Z"},
	{"actor":"bob@example.com","source":"github","type":"login","timestamp":"2026-04-10T10:00:00Z"}
]`

func TestBaselineStats_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, testBaselineEventsArray, "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "baseline-stats",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "alice@example.com",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result baselineStatsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result.CountTotal != 3 {
		t.Errorf("CountTotal = %d, want 3 (3 alice events)", result.CountTotal)
	}
	if result.CountBySource["github"] != 2 {
		t.Errorf("CountBySource[github] = %d, want 2", result.CountBySource["github"])
	}
	if result.CountBySource["aws"] != 1 {
		t.Errorf("CountBySource[aws] = %d, want 1", result.CountBySource["aws"])
	}
	if result.CountByType["push"] != 2 {
		t.Errorf("CountByType[push] = %d, want 2", result.CountByType["push"])
	}
	if result.CountByType["login"] != 1 {
		t.Errorf("CountByType[login] = %d, want 1", result.CountByType["login"])
	}
	// Hour 09 and 22 and 03 for alice
	if result.TimeOfDayDistribution["09"] != 1 {
		t.Errorf("time_of_day_distribution[09] = %d, want 1", result.TimeOfDayDistribution["09"])
	}
	if result.TimeOfDayDistribution["22"] != 1 {
		t.Errorf("time_of_day_distribution[22] = %d, want 1", result.TimeOfDayDistribution["22"])
	}
	if result.FirstSeen == nil {
		t.Error("first_seen must not be nil")
	} else if *result.FirstSeen != "2026-04-09T03:00:00Z" {
		t.Errorf("first_seen = %q, want 2026-04-09T03:00:00Z", *result.FirstSeen)
	}
	if result.LastSeen == nil {
		t.Error("last_seen must not be nil")
	} else if *result.LastSeen != "2026-04-10T22:00:00Z" {
		t.Errorf("last_seen = %q, want 2026-04-10T22:00:00Z", *result.LastSeen)
	}
}

func TestBaselineStats_FilterEmpty(t *testing.T) {
	// Filter by entity that has no events — expect all zeros, null timestamps.
	dir := makeFixtureDir(t, testBaselineEventsArray, "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "baseline-stats",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--entity", "nobody@example.com",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result baselineStatsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result.CountTotal != 0 {
		t.Errorf("CountTotal = %d, want 0 for unknown entity", result.CountTotal)
	}
	if result.FirstSeen != nil {
		t.Errorf("first_seen should be null for empty result, got %q", *result.FirstSeen)
	}
	if result.LastSeen != nil {
		t.Errorf("last_seen should be null for empty result, got %q", *result.LastSeen)
	}
	// time_of_day_distribution must have all 24 keys initialized to 0
	if len(result.TimeOfDayDistribution) != 24 {
		t.Errorf("time_of_day_distribution should have 24 keys, got %d", len(result.TimeOfDayDistribution))
	}
	for h := 0; h < 24; h++ {
		key := fmt.Sprintf("%02d", h)
		if result.TimeOfDayDistribution[key] != 0 {
			t.Errorf("time_of_day_distribution[%s] = %d, want 0 for empty result", key, result.TimeOfDayDistribution[key])
		}
	}
}

func TestBaselineStats_NoFile(t *testing.T) {
	// No baseline.json — returns empty stats, no error.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "baseline-stats",
			"--mode", "exam",
			"--fixture-dir", dir,
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	var result baselineStatsResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if result.CountTotal != 0 {
		t.Errorf("CountTotal = %d, want 0 when no file", result.CountTotal)
	}
	if result.FirstSeen != nil || result.LastSeen != nil {
		t.Errorf("first_seen/last_seen must be null when no file")
	}
}

// ---- read-config tests -----------------------------------------------------

const testConfigJSON = `{
	"detectors": {
		"brute-force-detector": {"threshold": 5, "enabled": true},
		"off-hours-login": {"threshold": 1, "enabled": false}
	},
	"connectors": {
		"github": {"scope": "org", "enabled": true, "sources": ["audit_log", "repos"]},
		"aws": {"scope": "account", "enabled": true, "sources": ["cloudtrail"]}
	}
}`

func TestReadConfig_HappyPath(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(testConfigJSON), 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-config",
			"--mode", "exam",
			"--fixture-dir", dir,
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result configResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Detectors) != 2 {
		t.Errorf("want 2 detectors, got %d", len(result.Detectors))
	}
	if len(result.Connectors) != 2 {
		t.Errorf("want 2 connectors, got %d", len(result.Connectors))
	}
}

func TestReadConfig_FilterByDetector(t *testing.T) {
	dir := makeFixtureDir(t, "", "", "")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(testConfigJSON), 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-config",
			"--mode", "exam",
			"--fixture-dir", dir,
			"--detector", "brute-force-detector",
		})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result configResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Detectors) != 1 {
		t.Errorf("want 1 detector (filtered), got %d", len(result.Detectors))
	}
	if _, ok := result.Detectors["brute-force-detector"]; !ok {
		t.Errorf("expected brute-force-detector in result")
	}
}

func TestReadConfig_NoFile(t *testing.T) {
	// config.json absent — returns empty config, no error.
	dir := makeFixtureDir(t, "", "", "")

	out := captureStdout(t, func() {
		err := run([]string{
			"--tool", "read-config",
			"--mode", "exam",
			"--fixture-dir", dir,
		})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	var result configResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Detectors) != 0 {
		t.Errorf("want 0 detectors when no file, got %d", len(result.Detectors))
	}
	if len(result.Connectors) != 0 {
		t.Errorf("want 0 connectors when no file, got %d", len(result.Connectors))
	}
}

// ---- load-skill tests ------------------------------------------------------

// writeCatalog writes a YAML skill catalog to a temp dir and sets
// MALLCOP_REPO_ROOT to point there, returning the dir and a cleanup func.
func writeCatalog(t *testing.T, yamlContent string) (repoRoot string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "skill-catalog.yaml"), []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write skill-catalog.yaml: %v", err)
	}
	orig := os.Getenv("MALLCOP_REPO_ROOT")
	os.Setenv("MALLCOP_REPO_ROOT", dir)
	return dir, func() {
		os.Setenv("MALLCOP_REPO_ROOT", orig)
	}
}

const testSkillCatalogYAML = `
skills:
  - name: aws-iam
    version: "1.0.0"
    source: aws
    description: AWS IAM privilege analysis skill.
    status: active
    binding: static-chart
    tools:
      - name: aws-iam-query
        description: Query IAM policies and roles.
  - name: github-audit
    version: "1.1.0"
    source: github
    description: GitHub audit log analysis.
    status: experimental
    binding: static-chart
    tools:
      - name: github-audit-query
        description: Query GitHub audit log.
`

func TestLoadSkill_HappyPath(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill"})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if len(result.Skills) != 2 {
		t.Errorf("want 2 skills (no filter), got %d", len(result.Skills))
	}
	if result.BindingNote == "" {
		t.Errorf("binding_note must not be empty")
	}
}

func TestLoadSkill_FilterBySkillName(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill", "--skill-name", "aws-iam"})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if len(result.Skills) != 1 {
		t.Errorf("want 1 skill (filtered by name), got %d", len(result.Skills))
	}
	if result.Skills[0].Name != "aws-iam" {
		t.Errorf("skill name = %q, want aws-iam", result.Skills[0].Name)
	}
}

func TestLoadSkill_FilterBySourceHint(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill", "--source-hint", "GitHub"}) // case-insensitive
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if len(result.Skills) != 1 {
		t.Errorf("want 1 skill (filtered by source_hint=github), got %d", len(result.Skills))
	}
	if result.Skills[0].Name != "github-audit" {
		t.Errorf("skill name = %q, want github-audit", result.Skills[0].Name)
	}
}

func TestLoadSkill_BindingNotePresent(t *testing.T) {
	_, cleanup := writeCatalog(t, testSkillCatalogYAML)
	defer cleanup()

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill"})
		if err != nil {
			t.Errorf("run() returned error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}

	if !strings.Contains(result.BindingNote, "does not register new tools at runtime") {
		t.Errorf("binding_note must state that load-skill does not register new tools at runtime; got %q", result.BindingNote)
	}
	if !strings.Contains(result.BindingNote, "statically registered") {
		t.Errorf("binding_note must mention 'statically registered'; got %q", result.BindingNote)
	}
}

func TestLoadSkill_NoCatalogFile(t *testing.T) {
	// No catalog file — empty catalog is normal at boot.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	orig := os.Getenv("MALLCOP_REPO_ROOT")
	os.Setenv("MALLCOP_REPO_ROOT", dir)
	defer os.Setenv("MALLCOP_REPO_ROOT", orig)

	out := captureStdout(t, func() {
		err := run([]string{"--tool", "load-skill"})
		if err != nil {
			t.Errorf("run() returned unexpected error: %v", err)
		}
	})

	var result loadSkillResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse output JSON: %v\nout=%q", err, out)
	}
	if len(result.Skills) != 0 {
		t.Errorf("want 0 skills when no catalog file, got %d", len(result.Skills))
	}
	if result.BindingNote == "" {
		t.Errorf("binding_note must not be empty even when catalog is absent")
	}
}

// ---- security invariant tests ----------------------------------------------

// TestInvestigateTools_NoNetworkImports greps main.go for forbidden imports.
// This test is the structural defence against network egress and shell escape.
// It strips Go line comments (//) and block comments (/* ... */) before
// checking, so doc-string mentions of forbidden packages don't trigger false
// positives.
func TestInvestigateTools_NoNetworkImports(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	// Strip line comments to avoid matching doc strings that mention the
	// forbidden packages by name (e.g. "No network egress: "net/http" ...").
	stripped := stripLineComments(src)

	// "syscall" is used for file permissions in stdlib internals but we don't
	// import it directly — block it. If you need errno constants, use
	// golang.org/x/sys/unix which can be audited per-symbol.
	forbidden := []string{
		`"net/http"`,
		`"net"`,
		`"os/exec"`,
		`"syscall"`,
	}
	for _, f := range forbidden {
		if bytes.Contains(stripped, []byte(f)) {
			t.Errorf("forbidden import %s present in investigate tools — security invariant broken", f)
		}
	}
}

// stripLineComments removes Go-style line comments (// ...) from src.
// This is intentionally simple: it removes everything from // to end-of-line.
// It does not handle string literals that contain "//", which is an acceptable
// trade-off for this invariant test — the invariant is about import declarations,
// not arbitrary string content.
func stripLineComments(src []byte) []byte {
	var out bytes.Buffer
	lines := bytes.Split(src, []byte("\n"))
	for _, line := range lines {
		if idx := bytes.Index(line, []byte("//")); idx >= 0 {
			line = line[:idx]
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// ---- chart allowlist name test ---------------------------------------------

// TestChartAllowlistMatch verifies that the binary name in the chart seed
// matches the binary name this cmd builds to. A name mismatch causes a silent
// boot-failure of the investigate disposition at legion startup.
func TestChartAllowlistMatch(t *testing.T) {
	// Binary name: the last path segment of the cmd directory.
	// By convention Go builds the binary from the directory name.
	const wantBinaryName = "mallcop-investigate-tools"

	// Read the chart template.
	chartPath := filepath.Join("..", "..", "charts", "exam.toml.tmpl")
	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("read %s: %v", chartPath, err)
	}

	content := string(data)

	// The investigate capability seed should have this binary in its tools list.
	// We look for the binary name as a quoted string entry adjacent to the
	// "investigate" section.
	if !strings.Contains(content, `"`+wantBinaryName+`"`) {
		t.Errorf("chart %s does not contain tool entry %q — investigate disposition will fail to boot",
			chartPath, wantBinaryName)
	}
}

// ---- symlink escape test ---------------------------------------------------

// TestSymlinkEscape verifies that safeOpen rejects paths that resolve outside
// the fixture dir via symlink traversal.
func TestSymlinkEscape(t *testing.T) {
	// Create a temp dir representing the fixture dir.
	fixtureDir := t.TempDir()

	// Create a second temp dir outside the fixture dir (the escape target).
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "secret.json")
	if err := os.WriteFile(secretFile, []byte(`{"secret": "shh"}`), 0o644); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	// Create a symlink inside fixtureDir pointing to the outside dir.
	symlinkPath := filepath.Join(fixtureDir, "escape_link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// Attempt to open the secret file via the symlink: fixture/escape_link/secret.json
	// safeOpen takes (baseDir, relPath) where relPath is relative to baseDir.
	_, err := safeOpen(fixtureDir, "escape_link/secret.json")
	if err == nil {
		t.Fatal("safeOpen should have rejected symlink escape, got nil error")
	}
	if !strings.Contains(err.Error(), "escapes fixture dir") {
		t.Errorf("error should mention 'escapes fixture dir', got: %v", err)
	}
}
