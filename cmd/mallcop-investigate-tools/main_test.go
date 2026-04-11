package main

import (
	"bytes"
	"encoding/json"
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
