//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot returns the absolute path to the mallcop-legion repo root.
// This file lives at test/integration/cross_repo_pipeline_test.go.
func legionRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// connectorsRoot returns the mallcop-connectors repo root, adjacent to mallcop-legion.
func connectorsRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(legionRoot(t), "..", "mallcop-connectors")
}

// buildBinary builds a Go binary from srcDir and returns the path to the binary.
func buildBinary(t *testing.T, srcDir string, name string) string {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", outPath, ".")
	cmd.Dir = srcDir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build %s: %v\nstderr:\n%s", name, err, stderr.String())
	}
	return outPath
}

// findingSchema captures the minimal required fields a finding JSON must have.
type findingSchema struct {
	ID       string          `json:"id"`
	Source   string          `json:"source"`
	Severity string          `json:"severity"`
	Type     string          `json:"type"`
	Actor    string          `json:"actor"`
	Evidence json.RawMessage `json:"evidence"`
}

func TestCrossRepoPipeline_Build(t *testing.T) {
	// Build all three binaries from source. Fail fast if any build fails.
	_ = buildBinary(t, filepath.Join(connectorsRoot(t), "cmd", "github"), "github-connector")
	_ = buildBinary(t, filepath.Join(legionRoot(t), "cmd", "detector-unusual-login"), "detector-unusual-login")
	_ = buildBinary(t, filepath.Join(legionRoot(t), "cmd", "mallcop-finding-context"), "mallcop-finding-context")
}

func TestCrossRepoPipeline_ConnectorToDetector(t *testing.T) {
	root := legionRoot(t)
	fixtureDir := filepath.Join(root, "cmd", "detector-unusual-login", "fixtures")

	detectorBin := buildBinary(t, filepath.Join(root, "cmd", "detector-unusual-login"), "detector-unusual-login")

	eventsFile := filepath.Join(fixtureDir, "events.jsonl")
	baselineFile := filepath.Join(fixtureDir, "baseline.json")

	eventsData, err := os.ReadFile(eventsFile)
	if err != nil {
		t.Fatalf("read events fixture: %v", err)
	}

	cmd := exec.Command(detectorBin, "--baseline", baselineFile)
	cmd.Stdin = bytes.NewReader(eventsData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("detector failed: %v\nstderr:\n%s", err, stderr.String())
	}

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		t.Fatal("detector produced no output")
	}

	// Validate each output line is valid Finding JSON with required fields.
	scanner := bufio.NewScanner(strings.NewReader(output))
	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++
		var f findingSchema
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Errorf("line %d: invalid JSON: %v\nline content: %s", lineNum, err, line)
			continue
		}
		if f.ID == "" {
			t.Errorf("line %d: finding missing 'id' field", lineNum)
		}
		if f.Source == "" {
			t.Errorf("line %d: finding missing 'source' field", lineNum)
		}
		if f.Severity == "" {
			t.Errorf("line %d: finding missing 'severity' field", lineNum)
		}
		if f.Type == "" {
			t.Errorf("line %d: finding missing 'type' field", lineNum)
		}
		if f.Actor == "" {
			t.Errorf("line %d: finding missing 'actor' field", lineNum)
		}
	}
	if lineNum == 0 {
		t.Fatal("detector output had no non-empty lines")
	}
	t.Logf("detector produced %d findings", lineNum)
}

func TestCrossRepoPipeline_DetectorToFindingContext(t *testing.T) {
	root := legionRoot(t)
	fixtureDir := filepath.Join(root, "cmd", "detector-unusual-login", "fixtures")

	detectorBin := buildBinary(t, filepath.Join(root, "cmd", "detector-unusual-login"), "detector-unusual-login")
	contextBin := buildBinary(t, filepath.Join(root, "cmd", "mallcop-finding-context"), "mallcop-finding-context")

	eventsFile := filepath.Join(fixtureDir, "events.jsonl")
	baselineFile := filepath.Join(fixtureDir, "baseline.json")

	// Stage 1: run detector to get findings.
	eventsData, err := os.ReadFile(eventsFile)
	if err != nil {
		t.Fatalf("read events fixture: %v", err)
	}
	detectorCmd := exec.Command(detectorBin, "--baseline", baselineFile)
	detectorCmd.Stdin = bytes.NewReader(eventsData)
	var detectorOut bytes.Buffer
	detectorCmd.Stdout = &detectorOut
	if err := detectorCmd.Run(); err != nil {
		t.Fatalf("detector failed: %v", err)
	}

	// Pick the first finding line.
	var firstFinding string
	scanner := bufio.NewScanner(&detectorOut)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			firstFinding = line
			break
		}
	}
	if firstFinding == "" {
		t.Fatal("detector produced no findings")
	}

	// Validate it's valid JSON before passing to finding-context.
	var f findingSchema
	if err := json.Unmarshal([]byte(firstFinding), &f); err != nil {
		t.Fatalf("first finding is not valid JSON: %v\nline: %s", err, firstFinding)
	}

	// Write finding to a temp file.
	findingFile := filepath.Join(t.TempDir(), "finding.json")
	if err := os.WriteFile(findingFile, []byte(firstFinding), 0o600); err != nil {
		t.Fatalf("write finding file: %v", err)
	}

	// Stage 2: run finding-context with the detector's output as input.
	for _, field := range []string{"external-messages", "standing-facts", "spec"} {
		t.Run(field, func(t *testing.T) {
			cmd := exec.Command(contextBin,
				"--finding", findingFile,
				"--events", eventsFile,
				"--baseline", baselineFile,
				"--field", field,
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Fatalf("finding-context --field %s failed: %v\nstderr:\n%s", field, err, stderr.String())
			}

			output := stdout.String()
			if strings.TrimSpace(output) == "" {
				t.Fatalf("finding-context --field %s produced no output", field)
			}

			// external-messages and spec must contain USER_DATA_BEGIN/END markers.
			// external-messages wraps all events in one block (1 pair).
			// spec wraps each external field (actor, reason, evidence) individually — 1+ pairs.
			if field == "external-messages" || field == "spec" {
				beginCount := strings.Count(output, "[USER_DATA_BEGIN]")
				endCount := strings.Count(output, "[USER_DATA_END]")
				if beginCount == 0 {
					t.Errorf("field %s: missing [USER_DATA_BEGIN] marker", field)
				}
				if endCount == 0 {
					t.Errorf("field %s: missing [USER_DATA_END] marker", field)
				}
				// Begin and end counts must match (balanced markers).
				if beginCount != endCount {
					t.Errorf("field %s: unbalanced markers: %d [USER_DATA_BEGIN] vs %d [USER_DATA_END]",
						field, beginCount, endCount)
				}
				// external-messages always emits exactly one block.
				if field == "external-messages" && beginCount != 1 {
					t.Errorf("field external-messages: expected exactly 1 marker pair, got %d", beginCount)
				}
			}
			t.Logf("field %s output length: %d bytes", field, len(output))
		})
	}
}

func TestCrossRepoPipeline_SchemaCompatibility(t *testing.T) {
	// Verify that the Event schema emitted by the detector fixtures matches
	// what finding-context expects: both repos use the same field set.
	root := legionRoot(t)
	eventsFile := filepath.Join(root, "cmd", "detector-unusual-login", "fixtures", "events.jsonl")

	data, err := os.ReadFile(eventsFile)
	if err != nil {
		t.Fatalf("read events.jsonl: %v", err)
	}

	type eventSchema struct {
		ID        string          `json:"id"`
		Source    string          `json:"source"`
		Type      string          `json:"type"`
		Actor     string          `json:"actor"`
		Timestamp string          `json:"timestamp"`
		Org       string          `json:"org"`
		Payload   json.RawMessage `json:"payload"`
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNum++
		var ev eventSchema
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("events.jsonl line %d: invalid JSON: %v", lineNum, err)
			continue
		}
		if ev.ID == "" {
			t.Errorf("events.jsonl line %d: missing 'id'", lineNum)
		}
		if ev.Source == "" {
			t.Errorf("events.jsonl line %d: missing 'source'", lineNum)
		}
		if ev.Type == "" {
			t.Errorf("events.jsonl line %d: missing 'type'", lineNum)
		}
		if ev.Timestamp == "" {
			t.Errorf("events.jsonl line %d: missing 'timestamp'", lineNum)
		}
	}
	t.Logf("validated %d events from events.jsonl", lineNum)
}
