// Package main tests for exam-render-chart.
//
// Legion internal/chart package import strategy: OPTION (c)
//
// github.com/3dl-dev/legion/internal/chart is not reachable from this module
// (mallcop-legion) without adding a go.work pointing at ~/projects/legion.
// Rather than wiring a go.work for a single test, we parse the rendered TOML
// directly with github.com/BurntSushi/toml (already in go.mod) and assert the
// structural invariants by hand:
//   - exactly 5 [[capabilities.seed]] entries
//   - exactly 2 [[hooks]] entries
//   - campfire.transport_dir is set and contains the run ID
//
// If the legion module is later added to go.work, the tests can be upgraded to
// use chart.ParseChart for full validation.
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// renderForTest is a test helper that calls renderTemplate with a temp out dir.
func renderForTest(t *testing.T, runID, forgeURL string) (chartPath string, runDir string) {
	t.Helper()

	tmplPath := filepath.Join("..", "..", "charts", "exam.toml.tmpl")
	// Resolve relative to the test file location.
	if _, err := os.Stat(tmplPath); err != nil {
		// When go test is run from the repo root, the path differs.
		tmplPath = "charts/exam.toml.tmpl"
	}

	tmpDir := t.TempDir()
	outChart := filepath.Join(tmpDir, "chart.toml")
	runDir = filepath.Join(tmpDir, ".run", "exam-"+runID)

	// Patch run to use tmpDir so .run/ lands under t.TempDir().
	rendered, err := renderTemplate(tmplPath, runID, forgeURL)
	if err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}

	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := writeIdentity(runDir); err != nil {
		t.Fatalf("writeIdentity: %v", err)
	}
	if err := os.WriteFile(outChart, []byte(rendered), 0o644); err != nil {
		t.Fatalf("WriteFile chart: %v", err)
	}

	return outChart, runDir
}

// findTemplate walks up from the test binary's working dir to find the template.
func templatePath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"../../charts/exam.toml.tmpl",
		"charts/exam.toml.tmpl",
		"../charts/exam.toml.tmpl",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Fatal("cannot find charts/exam.toml.tmpl relative to test working dir")
	return ""
}

// TestTemplateSubstitution verifies {{RUN_ID}} and {{FORGE_API_URL}} are
// replaced and no template placeholders remain.
func TestTemplateSubstitution(t *testing.T) {
	tmpl := templatePath(t)
	rendered, err := renderTemplate(tmpl, "R1", "http://fake-forge:4000")
	if err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}

	if !strings.Contains(rendered, "exam-R1") {
		t.Error("rendered chart does not contain 'exam-R1'")
	}
	if !strings.Contains(rendered, "http://fake-forge:4000") {
		t.Error("rendered chart does not contain forge URL")
	}
	if strings.Contains(rendered, "{{") {
		t.Errorf("rendered chart still contains {{ placeholders:\n%s", rendered)
	}
}

// rawChart mirrors the subset of the legion chart TOML structure we need for
// structural assertions. Using BurntSushi/toml (already in go.mod) — option (c).
type rawChart struct {
	Capabilities struct {
		Seed []struct {
			Name string `toml:"name"`
		} `toml:"seed"`
	} `toml:"capabilities"`
	Hooks []struct {
		Point   string `toml:"point"`
		Type    string `toml:"type"`
		Command string `toml:"command"`
	} `toml:"hooks"`
	Campfire struct {
		TransportDir string `toml:"transport_dir"`
	} `toml:"campfire"`
	Identity struct {
		Name    string `toml:"name"`
		KeyFile string `toml:"key_file"`
	} `toml:"identity"`
}

// TestLegionChartParse renders for run R1 and parses the TOML, asserting:
//   - zero parse errors
//   - exactly 5 [[capabilities.seed]] entries
//   - exactly 2 [[hooks]] entries
//   - campfire.transport_dir contains "R1"
func TestLegionChartParse(t *testing.T) {
	chartPath, _ := renderForTest(t, "R1", "")

	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("reading chart: %v", err)
	}

	var c rawChart
	if err := toml.Unmarshal(data, &c); err != nil {
		t.Fatalf("TOML parse error: %v", err)
	}

	if got := len(c.Capabilities.Seed); got != 5 {
		t.Errorf("expected 5 capabilities.seed entries, got %d", got)
	}

	if got := len(c.Hooks); got != 2 {
		t.Errorf("expected 2 hooks entries, got %d", got)
	}

	if !strings.Contains(c.Campfire.TransportDir, "R1") {
		t.Errorf("campfire.transport_dir %q does not contain run ID 'R1'", c.Campfire.TransportDir)
	}

	if !strings.Contains(c.Identity.Name, "R1") {
		t.Errorf("identity.name %q does not contain run ID 'R1'", c.Identity.Name)
	}

	expectedSeeds := []string{"triage", "investigate", "heal", "judge", "report"}
	for i, s := range c.Capabilities.Seed {
		if i >= len(expectedSeeds) {
			break
		}
		if s.Name != expectedSeeds[i] {
			t.Errorf("capabilities.seed[%d].name: expected %q, got %q", i, expectedSeeds[i], s.Name)
		}
	}
}

// TestIdentityGeneration verifies that rendering creates .run/exam-<run>/identity.json
// with a valid ed25519 private key (64 bytes hex-encoded = 128 hex chars).
func TestIdentityGeneration(t *testing.T) {
	_, runDir := renderForTest(t, "R1", "")

	identityPath := filepath.Join(runDir, "identity.json")
	data, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("identity.json not created at %s: %v", identityPath, err)
	}

	var id identityFile
	if err := json.Unmarshal(data, &id); err != nil {
		t.Fatalf("identity.json is not valid JSON: %v", err)
	}

	if id.PrivateKey == "" {
		t.Fatal("identity.json private_key is empty")
	}

	decoded, err := hex.DecodeString(id.PrivateKey)
	if err != nil {
		t.Fatalf("private_key is not valid hex: %v", err)
	}

	// ed25519 private key (seed + public) = 64 bytes.
	if len(decoded) != 64 {
		t.Errorf("ed25519 private key should be 64 bytes, got %d", len(decoded))
	}
}
