//go:build e2e

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestDoctorPublishStep_E2E_RealBinaryRealGitStore is the mallcoppro-62c
// headline REAL-PATH proof: it does not re-implement or re-describe the
// "Publish doctor reports" step's shell logic — it extracts the ACTUAL
// `run:` block from the rendered scan.yml template (renderScanWorkflow,
// parsed as real YAML) and executes it, verbatim, with `bash -c`, against:
//
//   - a REAL built mallcop binary (buildMallcop, the same helper
//     scan_e2e_test.go's own binary-driven proof uses) on PATH;
//   - a REAL mallcop.yaml naming two REAL kind:cloud connectors, each
//     forking a REAL sibling subprocess (connect/exec.ExecConnector, not a
//     stand-in) — one deficient, one healthy;
//   - a REAL git-backed store/ directory, initialized through the SAME
//     openOrInitStore production code path 'mallcop scan' itself uses (not
//     a hand-rolled git init).
//
// It asserts the step, run exactly as GitHub Actions would run it:
//
//  1. writes store/doctor.json as a JSON array with exactly the 2 diagnosed
//     connectors' reports (deficient + healthy, matching the fixtures);
//  2. commits it on store's real git history with the exact commit message
//     the template promises ("mallcop doctor: publish diagnosis reports"),
//     staging ONLY doctor.json (git status is otherwise clean);
//  3. exits 0 — the step must never fail the job even though the aggregate
//     mallcop doctor --all invocation itself would exit 1 (one connector is
//     deficient).
func TestDoctorPublishStep_E2E_RealBinaryRealGitStore(t *testing.T) {
	mallcopBin := buildMallcop(t)
	t.Setenv("PATH", filepath.Dir(mallcopBin)+string(os.PathListSeparator)+os.Getenv("PATH"))

	tmp := t.TempDir()
	stateFile := filepath.Join(tmp, "state")
	writeFile(t, stateFile, "deficient")
	// The sibling scripts (doctorFakeSibling/doctorHealthySibling, the same
	// fixtures cli/doctor_test.go's own real-subprocess proof uses) read
	// their diagnosis state from $DOCTOR_STATE_FILE. A real deploy repo's
	// mallcop.yaml declares connector env NAMES (env: [...]) that
	// connect/exec.ExecConnector passes through from THIS process's own
	// environment into the child -- t.Setenv here stands in for a real
	// repo/Actions secret already present in the runner's env.
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	deficientBin := writeFakeSibling(t, tmp, "deficient-sibling", doctorFakeSibling)
	healthyBin := writeFakeSibling(t, tmp, "healthy-sibling", doctorHealthySibling)

	cfgPath := filepath.Join(tmp, "mallcop.yaml")
	storePath := filepath.Join(tmp, "store")
	writeDoctorConfigMulti(t, cfgPath, storePath, map[string]string{
		"azure-prod": deficientBin,
		"gcp-prod":   healthyBin,
	})

	// Simulate exactly what the workflow's "Restore findings store from
	// previous runs" step leaves behind: a real git-backed store/ directory,
	// through the SAME production helper 'mallcop scan' itself calls (not a
	// hand-rolled git init).
	if _, err := openOrInitStore(storePath); err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}

	runBlock := extractStepRun(t, renderScanWorkflow("v0.7.0"), "Publish doctor reports (self-heal loop)")

	cmd := exec.Command("bash", "-c", runBlock)
	cmd.Dir = tmp // mallcop.yaml auto-discovers from cwd, exactly like the real checkout root
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("the rendered doctor-publish step failed (it must NEVER fail the job): %v\noutput:\n%s", err, out.String())
	}

	doctorJSON, err := os.ReadFile(filepath.Join(storePath, "doctor.json"))
	if err != nil {
		t.Fatalf("store/doctor.json was not written by the real step: %v\nstep output:\n%s", err, out.String())
	}
	var reports []struct {
		ConnectorID string `json:"connector_id"`
		Diagnosis   struct {
			Known   bool   `json:"known"`
			Summary string `json:"summary"`
		} `json:"diagnosis"`
	}
	if err := json.Unmarshal(doctorJSON, &reports); err != nil {
		t.Fatalf("store/doctor.json is not a valid JSON array: %v\ncontent: %s", err, doctorJSON)
	}
	if len(reports) != 2 {
		t.Fatalf("store/doctor.json has %d entries, want exactly 2 (one per real diagnosable connector): %s", len(reports), doctorJSON)
	}
	byID := map[string]bool{}
	for _, r := range reports {
		byID[r.ConnectorID] = r.Diagnosis.Known
	}
	if known, ok := byID["azure-prod"]; !ok || !known {
		t.Errorf("azure-prod entry missing or not a classified diagnosis: %s", doctorJSON)
	}
	if known, ok := byID["gcp-prod"]; !ok || !known {
		t.Errorf("gcp-prod entry missing or not a classified diagnosis: %s", doctorJSON)
	}

	// The commit must exist, with the exact promised message, on store's REAL
	// git history.
	logCmd := exec.Command("git", "-C", storePath, "log", "-1", "--format=%s")
	logOut, err := logCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log in store/: %v\n%s", err, logOut)
	}
	if got := strings.TrimSpace(string(logOut)); got != "mallcop doctor: publish diagnosis reports" {
		t.Errorf("store/'s latest commit message = %q, want the exact promised message", got)
	}

	// Staging discipline: after the step, the store working tree must be
	// clean (doctor.json was staged AND committed -- nothing else touched).
	statusCmd := exec.Command("git", "-C", storePath, "status", "--porcelain")
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git status in store/: %v\n%s", err, statusOut)
	}
	if strings.TrimSpace(string(statusOut)) != "" {
		t.Errorf("store/ working tree is not clean after the doctor-publish step: %q", statusOut)
	}
}

// extractStepRun parses workflowYAML as real YAML, finds the scan job's step
// named stepName, and returns its run: block verbatim -- the SAME text
// GitHub Actions itself would execute, not a re-derived copy.
func extractStepRun(t *testing.T, workflowYAML, stepName string) string {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(workflowYAML), &doc); err != nil {
		t.Fatalf("workflow does not parse as YAML: %v", err)
	}
	jobs, _ := doc["jobs"].(map[string]any)
	scanJob, _ := jobs["scan"].(map[string]any)
	steps, _ := scanJob["steps"].([]any)
	for _, s := range steps {
		stepMap, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := stepMap["name"].(string); name == stepName {
			run, _ := stepMap["run"].(string)
			if run == "" {
				t.Fatalf("step %q has no run: block", stepName)
			}
			return run
		}
	}
	t.Fatalf("no step named %q found in the rendered workflow", stepName)
	return ""
}
