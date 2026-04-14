package main

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// requireCF skips the test if cf is not on PATH.
func requireCF(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skip("cf binary not found on PATH — skipping campfire integration tests")
	}
	return p
}

// newIsolatedCampfire initialises a fresh cf home and creates a campfire.
// It sets CF_HOME on the test environment and returns (cfHome, campfireID).
func newIsolatedCampfire(t *testing.T, cfBin string) (string, string) {
	t.Helper()

	cfHome := t.TempDir()
	t.Setenv("CF_HOME", cfHome)

	// Init identity
	initCmd := exec.Command(cfBin, "init")
	initCmd.Env = append(os.Environ(), "CF_HOME="+cfHome)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("cf init: %v\n%s", err, out)
	}

	// Create campfire; use --json to get structured output with campfire_id
	createCmd := exec.Command(cfBin, "create", "--description", "test-exam-"+t.Name(), "--json")
	createCmd.Env = append(os.Environ(), "CF_HOME="+cfHome)
	out, err := createCmd.Output()
	if err != nil {
		t.Fatalf("cf create: %v\n%s", err, out)
	}

	// Parse campfire_id from JSON output
	var createResult struct {
		CampfireID string `json:"campfire_id"`
	}
	if err := json.Unmarshal(out, &createResult); err != nil {
		t.Fatalf("could not parse cf create JSON output: %v\n%s", err, out)
	}
	campfireID := createResult.CampfireID
	if campfireID == "" {
		t.Fatalf("cf create returned empty campfire_id:\n%s", out)
	}

	return cfHome, campfireID
}

// sendVerdict posts a single judge:verdict message to the campfire.
func sendVerdict(t *testing.T, cfBin, cfHome, campfireID string, v JudgeVerdict) {
	t.Helper()

	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal verdict: %v", err)
	}

	cmd := exec.Command(cfBin, "send", campfireID, string(payload), "--tag", "judge:verdict")
	cmd.Env = append(os.Environ(), "CF_HOME="+cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cf send: %v\n%s", err, out)
	}
}

// buildBinary compiles the mallcop-exam-report binary into a temp dir.
func buildAggregatorBinary(t *testing.T) string {
	t.Helper()

	// Locate repo root by walking up from this file's directory.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found)")
		}
		dir = parent
	}

	bin := filepath.Join(t.TempDir(), "mallcop-exam-report")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop-exam-report")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build mallcop-exam-report: %v\n%s", err, out)
	}
	return bin
}

// canned verdicts for the happy-path test
var cannedVerdicts = []JudgeVerdict{
	{
		FindingID: "f-001",
		Verdict:   "pass",
		Rubric:    Rubric{ReasoningQuality: 4, InvestigationThoroughness: 4, ResolveQuality: 4, EscalationActionability: 1},
		Rationale: "Strong evidence chain with specific event IDs cited.",
		FixTarget: "none",
	},
	{
		FindingID: "f-002",
		Verdict:   "pass",
		Rubric:    Rubric{ReasoningQuality: 5, InvestigationThoroughness: 5, ResolveQuality: 5, EscalationActionability: 1},
		Rationale: "Airtight case. All signals addressed.",
		FixTarget: "none",
	},
	{
		FindingID: "f-003",
		Verdict:   "warn",
		Rubric:    Rubric{ReasoningQuality: 2, InvestigationThoroughness: 4, ResolveQuality: 2, EscalationActionability: 1},
		Rationale: "Correct action but reasoning did not cite specific evidence.",
		FixTarget: "investigate_prompt",
	},
	{
		FindingID: "f-004",
		Verdict:   "fail",
		Rubric:    Rubric{ReasoningQuality: 1, InvestigationThoroughness: 1, ResolveQuality: 1, EscalationActionability: 1},
		Rationale: "No investigation. Decided without using tools.",
		FixTarget: "investigate_prompt",
	},
	{
		FindingID: "f-005",
		Verdict:   "fail",
		Rubric:    Rubric{ReasoningQuality: 1, InvestigationThoroughness: 2, ResolveQuality: 1, EscalationActionability: 1},
		Rationale: "Minimal investigation; conclusion not supported by evidence.",
		FixTarget: "connector_tool",
	},
}

// TestHappyPath_FeatureDepth seeds 5 canned verdicts, runs the aggregator,
// and asserts the report matches expected counts, bucketing, and pass rate.
func TestHappyPath_FeatureDepth(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildAggregatorBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	for _, v := range cannedVerdicts {
		sendVerdict(t, cfBin, cfHome, campfireID, v)
	}

	outDir := t.TempDir()

	cmd := exec.Command(bin, "--campfire", campfireID, "--out-dir", outDir, "--run-id", "test-run-001")
	cmd.Env = append(os.Environ(), "CF_HOME="+cfHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mallcop-exam-report failed: %v\n%s", err, out)
	}

	// Read report.json
	data, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatalf("reading report.json: %v", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshalling report.json: %v", err)
	}

	// Assert run_id
	if report.RunID != "test-run-001" {
		t.Errorf("run_id: got %q, want %q", report.RunID, "test-run-001")
	}

	// Assert scenarios length
	if len(report.Scenarios) != 5 {
		t.Errorf("scenarios length: got %d, want 5", len(report.Scenarios))
	}

	// Assert counts
	s := report.Summary
	if s.Total != 5 {
		t.Errorf("total: got %d, want 5", s.Total)
	}
	if s.PassN != 2 {
		t.Errorf("pass_n: got %d, want 2", s.PassN)
	}
	if s.WarnN != 1 {
		t.Errorf("warn_n: got %d, want 1", s.WarnN)
	}
	if s.FailN != 2 {
		t.Errorf("fail_n: got %d, want 2", s.FailN)
	}

	// Assert by_fix_target bucketing
	expectedBuckets := map[string]int{
		"none":               2,
		"investigate_prompt": 2,
		"connector_tool":     1,
	}
	for k, want := range expectedBuckets {
		got := s.ByFixTarget[k]
		if got != want {
			t.Errorf("by_fix_target[%q]: got %d, want %d", k, got, want)
		}
	}

	// Assert pass_rate with float tolerance
	expectedRate := 2.0 / 5.0
	if math.Abs(s.PassRate-expectedRate) > 1e-9 {
		t.Errorf("pass_rate: got %f, want %f", s.PassRate, expectedRate)
	}

	// Assert report.md exists
	if _, err := os.Stat(filepath.Join(outDir, "report.md")); err != nil {
		t.Errorf("report.md not found: %v", err)
	}
}

// TestEmptyCampfire verifies that an empty campfire produces total==0 and
// pass_rate==0.0 (not NaN) without panicking.
func TestEmptyCampfire(t *testing.T) {
	cfBin := requireCF(t)
	bin := buildAggregatorBinary(t)
	cfHome, campfireID := newIsolatedCampfire(t, cfBin)

	outDir := t.TempDir()

	cmd := exec.Command(bin, "--campfire", campfireID, "--out-dir", outDir, "--run-id", "test-run-empty")
	cmd.Env = append(os.Environ(), "CF_HOME="+cfHome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mallcop-exam-report failed on empty campfire: %v\n%s", err, out)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "report.json"))
	if err != nil {
		t.Fatalf("reading report.json: %v", err)
	}

	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshalling report.json: %v", err)
	}

	s := report.Summary
	if s.Total != 0 {
		t.Errorf("total: got %d, want 0", s.Total)
	}
	if math.IsNaN(s.PassRate) {
		t.Errorf("pass_rate is NaN on empty campfire — should be 0.0")
	}
	if s.PassRate != 0.0 {
		t.Errorf("pass_rate: got %f, want 0.0", s.PassRate)
	}

	// Scenarios slice should be empty (not nil matters for JSON — both acceptable)
	if len(report.Scenarios) != 0 {
		t.Errorf("scenarios length: got %d, want 0", len(report.Scenarios))
	}

	// report.md should still exist
	if _, err := os.Stat(filepath.Join(outDir, "report.md")); err != nil {
		t.Errorf("report.md not found: %v", err)
	}
}

// TestAggregate_Unit tests the pure aggregate() function in isolation.
func TestAggregate_Unit(t *testing.T) {
	verdicts := []JudgeVerdict{
		{FindingID: "a", Verdict: "pass", FixTarget: "none"},
		{FindingID: "b", Verdict: "warn", FixTarget: "triage_prompt"},
		{FindingID: "c", Verdict: "fail", FixTarget: "triage_prompt"},
	}
	r := aggregate("unit-run", verdicts)

	if r.Summary.Total != 3 {
		t.Errorf("total want 3 got %d", r.Summary.Total)
	}
	if r.Summary.PassN != 1 || r.Summary.WarnN != 1 || r.Summary.FailN != 1 {
		t.Errorf("counts wrong: pass=%d warn=%d fail=%d", r.Summary.PassN, r.Summary.WarnN, r.Summary.FailN)
	}
	if r.Summary.ByFixTarget["triage_prompt"] != 2 {
		t.Errorf("by_fix_target[triage_prompt] want 2 got %d", r.Summary.ByFixTarget["triage_prompt"])
	}
	expected := 1.0 / 3.0
	if math.Abs(r.Summary.PassRate-expected) > 1e-9 {
		t.Errorf("pass_rate want %f got %f", expected, r.Summary.PassRate)
	}
}

// TestAggregate_ZeroTotal verifies divide-by-zero guard.
func TestAggregate_ZeroTotal(t *testing.T) {
	r := aggregate("empty", nil)
	if r.Summary.Total != 0 {
		t.Errorf("total want 0 got %d", r.Summary.Total)
	}
	if math.IsNaN(r.Summary.PassRate) {
		t.Error("pass_rate is NaN for zero total")
	}
	if r.Summary.PassRate != 0.0 {
		t.Errorf("pass_rate want 0.0 got %f", r.Summary.PassRate)
	}
}

// --- helpers ---

func splitLines(s string) []string {
	var lines []string
	for _, line := range splitByNewline(s) {
		trimmed := trimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

func splitByNewline(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

