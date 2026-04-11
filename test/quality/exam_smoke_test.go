//go:build e2e

// Package quality_test contains end-to-end quality gate tests for the
// mallcop-legion exam pipeline.
//
// TestExamID01 is the Phase 1 capstone: it proves the full pipeline from
// chart render → exam seed → real `we` subprocess → judge verdict →
// report.json → pass.
//
// # Canned backend reuse strategy
//
// Option (a) was chosen: the CannedBackend implementation was promoted from
// test/budget/canned_backend.go (//go:build e2e, package budget) to
// internal/testutil/cannedbackend/ (no build tag, importable from any test
// package). test/budget/canned_backend.go now re-exports the types via type
// aliases. This avoids cross-package build-tag issues while keeping a single
// source of truth for the server logic.
//
// The exam-specific canned responses (ExamID01CannedResolutionForCall) return
// content that causes the judge disposition to award reasoning_quality >= 3
// and investigation_thoroughness >= 3, producing a "pass" verdict.
//
// # Campfire wiring
//
// The exam chart uses transport_dir = ".run/exam-<runID>/campfires" (relative
// to the cwd of `we`). exam-render-chart creates .run/exam-<runID>/identity.json
// in the same directory. The test sets:
//
//	cfHome = repoRoot + "/.run/exam-" + runID    (same dir as transport_dir parent)
//
// CF aliases are set in cfHome so that "exam-<runID>" resolves to the hex
// campfire ID. exam-seed and mallcop-exam-report inherit CF_HOME via env.
// `we start` runs with Dir=repoRoot and CF_HOME=cfHome so relative paths in
// the chart resolve correctly.
package quality_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/internal/testutil/cannedbackend"
)

// repoRootQuality resolves the repository root from this test file's location.
// This file lives at test/quality/, two levels below the repo root.
func repoRootQuality(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// test/quality/exam_smoke_test.go → ../.. → repo root
	abs, err := filepath.Abs(filepath.Join(filepath.Dir(filename), "..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	return abs
}

// weWrapperQuality returns the path to bin/we in the repo.
func weWrapperQuality(root string) string {
	return filepath.Join(root, "bin", "we")
}

// requireBinary skips the test if the given binary is not present or not executable.
func requireBinary(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Skipf("binary %s not found (run bin/we itself to download latest release): %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Skipf("binary %s is not executable (mode %s)", path, info.Mode())
	}
}

// requireCFBinary skips the test if cf is not on PATH.
func requireCFBinary(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cf")
	if err != nil {
		t.Skipf("cf binary not on PATH: %v", err)
	}
	return p
}

// initCampfire creates a fresh cf home at cfHome, initialises an identity,
// creates a campfire, and sets an alias so that aliasName resolves to the hex ID.
// Returns the hex campfire ID.
func initCampfire(t *testing.T, cfBin, cfHome, aliasName string) string {
	t.Helper()

	if err := os.MkdirAll(cfHome, 0o755); err != nil {
		t.Fatalf("mkdir cfHome %s: %v", cfHome, err)
	}

	env := setEnvQuality(os.Environ(), "CF_HOME", cfHome)

	// Init identity.
	initCmd := exec.Command(cfBin, "init")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("cf init: %v\n%s", err, out)
	}

	// Create campfire with --protocol open so any identity (including the
	// `we` automaton identity from key_file) can read/write without explicit
	// cf admit. The exam campfire is ephemeral and hermetic; open protocol is
	// fine here.
	createCmd := exec.Command(cfBin, "create", "--description", aliasName, "--no-config", "--protocol", "open")
	createCmd.Env = env
	out, err := createCmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if isExitErrQuality(err, &exitErr) {
			t.Fatalf("cf create: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("cf create: %v", err)
	}

	// Parse campfire ID from stdout — first 64-hex-char line.
	campfireID := ""
	for _, line := range splitLinesQuality(string(out)) {
		if len(line) == 64 && isHexQuality(line) {
			campfireID = line
			break
		}
	}
	if campfireID == "" {
		t.Fatalf("could not parse campfire ID from cf create output:\n%s", out)
	}

	// Set alias so "exam-<runID>" resolves to the hex ID.
	aliasCmd := exec.Command(cfBin, "alias", "set", aliasName, campfireID)
	aliasCmd.Env = env
	if out, err := aliasCmd.CombinedOutput(); err != nil {
		t.Fatalf("cf alias set: %v\n%s", err, out)
	}

	return campfireID
}

// patchChartCampfireID replaces the symbolic campfire alias name with the actual
// hex campfire ID in the [[worksources]] section of the rendered chart.
//
// The chart template renders `campfire = "exam-<runID>"` which the legion
// campfire client cannot resolve (it uses transportDir filesystem lookup, not
// CF_HOME aliases). This patch replaces the symbolic name with the hex ID so
// the ReadyWorkSource finds the correct campfire directory.
func patchChartCampfireID(t *testing.T, chartPath, aliasName, hexID string) {
	t.Helper()
	data, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatalf("patchChartCampfireID: read chart %s: %v", chartPath, err)
	}
	// Replace campfire = "exam-<runID>" with campfire = "<hex-id>".
	old := fmt.Sprintf(`campfire = "%s"`, aliasName)
	new := fmt.Sprintf(`campfire = "%s"`, hexID)
	patched := strings.ReplaceAll(string(data), old, new)
	if patched == string(data) {
		t.Fatalf("patchChartCampfireID: pattern %q not found in chart %s", old, chartPath)
	}
	if err := os.WriteFile(chartPath, []byte(patched), 0o644); err != nil {
		t.Fatalf("patchChartCampfireID: write chart %s: %v", chartPath, err)
	}
}

// runExamRenderChart runs the exam-render-chart command from dir (which becomes
// the working directory so relative .run/ paths land there).
func runExamRenderChart(t *testing.T, dir, templatePath, runID, outPath, forgeURL string) {
	t.Helper()

	cmd := exec.Command(
		"go", "run", "./cmd/exam-render-chart",
		"--template", templatePath,
		"--run", runID,
		"--out", outPath,
		"--forge-url", forgeURL,
	)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exam-render-chart: %v\n%s", err, out)
	}
}

// runExamSeed runs the exam-seed command using cf to post work items.
func runExamSeed(t *testing.T, dir, cfHome, runID, campfireAlias, scenariosDir, fixturesDir string) {
	t.Helper()

	cmd := exec.Command(
		"go", "run", "./cmd/exam-seed",
		"--run", runID,
		"--campfire", campfireAlias,
		"--scenarios-dir", scenariosDir,
		"--fixtures-dir", fixturesDir,
		"--scenario", "ID-01-new-actor-benign-onboarding",
	)
	cmd.Dir = dir
	cmd.Env = setEnvQuality(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exam-seed: %v\n%s", err, out)
	}
	t.Logf("exam-seed output:\n%s", "seeded OK")
}

// runExamReport runs mallcop-exam-report to aggregate judge verdicts.
func runExamReport(t *testing.T, dir, cfHome, campfireAlias, outDir, runID string) {
	t.Helper()

	cmd := exec.Command(
		"go", "run", "./cmd/mallcop-exam-report",
		"--campfire", campfireAlias,
		"--out-dir", outDir,
		"--run-id", runID,
	)
	cmd.Dir = dir
	cmd.Env = setEnvQuality(os.Environ(), "CF_HOME", cfHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mallcop-exam-report: %v\n%s", err, out)
	}
}

// Report mirrors cmd/mallcop-exam-report's Report struct for JSON decoding.
type examReport struct {
	RunID     string           `json:"run_id"`
	Scenarios []examScenResult `json:"scenarios"`
	Summary   examSummary      `json:"summary"`
}

type examScenResult struct {
	ID        string    `json:"id"`
	Verdict   string    `json:"verdict"`
	Rubric    examRubric `json:"rubric"`
	Rationale string    `json:"rationale"`
	FixTarget string    `json:"fix_target"`
}

type examRubric struct {
	ReasoningQuality          int `json:"reasoning_quality"`
	InvestigationThoroughness int `json:"investigation_thoroughness"`
	ResolveQuality            int `json:"resolve_quality"`
	EscalationActionability   int `json:"escalation_actionability"`
}

type examSummary struct {
	Total    int     `json:"total"`
	PassN    int     `json:"pass_n"`
	PassRate float64 `json:"pass_rate"`
}

// TestExamID01 is the Phase 1 capstone end-to-end test.
//
// Pipeline: chart render → exam seed → real `we start --exit-on-idle` subprocess
// → triage+judge+report dispositions against canned backend → read report.json
// → assert verdict=pass with rubric reasoning/thoroughness >= 3.
//
// Skip conditions: bin/we not executable, cf not on PATH.
// Timeout: 120 seconds for the `we` subprocess.
func TestExamID01(t *testing.T) {
	root := repoRootQuality(t)
	weBin := weWrapperQuality(root)
	cfBin := requireCFBinary(t)

	// Preflight: verify bin/we exists and is executable, then check --exit-on-idle support.
	requireBinary(t, weBin)

	probe := exec.Command(weBin, "start", "--exit-on-idle", "--chart", "/nonexistent-preflight")
	probeOut, _ := probe.CombinedOutput()
	if bytes.Contains(probeOut, []byte("flag provided but not defined")) {
		t.Skip("BLOCKED: installed `we` release does not support --exit-on-idle; bump .we-version")
	}

	// Ensure agent identities exist for all exam dispositions.
	// Legion's pilot loads agent identities from agents/<name>/identity.json.
	// ensureExamAgentIdentities creates the symlinks (same approach as chain_budget_test).
	for _, disposition := range []string{"triage", "investigate", "heal", "judge", "report"} {
		ensureExamAgentIdentity(t, root, disposition)
	}

	// Unique run ID — use a fixed but distinctive name so cleanup is easy.
	runID := fmt.Sprintf("smoke-01-%d", time.Now().UnixNano()%1_000_000)
	campfireAlias := "exam-" + runID

	// cfHome = .run/exam-<runID>/ (within the repo working directory).
	// exam-render-chart creates .run/exam-<runID>/identity.json here,
	// and the chart's transport_dir = ".run/exam-<runID>/campfires" resolves
	// to cfHome/campfires/ when we runs from root — matching CF_HOME campfire storage.
	cfHome := filepath.Join(root, ".run", "exam-"+runID)

	// Cleanup: remove all run artifacts after the test.
	t.Cleanup(func() {
		_ = os.RemoveAll(cfHome)                                           // .run/exam-<runID>/
		_ = os.RemoveAll(filepath.Join(root, "exams", "fixtures", runID)) // seeded fixtures
		_ = os.RemoveAll(filepath.Join(root, "exams", "reports", runID))  // report output
	})

	// Start canned backend with exam-specific responses.
	b := &cannedbackend.CannedBackend{
		TokensPerResponse:    4000,
		CannedResolutionFunc: cannedbackend.ExamID01CannedResolutionForCall,
	}
	if err := b.Start(); err != nil {
		t.Fatalf("canned backend start: %v", err)
	}
	defer b.Stop()

	forgeURL := b.URL()
	t.Logf("canned backend at %s", forgeURL)

	// Step 1: Render the chart (this creates cfHome/.run/exam-<runID>/identity.json).
	chartPath := filepath.Join(cfHome, "chart.toml")
	templatePath := filepath.Join(root, "charts", "exam.toml.tmpl")
	runExamRenderChart(t, root, templatePath, runID, chartPath, forgeURL)
	t.Logf("chart rendered to %s", chartPath)

	// Step 1b: Symlink campfire-identity.json → identity.json so that `we`'s
	// embedded campfire client uses the same ed25519 key as the cf CLI identity.
	//
	// Background: legion's boot.go constructs the campfire client identity path as
	// filepath.Join(identityDir, "campfire-identity.json"). When that file does not
	// exist, rdcampfire.NewCampfireClient creates a brand-new identity in a
	// campfire-identity/ sub-directory — a DIFFERENT key than the one that created
	// the campfire. This causes we's Read() to get an empty result even on an open
	// campfire because the auto-join guard (isAdmittedInTransport) only fires when
	// the campfire client's key already appears in the transport members list.
	// Symlinking campfire-identity.json → identity.json makes both cf CLI and the
	// legion campfire client use the identical key, so we joins and reads correctly.
	cfIdentityLink := filepath.Join(cfHome, "campfire-identity.json")
	cfIdentitySrc := filepath.Join(cfHome, "identity.json")
	if err := os.Symlink(cfIdentitySrc, cfIdentityLink); err != nil && !os.IsExist(err) {
		t.Fatalf("symlink campfire-identity.json: %v", err)
	}

	// Step 2: Init isolated campfire (cfHome was created by exam-render-chart).
	// initCampfire also sets up the alias "exam-<runID>" → <hex-id>.
	campfireID := initCampfire(t, cfBin, cfHome, campfireAlias)
	t.Logf("campfire %s → %s", campfireAlias, campfireID)

	// Step 2b: Patch the rendered chart to replace the symbolic campfire name
	// "exam-<runID>" with the actual hex campfire ID.
	//
	// Background: chart.Resolve() passes campfire names through unchanged to the
	// campfire client. The internal campfire client (backed by transportDir) does
	// not resolve CF_HOME aliases — it looks for transportDir/<campfireID>/ directly.
	// Only the hex ID matches the directory on disk. The alias exists in
	// CF_HOME/aliases.json for cf CLI commands (exam-seed, exam-report) but not for
	// the embedded campfire client used by `we`.
	patchChartCampfireID(t, chartPath, campfireAlias, campfireID)
	t.Logf("chart patched: %s → %s", campfireAlias, campfireID[:12])

	// Step 3: Seed the scenario. Use the hex campfire ID (not alias) because
	// exam-seed shells out to `cf send <campfire-id>` — cf CLI resolves aliases
	// via CF_HOME, so either form works; hex ID is unambiguous.
	scenariosDir := filepath.Join(root, "exams", "scenarios")
	fixturesDir := filepath.Join(root, "exams", "fixtures")
	runExamSeed(t, root, cfHome, runID, campfireID, scenariosDir, fixturesDir)
	t.Logf("scenario ID-01-new-actor-benign-onboarding seeded to campfire %s", campfireID[:12])

	// Step 4: Spawn `we start --chart <path> --exit-on-idle`.
	// Timeout: 120 seconds.
	//
	// ANTHROPIC_BASE_URL is set to the canned backend URL so that Claude Code
	// workers spawned by `we` call the canned backend instead of the real
	// Anthropic API. This makes the test deterministic and fast: worker inference
	// completes in milliseconds, the whole pipeline finishes in seconds.
	//
	// Claude Code respects ANTHROPIC_BASE_URL as the API endpoint, so any
	// /v1/messages call from a worker subprocess hits the canned backend. The
	// canned backend serves ExamID01CannedResolutionForCall which returns
	// scenario-appropriate triage (call 0) and judge (call 1) responses.
	cmd := exec.Command(weBin, "start", "--chart", chartPath, "--exit-on-idle")
	cmd.Dir = root
	cmd.Env = setEnvQuality(os.Environ(),
		"FORGE_API_URL", forgeURL,
		"CF_HOME", cfHome,
		"ANTHROPIC_BASE_URL", forgeURL,
	)

	// Pipe stdout+stderr to both a buffer (for assertions) and test log (for visibility).
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		t.Fatalf("we start: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		_ = pw.Close()
	}()

	// Close pipe writer when the process exits so scanner sees EOF.
	go func() {
		_ = cmd.Wait()
		_ = pw.Close()
	}()

	var outBuf bytes.Buffer
	idleMarker := "exiting (--exit-on-idle)"
	deadline := time.After(120 * time.Second)
	idleSeen := make(chan struct{})

	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			outBuf.WriteString(line)
			outBuf.WriteByte('\n')
			t.Logf("[we] %s", line)
			if strings.Contains(line, idleMarker) {
				select {
				case <-idleSeen:
				default:
					close(idleSeen)
				}
			}
		}
	}()

	select {
	case <-idleSeen:
		t.Logf("we reached exit-on-idle marker")
	case <-deadline:
		t.Fatalf("we did not reach --exit-on-idle marker within 120s\nstdout+stderr:\n%s",
			outBuf.String())
	}

	// Brief pause to let scanner flush remaining buffered lines.
	time.Sleep(250 * time.Millisecond)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	_ = pw.Close()

	weOutput := outBuf.String()
	t.Logf("we total output length: %d bytes", len(weOutput))

	// Step 5: Aggregate judge verdicts into report.json.
	// Use the hex campfire ID so `cf read <id>` resolves correctly.
	reportDir := filepath.Join(root, "exams", "reports", runID)
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	runExamReport(t, root, cfHome, campfireID, reportDir, runID)
	t.Logf("report aggregated to %s", reportDir)

	// Step 6: Read and assert report.json.
	reportPath := filepath.Join(reportDir, "report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report.json: %v\nwe output:\n%s", err, weOutput)
	}

	var report examReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse report.json: %v\nraw:\n%s", err, data)
	}

	t.Logf("report.json: run_id=%s scenarios=%d pass_n=%d",
		report.RunID, len(report.Scenarios), report.Summary.PassN)

	// Assertions.
	if len(report.Scenarios) != 1 {
		t.Errorf("scenarios count: got %d, want 1\nfull report:\n%s", len(report.Scenarios), data)
	}

	if len(report.Scenarios) > 0 {
		sc := report.Scenarios[0]
		t.Logf("scenario[0]: id=%s verdict=%s reasoning=%d thoroughness=%d",
			sc.ID, sc.Verdict, sc.Rubric.ReasoningQuality, sc.Rubric.InvestigationThoroughness)

		if sc.Verdict != "pass" {
			t.Errorf("verdict: got %q, want \"pass\"\nrationale: %s\nwe output:\n%s",
				sc.Verdict, sc.Rationale, weOutput)
		}
		if sc.Rubric.ReasoningQuality < 3 {
			t.Errorf("rubric.reasoning_quality: got %d, want >= 3",
				sc.Rubric.ReasoningQuality)
		}
		if sc.Rubric.InvestigationThoroughness < 3 {
			t.Errorf("rubric.investigation_thoroughness: got %d, want >= 3",
				sc.Rubric.InvestigationThoroughness)
		}
	}

	t.Logf("TestExamID01 PASS — canned backend received %d calls", b.CallCount())
}

// ---------------------------------------------------------------------------
// Agent identity helpers
// ---------------------------------------------------------------------------

// ensureExamAgentIdentity ensures agents/<name>/identity.json exists as a
// symlink to ~/.campfire/agents/<name>/identity.json. Mirrors the helper from
// test/budget/chain_budget_test.go:ensureAgentIdentity — see that file for
// the rationale. If the cf-managed identity is missing, runs `cf init --name`.
func ensureExamAgentIdentity(t *testing.T, root, name string) {
	t.Helper()
	repoLink := filepath.Join(root, "agents", name, "identity.json")
	if _, err := os.Lstat(repoLink); err == nil {
		return // already exists (file or symlink)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	cfPath := filepath.Join(home, ".campfire", "agents", name, "identity.json")
	if _, err := os.Stat(cfPath); err != nil {
		// Create the named agent identity via cf.
		cfBin, lookErr := exec.LookPath("cf")
		if lookErr != nil {
			t.Skipf("cf binary not on PATH — cannot bootstrap agent identity %q", name)
		}
		cmd := exec.Command(cfBin, "init", "--name", name)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("cf init --name %s failed: %v\n%s", name, err, out)
		}
	}
	if err := os.MkdirAll(filepath.Dir(repoLink), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(repoLink), err)
	}
	if err := os.Symlink(cfPath, repoLink); err != nil && !os.IsExist(err) {
		t.Fatalf("symlink %s -> %s: %v", repoLink, cfPath, err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setEnvQuality returns a copy of env with the key=val pairs set (replaces
// existing entries). Accepts pairs: setEnvQuality(env, "K1","V1", "K2","V2").
func setEnvQuality(env []string, pairs ...string) []string {
	if len(pairs)%2 != 0 {
		panic("setEnvQuality: odd number of key/value pairs")
	}
	result := make([]string, 0, len(env)+len(pairs)/2)
	prefixes := make([]string, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		prefixes[i/2] = pairs[i] + "="
	}
outer:
	for _, e := range env {
		for _, p := range prefixes {
			if strings.HasPrefix(e, p) {
				continue outer
			}
		}
		result = append(result, e)
	}
	for i := 0; i < len(pairs); i += 2 {
		result = append(result, pairs[i]+"="+pairs[i+1])
	}
	return result
}

func splitLinesQuality(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r\t ")
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func isHexQuality(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isExitErrQuality(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		if target != nil {
			*target = e
		}
		return true
	}
	return false
}
