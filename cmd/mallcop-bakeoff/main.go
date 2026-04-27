// Command mallcop-bakeoff runs the academy bakeoff against real Forge for an
// arbitrary candidate model slate.
//
// Architecture:
//
//   - One legion automaton per candidate model. Each automaton owns a
//     dedicated rd campfire, a rendered chart, and the full per-model
//     scenario sweep (triage → judge → report).
//   - Automatons run concurrently up to --max-concurrent. Each "we start"
//     uses --exit-on-idle and self-terminates when its work source drains.
//     The orchestrator does NOT impose a wall-clock kill on running
//     automatons; budget enforcement is pre-flight and chart-budget based.
//   - After all automatons exit, per-model report.json artifacts are produced
//     by mallcop-exam-report (reading judge:verdict messages from the campfire),
//     then transformed into bakeoff-aggregate.py-compatible JSON files.
//
// CLI:
//
//	mallcop-bakeoff \
//	  --slate exams/slates/<name>.yaml \
//	  --run-id <id> \
//	  [--scenarios-dir exams/scenarios] \
//	  [--scenario <single-scenario-id>] \
//	  [--max-concurrent 4] \
//	  [--budget-usd 150.00] \
//	  [--output-dir docs/bakeoff/<run-id>] \
//	  [--forge-url https://forge.3dl.dev] \
//	  [--catalog ~/projects/forge/internal/catalog/models.yaml]
//
// Env: FORGE_API_KEY (required, no default).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Slate is the YAML format for the candidate model list.
//
//	models:
//	  - id: glm-4.7-flash
//	    sovereignty: open
//	  - id: claude-haiku-4-5
//	    sovereignty: us_only
type Slate struct {
	Models []SlateModel `yaml:"models"`
}

type SlateModel struct {
	ID          string `yaml:"id"`
	Sovereignty string `yaml:"sovereignty,omitempty"`
}

// CatalogModel is the Forge models.yaml entry shape we care about for
// pre-flight budget estimation and bakeoff-aggregate cost passthrough.
type CatalogModel struct {
	ID                   string  `yaml:"id"`
	Sovereignty          string  `yaml:"sovereignty"`
	BedrockInputPerMtok  float64 `yaml:"bedrock_input_per_mtok"`
	BedrockOutputPerMtok float64 `yaml:"bedrock_output_per_mtok"`
}

type Catalog struct {
	Models []CatalogModel `yaml:"models"`
}

// PerModelResult is the bakeoff-aggregate.py-compatible per-model record.
// See mallcop-pro/scripts/bakeoff-aggregate.py merge_results() for schema.
type PerModelResult struct {
	PassRate        *float64 `json:"pass_rate"`
	Sovereignty     string   `json:"sovereignty,omitempty"`
	ScenariosRun    int      `json:"scenarios_run"`
	ScenariosPassed int      `json:"scenarios_passed"`
	Errors          []string `json:"errors,omitempty"`
	BlendedPerMtok  float64  `json:"blended_per_mtok,omitempty"`
}

// BakeoffPerModelFile is the on-disk JSON written per model. The aggregator
// reads `data["models"][<alias>]` so we wrap the per-model record under the
// alias key.
type BakeoffPerModelFile struct {
	Models map[string]PerModelResult `json:"models"`
}

// ExamReportSummary mirrors mallcop-exam-report's report.json summary block.
type ExamReportSummary struct {
	Total    int     `json:"total"`
	PassN    int     `json:"pass_n"`
	WarnN    int     `json:"warn_n"`
	FailN    int     `json:"fail_n"`
	PassRate float64 `json:"pass_rate"`
}

type ExamReport struct {
	RunID   string            `json:"run_id"`
	Summary ExamReportSummary `json:"summary"`
}

type runState struct {
	model         SlateModel
	workDir       string
	chartPath     string
	wePID         int
	exitErr       error
	wallTime      time.Duration
	bakeoffPath   string
	reportPath    string
	scenariosRun  int
	passN         int
	failN         int
	tokensInput   int64 // reserved for future telemetry; not populated in v1
	tokensOutput  int64
	usdEstimated  float64
	skipped       string // populated when the model was skipped (e.g. seed failure)
}

func main() {
	var (
		slatePath     string
		runID         string
		scenariosDir  string
		scenarioID    string
		maxConcurrent int
		budgetUSD     float64
		outputDir     string
		forgeURL      string
		catalogPath   string
	)
	flag.StringVar(&slatePath, "slate", "", "path to slate YAML file (required)")
	flag.StringVar(&runID, "run-id", "", "run identifier (required)")
	flag.StringVar(&scenariosDir, "scenarios-dir", "", "scenarios directory (default: <repo>/exams/scenarios)")
	flag.StringVar(&scenarioID, "scenario", "", "optional: limit to single scenario ID (passed through to exam-seed)")
	flag.IntVar(&maxConcurrent, "max-concurrent", 4, "maximum concurrent legion automatons")
	flag.Float64Var(&budgetUSD, "budget-usd", 150.0, "hard USD budget cap for the slate (worst-case pre-flight enforced)")
	flag.StringVar(&outputDir, "output-dir", "", "output directory for per-model bakeoff JSON files (default: <repo>/docs/bakeoff/<run-id>)")
	flag.StringVar(&forgeURL, "forge-url", "https://forge.3dl.dev", "Forge API URL")
	flag.StringVar(&catalogPath, "catalog", "", "path to Forge models.yaml catalog (optional; enables sovereignty + cost in per-model JSON)")
	flag.Parse()

	if err := run(runArgs{
		slatePath:     slatePath,
		runID:         runID,
		scenariosDir:  scenariosDir,
		scenarioID:    scenarioID,
		maxConcurrent: maxConcurrent,
		budgetUSD:     budgetUSD,
		outputDir:     outputDir,
		forgeURL:      forgeURL,
		catalogPath:   catalogPath,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

type runArgs struct {
	slatePath     string
	runID         string
	scenariosDir  string
	scenarioID    string
	maxConcurrent int
	budgetUSD     float64
	outputDir     string
	forgeURL      string
	catalogPath   string
}

func run(a runArgs) error {
	// --- Validation -----------------------------------------------------
	if a.slatePath == "" {
		return errors.New("--slate is required")
	}
	if a.runID == "" {
		return errors.New("--run-id is required")
	}
	if !runIDRegexp.MatchString(a.runID) {
		return fmt.Errorf("--run-id must match %s (got %q)", runIDRegexp, a.runID)
	}
	if a.maxConcurrent < 1 {
		return errors.New("--max-concurrent must be >= 1")
	}
	if a.budgetUSD <= 0 {
		return errors.New("--budget-usd must be > 0")
	}
	apiKey := os.Getenv("FORGE_API_KEY")
	if apiKey == "" {
		return errors.New("FORGE_API_KEY environment variable is required (must not be hardcoded)")
	}

	repoRoot, err := repoRoot()
	if err != nil {
		return err
	}

	if a.scenariosDir == "" {
		a.scenariosDir = filepath.Join(repoRoot, "exams", "scenarios")
	}
	if a.outputDir == "" {
		a.outputDir = filepath.Join(repoRoot, "docs", "bakeoff", a.runID)
	}
	chartTmpl := filepath.Join(repoRoot, "charts", "exam-bakeoff.toml.tmpl")
	if _, err := os.Stat(chartTmpl); err != nil {
		return fmt.Errorf("chart template not found at %s: %w", chartTmpl, err)
	}
	binDir := filepath.Join(repoRoot, "bin")
	weBin := filepath.Join(binDir, "we")
	rdBin, err := exec.LookPath("rd")
	if err != nil {
		return fmt.Errorf("rd binary not on PATH: %w", err)
	}
	examSeed := filepath.Join(binDir, "exam-seed")
	examReport := filepath.Join(binDir, "mallcop-exam-report")
	for _, b := range []string{weBin, examSeed, examReport} {
		if _, err := os.Stat(b); err != nil {
			return fmt.Errorf("required binary missing: %s: %w", b, err)
		}
	}

	// --- Slate + catalog ------------------------------------------------
	slate, err := loadSlate(a.slatePath)
	if err != nil {
		return fmt.Errorf("load slate: %w", err)
	}
	if len(slate.Models) == 0 {
		return errors.New("slate has no models")
	}
	var catalogIdx map[string]CatalogModel
	if a.catalogPath != "" {
		catalogIdx, err = loadCatalog(a.catalogPath)
		if err != nil {
			return fmt.Errorf("load catalog: %w", err)
		}
		// Cross-pollinate sovereignty from catalog into slate entries that
		// didn't specify it. Fail-fast on unknown IDs since the bakeoff
		// will fail later anyway.
		for i, m := range slate.Models {
			cat, ok := catalogIdx[m.ID]
			if !ok {
				return fmt.Errorf("model %q not in catalog %s", m.ID, a.catalogPath)
			}
			if slate.Models[i].Sovereignty == "" {
				slate.Models[i].Sovereignty = cat.Sovereignty
			}
		}
	}

	// --- Pre-flight budget guard ---------------------------------------
	if err := preflightBudget(slate, catalogIdx, a.budgetUSD); err != nil {
		return err
	}

	// --- Wrapper warm-up (avoid cold-cache races at parallel launch) ----
	fmt.Fprintf(os.Stderr, ">>> warming we wrapper cache ...\n")
	if out, err := exec.Command(weBin, "--version").CombinedOutput(); err != nil {
		return fmt.Errorf("we wrapper warm-up failed: %s: %w", strings.TrimSpace(string(out)), err)
	} else {
		fmt.Fprintf(os.Stderr, "    we %s", string(out))
	}

	// --- Output dir setup ----------------------------------------------
	if err := os.MkdirAll(a.outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	runRoot := filepath.Join(repoRoot, ".run", "bakeoff-"+a.runID)
	if err := os.MkdirAll(runRoot, 0o755); err != nil {
		return fmt.Errorf("create run root: %w", err)
	}

	// --- Signal handling: orchestrator-level shutdown ------------------
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// --- Per-model setup (sequential — exam-seed touches shared paths) -
	states := make([]*runState, len(slate.Models))
	for i, m := range slate.Models {
		s := &runState{model: m, workDir: filepath.Join(runRoot, sanitizeID(m.ID))}
		states[i] = s
		if err := perModelSetup(setupArgs{
			repoRoot:     repoRoot,
			runID:        a.runID,
			model:        m,
			workDir:      s.workDir,
			chartTmpl:    chartTmpl,
			binDir:       binDir,
			rdBin:        rdBin,
			weBin:        weBin,
			examSeed:     examSeed,
			scenariosDir: a.scenariosDir,
			scenarioID:   a.scenarioID,
			forgeURL:     a.forgeURL,
			forgeAPIKey:  apiKey,
		}, s); err != nil {
			s.skipped = err.Error()
			fmt.Fprintf(os.Stderr, "WARN: setup failed for %s: %v\n", m.ID, err)
		}
	}

	// --- Concurrent automaton launch -----------------------------------
	fmt.Fprintf(os.Stderr, ">>> launching %d automatons (max-concurrent=%d) with --exit-on-idle\n",
		countLaunchable(states), a.maxConcurrent)
	sem := make(chan struct{}, a.maxConcurrent)
	var wg sync.WaitGroup
	for _, s := range states {
		if s.skipped != "" {
			continue
		}
		wg.Add(1)
		go func(s *runState) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			runAutomaton(ctx, weBin, repoRoot, s)
		}(s)
	}
	wg.Wait()

	// --- Post-run harvest ----------------------------------------------
	fmt.Fprintf(os.Stderr, ">>> harvesting reports\n")
	for _, s := range states {
		if s.skipped != "" {
			continue
		}
		if err := harvestModel(harvestArgs{
			runID:        a.runID,
			examReport:   examReport,
			outputDir:    a.outputDir,
			catalogIdx:   catalogIdx,
		}, s); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: harvest failed for %s: %v\n", s.model.ID, err)
		}
	}

	// --- Summary -------------------------------------------------------
	summaryPath := filepath.Join(a.outputDir, "run-summary.txt")
	if err := writeSummary(summaryPath, a, states); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	printSummary(states, a.outputDir)
	return nil
}

var runIDRegexp = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func sanitizeID(id string) string {
	// model IDs may contain dots; keep them but replace anything else
	// problematic in path components.
	return strings.NewReplacer("/", "_").Replace(id)
}

func countLaunchable(s []*runState) int {
	n := 0
	for _, st := range s {
		if st.skipped == "" {
			n++
		}
	}
	return n
}

func loadSlate(path string) (*Slate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Slate
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func loadCatalog(path string) (map[string]CatalogModel, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	idx := make(map[string]CatalogModel, len(c.Models))
	for _, m := range c.Models {
		idx[m.ID] = m
	}
	return idx, nil
}

// preflightBudget refuses to start if the worst-case sum of per-model token
// allowances × per-model blended cost exceeds budget * 1.5 (50% over-budget
// guard). Worst-case uses the chart's max_tokens_per_session = 5_000_000.
//
// When --catalog is not provided, the per-model rate is unknown so the guard
// is advisory (logs a warning, proceeds). Always pass --catalog for hard
// enforcement.
func preflightBudget(slate *Slate, catalog map[string]CatalogModel, budgetUSD float64) error {
	const maxTokensPerSession = 5_000_000.0
	const overBudgetTolerance = 1.5
	if catalog == nil {
		fmt.Fprintf(os.Stderr,
			"WARN: --catalog not provided; budget guard is advisory. Pass --catalog for default-deny enforcement.\n")
		return nil
	}
	worst := 0.0
	for _, m := range slate.Models {
		cat, ok := catalog[m.ID]
		if !ok {
			continue // already checked in run()
		}
		blended := (cat.BedrockInputPerMtok + cat.BedrockOutputPerMtok) / 2.0
		modelWorst := (maxTokensPerSession / 1_000_000.0) * blended
		worst += modelWorst
		fmt.Fprintf(os.Stderr, "    budget: %s worst-case $%.2f (cap=%.0fM tokens × $%.4f/Mtok blended)\n",
			m.ID, modelWorst, maxTokensPerSession/1_000_000.0, blended)
	}
	limit := budgetUSD * overBudgetTolerance
	fmt.Fprintf(os.Stderr, "    budget: total worst-case $%.2f vs cap $%.2f (×%.1f tolerance = $%.2f)\n",
		worst, budgetUSD, overBudgetTolerance, limit)
	if worst > limit {
		return fmt.Errorf("pre-flight budget refused: worst-case $%.2f exceeds $%.2f (cap=$%.2f × %.1f). "+
			"Reduce slate, lower chart [budget].max_tokens_per_session, or raise --budget-usd",
			worst, limit, budgetUSD, overBudgetTolerance)
	}
	return nil
}

type setupArgs struct {
	repoRoot     string
	runID        string
	model        SlateModel
	workDir      string
	chartTmpl    string
	binDir       string
	rdBin        string
	weBin        string
	examSeed     string
	scenariosDir string
	scenarioID   string
	forgeURL     string
	forgeAPIKey  string
}

// perModelSetup creates per-model directories, initialises the per-model rd
// campfire, joins a worker identity, renders the chart, and seeds scenarios.
// All sequential — these steps share filesystem state and short-lived rd
// subprocess invocations.
func perModelSetup(a setupArgs, s *runState) error {
	opCFHome := filepath.Join(a.workDir, "op-cf")
	workerCFHome := filepath.Join(a.workDir, "worker-cf")
	projectDir := filepath.Join(a.workDir, "project")
	workerProjectDir := filepath.Join(a.workDir, "worker-project")
	for _, d := range []string{opCFHome, workerCFHome, projectDir, workerProjectDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// rd init the project campfire
	if out, err := envCmd(opCFHome, projectDir, a.rdBin, "init", "--name", "bakeoff-"+a.runID+"-"+sanitizeID(a.model.ID)).CombinedOutput(); err != nil {
		return fmt.Errorf("rd init: %s: %w", strings.TrimSpace(string(out)), err)
	}
	rootFile := filepath.Join(projectDir, ".campfire", "root")
	rootBytes, err := os.ReadFile(rootFile)
	if err != nil {
		return fmt.Errorf("rd init did not create %s: %w", rootFile, err)
	}
	campfireID := strings.TrimSpace(string(rootBytes))
	if campfireID == "" {
		return fmt.Errorf("empty campfire ID in %s", rootFile)
	}

	// rd invite agent token
	inviteOut, err := envCmd(opCFHome, projectDir, a.rdBin, "invite", "--role", "agent", "--ttl", "60m").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rd invite: %s: %w", strings.TrimSpace(string(inviteOut)), err)
	}
	token := extractToken(string(inviteOut))
	if token == "" {
		return fmt.Errorf("could not extract invite token from: %s", strings.TrimSpace(string(inviteOut)))
	}

	// rd join from worker side
	if out, err := envCmd(workerCFHome, workerProjectDir, a.rdBin, "join", token).CombinedOutput(); err != nil {
		return fmt.Errorf("rd join: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Register automaton fleet entry (we init's side effect of writing to
	// ~/.legion/automata/<name>/ — the actual key_file used is the rd-joined
	// identity copied below). Mirrors run-smoke.sh's "wire automaton identity"
	// step. --force lets re-runs reuse the same alias.
	weAlias := "bakeoff-" + a.runID + "-" + sanitizeID(a.model.ID)
	if out, err := exec.Command(a.weBin, "init", "--name", weAlias, "--force").CombinedOutput(); err != nil {
		return fmt.Errorf("we init: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Copy the rd-joined identity to the per-model identity path the chart
	// will reference, AND to campfire-identity.json — boot.go derives that
	// path from filepath.Dir(key_file) and uses it for CampfireClient init.
	// Without it, the worker boots with a fresh campfire identity that has
	// no membership in the work campfire, so PollForWork sees zero items.
	identitySrc := filepath.Join(workerCFHome, "identity.json")
	identityDst := filepath.Join(a.workDir, "identity.json")
	cfIdentityDst := filepath.Join(a.workDir, "campfire-identity.json")
	if err := copyFile(identitySrc, identityDst); err != nil {
		return fmt.Errorf("copy identity: %w", err)
	}
	if err := copyFile(identitySrc, cfIdentityDst); err != nil {
		return fmt.Errorf("copy campfire-identity: %w", err)
	}

	// Render chart
	chartOut := filepath.Join(a.workDir, "chart.toml")
	if err := renderChart(a.chartTmpl, chartOut, map[string]string{
		"MODEL":          a.model.ID,
		"RUN_ID":         a.runID,
		"FORGE_API_URL":  a.forgeURL,
		"FORGE_API_KEY":  a.forgeAPIKey,
		"TOOL_BIN_DIR":   a.binDir,
	}); err != nil {
		return fmt.Errorf("render chart: %w", err)
	}
	// Substitute per-model campfire ID, transport_dir, and identity key_file.
	if err := postProcessChart(chartOut, a.runID, campfireID, opCFHome, identityDst); err != nil {
		return fmt.Errorf("post-process chart: %w", err)
	}
	s.chartPath = chartOut

	// Seed scenarios
	args := []string{
		"-campfire", campfireID,
		"-run", a.runID,
		"-scenarios-dir", a.scenariosDir,
	}
	if a.scenarioID != "" {
		args = append(args, "-scenario", a.scenarioID)
	}
	seedCmd := envCmd(opCFHome, a.repoRoot, a.examSeed, args...)
	if out, err := seedCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("exam-seed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Settle window: the ready worksource projection needs a moment to
	// observe and index the just-posted work:create messages before the
	// automaton's first poll. Without this, the first poll reports
	// "queue empty" even though messages are on disk, and --exit-on-idle
	// fires immediately on a still-warming index. (Mirrors run-smoke.sh's
	// "waiting 5s for messages to settle" step.)
	time.Sleep(5 * time.Second)
	return nil
}

// renderChart performs whole-token replacement of {{KEY}} placeholders.
func renderChart(tmplPath, outPath string, vars map[string]string) error {
	b, err := os.ReadFile(tmplPath)
	if err != nil {
		return err
	}
	s := string(b)
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return os.WriteFile(outPath, []byte(s), 0o644)
}

// postProcessChart fixes three values that depend on per-model state and
// aren't in the template variables:
//   - worksources.campfire: the rd campfire ID created for this model
//   - campfire.transport_dir: per-model op-cf-home/campfires
//   - identity.key_file: per-model identity (absolute, since the per-model
//     workdir doesn't match the template's repo-relative .run/exam-<id>/
func postProcessChart(path, runID, campfireID, opCFHome, identityPath string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(b)
	s = strings.ReplaceAll(s,
		`campfire = "exam-`+runID+`"`,
		`campfire = "`+campfireID+`"`)
	s = strings.ReplaceAll(s,
		`transport_dir = ".run/exam-`+runID+`/campfires"`,
		`transport_dir = "`+filepath.Join(opCFHome, "campfires")+`"`)
	s = strings.ReplaceAll(s,
		`key_file = ".run/exam-`+runID+`/identity.json"`,
		`key_file = "`+identityPath+`"`)
	return os.WriteFile(path, []byte(s), 0o644)
}

// copyFile writes the contents of src to dst (overwriting), preserving
// only file mode 0o600 since identity files are private keys.
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

// runAutomaton executes `we start --chart <path> --exit-on-idle -v` from the
// repo root (so the chart's relative paths under [agents].dir and
// [sandbox].extra_ro resolve correctly). The orchestrator does NOT impose a
// wall-clock kill — the automaton terminates on its own when the work source
// drains. The orchestrator's context is honoured for orchestrator-level
// shutdown only (Ctrl-C).
//
// EVENT-DRIVEN REAPER (workaround for mallcoppro-ce1): legion v0.4.3's
// --exit-on-idle logs "automaton runtime stopped" and "poll loop stopping"
// when shutdown completes, but a leaked goroutine (capability watcher /
// campfire transport) keeps the process alive indefinitely. To recover, the
// reaper goroutine tails we.log; once the runtime-stopped signal appears, it
// gives the process a grace window to exit cleanly, then SIGTERMs.
//
// This is NOT a wall-clock timeout — the kill is gated on legion's own
// "I'm done" signal, never on elapsed time alone. Remove this workaround
// when mallcoppro-ce1 ships an upstream fix.
func runAutomaton(ctx context.Context, weBin, repoRoot string, s *runState) {
	logPath := filepath.Join(s.workDir, "we.log")
	logF, err := os.Create(logPath)
	if err != nil {
		s.exitErr = fmt.Errorf("open we.log: %w", err)
		return
	}
	defer logF.Close()

	workerCFHome := filepath.Join(s.workDir, "worker-cf")
	cmd := exec.CommandContext(ctx, weBin, "start", "--chart", s.chartPath, "--exit-on-idle", "-v")
	cmd.Env = append(os.Environ(), "CF_HOME="+workerCFHome)
	cmd.Dir = repoRoot
	cmd.Stdout = logF
	cmd.Stderr = logF

	start := time.Now()
	fmt.Fprintf(os.Stderr, ">>> [%s] starting (log: %s)\n", s.model.ID, logPath)
	if err := cmd.Start(); err != nil {
		s.exitErr = fmt.Errorf("we start: %w", err)
		return
	}
	s.wePID = cmd.Process.Pid

	// Spawn the legion-shutdown-detection reaper. See doc comment above.
	reaperDone := make(chan struct{})
	go reapAfterRuntimeStopped(ctx, cmd.Process, logPath, s.model.ID, reaperDone)

	s.exitErr = cmd.Wait()
	close(reaperDone)
	s.wallTime = time.Since(start)
	fmt.Fprintf(os.Stderr, ">>> [%s] exited after %s (err=%v)\n", s.model.ID, s.wallTime.Round(time.Second), s.exitErr)
}

// reapAfterRuntimeStopped is the event-driven reaper for the legion
// --exit-on-idle leak (mallcoppro-ce1). It tails the we.log, watches for the
// "automaton runtime stopped" line, then gives the process up to
// runtimeStoppedGrace before SIGTERMing it.
//
// Returns early if the process exits cleanly (reaperDone closes) or the
// orchestrator's context is cancelled.
const runtimeStoppedGrace = 10 * time.Second

func reapAfterRuntimeStopped(ctx context.Context, proc *os.Process, logPath, modelID string, done <-chan struct{}) {
	const stopSignal = "automaton runtime stopped"
	deadline := time.Time{}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			b, err := os.ReadFile(logPath)
			if err != nil {
				continue
			}
			if !strings.Contains(string(b), stopSignal) {
				continue
			}
			if deadline.IsZero() {
				deadline = time.Now().Add(runtimeStoppedGrace)
				fmt.Fprintf(os.Stderr,
					">>> [%s] legion logged shutdown — grace window %s before reaper SIGTERMs\n",
					modelID, runtimeStoppedGrace)
				continue
			}
			if time.Now().Before(deadline) {
				continue
			}
			fmt.Fprintf(os.Stderr,
				">>> [%s] grace expired; sending SIGTERM (mallcoppro-ce1 leak)\n", modelID)
			_ = proc.Signal(syscall.SIGTERM)
			return
		}
	}
}

type harvestArgs struct {
	runID      string
	examReport string
	outputDir  string
	catalogIdx map[string]CatalogModel
}

// harvestModel runs mallcop-exam-report against the per-model campfire to
// produce report.json, then transforms it into the bakeoff-aggregate.py
// per-model schema written to <output-dir>/bakeoff-<model>.json.
func harvestModel(a harvestArgs, s *runState) error {
	opCFHome := filepath.Join(s.workDir, "op-cf")
	rootFile := filepath.Join(s.workDir, "project", ".campfire", "root")
	rootBytes, err := os.ReadFile(rootFile)
	if err != nil {
		return fmt.Errorf("read campfire root: %w", err)
	}
	campfireID := strings.TrimSpace(string(rootBytes))

	modelOutDir := filepath.Join(s.workDir, "report")
	if err := os.MkdirAll(modelOutDir, 0o755); err != nil {
		return err
	}
	cmd := envCmd(opCFHome, s.workDir, a.examReport,
		"--campfire", campfireID,
		"--out-dir", modelOutDir,
		"--run-id", a.runID,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mallcop-exam-report: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Read the produced report.json
	reportPath := filepath.Join(modelOutDir, "report.json")
	rb, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report.json: %w", err)
	}
	var rep ExamReport
	if err := json.Unmarshal(rb, &rep); err != nil {
		return fmt.Errorf("parse report.json: %w", err)
	}
	s.scenariosRun = rep.Summary.Total
	s.passN = rep.Summary.PassN
	s.failN = rep.Summary.FailN
	s.reportPath = reportPath

	// Build the bakeoff-aggregate per-model record
	pmr := PerModelResult{
		Sovereignty:     s.model.Sovereignty,
		ScenariosRun:    rep.Summary.Total,
		ScenariosPassed: rep.Summary.PassN,
	}
	if rep.Summary.Total > 0 {
		pr := rep.Summary.PassRate
		pmr.PassRate = &pr
	}
	if cat, ok := a.catalogIdx[s.model.ID]; ok {
		pmr.BlendedPerMtok = (cat.BedrockInputPerMtok + cat.BedrockOutputPerMtok) / 2.0
		if pmr.Sovereignty == "" {
			pmr.Sovereignty = cat.Sovereignty
		}
	}

	out := BakeoffPerModelFile{Models: map[string]PerModelResult{s.model.ID: pmr}}
	bakeoffPath := filepath.Join(a.outputDir, "bakeoff-"+sanitizeID(s.model.ID)+".json")
	bb, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(bakeoffPath, bb, 0o644); err != nil {
		return err
	}
	s.bakeoffPath = bakeoffPath
	return nil
}

func writeSummary(path string, a runArgs, states []*runState) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Bakeoff run: %s\n", a.runID)
	fmt.Fprintf(&sb, "Slate: %s (%d models)\n", a.slatePath, len(states))
	fmt.Fprintf(&sb, "Scenarios dir: %s\n", a.scenariosDir)
	if a.scenarioID != "" {
		fmt.Fprintf(&sb, "Scenario filter: %s\n", a.scenarioID)
	}
	fmt.Fprintf(&sb, "Max concurrent: %d\n", a.maxConcurrent)
	fmt.Fprintf(&sb, "Budget cap: $%.2f (pre-flight enforced)\n", a.budgetUSD)
	fmt.Fprintf(&sb, "\nPer-model results:\n")
	for _, s := range states {
		if s.skipped != "" {
			fmt.Fprintf(&sb, "  %-24s SKIPPED: %s\n", s.model.ID, s.skipped)
			continue
		}
		exitInfo := "ok"
		if s.exitErr != nil {
			exitInfo = "err: " + s.exitErr.Error()
		}
		passRate := 0.0
		if s.scenariosRun > 0 {
			passRate = float64(s.passN) / float64(s.scenariosRun)
		}
		fmt.Fprintf(&sb, "  %-24s wall=%s scenarios=%d pass=%d fail=%d pass_rate=%.2f exit=%s\n",
			s.model.ID,
			s.wallTime.Round(time.Second),
			s.scenariosRun, s.passN, s.failN, passRate,
			exitInfo,
		)
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func printSummary(states []*runState, outputDir string) {
	fmt.Fprintf(os.Stderr, "\n=== bakeoff complete ===\n")
	for _, s := range states {
		if s.skipped != "" {
			fmt.Fprintf(os.Stderr, "  %s: SKIPPED (%s)\n", s.model.ID, s.skipped)
			continue
		}
		passRate := 0.0
		if s.scenariosRun > 0 {
			passRate = float64(s.passN) / float64(s.scenariosRun)
		}
		fmt.Fprintf(os.Stderr, "  %-24s scenarios=%d pass=%d pass_rate=%.2f\n",
			s.model.ID, s.scenariosRun, s.passN, passRate)
	}
	fmt.Fprintf(os.Stderr, "Outputs: %s\n", outputDir)
}

// envCmd builds an exec.Cmd with CF_HOME set and an explicit working directory.
func envCmd(cfHome, workDir, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "CF_HOME="+cfHome)
	cmd.Dir = workDir
	return cmd
}

var tokenRegexp = regexp.MustCompile(`rdx1_[A-Za-z0-9_-]+`)

func extractToken(s string) string {
	return tokenRegexp.FindString(s)
}

// repoRoot resolves the mallcop-legion repo root by walking up from this
// binary's directory until a go.mod file is found that names this module.
// Falls back to the current working directory if running from outside the
// repo (e.g. via `go run` from another dir).
func repoRoot() (string, error) {
	// Prefer the binary's own location (after install/build under ./bin/).
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		if root := walkForGoMod(dir); root != "" {
			return root, nil
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root := walkForGoMod(cwd); root != "" {
		return root, nil
	}
	return "", fmt.Errorf("could not locate mallcop-legion repo root (no go.mod with module github.com/thirdiv/mallcop-legion found)")
}

func walkForGoMod(start string) string {
	dir := start
	for {
		modPath := filepath.Join(dir, "go.mod")
		if b, err := os.ReadFile(modPath); err == nil {
			if strings.Contains(string(b), "module github.com/thirdiv/mallcop-legion") {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// Reserve io for future use (streaming we.log to operator without buffering).
var _ = io.Discard
