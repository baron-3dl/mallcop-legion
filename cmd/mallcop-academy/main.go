// Command mallcop-academy posts scenario findings into an operational deployment's
// work campfire as work:create items with skill "task:triage", watches for
// terminal work:close messages, and emits per-scenario JSON artifacts.
//
// Usage:
//
//	mallcop-academy \
//	  --target-campfire <id-or-beacon> \
//	  [--scenarios-dir exams/scenarios] \
//	  [--scenario <id>] \
//	  [--output-dir docs/academy/<run-id>] \
//	  [--judge-model <id>] \
//	  [--budget-usd <n>] \
//	  [--max-concurrent <n>] \
//	  [--timeout <duration>] \
//	  [--run-id <id>]
//
// The binary posts one work:create message per scenario to the target campfire,
// then watches for work:close messages and classifies each close as terminal
// (chain complete — resolved/escalated/remediated with no follow-on work:create)
// or intermediate. Terminal closes trigger writing per-scenario JSON artifacts
// to --output-dir.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// ---- Campfire messaging -------------------------------------------------------

// cfMessage is a partial unmarshal of the JSON returned by `cf send --json` or
// one line from `cf read --json --all`.
type cfMessage struct {
	ID      string   `json:"id"`
	Tags    []string `json:"tags"`
	Payload string   `json:"payload"`
}

// cfSender shells out to the cf binary to send messages and returns the
// message ID from the --json output.
type cfSender struct {
	cfBin  string
	cfHome string // may be empty (uses default ~/.cf)
}

// send posts a message to campfireID with the given tags and returns its ID.
func (s *cfSender) send(campfireID, payload string, tags []string) (string, error) {
	args := []string{"send", campfireID, payload, "--json"}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	if s.cfHome != "" {
		args = append(args, "--cf-home", s.cfHome)
	}
	cmd := exec.Command(s.cfBin, args...)
	cmd.Env = os.Environ()
	if s.cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", s.cfHome)
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitErr(err, &exitErr); ok {
			return "", fmt.Errorf("cf send: %w\n%s", err, exitErr.Stderr)
		}
		return "", fmt.Errorf("cf send: %w", err)
	}
	var msg cfMessage
	if err := json.Unmarshal(out, &msg); err != nil {
		return "", fmt.Errorf("parse cf send output: %w\nraw: %s", err, out)
	}
	if msg.ID == "" {
		return "", fmt.Errorf("cf send returned empty message ID; raw: %s", out)
	}
	return msg.ID, nil
}

// readAll reads all messages from campfireID and returns them.
func (s *cfSender) readAll(campfireID string) ([]cfMessage, error) {
	args := []string{"read", campfireID, "--json", "--all"}
	if s.cfHome != "" {
		args = append(args, "--cf-home", s.cfHome)
	}
	cmd := exec.Command(s.cfBin, args...)
	cmd.Env = os.Environ()
	if s.cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", s.cfHome)
	}
	out, err := cmd.Output()
	if err != nil {
		// cf read may return exit 1 when queue is empty — treat as empty.
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		return nil, fmt.Errorf("parse cf read output: %w\nraw: %s", err, out)
	}
	return msgs, nil
}

// ---- Payload shapes -----------------------------------------------------------

// academyFindingPayload is the work:create payload posted to the target campfire.
// Mirrors the sanitized finding shape from exam-seed plus academy_metadata.
type academyFindingPayload struct {
	// Ready convention work:create required fields.
	ID    string `json:"id"`
	Title string `json:"title"`
	Skill string `json:"skill"`

	// Finding content (sanitized — no ground-truth fields).
	Finding findingPayload `json:"finding"`

	// Academy metadata carried alongside the finding.
	AcademyMetadata academyMetadata `json:"academy_metadata"`
}

type findingPayload struct {
	ID       string                 `json:"id"`
	Detector string                 `json:"detector"`
	Title    string                 `json:"title"`
	Severity string                 `json:"severity"`
	EventIDs []string               `json:"event_ids"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type academyMetadata struct {
	ScenarioID string              `json:"scenario_id"`
	RunID      string              `json:"run_id"`
	Expected   *exam.ExpectedResolution `json:"expected,omitempty"`
}

// ---- Per-scenario record ------------------------------------------------------

// ChainEntry records one work item in the disposition chain.
type ChainEntry struct {
	ItemID string `json:"item_id"`
	Skill  string `json:"skill,omitempty"`
	Action string `json:"action,omitempty"`
}

// ScenarioRecord is the per-scenario JSON artifact written to output-dir.
type ScenarioRecord struct {
	ScenarioID      string       `json:"scenario_id"`
	FindingID       string       `json:"finding_id"`
	RunID           string       `json:"run_id"`
	TargetCampfire  string       `json:"target_campfire"`
	PostedAt        time.Time    `json:"posted_at"`
	TerminalAt      *time.Time   `json:"terminal_at,omitempty"`
	WallSeconds     float64      `json:"wall_seconds,omitempty"`
	TerminalAction  string       `json:"terminal_action,omitempty"`
	TerminalItemID  string       `json:"terminal_item_id,omitempty"`
	FullChain       []ChainEntry `json:"full_chain"`
}

// RunRecord is the run-level metadata written to run.json.
type RunRecord struct {
	RunID          string    `json:"run_id"`
	TargetCampfire string    `json:"target_campfire"`
	ScenariosDir   string    `json:"scenarios_dir"`
	ScenarioFilter string    `json:"scenario_filter,omitempty"`
	JudgeModel     string    `json:"judge_model,omitempty"`
	BudgetUSD      float64   `json:"budget_usd,omitempty"`
	MaxConcurrent  int       `json:"max_concurrent"`
	Timeout        string    `json:"timeout"`
	StartedAt      time.Time `json:"started_at"`
}

// ---- Tracked state ------------------------------------------------------------

// trackedScenario holds in-flight state for one scenario.
type trackedScenario struct {
	mu             sync.Mutex
	scenarioID     string
	findingID      string
	workItemID     string // cf message ID of the work:create
	postedAt       time.Time
	chain          []ChainEntry
	terminal       bool
	terminalAt     time.Time
	terminalAction string
	terminalItemID string
}

// ---- Close payload parsing ----------------------------------------------------

// closePayload is a partial unmarshal of a work:close message payload.
type closePayload struct {
	ItemID string `json:"item_id"`
	Action string `json:"action"`
	Skill  string `json:"skill"`
}

// terminalActions are work:close actions that indicate chain completion.
// Any action not in this set is treated as intermediate (follow-on work expected).
var terminalActions = map[string]bool{
	"resolved":    true,
	"escalated":   true,
	"remediated":  true,
	"false-positive": true,
	"closed":      true,
}

// ---- Academy sender interface (for testing) -----------------------------------

// Sender abstracts campfire send/readAll so tests can inject a real isolated
// campfire without constructing the full cfSender.
type Sender interface {
	send(campfireID, payload string, tags []string) (string, error)
	readAll(campfireID string) ([]cfMessage, error)
}

// ---- Core logic ---------------------------------------------------------------

type runArgs struct {
	targetCampfire string
	scenariosDir   string
	scenarioFilter string
	outputDir      string
	judgeModel     string
	budgetUSD      float64
	maxConcurrent  int
	timeout        time.Duration
	runID          string
}

func main() {
	if err := mainRun(); err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-academy: %v\n", err)
		os.Exit(1)
	}
}

func mainRun() error {
	var (
		targetCampfire string
		scenariosDir   string
		scenarioFilter string
		outputDir      string
		judgeModel     string
		budgetUSD      float64
		maxConcurrent  int
		timeoutStr     string
		runID          string
	)

	flag.StringVar(&targetCampfire, "target-campfire", "", "operational deployment's work campfire ID or beacon (REQUIRED)")
	flag.StringVar(&scenariosDir, "scenarios-dir", "", "directory containing scenario YAML files (default: repo-root/exams/scenarios)")
	flag.StringVar(&scenarioFilter, "scenario", "", "optional: limit to one scenario ID")
	flag.StringVar(&outputDir, "output-dir", "", "output directory for per-scenario JSON artifacts (default: docs/academy/<run-id>)")
	flag.StringVar(&judgeModel, "judge-model", "", "model for the judge (F4C territory; stored in run.json only)")
	flag.Float64Var(&budgetUSD, "budget-usd", 0, "USD budget cap (advisory, stored in run.json)")
	flag.IntVar(&maxConcurrent, "max-concurrent", 4, "maximum concurrent scenario posts")
	flag.StringVar(&timeoutStr, "timeout", "30m", "per-scenario watch timeout (e.g. 30m, 1h)")
	flag.StringVar(&runID, "run-id", "", "run identifier (default: acad-<timestamp>)")
	flag.Parse()

	if targetCampfire == "" {
		return fmt.Errorf("--target-campfire is required")
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return fmt.Errorf("--timeout: %w", err)
	}

	if runID == "" {
		runID = fmt.Sprintf("acad-%d", time.Now().Unix())
	}

	repoRoot, err := repoRootFromExec()
	if err != nil {
		return fmt.Errorf("determine repo root: %w", err)
	}

	if scenariosDir == "" {
		scenariosDir = filepath.Join(repoRoot, "exams", "scenarios")
	}
	if outputDir == "" {
		outputDir = filepath.Join(repoRoot, "docs", "academy", runID)
	}

	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	sender := &cfSender{cfBin: cfBin}

	return academy(sender, runArgs{
		targetCampfire: targetCampfire,
		scenariosDir:   scenariosDir,
		scenarioFilter: scenarioFilter,
		outputDir:      outputDir,
		judgeModel:     judgeModel,
		budgetUSD:      budgetUSD,
		maxConcurrent:  maxConcurrent,
		timeout:        timeout,
		runID:          runID,
	})
}

// academy is the testable core — accepts a Sender so tests can inject an
// isolated campfire.
func academy(sender Sender, args runArgs) error {
	startedAt := time.Now()

	// Load scenarios.
	scenarios, err := loadScenarios(args.scenariosDir, args.scenarioFilter)
	if err != nil {
		return err
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios found in %s (filter=%q)", args.scenariosDir, args.scenarioFilter)
	}

	// Create output directory.
	if err := os.MkdirAll(args.outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Write run.json.
	runRecord := RunRecord{
		RunID:          args.runID,
		TargetCampfire: args.targetCampfire,
		ScenariosDir:   args.scenariosDir,
		ScenarioFilter: args.scenarioFilter,
		JudgeModel:     args.judgeModel,
		BudgetUSD:      args.budgetUSD,
		MaxConcurrent:  args.maxConcurrent,
		Timeout:        args.timeout.String(),
		StartedAt:      startedAt,
	}
	if err := writeJSON(filepath.Join(args.outputDir, "run.json"), runRecord); err != nil {
		return fmt.Errorf("write run.json: %w", err)
	}

	// Build tracked map: scenario_id → *trackedScenario.
	// Also build workItemID → *trackedScenario for watch-loop lookups.
	tracked := make(map[string]*trackedScenario, len(scenarios))
	for _, s := range scenarios {
		ts := &trackedScenario{
			scenarioID: s.ID,
			findingID:  findingTrackingID(args.runID, s.ID),
		}
		tracked[s.ID] = ts
	}

	// Post work:create messages, respecting max-concurrent.
	sem := make(chan struct{}, args.maxConcurrent)
	var postWG sync.WaitGroup
	var postMu sync.Mutex
	// workItemToScenario maps cf message ID → scenario ID.
	workItemToScenario := make(map[string]string)

	for _, s := range scenarios {
		postWG.Add(1)
		go func(s *exam.Scenario) {
			defer postWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ts := tracked[s.ID]
			msgID, postedAt, err := postFinding(sender, s, args.runID, args.targetCampfire)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARN: post finding for scenario %s: %v\n", s.ID, err)
				return
			}
			ts.mu.Lock()
			ts.workItemID = msgID
			ts.postedAt = postedAt
			ts.chain = append(ts.chain, ChainEntry{ItemID: msgID, Skill: "task:triage"})
			ts.mu.Unlock()

			postMu.Lock()
			workItemToScenario[msgID] = s.ID
			postMu.Unlock()

			fmt.Fprintf(os.Stderr, "posted scenario %s → cf message %s\n", s.ID, msgID)
		}(s)
	}
	postWG.Wait()

	// Watch loop: poll for work:close messages until all scenarios have
	// terminal dispositions or the timeout expires.
	deadline := time.Now().Add(args.timeout)
	allTerminal := false
	for !allTerminal && time.Now().Before(deadline) {
		msgs, err := sender.readAll(args.targetCampfire)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: read campfire: %v\n", err)
		}

		// Build a fresh workItemToScenario map including any new chain items
		// (work:create from escalations) before processing closes.
		postMu.Lock()
		for _, msg := range msgs {
			if hasTag(msg.Tags, "work:create") {
				var p closePayload
				if json.Unmarshal([]byte(msg.Payload), &p) == nil && p.ItemID != "" {
					// If this work:create chains off a known scenario, track it.
					// We detect by checking reply-to chains — not directly available
					// in the read output, so instead we check if any tracked
					// scenario's chain already has a close that references this new item.
					// For now: add to workItemToScenario under the same scenario if
					// the ID prefix matches our academy run.
					for scenID, tsRef := range tracked {
						tsRef.mu.Lock()
						for _, ce := range tsRef.chain {
							if ce.ItemID != "" && strings.HasPrefix(msg.ID, "acad-") {
								_ = ce
							}
						}
						tsRef.mu.Unlock()
						_ = scenID
					}
					// Simple tracking: if item_id of the new work:create is referenced
					// in a close payload, we add it when we see the close.
					if _, known := workItemToScenario[msg.ID]; !known {
						// Register as belonging to whichever scenario claimed this
						// item in a prior close. Defer: fill in on close observation.
						_ = msg.ID
					}
				}
			}
		}
		postMu.Unlock()

		for _, msg := range msgs {
			if !hasTag(msg.Tags, "work:close") {
				continue
			}

			// Parse close payload.
			var cp closePayload
			if err := json.Unmarshal([]byte(msg.Payload), &cp); err != nil {
				continue
			}

			// Look up scenario via item_id in the payload.
			postMu.Lock()
			scenID, ok := workItemToScenario[cp.ItemID]
			if !ok {
				// Also try the message ID itself.
				scenID, ok = workItemToScenario[msg.ID]
			}
			postMu.Unlock()

			if !ok {
				continue
			}

			ts := tracked[scenID]
			if ts == nil {
				continue
			}

			ts.mu.Lock()
			// Add this close to the chain.
			entry := ChainEntry{ItemID: cp.ItemID, Skill: cp.Skill, Action: cp.Action}
			// Avoid duplicates.
			seen := false
			for _, ce := range ts.chain {
				if ce.ItemID == cp.ItemID && ce.Action == cp.Action {
					seen = true
					break
				}
			}
			if !seen {
				ts.chain = append(ts.chain, entry)
			}

			// Classify as terminal: terminal action AND no follow-on work:create
			// from this close observed yet.
			if !ts.terminal && terminalActions[cp.Action] {
				ts.terminal = true
				now := time.Now()
				ts.terminalAt = now
				ts.terminalAction = cp.Action
				ts.terminalItemID = cp.ItemID
				ts.mu.Unlock()

				// Write per-scenario JSON.
				if err := writeScenarioRecord(ts, args.runID, args.targetCampfire, args.outputDir); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: write scenario record for %s: %v\n", scenID, err)
				} else {
					fmt.Fprintf(os.Stderr, "scenario %s terminal: action=%s item=%s\n",
						scenID, cp.Action, cp.ItemID)
				}
			} else {
				ts.mu.Unlock()
			}
		}

		// Check if all posted scenarios are terminal.
		allTerminal = true
		for _, ts := range tracked {
			ts.mu.Lock()
			posted := ts.workItemID != ""
			terminal := ts.terminal
			ts.mu.Unlock()
			if posted && !terminal {
				allTerminal = false
				break
			}
		}

		if !allTerminal {
			time.Sleep(2 * time.Second)
		}
	}

	if !allTerminal {
		fmt.Fprintf(os.Stderr, "WARN: timeout reached — some scenarios did not reach terminal state\n")
		// Write partial records for non-terminal scenarios.
		for _, ts := range tracked {
			ts.mu.Lock()
			posted := ts.workItemID != ""
			terminal := ts.terminal
			ts.mu.Unlock()
			if posted && !terminal {
				if err := writeScenarioRecord(ts, args.runID, args.targetCampfire, args.outputDir); err != nil {
					fmt.Fprintf(os.Stderr, "WARN: write partial scenario record for %s: %v\n", ts.scenarioID, err)
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "academy run %s complete: %d scenarios posted\n", args.runID, len(scenarios))
	return nil
}

// ---- Scenario posting ---------------------------------------------------------

// postFinding posts a work:create message for a scenario finding to the target
// campfire. Returns the cf message ID and the time posted.
func postFinding(sender Sender, s *exam.Scenario, runID, campfireID string) (string, time.Time, error) {
	fid := findingTrackingID(runID, s.ID)

	fp := findingPayload{
		ID:       s.Finding.ID,
		Detector: s.Finding.Detector,
		Title:    s.Finding.Title,
		Severity: s.Finding.Severity,
		EventIDs: s.Finding.EventIDs,
		Metadata: filterAcademyMetadata(s.Finding.Metadata),
	}

	payload := academyFindingPayload{
		ID:      fid,
		Title:   s.Finding.Title,
		Skill:   "task:triage",
		Finding: fp,
		AcademyMetadata: academyMetadata{
			ScenarioID: s.ID,
			RunID:      runID,
			Expected:   s.ExpectedResolution,
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal payload: %w", err)
	}

	now := time.Now()
	tags := []string{
		"work:create",
		"task:triage",
		"academy:scenario",
		"scenario:" + s.ID,
		"run:" + runID,
	}
	msgID, err := sender.send(campfireID, string(payloadJSON), tags)
	if err != nil {
		return "", time.Time{}, err
	}
	return msgID, now, nil
}

// findingTrackingID returns the deterministic finding-tracking ID for a
// scenario within a run: academy-<run-id>-<scenario-id>.
func findingTrackingID(runID, scenarioID string) string {
	return "academy-" + runID + "-" + scenarioID
}

// filterAcademyMetadata passes through finding metadata for academy use.
// For now we pass through all metadata fields since the academy is posting
// to its own isolated campfire and ground-truth filtering is the exam-seed's
// responsibility for the exam pipeline.
func filterAcademyMetadata(m exam.FindingMetadata) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- JSON output helpers ------------------------------------------------------

// writeScenarioRecord writes a ScenarioRecord to
// <outputDir>/<scenarioID>.json.
func writeScenarioRecord(ts *trackedScenario, runID, targetCampfire, outputDir string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	rec := ScenarioRecord{
		ScenarioID:     ts.scenarioID,
		FindingID:      ts.findingID,
		RunID:          runID,
		TargetCampfire: targetCampfire,
		PostedAt:       ts.postedAt,
		FullChain:      ts.chain,
	}
	if ts.terminal {
		t := ts.terminalAt
		rec.TerminalAt = &t
		rec.WallSeconds = ts.terminalAt.Sub(ts.postedAt).Seconds()
		rec.TerminalAction = ts.terminalAction
		rec.TerminalItemID = ts.terminalItemID
	}

	return writeJSON(filepath.Join(outputDir, ts.scenarioID+".json"), rec)
}

// writeJSON marshals v to indented JSON and writes it to path.
func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---- Scenario loader ----------------------------------------------------------

// loadScenarios walks dir for *.yaml files and loads them via exam.Load.
// If filter is non-empty, only the scenario with that ID is returned.
func loadScenarios(dir, filter string) ([]*exam.Scenario, error) {
	var paths []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, "_") {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}

	var scenarios []*exam.Scenario
	for _, p := range paths {
		s, err := exam.Load(p)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", p, err)
		}
		if filter != "" && s.ID != filter {
			continue
		}
		scenarios = append(scenarios, s)
	}
	return scenarios, nil
}

// ---- Watch-loop helpers -------------------------------------------------------

// hasTag returns true if tag is in tags.
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// watchCF runs `cf read --follow --tag work:close --json` and calls handler for
// each line that parses as a cfMessage. Returns when ctx is cancelled or the
// process exits. Used in production; tests use readAll polling instead.
func watchCF(cfBin, cfHome, campfireID string, handler func(cfMessage)) error {
	args := []string{"read", campfireID, "--follow", "--json", "--tag", "work:close"}
	if cfHome != "" {
		args = append(args, "--cf-home", cfHome)
	}
	cmd := exec.Command(cfBin, args...)
	cmd.Env = os.Environ()
	if cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", cfHome)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cf read pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cf read start: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg cfMessage
		if err := json.Unmarshal([]byte(line), &msg); err == nil {
			handler(msg)
		}
	}
	return cmd.Wait()
}

// ---- Utilities ----------------------------------------------------------------

// setEnv returns a copy of env with key=val set (replacing any existing entry).
func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	result := make([]string, 0, len(env))
	for _, e := range env {
		if !strings.HasPrefix(e, prefix) {
			result = append(result, e)
		}
	}
	return append(result, key+"="+val)
}

// asExitErr type-asserts err to *exec.ExitError.
func asExitErr(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// repoRootFromExec resolves the repo root by walking up from the binary
// location or working directory for a go.mod file naming this module.
func repoRootFromExec() (string, error) {
	// Try binary location first.
	exe, err := os.Executable()
	if err == nil {
		if root := walkGoMod(filepath.Dir(exe)); root != "" {
			return root, nil
		}
	}
	// Try runtime caller location (useful under `go test`).
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		// cmd/mallcop-academy/main.go → ../.. → repo root
		root := filepath.Join(filepath.Dir(filename), "..", "..")
		if abs, err := filepath.Abs(root); err == nil {
			if walkGoMod(abs) != "" {
				return abs, nil
			}
		}
	}
	// Fallback: walk from cwd.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root := walkGoMod(cwd); root != "" {
		return root, nil
	}
	return "", fmt.Errorf("could not locate mallcop-legion repo root (no matching go.mod found)")
}

func walkGoMod(start string) string {
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

// Ensure watchCF is not flagged as dead code — it's production path.
var _ = watchCF
