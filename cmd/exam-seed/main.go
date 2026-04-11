// Command exam-seed walks exams/scenarios/, loads each YAML via
// internal/exam.Load, materializes fixture files, and posts work:create
// messages to a campfire for each scenario plus one final exam:report item.
//
// Usage:
//
//	exam-seed --run <id> --campfire <id-or-beacon> \
//	          [--scenarios-dir <path>] \
//	          [--fixtures-dir <path>] \
//	          [--scenario <id>]
//
// Ground-truth enforcement: the work:create payload is built from a dedicated
// sanitized struct. ExpectedResolution, TrapDescription, and TrapResolvedMeans
// are never serialized into emitted messages.
//
// Uses pkg/workclient.ReadySender.SendWithAntecedents semantics via the
// cfSender type, which shells out to `cf send --reply-to` with --json output
// to capture the returned message ID.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/thirdiv/mallcop-legion/internal/exam"
)

// ReadySender posts messages to a campfire and returns the posted message ID.
// This interface mirrors workclient.ReadySender.SendWithAntecedents from the
// legion repo. exam-seed provides its own implementation backed by cf send.
type ReadySender interface {
	SendWithAntecedents(campfireID, payload string, tags []string, antecedents []string) (string, error)
}

// cfSender implements ReadySender by shelling out to the cf binary.
type cfSender struct {
	cfBin  string
	cfHome string // may be empty (uses default ~/.cf)
}

// cfMessage is a partial unmarshal of the JSON returned by `cf send --json`.
type cfMessage struct {
	ID         string   `json:"id"`
	Antecedents []string `json:"antecedents"`
	Tags       []string `json:"tags"`
	Payload    string   `json:"payload"`
}

// SendWithAntecedents sends a campfire message and returns its ID.
// antecedents are passed as --reply-to flags. If len(antecedents)==0 none
// are added. The message ID is parsed from the --json output.
func (s *cfSender) SendWithAntecedents(campfireID, payload string, tags []string, antecedents []string) (string, error) {
	args := []string{"send", campfireID, payload, "--json"}
	for _, t := range tags {
		args = append(args, "--tag", t)
	}
	for _, a := range antecedents {
		args = append(args, "--reply-to", a)
	}
	if s.cfHome != "" {
		args = append(args, "--cf-home", s.cfHome)
	}

	cmd := exec.Command(s.cfBin, args...)
	// Inherit environment so CF_HOME env var takes effect if set.
	cmd.Env = os.Environ()
	if s.cfHome != "" {
		cmd.Env = setEnv(cmd.Env, "CF_HOME", s.cfHome)
	}

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if ok := isExitErr(err, &exitErr); ok {
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

// scenarioPayload is the sanitized per-scenario work:create payload.
// It deliberately omits ExpectedResolution, TrapDescription, TrapResolvedMeans.
//
// The top-level fields (id, title, skill) satisfy the ReadyWorkSource
// workCreatePayload contract so that `we`'s PollForWork can discover and
// claim these items. The exam-specific fields (scenario_id, fixture_path,
// finding) carry the data the triage worker needs and are stored in the
// campfire message payload. The worker reads them by replaying the work:create
// message from the campfire.
type scenarioPayload struct {
	// Ready convention fields — required by ReadyWorkSource.PollForWork.
	ID    string `json:"id"`    // finding ID (e.g. fnd_shk_001)
	Title string `json:"title"` // finding title (e.g. "New actor observed: deploy-svc-new")
	Skill string `json:"skill"` // capability routing tag (always "exam:scenario")

	// Exam-specific fields.
	ScenarioID  string         `json:"scenario_id"`
	FixturePath string         `json:"fixture_path"`
	Finding     findingPayload `json:"finding"`
}

// findingPayload mirrors ScenarioFinding without any ground-truth fields.
// Metadata is filtered through metadataAllowlist before serialization —
// the passthrough map[string]interface{} is never written verbatim.
type findingPayload struct {
	ID       string                 `json:"id"`
	Detector string                 `json:"detector"`
	Title    string                 `json:"title"`
	Severity string                 `json:"severity"`
	EventIDs []string               `json:"event_ids"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// metadataAllowlist is the set of finding.metadata keys that may pass
// through to worker input. Any key not in this set is silently dropped.
// This prevents semantic leaks through arbitrary key names
// (e.g. finding.metadata.correct_action or finding.metadata.trap_description).
// The values are all factual/observational; none are ground-truth.
var metadataAllowlist = map[string]bool{
	"actor":              true,
	"source":             true,
	"event_type":         true,
	"volume_ratio":       true,
	"window_minutes":     true,
	"window_hours":       true,
	"distinct_api_count": true,
	"new_resource":       true,
	"subject":            true,
	"injection_type":     true,
	"payload_location":   true,
	"pattern":            true,
	"accounts_affected":  true,
	"distinct_ips":       true,
	"total_failures":     true,
	"correlated_findings":  true,
	"concurrent_detectors": true,
	"prior_resolution":     true,
	"prior_triage_actor":   true,
	"prior_triage_date":    true,
	"external_user":        true,
	"external_domain":      true,
	"external_org":         true,
	"container_app":        true,
	"unmatched_percent":    true,
}

// filterMetadata returns a copy of m with only allowlisted keys retained.
// Returns nil if m is nil or the filtered result is empty.
func filterMetadata(m map[string]interface{}) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if metadataAllowlist[k] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// forbiddenKeys is the set of map keys (case-folded) that are forbidden in
// fixture files. scrubMap drops any key whose lowercased form matches.
var forbiddenKeys = []string{
	"trap_description",
	"trap_resolved_means",
	"expected_resolution",
	"chain_action",
	"triage_action",
	"reasoning_must_mention",
	"reasoning_must_not_mention",
	"investigate_must_use_tools",
}

// scrubMap returns a shallow copy of m with forbidden keys removed.
// Keys are matched case-insensitively by lowercasing before comparison.
func scrubMap(m map[string]interface{}) map[string]interface{} {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		lower := strings.ToLower(k)
		forbidden := false
		for _, f := range forbiddenKeys {
			if lower == f {
				forbidden = true
				break
			}
		}
		if !forbidden {
			out[k] = v
		}
	}
	return out
}

// reportPayload is the work:create payload for the exam:report item.
// Top-level id/title/skill satisfy ReadyWorkSource.workCreatePayload.
type reportPayload struct {
	ID    string `json:"id"`    // e.g. "exam-report-<runID>"
	Title string `json:"title"` // e.g. "exam report: <runID>"
	Skill string `json:"skill"` // "exam:report"
	RunID string `json:"run_id"`
}

// fixtureEvents is the on-disk shape of events.json.
type fixtureEvents struct {
	Events []exam.Event `json:"events"`
}

// fixtureBaseline is the on-disk shape of baseline.json.
type fixtureBaseline struct {
	KnownEntities   exam.KnownEntities              `json:"known_entities"`
	FrequencyTables map[string]int                  `json:"frequency_tables,omitempty"`
	Relationships   map[string]exam.RelationshipEntry `json:"relationships,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "exam-seed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	runID := flag.String("run", "", "run identifier (required)")
	campfireID := flag.String("campfire", "", "campfire ID or beacon to post messages to (required)")
	scenariosDir := flag.String("scenarios-dir", "exams/scenarios", "directory containing scenario YAML files")
	fixturesDir := flag.String("fixtures-dir", "exams/fixtures", "directory for materialized fixture files")
	scenarioFilter := flag.String("scenario", "", "optional: limit to one scenario ID")
	flag.Parse()

	if *runID == "" {
		return fmt.Errorf("--run is required")
	}
	if *campfireID == "" {
		return fmt.Errorf("--campfire is required")
	}

	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	sender := &cfSender{cfBin: cfBin}
	return seed(sender, *runID, *campfireID, *scenariosDir, *fixturesDir, *scenarioFilter)
}

// seed is the testable core — it accepts a ReadySender so tests can inject
// a sender pointed at an isolated campfire.
func seed(sender ReadySender, runID, campfireID, scenariosDir, fixturesDir, scenarioFilter string) error {
	scenarios, err := loadScenarios(scenariosDir, scenarioFilter)
	if err != nil {
		return err
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenarios found in %s (filter=%q)", scenariosDir, scenarioFilter)
	}

	var scenarioMsgIDs []string
	for _, s := range scenarios {
		msgID, err := seedScenario(sender, s, runID, campfireID, fixturesDir)
		if err != nil {
			return fmt.Errorf("scenario %s: %w", s.ID, err)
		}
		scenarioMsgIDs = append(scenarioMsgIDs, msgID)
	}

	// Post the exam:report item with all scenario message IDs as antecedents.
	rp := reportPayload{
		ID:    "exam-report-" + runID,
		Title: "exam report: " + runID,
		Skill: "exam:report",
		RunID: runID,
	}
	rpJSON, err := json.Marshal(rp)
	if err != nil {
		return fmt.Errorf("marshal report payload: %w", err)
	}

	reportTags := []string{"work:create", "exam:report"}
	if _, err := sender.SendWithAntecedents(campfireID, string(rpJSON), reportTags, scenarioMsgIDs); err != nil {
		return fmt.Errorf("post exam:report: %w", err)
	}

	fmt.Printf("seeded %d scenarios + 1 report for run %s\n", len(scenarios), runID)
	return nil
}

// loadScenarios walks scenariosDir, loads all *.yaml files, and optionally
// filters to a single scenario ID.
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
		// Skip schema/template files (prefixed with _).
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

// seedScenario materializes fixture files and posts the work:create message.
// Returns the campfire message ID of the posted message.
func seedScenario(sender ReadySender, s *exam.Scenario, runID, campfireID, fixturesDir string) (string, error) {
	// Materialize fixtures.
	fixturePath, err := materializeFixtures(s, runID, fixturesDir)
	if err != nil {
		return "", fmt.Errorf("materialize fixtures: %w", err)
	}

	// Build sanitized payload — ground-truth fields are deliberately excluded.
	// finding.Metadata is filtered through metadataAllowlist to prevent
	// semantic leaks via arbitrary key names.
	fp := findingPayload{
		ID:       s.Finding.ID,
		Detector: s.Finding.Detector,
		Title:    s.Finding.Title,
		Severity: s.Finding.Severity,
		EventIDs: s.Finding.EventIDs,
		Metadata: filterMetadata(s.Finding.Metadata),
	}
	sp := scenarioPayload{
		ID:          s.Finding.ID,
		Title:       s.Finding.Title,
		Skill:       "exam:scenario",
		ScenarioID:  s.ID,
		FixturePath: fixturePath,
		Finding:     fp,
	}
	payloadJSON, err := json.Marshal(sp)
	if err != nil {
		return "", fmt.Errorf("marshal scenario payload: %w", err)
	}

	tags := []string{
		"work:create",
		"exam:scenario",
		"scenario:" + s.ID,
	}
	msgID, err := sender.SendWithAntecedents(campfireID, string(payloadJSON), tags, nil)
	if err != nil {
		return "", fmt.Errorf("send work:create: %w", err)
	}
	return msgID, nil
}

// materializeFixtures writes events.json and baseline.json to
// fixturesDir/<runID>/<scenarioID>/ and returns the fixture directory path.
func materializeFixtures(s *exam.Scenario, runID, fixturesDir string) (string, error) {
	dir := filepath.Join(fixturesDir, runID, s.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Write events.json. Scrub event.Raw and event.Metadata of any
	// forbidden keys before writing to disk (surgical scrub: preserves
	// legitimate IP, user_agent, operation data while blocking trap leaks).
	scrubbed := make([]exam.Event, len(s.Events))
	for i, ev := range s.Events {
		scrubbed[i] = ev
		if raw, ok := ev.Raw.(map[string]interface{}); ok {
			scrubbed[i].Raw = scrubMap(raw)
		}
		if len(ev.Metadata) > 0 {
			scrubbed[i].Metadata = exam.EventMetadata(scrubMap(map[string]interface{}(ev.Metadata)))
		}
	}
	evts := fixtureEvents{Events: scrubbed}
	if err := writeJSON(filepath.Join(dir, "events.json"), evts); err != nil {
		return "", fmt.Errorf("write events.json: %w", err)
	}

	// Write baseline.json (even if scenario has no baseline — write empty).
	var bl fixtureBaseline
	if s.Baseline != nil {
		bl = fixtureBaseline{
			KnownEntities:   s.Baseline.KnownEntities,
			FrequencyTables: s.Baseline.FrequencyTables,
			Relationships:   s.Baseline.Relationships,
		}
	}
	if err := writeJSON(filepath.Join(dir, "baseline.json"), bl); err != nil {
		return "", fmt.Errorf("write baseline.json: %w", err)
	}

	return dir, nil
}

// writeJSON marshals v to indented JSON and writes it to path.
func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

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

// isExitErr type-asserts err to *exec.ExitError.
func isExitErr(err error, target **exec.ExitError) bool {
	var e *exec.ExitError
	if ok := errorAs(err, &e); ok {
		*target = e
		return true
	}
	return false
}

// errorAs is a thin wrapper around errors.As to avoid importing errors in main.
func errorAs(err error, target interface{}) bool {
	type asErr interface{ As(interface{}) bool }
	if x, ok := err.(asErr); ok {
		return x.As(target)
	}
	// Fallback: standard errors.As via type assertion chain.
	// We use a direct type assertion here since exec.ExitError is concrete.
	if e, ok := err.(*exec.ExitError); ok {
		if ep, ok := target.(**exec.ExitError); ok {
			*ep = e
			return true
		}
	}
	return false
}
