// Command mallcop-exam-report aggregates judge:verdict messages from a campfire
// into a structured exam report (report.json + report.md).
//
// Usage:
//
//	mallcop-exam-report --campfire <id> --out-dir <path> --run-id <string>
//
// The campfire may be a campfire ID (hex) or a filesystem path to a local
// campfire directory. judge:verdict messages are read via `cf read --tag judge:verdict --json`.
//
// Pass-rate guard: when total==0, pass_rate is 0.0 (not NaN).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// Rubric holds the four-axis scoring from the judge.
type Rubric struct {
	ReasoningQuality          int `json:"reasoning_quality"`
	InvestigationThoroughness int `json:"investigation_thoroughness"`
	ResolveQuality            int `json:"resolve_quality"`
	EscalationActionability   int `json:"escalation_actionability"`
}

// JudgeVerdict is the JSON body of a judge:verdict campfire message.
type JudgeVerdict struct {
	FindingID  string `json:"finding_id"`
	Verdict    string `json:"verdict"`
	Rubric     Rubric `json:"rubric"`
	Rationale  string `json:"rationale"`
	FixTarget  string `json:"fix_target"`
}

// ScenarioResult is the per-scenario entry in report.json.
type ScenarioResult struct {
	ID        string `json:"id"`
	Verdict   string `json:"verdict"`
	Rubric    Rubric `json:"rubric"`
	Rationale string `json:"rationale"`
	FixTarget string `json:"fix_target"`
}

// Summary holds the aggregate statistics.
type Summary struct {
	Total       int                `json:"total"`
	PassN       int                `json:"pass_n"`
	WarnN       int                `json:"warn_n"`
	FailN       int                `json:"fail_n"`
	ByFixTarget map[string]int     `json:"by_fix_target"`
	PassRate    float64            `json:"pass_rate"`
}

// Report is the schema written to report.json.
type Report struct {
	RunID     string           `json:"run_id"`
	Scenarios []ScenarioResult `json:"scenarios"`
	Summary   Summary          `json:"summary"`
}

// cfMessage is a partial unmarshal of a campfire message JSON object.
type cfMessage struct {
	Payload string   `json:"payload"`
	Tags    []string `json:"tags"`
}

func main() {
	campfire := flag.String("campfire", "", "campfire ID or filesystem path to read judge:verdict messages from (required)")
	outDir := flag.String("out-dir", "", "directory to write report.json and report.md (required)")
	runID := flag.String("run-id", "", "run identifier (required)")
	flag.Parse()

	if *campfire == "" || *outDir == "" || *runID == "" {
		fmt.Fprintln(os.Stderr, "usage: mallcop-exam-report --campfire <id> --out-dir <path> --run-id <string>")
		os.Exit(1)
	}

	verdicts, err := readVerdicts(*campfire)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading verdicts: %v\n", err)
		os.Exit(1)
	}

	report := aggregate(*runID, verdicts)

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating out-dir: %v\n", err)
		os.Exit(1)
	}

	if err := writeJSON(filepath.Join(*outDir, "report.json"), report); err != nil {
		fmt.Fprintf(os.Stderr, "error writing report.json: %v\n", err)
		os.Exit(1)
	}

	if err := writeMarkdown(filepath.Join(*outDir, "report.md"), report); err != nil {
		fmt.Fprintf(os.Stderr, "error writing report.md: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("report written to %s\n", *outDir)
}

// readVerdicts queries the campfire for judge worker outputs and extracts the
// verdict JSON from each.
//
// Source-of-truth tags: `exam:judge` AND `work:output` — both must be
// present. cf's `--tag` flag is OR semantics (repeatable matches ANY tag),
// so we filter by `exam:judge` server-side and intersect with `work:output`
// in code. We deliberately do NOT rely on legion's content-aware
// `judge:verdict` auto-tag — that tag is a courtesy that only fires when
// the payload parses as raw JSON, but glm-* models intermittently wrap
// their output in ```json``` markdown fences which defeats it. The
// formatting is the consumer's problem (we picked the model and wrote
// the agent prompt), so we tolerate it here.
//
// Payload shape: legion's PostWorkerOutput posts the work:output envelope
//   {"item_id": "<id>", "output": "<raw model text>"}
// where the raw text is the judge agent's final response — the verdict JSON,
// possibly fence-wrapped. We unwrap the envelope, strip any markdown fence,
// then parse as JudgeVerdict. For backward compatibility with judge outputs
// that legion DID auto-tag (raw JSON with no fence), we also accept the
// payload directly as JudgeVerdict when the envelope unwrap fails.
//
// Empty-verdict guard: parseJudgeOutput rejects any payload that parses
// without a populated `verdict` field. Without this, triage outputs and
// exam-report run summaries — which share neither tag combination but
// could leak through if the query is loosened — would inflate counts.
func readVerdicts(campfire string) ([]JudgeVerdict, error) {
	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return nil, fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	cmd := exec.Command(cfBin, "read", campfire, "--tag", "exam:judge", "--json", "--all")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cf read: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var msgs []cfMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		return nil, fmt.Errorf("parse cf read output: %w", err)
	}

	var verdicts []JudgeVerdict
	for _, msg := range msgs {
		// Intersect: server-side filter is exam:judge OR work:output (cf's
		// --tag is OR); we need both. Skip messages missing work:output.
		if !hasTag(msg.Tags, "work:output") {
			continue
		}
		v, err := parseJudgeOutput(msg.Payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: skipping unparseable judge output: %v\n", err)
			continue
		}
		verdicts = append(verdicts, v)
	}

	return verdicts, nil
}

// hasTag reports whether tags contains target (exact match).
func hasTag(tags []string, target string) bool {
	for _, t := range tags {
		if t == target {
			return true
		}
	}
	return false
}

// parseJudgeOutput extracts the verdict JSON from a judge worker's
// work:output payload. Handles two payload shapes:
//
//  1. Envelope: {"item_id": "...", "output": "<raw text>"} — the standard
//     legion PostWorkerOutput shape. The "output" string is the agent's
//     final response, optionally wrapped in a markdown ```json fence.
//  2. Direct: a raw JudgeVerdict JSON object — happens when legion's
//     content-aware auto-tag path posted the verdict body unwrapped.
//     Retained for backward compatibility with older judge outputs.
func parseJudgeOutput(payload string) (JudgeVerdict, error) {
	// Shape 2 first — direct parse. If this works AND yields a populated
	// verdict (the field every judge MUST emit), we're done.
	var direct JudgeVerdict
	if err := json.Unmarshal([]byte(payload), &direct); err == nil && direct.Verdict != "" {
		return direct, nil
	}

	// Shape 1 — envelope. Extract the inner output string, strip any fence,
	// then parse as JudgeVerdict.
	var env struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		return JudgeVerdict{}, fmt.Errorf("payload is neither verdict JSON nor work:output envelope: %w", err)
	}
	stripped := stripJSONFence(env.Output)
	var v JudgeVerdict
	if err := json.Unmarshal([]byte(stripped), &v); err != nil {
		return JudgeVerdict{}, fmt.Errorf("envelope.output not parseable as verdict (after fence-strip): %w", err)
	}
	// Empty-verdict guard: encoding/json is lenient — triage outputs (which
	// have action/reason but no verdict) parse cleanly into a zero-valued
	// JudgeVerdict and would otherwise inflate scenario counts. Reject any
	// payload that doesn't carry an actual verdict.
	if v.Verdict == "" {
		return JudgeVerdict{}, fmt.Errorf("envelope.output parsed but has no verdict field (probably a triage or report output that slipped past the tag filter)")
	}
	return v, nil
}

// stripJSONFence removes a leading ```json (or bare ```) line and trailing
// ``` line from s. If no fence is present, returns s unchanged. The agent
// POST.md tells the model to emit raw JSON, but glm-* models intermittently
// add a fence anyway — this is the tolerance layer.
func stripJSONFence(s string) string {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "```") {
		return t
	}
	// Strip opening fence (```json\n or ```\n).
	nl := strings.IndexByte(t, '\n')
	if nl < 0 {
		return t
	}
	t = t[nl+1:]
	// Strip closing fence: trim trailing whitespace, then drop trailing ```.
	t = strings.TrimRight(t, " \t\n\r")
	t = strings.TrimSuffix(t, "```")
	return strings.TrimRight(t, " \t\n\r")
}

// aggregate builds the Report from a slice of JudgeVerdicts.
func aggregate(runID string, verdicts []JudgeVerdict) Report {
	scenarios := make([]ScenarioResult, 0, len(verdicts))
	byFixTarget := make(map[string]int)
	var passN, warnN, failN int

	for _, v := range verdicts {
		scenarios = append(scenarios, ScenarioResult{
			ID:        v.FindingID,
			Verdict:   v.Verdict,
			Rubric:    v.Rubric,
			Rationale: v.Rationale,
			FixTarget: v.FixTarget,
		})
		byFixTarget[v.FixTarget]++
		switch v.Verdict {
		case "pass":
			passN++
		case "warn":
			warnN++
		default:
			failN++
		}
	}

	total := len(verdicts)
	passRate := 0.0
	if total > 0 {
		passRate = float64(passN) / float64(total)
	}
	// Guard against floating-point edge cases.
	if math.IsNaN(passRate) || math.IsInf(passRate, 0) {
		passRate = 0.0
	}

	return Report{
		RunID:     runID,
		Scenarios: scenarios,
		Summary: Summary{
			Total:       total,
			PassN:       passN,
			WarnN:       warnN,
			FailN:       failN,
			ByFixTarget: byFixTarget,
			PassRate:    passRate,
		},
	}
}

func writeJSON(path string, report Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

const mdTmpl = `# Exam Report — {{ .RunID }}

Generated: {{ .GeneratedAt }}

## Summary

| Metric | Value |
|--------|-------|
| Total scenarios | {{ .Report.Summary.Total }} |
| Pass | {{ .Report.Summary.PassN }} |
| Warn | {{ .Report.Summary.WarnN }} |
| Fail | {{ .Report.Summary.FailN }} |
| Pass rate | {{ printf "%.1f" (mul .Report.Summary.PassRate 100.0) }}% |

## Fix Target Breakdown

| Fix Target | Count |
|------------|-------|
{{ range $k, $v := .Report.Summary.ByFixTarget -}}
| {{ $k }} | {{ $v }} |
{{ end }}
## Scenarios

{{ range .Report.Scenarios -}}
### {{ .ID }}

- **Verdict**: {{ .Verdict }}
- **Fix target**: {{ .FixTarget }}
- **Rationale**: {{ .Rationale }}
- **Rubric**: reasoning={{ .Rubric.ReasoningQuality }} thoroughness={{ .Rubric.InvestigationThoroughness }} resolve={{ .Rubric.ResolveQuality }} escalation={{ .Rubric.EscalationActionability }}

{{ end -}}
`

func writeMarkdown(path string, report Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(mdTmpl)
	if err != nil {
		return err
	}

	return tmpl.Execute(f, struct {
		Report      Report
		RunID       string
		GeneratedAt string
	}{
		Report:      report,
		RunID:       report.RunID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	})
}
