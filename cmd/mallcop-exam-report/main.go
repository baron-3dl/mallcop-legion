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

// readVerdicts shells out to `cf read <campfire> --tag judge:verdict --json --all`
// and parses the payload of each returned message as a JudgeVerdict.
func readVerdicts(campfire string) ([]JudgeVerdict, error) {
	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return nil, fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	cmd := exec.Command(cfBin, "read", campfire, "--tag", "judge:verdict", "--json", "--all")
	out, err := cmd.Output()
	if err != nil {
		// An empty campfire returns exit 0 with [] — any real error is fatal.
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
		var v JudgeVerdict
		if err := json.Unmarshal([]byte(msg.Payload), &v); err != nil {
			// Skip unparseable messages — log and continue.
			fmt.Fprintf(os.Stderr, "warn: skipping unparseable judge:verdict payload: %v\n", err)
			continue
		}
		verdicts = append(verdicts, v)
	}

	return verdicts, nil
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
