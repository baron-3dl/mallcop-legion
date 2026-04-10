package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/finding"
	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

const (
	defaultChart   = "charts/vertical-slice.toml"
	defaultTimeout = 10 * time.Minute
)

// ScanSummary holds the results of a completed scan cycle.
type ScanSummary struct {
	EventsScanned    int `json:"events_scanned"`
	FindingsDetected int `json:"findings_detected"`
	Escalated        int `json:"escalated"`
	Resolved         int `json:"resolved"`
}

// scanOutput collects structured output emitted by `we start --once` to stdout.
// Lines are JSONL; each line may be a Finding or a Resolution.
type scanOutput struct {
	findings    []finding.Finding
	resolutions []resolution.Resolution
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	chartPath := fs.String("chart", defaultChart, "Path to the legion chart TOML")
	timeoutStr := fs.String("timeout", "10m", "Max wait time for scan completion")
	asJSON := fs.Bool("json", false, "Output results as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	timeout, err := time.ParseDuration(*timeoutStr)
	if err != nil {
		return fmt.Errorf("invalid --timeout %q: %w", *timeoutStr, err)
	}

	// Resolve we binary: prefer PATH, fall back to bin/we relative to chart dir.
	weBin, err := resolveWe(*chartPath)
	if err != nil {
		return fmt.Errorf("cannot locate 'we' binary: %w", err)
	}

	// Build output directory path derived from chart location.
	outDir := scanOutputDir(*chartPath)

	// Invoke we start --chart <chart> --once
	cmd := exec.Command(weBin, "start", "--chart", *chartPath, "--once")
	cmd.Stderr = os.Stderr

	// Capture stdout so we can parse JSONL findings.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	// Run with timeout via a timer goroutine.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting we: %w", err)
	}

	done := make(chan error, 1)
	var out scanOutput

	// Parse stdout lines in background.
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			// Echo the line so the operator can see live output.
			fmt.Println(line)
			// Try to decode as Finding or Resolution.
			parseScanLine(line, &out)
		}
	}()

	// Wait for process in background.
	go func() {
		done <- cmd.Wait()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("we exited with error: %w", err)
		}
	case <-timer.C:
		_ = cmd.Process.Kill()
		return fmt.Errorf("scan timed out after %s", timeout)
	}

	// If we binary emitted findings inline, use them.
	// Otherwise fall back to reading from the output directory.
	if len(out.findings) == 0 && outDir != "" {
		out.findings = readFindingsDir(outDir)
	}
	if len(out.resolutions) == 0 && outDir != "" {
		out.resolutions = readResolutionsDir(outDir)
	}

	summary := buildSummary(out)

	if *asJSON {
		return printJSON(summary)
	}
	printSummary(summary)

	if summary.FindingsDetected > 0 {
		// Exit code 1 signalled by returning a sentinel that main.go converts.
		return errFindings
	}
	return nil
}

// errFindings is returned by runScan when findings are present (exit code 1).
var errFindings = &findingsError{}

type findingsError struct{}

func (e *findingsError) Error() string { return "findings detected" }

// isFindingsError reports whether err is the findings sentinel.
func isFindingsError(err error) bool {
	_, ok := err.(*findingsError)
	return ok
}

// resolveWe finds the `we` binary. Checks PATH first, then bin/we relative to chart.
func resolveWe(chartPath string) (string, error) {
	if p, err := exec.LookPath("we"); err == nil {
		return p, nil
	}
	// Try bin/we relative to directory containing the chart.
	chartDir := filepath.Dir(chartPath)
	candidate := filepath.Join(chartDir, "..", "bin", "we")
	candidate = filepath.Clean(candidate)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		return candidate, nil
	}
	// Also try cwd/bin/we.
	if cwd, err := os.Getwd(); err == nil {
		candidate = filepath.Join(cwd, "bin", "we")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("'we' not found in PATH or bin/we; install legion or add it to PATH")
}

// scanOutputDir returns the directory where we writes findings/resolutions,
// derived from chart location. Returns "" if not determinable.
func scanOutputDir(chartPath string) string {
	chartDir := filepath.Dir(chartPath)
	candidate := filepath.Join(chartDir, "..", "output")
	return filepath.Clean(candidate)
}

// parseScanLine attempts to decode a JSONL line as Finding or Resolution.
func parseScanLine(line string, out *scanOutput) {
	// Heuristic: lines with "finding_id" are Resolutions; lines with "severity" and "source" are Findings.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &probe); err != nil {
		return
	}
	if _, hasFindingID := probe["finding_id"]; hasFindingID {
		var res resolution.Resolution
		if err := json.Unmarshal([]byte(line), &res); err == nil {
			out.resolutions = append(out.resolutions, res)
		}
		return
	}
	if _, hasSeverity := probe["severity"]; hasSeverity {
		var f finding.Finding
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			out.findings = append(out.findings, f)
		}
	}
}

// readFindingsDir reads *.json finding files from dir.
func readFindingsDir(dir string) []finding.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var findings []finding.Finding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "finding-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var f finding.Finding
		if err := json.Unmarshal(data, &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings
}

// readResolutionsDir reads *.json resolution files from dir.
func readResolutionsDir(dir string) []resolution.Resolution {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var resolutions []resolution.Resolution
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if !strings.HasPrefix(e.Name(), "resolution-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var res resolution.Resolution
		if err := json.Unmarshal(data, &res); err == nil {
			resolutions = append(resolutions, res)
		}
	}
	return resolutions
}

// buildSummary computes scan statistics from collected output.
func buildSummary(out scanOutput) ScanSummary {
	s := ScanSummary{
		FindingsDetected: len(out.findings),
	}
	for _, res := range out.resolutions {
		switch res.Action {
		case "escalate":
			s.Escalated++
		default:
			s.Resolved++
		}
	}
	return s
}

// printSummary writes a human-readable summary to stdout.
func printSummary(s ScanSummary) {
	fmt.Printf("Scan complete\n")
	fmt.Printf("  Events scanned:     %d\n", s.EventsScanned)
	fmt.Printf("  Findings detected:  %d\n", s.FindingsDetected)
	fmt.Printf("  Escalated:          %d\n", s.Escalated)
	fmt.Printf("  Resolved:           %d\n", s.Resolved)
}

// printJSON writes the summary as JSON to stdout.
func printJSON(s ScanSummary) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
