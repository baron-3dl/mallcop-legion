//go:build e2e

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thirdiv/mallcop-legion/pkg/finding"
	"github.com/thirdiv/mallcop-legion/pkg/resolution"
)

// TestScanE2E_FindingsPresent builds the mallcop binary, creates a fixture chart,
// plants a fake `we` binary that emits seeded findings, runs `mallcop scan`,
// and asserts exit code 1 + finding summary in stdout.
func TestScanE2E_FindingsPresent(t *testing.T) {
	// Build the mallcop binary.
	tmp := t.TempDir()
	mallcopBin := filepath.Join(tmp, "mallcop")
	build := exec.Command("go", "build", "-o", mallcopBin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "mallcop")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build mallcop: %v", err)
	}

	// Create fixture scan directory: charts/ bin/ output/
	scanDir := filepath.Join(tmp, "scan")
	chartsDir := filepath.Join(scanDir, "charts")
	binDir := filepath.Join(scanDir, "bin")
	outputDir := filepath.Join(scanDir, "output")
	for _, d := range []string{chartsDir, binDir, outputDir} {
		os.MkdirAll(d, 0o755)
	}

	// Write a minimal chart.
	chartFile := filepath.Join(chartsDir, "test.toml")
	os.WriteFile(chartFile, []byte("[identity]\nname=\"test\"\n"), 0o644)

	// Seed findings and resolutions into the output dir.
	seedFindings(t, outputDir)
	seedResolutions(t, outputDir)

	// Write a fake `we` binary that just exits 0 (findings already in output/).
	fakeBin := filepath.Join(binDir, "we")
	fakeScript := "#!/bin/sh\nexit 0\n"
	os.WriteFile(fakeBin, []byte(fakeScript), 0o755)

	// Run mallcop scan. PATH is set so `we` resolves to our fake binary.
	cmd := exec.Command(mallcopBin, "scan", "--chart", chartFile, "--timeout", "30s")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PATH=%s:%s", binDir, os.Getenv("PATH")))
	cmd.Dir = scanDir

	out, err := cmd.CombinedOutput()
	t.Logf("mallcop scan output:\n%s", out)

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error running mallcop scan: %v", err)
		}
	}

	// Expect exit code 1 (findings present).
	if exitCode != 1 {
		t.Errorf("expected exit code 1 (findings present), got %d", exitCode)
	}

	// Expect summary fields in stdout.
	outStr := string(out)
	for _, want := range []string{"Findings detected", "Scan complete"} {
		if !strings.Contains(outStr, want) {
			t.Errorf("output missing %q; got:\n%s", want, outStr)
		}
	}
}

// TestScanE2E_NoFindings runs mallcop scan with a fake `we` that emits no findings.
// Expects exit code 0.
func TestScanE2E_NoFindings(t *testing.T) {
	tmp := t.TempDir()
	mallcopBin := filepath.Join(tmp, "mallcop")
	build := exec.Command("go", "build", "-o", mallcopBin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "mallcop")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build mallcop: %v", err)
	}

	scanDir := filepath.Join(tmp, "scan2")
	chartsDir := filepath.Join(scanDir, "charts")
	binDir := filepath.Join(scanDir, "bin")
	for _, d := range []string{chartsDir, binDir} {
		os.MkdirAll(d, 0o755)
	}

	chartFile := filepath.Join(chartsDir, "test.toml")
	os.WriteFile(chartFile, []byte("[identity]\nname=\"test\"\n"), 0o644)

	fakeBin := filepath.Join(binDir, "we")
	os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755)

	cmd := exec.Command(mallcopBin, "scan", "--chart", chartFile, "--timeout", "30s")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PATH=%s:%s", binDir, os.Getenv("PATH")))
	cmd.Dir = scanDir

	out, err := cmd.CombinedOutput()
	t.Logf("mallcop scan output:\n%s", out)

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if exitCode != 0 {
		t.Errorf("expected exit code 0 (no findings), got %d", exitCode)
	}

	if !strings.Contains(string(out), "Scan complete") {
		t.Errorf("expected 'Scan complete' in output; got:\n%s", out)
	}
}

// TestScanE2E_ScanFailure tests exit code 2 when `we` exits with an error.
func TestScanE2E_ScanFailure(t *testing.T) {
	tmp := t.TempDir()
	mallcopBin := filepath.Join(tmp, "mallcop")
	build := exec.Command("go", "build", "-o", mallcopBin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "mallcop")
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build mallcop: %v", err)
	}

	scanDir := filepath.Join(tmp, "scan3")
	chartsDir := filepath.Join(scanDir, "charts")
	binDir := filepath.Join(scanDir, "bin")
	for _, d := range []string{chartsDir, binDir} {
		os.MkdirAll(d, 0o755)
	}

	chartFile := filepath.Join(chartsDir, "test.toml")
	os.WriteFile(chartFile, []byte("[identity]\nname=\"test\"\n"), 0o644)

	// Fake we exits 1 — simulates scan failure.
	fakeBin := filepath.Join(binDir, "we")
	os.WriteFile(fakeBin, []byte("#!/bin/sh\necho 'we: internal error' >&2\nexit 1\n"), 0o755)

	cmd := exec.Command(mallcopBin, "scan", "--chart", chartFile, "--timeout", "30s")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PATH=%s:%s", binDir, os.Getenv("PATH")))
	cmd.Dir = scanDir

	_, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		}
	}

	if exitCode != 2 {
		t.Errorf("expected exit code 2 (scan failure), got %d", exitCode)
	}
}

// seedFindings writes fixture finding JSON files to dir.
func seedFindings(t *testing.T, dir string) {
	t.Helper()
	ts := time.Now().UTC()
	findings := []finding.Finding{
		{ID: "f-e2e-001", Source: "detector:unusual-login", Severity: "high", Type: "unusual-login", Timestamp: ts},
		{ID: "f-e2e-002", Source: "detector:secrets-exposure", Severity: "critical", Type: "secrets-exposure", Timestamp: ts},
	}
	for _, f := range findings {
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("finding-%s.json", f.ID))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// seedResolutions writes fixture resolution JSON files to dir.
func seedResolutions(t *testing.T, dir string) {
	t.Helper()
	ts := time.Now().UTC()
	resolutions := []resolution.Resolution{
		{FindingID: "f-e2e-001", Action: "escalate", Severity: "high", Timestamp: ts},
		{FindingID: "f-e2e-002", Action: "block", Severity: "critical", Timestamp: ts},
	}
	for _, r := range resolutions {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("resolution-%s.json", r.FindingID))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// repoRoot walks up from the test file to find the go.mod root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// Walk up until we find go.mod.
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}
