package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// checkpoint is the on-disk scan state file written by the pipeline.
type checkpoint struct {
	Purpose           string    `json:"purpose"`
	LastCursor        string    `json:"last_cursor"`
	LastRun           time.Time `json:"last_run"`
	FindingsProcessed int       `json:"findings_processed"`
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	chartPath := fs.String("chart", defaultChart, "Path to the legion chart TOML")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Look for checkpoint file relative to chart directory.
	chartDir := filepath.Dir(*chartPath)
	checkpointPath := filepath.Join(chartDir, "..", "test", "fixtures", "e2e-checkpoint.json")
	checkpointPath = filepath.Clean(checkpointPath)

	// Also check output dir for a run-state.json.
	outDir := scanOutputDir(*chartPath)
	runStatePath := filepath.Join(outDir, "run-state.json")

	fmt.Printf("Chart:      %s\n", *chartPath)

	// Try output run-state first, fall back to e2e checkpoint.
	cp, err := loadCheckpoint(runStatePath)
	if err != nil {
		cp, err = loadCheckpoint(checkpointPath)
	}

	if err != nil {
		fmt.Printf("Last run:   unknown (no checkpoint found)\n")
		fmt.Printf("State:      idle\n")
		return nil
	}

	if cp.LastRun.IsZero() {
		fmt.Printf("Last run:   never\n")
	} else {
		fmt.Printf("Last run:   %s\n", cp.LastRun.UTC().Format(time.RFC3339))
	}
	if cp.LastCursor != "" {
		fmt.Printf("Cursor:     %s\n", cp.LastCursor)
	}
	fmt.Printf("Findings:   %d processed\n", cp.FindingsProcessed)
	fmt.Printf("State:      idle\n")
	return nil
}

func loadCheckpoint(path string) (*checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cp, nil
}
