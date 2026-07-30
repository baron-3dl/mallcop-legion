package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/store"
)

// runStatus implements `mallcop status`: report the current state of a findings
// store. It opens the git-backed store at --store and reports how many findings
// and resolutions are durably recorded. There is no chart and no separate
// run-state file — the store IS the state.
//
// Terminology: this prints "Decisions: N recorded" — the total count of
// resolution records ever written to the store (every cascade verdict,
// escalate included). That is deliberately a different word from `mallcop
// scan`'s per-run "Resolved: N" summary line, which counts only the
// non-escalate (auto-resolved-by-inference) subset of THIS scan's findings.
// Reusing "Resolved" for both would read as the same measurement when it
// isn't: a store can show "Decisions: 2 recorded" for a scan that itself
// reported "Resolved: 0" (both findings escalated).
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store to report on (required)")
	gate := fs.Bool("gate", false, "Exit nonzero (the errFindings sentinel) when the whole-pipeline liveness watchdog fails: the newest recorded scan is older than --max-age or did not complete successfully. Design §5 primitive 1 — runs on the customer's own cron; mallcop holds no standing credential.")
	maxAge := fs.Duration("max-age", 48*time.Hour, "Under --gate, how old the newest KindScans record may be before the liveness watchdog fails (e.g. 48h). Ignored without --gate.")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *storePath == "" {
		return fmt.Errorf("status: --store is required (the git-repo path written by `mallcop scan`)")
	}

	fmt.Printf("Store:      %s\n", *storePath)

	if _, err := os.Stat(filepath.Join(*storePath, ".git")); err != nil {
		fmt.Printf("State:      uninitialized (no scan has written here yet)\n")
		if *gate {
			// No store at all means no evidence the pipeline has ever run —
			// exactly the darkness the liveness watchdog (design §5) exists to
			// surface as a first-class dated failure, not silence.
			fmt.Printf("Liveness:   FAIL (no scan history recorded — the pipeline has never completed a run)\n")
			return errFindings
		}
		return nil
	}

	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("status: open store %q: %w", *storePath, err)
	}

	findings, err := st.Load(store.KindFindings)
	if err != nil {
		return fmt.Errorf("status: load findings: %w", err)
	}
	resolutions, err := st.Load(store.KindResolutions)
	if err != nil {
		return fmt.Errorf("status: load resolutions: %w", err)
	}

	fmt.Printf("Findings:   %d recorded\n", len(findings))
	fmt.Printf("Decisions:  %d recorded\n", len(resolutions))

	// Cases: read back store/cases.json — the SAME projection cli/cases.go's
	// collapseCases builds via core/cases.Collapse + ApplyCaseDirectives and
	// commits on every `mallcop scan` (mallcoppro-554) — and hand it straight
	// to cases.Summarize for counts/formatting. status NEVER re-clusters a
	// finding or re-derives a Case itself (R4, mallcoppro-a51): doing so would
	// let this section drift from cases.json exactly as a hand-rolled console
	// count would. A store with no cases.json yet (ReadSnapshot's documented
	// "not found is not an error" case) reads back as an empty case set, which
	// Summarize reports honestly as "0 open" — the section always prints,
	// never silently disappears on an empty store.
	casesRaw, err := st.ReadSnapshot(casesSnapshotName)
	if err != nil {
		return fmt.Errorf("status: read %s: %w", casesSnapshotName, err)
	}
	var caseSet []cases.Case
	if len(casesRaw) > 0 {
		if err := json.Unmarshal(casesRaw, &caseSet); err != nil {
			return fmt.Errorf("status: decode %s: %w", casesSnapshotName, err)
		}
	}
	summary := cases.Summarize(caseSet)
	if summary.Open > 0 {
		fmt.Printf("Cases:      %d open (%d recurring)\n", summary.Open, summary.Recurring)
	} else {
		fmt.Printf("Cases:      0 open\n")
	}
	for _, line := range summary.Lines {
		fmt.Println(line)
	}

	// Surface the STORE-PURE coverage gaps the self-heal loop tracks — the same
	// offline collectors `mallcop collect` runs, with no --fidelity (so no
	// detect_miss, which needs an exam dump) and no inference. This makes the
	// operator's own reported misses (mallcop feedback report-miss) and the
	// override/dissent gaps visible at a glance, and flags any RECALL RED — a
	// missed known attack the loop should have caught, which fails a scheduled
	// scan under `mallcop collect --gate`.
	gaps, err := collect.DetectorGaps(st, nil)
	if err != nil {
		return fmt.Errorf("status: detector gaps: %w", err)
	}
	recallReds := 0
	reportedMisses := 0
	for _, g := range gaps {
		if g.IsRecallRed() {
			recallReds++
		}
		if g.Kind == collect.GapReportedMiss {
			reportedMisses++
		}
	}
	fmt.Printf("Coverage gaps:   %d (%d reported miss)\n", len(gaps), reportedMisses)
	if recallReds > 0 {
		fmt.Printf("Recall reds:     %d (missed known attacks — fail a scheduled scan under 'mallcop collect --gate')\n", recallReds)
	}

	// Whole-pipeline liveness watchdog (design §5 primitive 1): under --gate,
	// fail loud when the pipeline has stopped running or keeps failing — the
	// exact "6-day silent failure" this primitive turns into a first-class
	// dated failing job on the customer's own cron (cli/deployrepo.go's
	// scanWorkflowTemplate `if: always()` step).
	if *gate {
		scans, err := st.LoadScans()
		if err != nil {
			return fmt.Errorf("status: load scans: %w", err)
		}
		result := evaluateLiveness(scans, *maxAge, time.Now())
		if !result.Healthy {
			fmt.Printf("Liveness:   FAIL (%s)\n", result.Reason)
			return errFindings
		}
		fmt.Printf("Liveness:   OK\n")
	}

	fmt.Printf("State:      idle\n")
	return nil
}

// livenessResult is the whole-pipeline liveness watchdog's pure decision
// (design §5 primitive 1), separated from I/O so it can be exercised
// directly by tests without a CLI invocation.
type livenessResult struct {
	Healthy bool
	// Reason is a human-readable explanation, populated only when !Healthy.
	Reason string
}

// evaluateLiveness applies the whole-pipeline liveness watchdog: the newest
// store.ScanRecord must be both RECENT (its FinishedAt within maxAge of now)
// and HEALTHY (Success, or a legacy pre-mallcoppro-24e record that predates
// the Success/FailedStage/Error fields entirely). A store with no scan
// history at all is unhealthy — the watchdog has no evidence the pipeline
// has ever run, which is exactly the darkness this primitive exists to
// surface as a dated failure instead of quiet confidence.
//
// Legacy-record caveat (mallcoppro-24e / mallcoppro-3c7): a ScanRecord
// written by a binary that predates the Success/FailedStage/Error fields
// decodes as Success=false via Go's JSON zero-value — indistinguishable at
// the field level from a genuine failure with an empty stage/error. This is
// disambiguated by treating FailedStage=="" AND Error=="" as
// legacy-completed (NOT a failure): every record written before these
// fields existed represents a run that reached the tail recordScan call — a
// COMPLETED scan (see store.ScanRecord's doc comment). A genuine failure on
// a post-24e binary always populates FailedStage (core/pipeline.recordScan
// sets it unconditionally on any non-nil runErr), so the empty/empty
// combination cannot occur on a real failure once 24e is in the binary that
// wrote the record.
func evaluateLiveness(scans []store.ScanRecord, maxAge time.Duration, now time.Time) livenessResult {
	if len(scans) == 0 {
		return livenessResult{Healthy: false, Reason: "no scan history recorded — the pipeline has never completed a run"}
	}

	// LoadScans replays oldest-first; the newest record is the last element.
	newest := scans[len(scans)-1]

	legacyCompleted := !newest.Success && newest.FailedStage == "" && newest.Error == ""
	if !newest.Success && !legacyCompleted {
		return livenessResult{
			Healthy: false,
			Reason: fmt.Sprintf("newest scan (started %s) failed at stage %q: %s",
				newest.StartedAt.UTC().Format(time.RFC3339), newest.FailedStage, newest.Error),
		}
	}

	if age := now.Sub(newest.FinishedAt); age > maxAge {
		return livenessResult{
			Healthy: false,
			Reason:  fmt.Sprintf("newest scan finished %s ago, exceeding --max-age %s", age.Round(time.Second), maxAge),
		}
	}

	return livenessResult{Healthy: true}
}
