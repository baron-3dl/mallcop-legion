package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// casesSnapshotName is the store-relative path WriteSnapshot/ReadSnapshot use
// for the case-collapse projection (mallcoppro-554).
const casesSnapshotName = "cases.json"

// buildTimestampLookup replays the store's full KindFindings stream and
// returns a closure resolving a finding ID to its ORIGINAL occurrence
// timestamp (finding.Timestamp, not a resolution's wall-clock stamp — the
// only one durably recoverable purely from finding_ids + findings.jsonl).
// Same full-stream-load idiom loadEscalatedResolutions already uses for
// KindResolutions — not a new cost pattern.
func buildTimestampLookup(st *store.Store) (func(string) (time.Time, bool), error) {
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]time.Time, len(raws))
	for _, raw := range raws {
		var f finding.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("decode finding for timestamp lookup: %w", err)
		}
		byID[f.ID] = f.Timestamp
	}
	return func(id string) (time.Time, bool) {
		t, ok := byID[id]
		return t, ok
	}, nil
}

// collapseCases reads back this scan's just-written findings + resolutions,
// projects the escalated ones into cases.Escalation, merges them into the
// existing store/cases.json (if any) via cases.Collapse, applies any pending
// close-case/recurrence-fine directive against the merged set (Gap C,
// mallcoppro-a1c), and commits the result. NEVER reads or writes
// resolutions.jsonl beyond the read-back below (see the consensus-invariant
// note on the call site in runScan and on cases.Escalation itself).
//
// The directive replay runs EVERY call, not just when this scan escalated
// something new: a `mallcop case close <id>` issued between scans must land
// on cases.json even on a scan that adds no new escalations to that case —
// otherwise a close/age directive issued when the source case last recurred
// stays inert until the case recurs again, which may be never. Directive
// replay is idempotent (ApplyCaseDirectives re-applying an already-applied
// close-case is a no-op status write) and WriteSnapshot itself no-ops on
// byte-identical content, so replaying every call costs nothing observable.
func collapseCases(st *store.Store, thisRun int) error {
	findingsWindow, err := loadThisRunFindings(st, thisRun)
	if err != nil {
		return fmt.Errorf("load this run's findings: %w", err)
	}
	resWindow, err := loadThisRunResolutions(st, thisRun)
	if err != nil {
		return fmt.Errorf("load this run's resolutions: %w", err)
	}
	// See loadThisRunFindings' doc comment: core/pipeline.Run's persistence
	// step keeps these two windows index-aligned 1:1 for a fixed thisRun. A
	// length mismatch means that invariant broke — fail loudly rather than
	// silently mispairing a finding with the wrong resolution.
	if len(findingsWindow) != len(resWindow) {
		return fmt.Errorf("findings/resolutions window length mismatch: %d findings, %d resolutions (thisRun=%d)",
			len(findingsWindow), len(resWindow), thisRun)
	}

	var escalations []cases.Escalation
	for i, f := range findingsWindow {
		r := resWindow[i]
		if r.Action != "escalate" {
			continue
		}
		escalations = append(escalations, cases.Escalation{
			FindingID: f.ID,
			Type:      f.Type,
			Actor:     r.Actor,
			Severity:  r.Severity,
			Entity:    cases.ExtractEntity(f.Evidence),
			Timestamp: f.Timestamp,
		})
	}

	existingRaw, err := st.ReadSnapshot(casesSnapshotName)
	if err != nil {
		return fmt.Errorf("read existing %s: %w", casesSnapshotName, err)
	}
	var existing []cases.Case
	if len(existingRaw) > 0 {
		if err := json.Unmarshal(existingRaw, &existing); err != nil {
			return fmt.Errorf("decode existing %s: %w", casesSnapshotName, err)
		}
	}
	if len(escalations) == 0 && len(existing) == 0 {
		// Nothing to collapse and nothing durable to replay a directive
		// against — writing an empty snapshot would just be noise on a
		// store that has never had a case.
		return nil
	}

	merged := existing
	if len(escalations) > 0 {
		lookup, err := buildTimestampLookup(st)
		if err != nil {
			return fmt.Errorf("build timestamp lookup: %w", err)
		}
		merged = cases.Collapse(existing, escalations, lookup)
	}

	directives, err := st.LoadDirectives()
	if err != nil {
		return fmt.Errorf("load directives for case replay: %w", err)
	}
	merged = pipeline.ApplyCaseDirectives(merged, directives)

	if _, err := st.WriteSnapshot(casesSnapshotName, merged); err != nil {
		return fmt.Errorf("write %s: %w", casesSnapshotName, err)
	}
	return nil
}
