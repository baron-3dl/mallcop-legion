// attach.go — the exported reader + re-vote attach path the low-confidence
// retrigger (mallcoppro-09a) uses. core/pipeline drives the deeper-investigation
// pass and the committee re-vote (it holds the cascade seam; core/inquest cannot,
// per imports_test.go's ban on core/agent's ResolveFindingWith — the structural
// consensus invariant), then attaches the re-vote OUTCOME back onto the finding's
// investigation record here. This is ADDITIVE only: it never writes to
// findings/resolutions/directives, exactly like every other write path in this
// package (see the package doc's consensus-invariant note).
package inquest

import (
	"fmt"

	"github.com/mallcop-app/mallcop/core/store"
)

// ReadRecord reads back the committed investigation record at key, if any.
// key is the caller's resolved record identity — EscalatedFinding.RecordKey()
// (a CaseID when resolved, else the finding's own ID; mallcoppro-42e) — the
// SAME key RunAll itself wrote the record at. It is the exported twin of the
// internal readExistingRecord — the pipeline's step-6 low-confidence
// retrigger needs to inspect each escalated finding's just-written record
// (its NarrativeStatus + Confidence) to decide whether it warrants a deeper
// pass + re-vote. found is false (with a nil error) when no record exists; a
// malformed record is a hard error.
func ReadRecord(st *store.Store, key string) (rec Record, found bool, err error) {
	return readExistingRecord(st, key)
}

// AttachRevote does a read-modify-write of the investigation record at key,
// setting its Revote field to outcome and bumping UpdatedAt, through the SAME
// size-capped WriteSnapshot/CAS path every other record write uses. key is
// the SAME EscalatedFinding.RecordKey() the deeper investigation pass wrote
// its record at (a CaseID when resolved, else the finding's own ID). It is
// ADDITIVE: the disposition (the escalate Resolution on the record and in the
// KindResolutions stream) is never touched — the re-vote is a second opinion
// attached to the EVIDENCE record, not a re-resolution (mallcoppro-09a, the
// consensus invariant). An absent record is an error: a re-vote can only be
// attached to a record that was actually written this scan.
func AttachRevote(st *store.Store, key string, outcome RevoteOutcome) error {
	rec, found, err := readExistingRecord(st, key)
	if err != nil {
		return fmt.Errorf("inquest: attach revote: read record for %s: %w", key, err)
	}
	if !found {
		return fmt.Errorf("inquest: attach revote: no investigation record for %s", key)
	}
	rec.Revote = &outcome
	rec.UpdatedAt = nowRFC3339()
	if _, err := writeRecord(st, key, rec); err != nil {
		return fmt.Errorf("inquest: attach revote: write record for %s: %w", key, err)
	}
	return nil
}
