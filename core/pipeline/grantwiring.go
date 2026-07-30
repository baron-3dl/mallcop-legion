// grantwiring.go wires the GrantClaim doctor's outputs (core/connect, design
// §Gap D — mallcoppro-b1f/62b, both merged) onto the operator-input spine
// (mallcoppro-d3f). The doctor itself — Probe/Diagnose/Remediate/Confirm, and
// the KindGrants append-only stream — is the AUTHORITY closure and is NOT
// re-planned here; this file only routes its two outcomes:
//
//   - a Diagnose returning Known:false → an E1 SecurityDecision-shaped ask,
//     carried on the SAME durable KindGrants row (recordConnectorDiagnosis);
//   - a Confirm/remediate outcome → a GrantOutcome resolution row a
//     subsequent scan reads back, idempotent across re-scans
//     (RecordConfirmOutcome).
//
// Plain Go wiring, no engine: both functions are ordinary calls into the
// already-built kernel (core/connect) and the already-built stream
// (core/store) — nothing here interprets a data spec.
package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/store"
)

// recordConnectorDiagnosis is called from Run when cfg.Connector.Pull fails.
// If the connector implements connect.Diagnosable, it asks it to self-check
// and appends exactly one GrantOutcome MISS row to KindGrants carrying what
// it found — and, when the diagnosis came back Known:false, the E1
// SecurityDecision-request fields (connect.RaiseUnknownDiagnosis) on that
// SAME row, so mallcop-pro's Gap-E1 consumer (mallcoppro-a7b4, the privileged
// side that actually holds a session and can email/raise the decision — see
// the DecisionKind field doc on store.GrantOutcome for why mallcop itself
// never calls that endpoint directly) has, the moment it reads this stream,
// everything an operator needs to judge the ask: which connector
// (Connector), what mallcop could tell about the failure (FailureClass), and
// a ready-to-send kind/blast_radius/question.
//
// A connector that does not implement Diagnosable is a no-op (nil error) —
// most connectors (e.g. FileConnector) have nothing to self-diagnose.
// Diagnose's own contract (core/connect/connect.go) never returns a raw,
// uninterpreted error for an expected degraded case, so a non-nil error here
// is reserved for something genuinely unrecoverable (e.g. ctx cancellation) —
// it is returned, not swallowed, so a caller can fold it into a wrapped
// error instead of silently losing it; it must never mask or replace the
// connect failure that is already the reason Run is returning an error.
func recordConnectorDiagnosis(ctx context.Context, st *store.Store, connector connect.Connector) error {
	diag, ok := connector.(connect.Diagnosable)
	if !ok {
		return nil
	}
	report, err := diag.Diagnose(ctx)
	if err != nil {
		return fmt.Errorf("pipeline: diagnose connect failure: %w", err)
	}

	row := store.GrantOutcome{
		Connector:    report.ConnectorID,
		FailureClass: report.Diagnosis.Summary,
		DetectedAt:   time.Now().UTC(),
		Resolved:     false,
	}
	if req, ok := connect.RaiseUnknownDiagnosis(report); ok {
		row.DecisionKind = req.Kind
		row.BlastRadius = req.BlastRadius
		row.Question = req.Question
	}

	if _, err := st.Append(store.KindGrants, row); err != nil {
		return fmt.Errorf("pipeline: record grant-miss diagnosis: %w", err)
	}
	return nil
}

// RecordConfirmOutcome persists a GrantClaim's Confirm result (core/connect,
// design §3/§11) as the RESOLUTION half of the KindGrants append-only pair
// (mallcoppro-62b) — the piece of Design §Gap D this item wires up. missSHA
// is the commit SHA Store.Append returned for the ORIGINAL GRANT-MISS row
// this Confirm call is closing (e.g. recordConnectorDiagnosis's return, or
// a prior manual/CLI-issued miss). connector/cloud/accessMode identify the
// SAME diagnosis the miss row carries — RecordConfirmOutcome cross-checks
// them against the resolved miss (via st.ResolveGrantMiss) so a caller
// cannot accidentally attach a resolution to the wrong row.
//
//   - result.Resolved == true: appends a resolution row (Resolved:true,
//     ResolvedRef: missSHA) — never a mutation of the miss row.
//   - result.Resolved == false: the RemediationOption that was applied did
//     NOT close the deficiency. diagnose.go's ConfirmResult doc (NEW-A19)
//     calls this itself a high-value GRANT-MISS, so a FRESH miss row is
//     appended instead (carrying the re-probed Diagnosis, and a fresh E1 ask
//     if it is STILL Known:false) — never a resolution.
//
// Idempotent across re-scans: if missSHA already has a resolution row on the
// stream, RecordConfirmOutcome appends nothing and returns appended=false —
// a second Confirm call for an already-closed miss (e.g. a re-scan that
// reruns the doctor before the operator's next check) must not grow the
// history with duplicate resolutions.
func RecordConfirmOutcome(st *store.Store, missSHA, connectorID, cloud, accessMode string, result connect.ConfirmResult) (sha string, appended bool, err error) {
	miss, err := st.ResolveGrantMiss(missSHA)
	if err != nil {
		return "", false, fmt.Errorf("pipeline: resolve original grant miss %s: %w", missSHA, err)
	}
	if miss.Resolved {
		return "", false, fmt.Errorf("pipeline: grant miss %s is itself a resolution row, not a miss", missSHA)
	}

	if !result.Resolved {
		row := store.GrantOutcome{
			Connector:    connectorID,
			Cloud:        cloud,
			AccessMode:   accessMode,
			FailureClass: result.Diagnosis.Summary,
			DetectedAt:   result.CheckedAt.UTC(),
			Resolved:     false,
		}
		if req, ok := connect.RaiseUnknownDiagnosis(connect.DiagnosisReport{ConnectorID: connectorID, Diagnosis: result.Diagnosis}); ok {
			row.DecisionKind = req.Kind
			row.BlastRadius = req.BlastRadius
			row.Question = req.Question
		}
		sha, err = st.Append(store.KindGrants, row)
		if err != nil {
			return "", false, fmt.Errorf("pipeline: record persisting grant-miss after confirm: %w", err)
		}
		return sha, true, nil
	}

	existing, err := st.LoadGrantOutcomes()
	if err != nil {
		return "", false, fmt.Errorf("pipeline: load grant outcomes for idempotency check: %w", err)
	}
	for _, r := range existing {
		if r.Resolved && r.ResolvedRef == missSHA {
			// Already resolved by an earlier call (or an earlier scan) —
			// idempotent no-op, not an error.
			return "", false, nil
		}
	}

	resolution := store.GrantOutcome{
		Connector:   connectorID,
		Cloud:       cloud,
		AccessMode:  accessMode,
		DetectedAt:  result.CheckedAt.UTC(),
		Resolved:    true,
		ResolvedRef: missSHA,
	}
	sha, err = st.Append(store.KindGrants, resolution)
	if err != nil {
		return "", false, fmt.Errorf("pipeline: record grant resolution: %w", err)
	}
	return sha, true, nil
}
