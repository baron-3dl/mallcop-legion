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

// diagnosables returns every connect.Diagnosable reachable from connector:
// itself, if it directly implements the interface, or — for the shape
// cli/scan.go's buildConnectors ALWAYS returns in production
// (connect.Multi(subs...), even for a single configured source, cfg/scan.go:558)
// — each of its wrapped sub-connectors that does (mallcoppro-d3f veracity
// rework, Route 1). *connect.MultiConnector never itself implements
// Diagnosable (core/connect/multi.go), so a caller that only ever asserts
// directly on cfg.Connector silently finds nothing for exactly the
// connectors — kind:cloud's ExecConnector — that actually HAVE a doctor. This
// helper is the one place both recordConnectorDiagnosis (the failure path)
// and confirmResolvedGrants (the success path, Route 2) reach the real leaf
// connectors from, so the walk is defined once, not duplicated.
func diagnosables(connector connect.Connector) []connect.Diagnosable {
	if d, ok := connector.(connect.Diagnosable); ok {
		return []connect.Diagnosable{d}
	}
	if m, ok := connector.(interface{ Diagnosables() []connect.Diagnosable }); ok {
		return m.Diagnosables()
	}
	return nil
}

// recordConnectorDiagnosis is called from Run when cfg.Connector.Pull fails.
// It walks every connect.Diagnosable reachable from connector (diagnosables,
// above — direct or wrapped in a production connect.Multi) and appends
// exactly one GrantOutcome MISS row per Diagnosable to KindGrants carrying
// what it found — and, when a given diagnosis came back Known:false, the E1
// SecurityDecision-request fields (connect.RaiseUnknownDiagnosis) on that
// SAME row, so mallcop-pro's Gap-E1 consumer (mallcoppro-a7b4, the privileged
// side that actually holds a session and can email/raise the decision — see
// the DecisionKind field doc on store.GrantOutcome for why mallcop itself
// never calls that endpoint directly) has, the moment it reads this stream,
// everything an operator needs to judge the ask: which connector
// (Connector), what mallcop could tell about the failure (FailureClass), and
// a ready-to-send kind/blast_radius/question.
//
// A connector with no reachable Diagnosable is a no-op (nil error) — most
// connectors (e.g. FileConnector) have nothing to self-diagnose. Diagnose's
// own contract (core/connect/connect.go) never returns a raw, uninterpreted
// error for an expected degraded case, so a non-nil error here is reserved
// for something genuinely unrecoverable (e.g. ctx cancellation) — it is
// returned, not swallowed, so a caller can fold it into a wrapped error
// instead of silently losing it; it must never mask or replace the connect
// failure that is already the reason Run is returning an error.
//
// Attribution: a MultiConnector's own Pull halts and returns on the FIRST
// sub-connector error (core/connect/multi.go), so which specific sub
// actually failed is not recoverable from the returned error alone. Rather
// than guess, every reachable Diagnosable is asked to self-check, and each
// row is attributed to the sub-connector that PRODUCED it
// (report.ConnectorID) — a healthy sub-connector's own Diagnose call still
// reports its (healthy) status, which is itself useful history, not noise:
// it is the same "Probe on every scheduled run" cadence the GrantClaim kernel
// documents (core/connect/diagnose.go).
func recordConnectorDiagnosis(ctx context.Context, st *store.Store, connector connect.Connector) error {
	diags := diagnosables(connector)
	if len(diags) == 0 {
		return nil
	}
	for _, diag := range diags {
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
	}
	return nil
}

// pendingGrantMiss returns the most recent UNRESOLVED GrantOutcome row for
// connectorID on the grants stream, and the commit SHA needed to resolve it
// (RecordConfirmOutcome's missSHA) — the READ half of Route 2's loop-closing
// wiring (mallcoppro-d3f veracity rework): the scan path must actually
// consult this stream before deciding a freshly-successful Pull is closing a
// PRIOR grant miss, not merely assume it. It walks the stream oldest-first
// (Store.LoadGrantOutcomesWithRefs), tracks every ResolvedRef a resolution
// row points at, then scans backward for the latest miss row belonging to
// connectorID that no resolution row has claimed. found is false when
// connectorID has never had a miss, or its most recent one is already
// resolved — the common steady-state case, so a healthy connector costs
// nothing beyond this one cheap store read (no live Diagnose call follows).
func pendingGrantMiss(st *store.Store, connectorID string) (missSHA string, miss store.GrantOutcome, found bool, err error) {
	records, err := st.LoadGrantOutcomesWithRefs()
	if err != nil {
		return "", store.GrantOutcome{}, false, fmt.Errorf("pipeline: load grant outcomes for pending-miss check: %w", err)
	}
	resolvedRefs := make(map[string]bool, len(records))
	for _, r := range records {
		if r.Resolved && r.ResolvedRef != "" {
			resolvedRefs[r.ResolvedRef] = true
		}
	}
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		if r.Resolved || r.Connector != connectorID {
			continue
		}
		if resolvedRefs[r.SHA] {
			continue
		}
		return r.SHA, r.GrantOutcome, true, nil
	}
	return "", store.GrantOutcome{}, false, nil
}

// confirmResolvedGrants is called from Run AFTER a SUCCESSFUL Pull
// (mallcoppro-d3f veracity rework, Route 2 — the WRITE half's real caller).
// For every connect.Diagnosable reachable from connector (diagnosables,
// above — direct or wrapped in the production connect.Multi shape), it reads
// the grants stream (pendingGrantMiss, above) for an outstanding, unresolved
// GRANT-MISS attributed to that connector's ID. Only when one is found does it
// pay for a live re-probe (diag.Diagnose) — a healthy connector with nothing
// outstanding costs one cheap store read, never a network call. The fresh
// diagnosis is recorded through RecordConfirmOutcome exactly like an
// operator-driven Confirm call would be: Known:true closes the loop with a
// resolution row the NEXT scan's own pendingGrantMiss check (or any
// operator-facing reader of the grants stream) sees; Known:false (still
// broken) appends a fresh miss row (RecordConfirmOutcome's NEW-A19 branch) —
// never silently drops the still-outstanding ask.
func confirmResolvedGrants(ctx context.Context, st *store.Store, connector connect.Connector) error {
	for _, diag := range diagnosables(connector) {
		id := diag.ID()
		if id == "" {
			continue
		}
		missSHA, miss, found, err := pendingGrantMiss(st, id)
		if err != nil {
			return err
		}
		if !found {
			continue
		}

		report, err := diag.Diagnose(ctx)
		if err != nil {
			return fmt.Errorf("pipeline: re-diagnose connector %q to confirm grant resolution: %w", id, err)
		}
		result := connect.ConfirmResult{
			Resolved:  report.Diagnosis.Known,
			Diagnosis: report.Diagnosis,
			CheckedAt: time.Now().UTC(),
		}
		if _, _, err := RecordConfirmOutcome(st, missSHA, id, miss.Cloud, miss.AccessMode, result); err != nil {
			return fmt.Errorf("pipeline: record confirm outcome for connector %q: %w", id, err)
		}
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
	// Cross-check the caller's identity against the resolved miss row itself
	// — the safety property this function's own doc comment claims (a caller
	// cannot accidentally attach a resolution to the wrong row). Without
	// this, a missSHA typo'd or copy-pasted from a DIFFERENT connector's miss
	// would silently attach that connector's resolution/re-miss to this one's
	// history.
	if miss.Connector != connectorID || miss.Cloud != cloud || miss.AccessMode != accessMode {
		return "", false, fmt.Errorf(
			"pipeline: confirm outcome identity mismatch: grant miss %s is connector=%q cloud=%q access_mode=%q, "+
				"but this call is for connector=%q cloud=%q access_mode=%q — refusing to attach a resolution to the wrong row",
			missSHA, miss.Connector, miss.Cloud, miss.AccessMode, connectorID, cloud, accessMode)
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
