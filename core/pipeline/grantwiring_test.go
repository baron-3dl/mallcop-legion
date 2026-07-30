package pipeline_test

// grantwiring_test.go proves the two Design §Gap D wiring routes
// (mallcoppro-d3f) through the REAL code path:
//
//   - TestPipeline_DiagnoseUnknown_RaisesE1SecurityDecision drives the
//     actual pipeline.Run entry point (not recordConnectorDiagnosis in
//     isolation) over a connector whose Pull fails and whose Diagnose comes
//     back Known:false, and reads the result back through the REAL
//     store.LoadGrantOutcomes — a real `git init` temp repo, real Store.Append
//     commits, exactly like scanrecord_failure_test.go's convention.
//   - TestPipeline_DiagnoseKnown_RecordsMissWithoutE1Ask is the companion
//     negative case: a CLASSIFIED diagnosis records the miss but must NOT
//     carry E1 fields — a classified failure has a ranked remediation to try,
//     it is not an operator ask.
//   - TestRecordConfirmOutcome_* exercise route 2 (Confirm outcome -> a
//     resolution row a subsequent scan reads back) directly against
//     RecordConfirmOutcome, again through the real store append+git path,
//     including the idempotent-across-re-scans requirement.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/core/pipeline"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// missRow is the seed GrantOutcome MISS row TestRecordConfirmOutcome_* append
// before exercising RecordConfirmOutcome against it — a fixed fixture so each
// test's seed is identical and the diffs under test are only in the Confirm
// result being recorded against it.
func missRow() store.GrantOutcome {
	return store.GrantOutcome{
		Connector:    "azure-sp-prod",
		Cloud:        "azure",
		AccessMode:   "read-only",
		FailureClass: "refresh token rejected by AAD for an unrecognized reason",
		DetectedAt:   time.Now().UTC(),
		Resolved:     false,
	}
}

// diagnosableConnector is a REAL connect.Connector + connect.Diagnosable
// implementation authored for this test — it is the same shape as this
// item's own AVAILABLE-TO-YOU boundary requires: the ONE real identity-family
// doctor (Azure SP, e2a) lives in the sibling mallcop-connectors repo and is
// out of this item's scope/reach. This stand-in exercises the KERNEL
// (connect.Diagnosable, connect.DiagnosisReport, connect.RaiseUnknownDiagnosis)
// and, critically, the REAL store append+git-commit path exactly the way a
// real sibling-binary doctor would drive it through connect/exec.ExecConnector
// — the thing under test here is the WIRING (pipeline.Run -> KindGrants),
// not a specific cloud vendor's probe logic.
type diagnosableConnector struct {
	pullErr error
	report  connect.DiagnosisReport
}

func (d diagnosableConnector) Pull(_ context.Context) ([]event.Event, error) {
	return nil, d.pullErr
}

func (d diagnosableConnector) ID() string {
	return d.report.ConnectorID
}

func (d diagnosableConnector) Diagnose(_ context.Context) (connect.DiagnosisReport, error) {
	return d.report, nil
}

var (
	_ connect.Connector   = diagnosableConnector{}
	_ connect.Diagnosable = diagnosableConnector{}
)

// TestPipeline_DiagnoseUnknown_RaisesE1SecurityDecision is the headline proof
// for route 1: a Diagnose returning Known:false must not dead-end silently —
// it must land a durable GrantOutcome MISS row carrying the E1
// SecurityDecision-request fields, through pipeline.Run's real connect stage.
func TestPipeline_DiagnoseUnknown_RaisesE1SecurityDecision(t *testing.T) {
	st := newGitStore(t)

	connector := diagnosableConnector{
		pullErr: errors.New("azuresp: AADSTS700082: refresh token expired"),
		report: connect.DiagnosisReport{
			ConnectorID: "azure-sp-prod",
			Diagnosis: connect.Diagnosis{
				Known:      false,
				Summary:    "refresh token rejected by AAD for an unrecognized reason",
				Confidence: 0.3,
			},
		},
	}

	cfg := pipeline.Config{
		Connector: connector,
		Client:    &inference.DirectClient{BaseURL: "http://unused.invalid", Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
	}

	_, err := pipeline.Run(context.Background(), cfg)
	if err == nil {
		t.Fatalf("pipeline.Run over a Pull-failing, Diagnosable connector returned nil error; want the wrapped connect error")
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 1 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want exactly 1 (the durable diagnosis)", len(grants))
	}

	row := grants[0]
	if row.Connector != "azure-sp-prod" {
		t.Errorf("row.Connector = %q, want %q (which connector)", row.Connector, "azure-sp-prod")
	}
	if row.Resolved || row.ResolvedRef != "" {
		t.Errorf("row = %+v, want a MISS row (Resolved=false, ResolvedRef=\"\")", row)
	}
	if row.FailureClass == "" {
		t.Errorf("row.FailureClass is empty, want the diagnosis summary (what mallcop could tell about the failure)")
	}

	// THE E1 ask: DecisionKind/BlastRadius/Question must be populated because
	// Diagnosis.Known was false.
	if row.DecisionKind != "grant" {
		t.Errorf("row.DecisionKind = %q, want %q (Known:false always asks for a grant/credential review)", row.DecisionKind, "grant")
	}
	if row.BlastRadius == "" {
		t.Errorf("row.BlastRadius is empty — an operator cannot judge an ask with no blast-radius text (mirrors mallcop-pro's own rejection of an empty blast_radius)")
	}
	if row.Question == "" {
		t.Errorf("row.Question is empty — what is being asked for must be stated")
	}

	// Prove the SecurityDecisionRequest projection round-trips into exactly
	// the fields recorded on the row — the same values, not a re-derivation
	// that could drift.
	req, ok := connect.RaiseUnknownDiagnosis(connector.report)
	if !ok {
		t.Fatalf("connect.RaiseUnknownDiagnosis(report) ok = false for a Known:false report")
	}
	if req.Kind != row.DecisionKind || req.BlastRadius != row.BlastRadius || req.Question != row.Question {
		t.Errorf("row fields (%q/%q/%q) do not match connect.RaiseUnknownDiagnosis's own projection (%q/%q/%q)",
			row.DecisionKind, row.BlastRadius, row.Question, req.Kind, req.BlastRadius, req.Question)
	}
}

// TestPipeline_DiagnoseKnown_RecordsMissWithoutE1Ask is the companion negative
// case: a CLASSIFIED diagnosis (Known:true) still records the miss (so the
// operator sees WHY the connector failed) but must NOT carry E1 fields — a
// classified failure has a ranked remediation to try (Remediate/Confirm,
// route 2), it is not an unresolved operator ask.
func TestPipeline_DiagnoseKnown_RecordsMissWithoutE1Ask(t *testing.T) {
	st := newGitStore(t)

	connector := diagnosableConnector{
		pullErr: errors.New("github: GET /orgs/atom/audit-log: 403 Forbidden"),
		report: connect.DiagnosisReport{
			ConnectorID: "github-audit",
			Diagnosis: connect.Diagnosis{
				Known:      true,
				Summary:    "missing read:audit_log scope",
				Confidence: 0.95,
			},
		},
	}

	cfg := pipeline.Config{
		Connector: connector,
		Client:    &inference.DirectClient{BaseURL: "http://unused.invalid", Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
	}

	if _, err := pipeline.Run(context.Background(), cfg); err == nil {
		t.Fatalf("pipeline.Run over a Pull-failing connector returned nil error")
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 1 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want exactly 1", len(grants))
	}
	row := grants[0]
	if row.Connector != "github-audit" || row.FailureClass != "missing read:audit_log scope" {
		t.Errorf("row = %+v, want the classified miss recorded", row)
	}
	if row.DecisionKind != "" || row.BlastRadius != "" || row.Question != "" {
		t.Errorf("row = %+v, want NO E1 fields set for a Known:true diagnosis (it has a ranked remediation, not an operator ask)", row)
	}
}

// TestPipeline_MultiConnectorWrapped_DiagnosisStillReachesSubConnector is the
// pipeline-level proof for the veracity rework's Route 1 finding: in
// PRODUCTION cfg.Connector is never a bare Diagnosable — cli/scan.go's
// buildConnectors ALWAYS wraps every configured source in connect.Multi(...),
// even a single one (cli/scan.go:558) — so asserting connector.(Diagnosable)
// directly (the ORIGINAL, rejected implementation) silently finds nothing for
// exactly the connectors that have a doctor. This test drives pipeline.Run
// with the connector wrapped in the REAL production connect.Multi (not a
// second hand-rolled type) and proves the diagnosis still lands.
func TestPipeline_MultiConnectorWrapped_DiagnosisStillReachesSubConnector(t *testing.T) {
	st := newGitStore(t)

	sub := diagnosableConnector{
		pullErr: errors.New("azuresp: AADSTS700082: refresh token expired"),
		report: connect.DiagnosisReport{
			ConnectorID: "azure-sp-prod",
			Diagnosis: connect.Diagnosis{
				Known:      false,
				Summary:    "refresh token rejected by AAD for an unrecognized reason",
				Confidence: 0.3,
			},
		},
	}

	cfg := pipeline.Config{
		// The load-bearing difference from TestPipeline_DiagnoseUnknown_RaisesE1SecurityDecision:
		// the connector cfg.Connector actually holds is the composed
		// *connect.MultiConnector production shape, not the bare Diagnosable.
		Connector: connect.Multi(sub),
		Client:    &inference.DirectClient{BaseURL: "http://unused.invalid", Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
	}

	if _, err := pipeline.Run(context.Background(), cfg); err == nil {
		t.Fatalf("pipeline.Run over a Pull-failing Multi-wrapped connector returned nil error")
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 1 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want exactly 1 — the Multi wrapper must not swallow the sub-connector's diagnosis", len(grants))
	}
	if grants[0].Connector != "azure-sp-prod" {
		t.Errorf("row.Connector = %q, want %q", grants[0].Connector, "azure-sp-prod")
	}
	if grants[0].DecisionKind != "grant" {
		t.Errorf("row.DecisionKind = %q, want %q", grants[0].DecisionKind, "grant")
	}
}

// TestPipeline_SuccessfulPullConfirmsPriorGrantMiss is the pipeline-level
// proof for Route 2's write+read wiring: pipeline.Run itself — not a test
// calling RecordConfirmOutcome directly — is the real caller. A prior
// unresolved GRANT-MISS is seeded on the store for connector "azure-sp-prod";
// pipeline.Run is then driven with a Diagnosable connector whose Pull now
// SUCCEEDS and whose Diagnose comes back Known:true. Run must (a) read the
// grants stream (pendingGrantMiss) to discover the outstanding miss for this
// exact connector ID, (b) re-probe it, and (c) record a resolution row a
// subsequent scan (or pendingGrantMiss call) reads back as closed.
func TestPipeline_SuccessfulPullConfirmsPriorGrantMiss(t *testing.T) {
	st := newGitStore(t)

	missSHA, err := st.Append(store.KindGrants, missRow())
	if err != nil {
		t.Fatalf("Append(KindGrants) seed miss: %v", err)
	}

	connector := diagnosableConnector{
		// pullErr is nil: Pull succeeds this scan (the operator's fix worked).
		report: connect.DiagnosisReport{
			ConnectorID: "azure-sp-prod",
			Diagnosis:   connect.Diagnosis{Known: true, Summary: "credentials valid", Confidence: 0.95},
		},
	}

	cfg := pipeline.Config{
		Connector: connect.Multi(connector),
		Client:    &inference.DirectClient{BaseURL: "http://unused.invalid", Model: "test-model"},
		Store:     st,
		Baseline:  knownActorsBaseline(),
	}

	if _, err := pipeline.Run(context.Background(), cfg); err != nil {
		t.Fatalf("pipeline.Run over a now-healthy connector: %v", err)
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 2 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want 2 (seed miss + the resolution pipeline.Run itself must have written)", len(grants))
	}
	resolution := grants[1]
	if !resolution.Resolved || resolution.ResolvedRef != missSHA {
		t.Fatalf("resolution row = %+v, want Resolved=true ResolvedRef=%q — pipeline.Run must call RecordConfirmOutcome, not merely proceed silently", resolution, missSHA)
	}
	if resolution.Connector != "azure-sp-prod" || resolution.Cloud != "azure" || resolution.AccessMode != "read-only" {
		t.Fatalf("resolution row = %+v, want it to carry the ORIGINAL miss row's connector/cloud/access_mode", resolution)
	}

	// A subsequent scan's own pendingGrantMiss check (exercised indirectly:
	// running Run a SECOND time) must see the miss as already closed and
	// write nothing further — the idempotency the acceptance criterion
	// requires ("the next scan reads it").
	if _, err := pipeline.Run(context.Background(), cfg); err != nil {
		t.Fatalf("second pipeline.Run: %v", err)
	}
	grantsAfterSecondScan, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes after second scan: %v", lerr)
	}
	if len(grantsAfterSecondScan) != 2 {
		t.Fatalf("LoadGrantOutcomes after a SECOND scan over an already-resolved connector = %d records, want still 2 (idempotent, no duplicate resolution)", len(grantsAfterSecondScan))
	}
}

// TestRecordConfirmOutcome_ResolvedAppendsResolutionRow proves route 2's
// success path: a Confirm outcome with Resolved:true lands as a SECOND
// appended GrantOutcome row (never a mutation) with ResolvedRef pointing at
// the original miss row's real commit SHA — resolvable back through
// Store.ResolveGrantMiss, exactly like TestKindGrantsAppendAndLoadRoundTrip
// (core/store/grants_test.go) already proves for the store layer alone. This
// test proves the PIPELINE-LEVEL wiring drives that same mechanism correctly.
func TestRecordConfirmOutcome_ResolvedAppendsResolutionRow(t *testing.T) {
	st := newGitStore(t)

	missSHA, err := st.Append(store.KindGrants, missRow())
	if err != nil {
		t.Fatalf("Append(KindGrants) seed miss: %v", err)
	}

	checkedAt := time.Now().UTC()
	sha, appended, err := pipeline.RecordConfirmOutcome(st, missSHA, "azure-sp-prod", "azure", "read-only",
		connect.ConfirmResult{Resolved: true, CheckedAt: checkedAt, Diagnosis: connect.Diagnosis{Known: true, Summary: "resolved"}})
	if err != nil {
		t.Fatalf("RecordConfirmOutcome: %v", err)
	}
	if !appended {
		t.Fatalf("RecordConfirmOutcome appended = false on the FIRST confirm, want true")
	}
	if sha == "" {
		t.Fatalf("RecordConfirmOutcome returned an empty sha for a fresh resolution")
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 2 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want 2 (miss + resolution, never mutated in place)", len(grants))
	}
	if grants[0].Resolved {
		t.Errorf("original miss row mutated: %+v", grants[0])
	}
	if !grants[1].Resolved || grants[1].ResolvedRef != missSHA {
		t.Fatalf("resolution row = %+v, want Resolved=true ResolvedRef=%q", grants[1], missSHA)
	}

	// Prove resolvability, not just string round-tripping.
	resolved, rerr := st.ResolveGrantMiss(grants[1].ResolvedRef)
	if rerr != nil {
		t.Fatalf("ResolveGrantMiss(%q): %v", grants[1].ResolvedRef, rerr)
	}
	if resolved.Connector != "azure-sp-prod" {
		t.Fatalf("ResolveGrantMiss returned %+v, want the original miss row back", resolved)
	}
}

// TestRecordConfirmOutcome_IdempotentAcrossRescans proves the acceptance
// criterion directly: calling RecordConfirmOutcome twice for the SAME
// already-resolved miss must not create a second resolution row — a
// subsequent scan re-reading the store sees exactly one resolution, not a
// growing duplicate history.
func TestRecordConfirmOutcome_IdempotentAcrossRescans(t *testing.T) {
	st := newGitStore(t)

	missSHA, err := st.Append(store.KindGrants, missRow())
	if err != nil {
		t.Fatalf("Append(KindGrants) seed miss: %v", err)
	}

	result := connect.ConfirmResult{Resolved: true, CheckedAt: time.Now().UTC()}
	if _, appended, err := pipeline.RecordConfirmOutcome(st, missSHA, "azure-sp-prod", "azure", "read-only", result); err != nil || !appended {
		t.Fatalf("first RecordConfirmOutcome: appended=%v err=%v, want appended=true err=nil", appended, err)
	}

	// A "next scan" (or a second confirm) re-runs the exact same call.
	sha2, appended2, err := pipeline.RecordConfirmOutcome(st, missSHA, "azure-sp-prod", "azure", "read-only", result)
	if err != nil {
		t.Fatalf("second RecordConfirmOutcome: %v", err)
	}
	if appended2 {
		t.Fatalf("second RecordConfirmOutcome appended = true, want false (idempotent no-op for an already-resolved miss)")
	}
	if sha2 != "" {
		t.Errorf("second RecordConfirmOutcome sha = %q, want empty on a no-op", sha2)
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 2 {
		t.Fatalf("LoadGrantOutcomes returned %d records after a repeated confirm, want exactly 2 (miss + ONE resolution, no duplicate)", len(grants))
	}
}

// TestRecordConfirmOutcome_StillFailing_AppendsFreshMissNotResolution proves
// the b1f ConfirmResult doc's NEW-A19 case: a RemediationOption that
// "succeeded" but left Resolved:false is itself a fresh GRANT-MISS, never a
// resolution row.
func TestRecordConfirmOutcome_StillFailing_AppendsFreshMissNotResolution(t *testing.T) {
	st := newGitStore(t)

	missSHA, err := st.Append(store.KindGrants, missRow())
	if err != nil {
		t.Fatalf("Append(KindGrants) seed miss: %v", err)
	}

	result := connect.ConfirmResult{
		Resolved:  false,
		CheckedAt: time.Now().UTC(),
		Diagnosis: connect.Diagnosis{Known: false, Summary: "still failing after the applied fix", Confidence: 0.2},
	}
	sha, appended, err := pipeline.RecordConfirmOutcome(st, missSHA, "azure-sp-prod", "azure", "read-only", result)
	if err != nil {
		t.Fatalf("RecordConfirmOutcome: %v", err)
	}
	if !appended || sha == "" {
		t.Fatalf("RecordConfirmOutcome appended=%v sha=%q, want a fresh row appended", appended, sha)
	}

	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 2 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want 2 (original miss + a FRESH miss, not a resolution)", len(grants))
	}
	fresh := grants[1]
	if fresh.Resolved || fresh.ResolvedRef != "" {
		t.Fatalf("fresh row = %+v, want Resolved=false ResolvedRef=\"\" (still failing is a NEW miss, not a resolution)", fresh)
	}
	if fresh.DecisionKind != "grant" {
		t.Errorf("fresh row DecisionKind = %q, want %q — still-failing-and-unclassified is a fresh E1 ask too", fresh.DecisionKind, "grant")
	}
}
