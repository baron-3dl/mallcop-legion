package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// doctorFakeSibling is a tiny POSIX-sh --doctor-capable sibling connector,
// the SAME real shape connect/exec/exec_test.go's doctorSibling drives (not a
// hand-invented fake connector type): it reads its diagnosis state from a
// file named by $DOCTOR_STATE_FILE, so a test can flip "deficient" ->
// "healthy" between two invocations to simulate an operator having applied a
// remediation, WITHOUT restarting a process — exactly the two-call
// diagnose-then-confirm shape `mallcop doctor` drives.
const doctorFakeSibling = `#!/bin/sh
if [ "$1" != "--doctor" ]; then
  printf '%s\n' '{"id":"e1","source":"fake","type":"login"}'
  exit 0
fi
state=$(cat "$DOCTOR_STATE_FILE" 2>/dev/null || echo deficient)
if [ "$state" = "healthy" ]; then
  printf '%s\n' '{"diagnosis":{"known":true,"summary":"credentials valid","confidence":0.95}}'
else
  printf '%s\n' '{"diagnosis":{"known":true,"summary":"missing read:audit_log scope","confidence":0.9},"remediation":[{"command":"az role assignment create --assignee OID --role Reader --scope SCOPE","blast_radius":"Lets OID read metadata of every resource in the group.","known_issues":["PROPOSED BUT UNVERIFIED: mallcop CI eval has never proven this against a live account."],"dry_run":"az role assignment list --assignee OID --scope SCOPE -o table"}]}'
fi
`

// doctorHealthySibling is always healthy, no remediation ever ranked — proves
// the exit-0 / "nothing to remediate" branch independent of any --confirm flow.
const doctorHealthySibling = `#!/bin/sh
if [ "$1" = "--doctor" ]; then
  printf '%s\n' '{"diagnosis":{"known":true,"summary":"credentials valid","confidence":0.95}}'
  exit 0
fi
printf '%s\n' '{"id":"e1","source":"fake","type":"login"}'
`

func writeFakeSibling(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sh-script fake sibling is POSIX-only")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake sibling: %v", err)
	}
	return p
}

// writeDoctorConfig writes a mallcop.yaml naming ONE kind:cloud connector at
// binaryPath, storing at storePath — the SAME shape TestScanConfigOnly_
// ByteIdenticalToFlags (cli/scan_config_test.go) uses, so `mallcop doctor`'s
// config -> connector construction is proven against the identical
// buildConnectors() config-loading path `mallcop scan` uses, not a
// hand-rolled parallel one.
func writeDoctorConfig(t *testing.T, cfgPath, storePath, connectorID, binaryPath string) {
	t.Helper()
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
  endpoint: ""
  key_env: MALLCOP_API_KEY
  model: mallcop-default
store:
  path: `+storePath+`
  baseline: ""
connectors:
  - kind: cloud
    id: `+connectorID+`
    binary: `+binaryPath+`
    env: [DOCTOR_STATE_FILE]
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
`)
}

// TestRunDoctor_DiagnoseThenConfirm_RealStoreGitPath is the headline
// acceptance proof: `mallcop doctor <connector>` against a connect.Multi-
// wrapped, recorded-fixture-backed connect/exec.ExecConnector (the REAL
// production Diagnosable, driven exactly the shape cli/scan.go's
// buildConnectors() produces — connect.Multi wrapping subs, never a bare
// Diagnosable) —
//
//  1. prints the diagnosis + ranked remediation (blast-radius / dry-run /
//     staleness KnownIssues banner) and records a GRANT-MISS row through the
//     REAL git-backed store;
//  2. --json emits the structured DiagnosisReport (embedded verbatim, plus
//     grant_ref);
//  3. the exit code reflects deficient (errFindings) vs healthy (nil);
//  4. after a SIMULATED operator apply (flipping the fixture's state file to
//     healthy) and a --confirm run, a SECOND KindGrants row — a resolution
//     referencing the original grant_ref — exists, through the real
//     store.Append + git commit path (core/store, not a mock).
func TestRunDoctor_DiagnoseThenConfirm_RealStoreGitPath(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	writeFile(t, stateFile, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	bin := writeFakeSibling(t, dir, "doctor-sibling", doctorFakeSibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfig(t, cfgPath, storePath, "azure-prod", bin)

	// --- (1) Plain diagnose: connector is currently deficient. ---
	var out string
	var err error
	out = captureStdout(t, func() {
		err = runDoctor([]string{"azure-prod", "--config", cfgPath, "--json"})
	})
	if !isFindingsError(err) {
		t.Fatalf("runDoctor over a deficient connector: err = %v, want the errFindings sentinel", err)
	}

	var report doctorReport
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil {
		t.Fatalf("--json output did not parse as doctorReport: %v\noutput: %s", jerr, out)
	}
	if report.ConnectorID != "azure-prod" {
		t.Errorf("report.ConnectorID = %q, want %q", report.ConnectorID, "azure-prod")
	}
	if !report.Diagnosis.Known || report.Diagnosis.Summary != "missing read:audit_log scope" {
		t.Fatalf("report.Diagnosis = %+v, want the classified deficiency from the fixture", report.Diagnosis)
	}
	if len(report.Remediation) != 1 {
		t.Fatalf("report.Remediation = %+v, want exactly 1 ranked option", report.Remediation)
	}
	opt := report.Remediation[0]
	if opt.BlastRadius == "" {
		t.Error("remediation option has no BlastRadius — an operator cannot judge an ask with no blast-radius text")
	}
	if opt.DryRun == nil || *opt.DryRun == "" {
		t.Error("remediation option has no DryRun preview")
	}
	if len(opt.KnownIssues) == 0 || !strings.Contains(opt.KnownIssues[0], "PROPOSED BUT UNVERIFIED") {
		t.Errorf("remediation option KnownIssues = %v, want the staleness banner as the first note", opt.KnownIssues)
	}
	if report.GrantRef == "" {
		t.Fatal("report.GrantRef is empty — need it to drive --confirm")
	}
	grantRef := report.GrantRef

	// The row must exist on the REAL grants stream, through the real store
	// append+git-commit path (core/store.Store, not a mock).
	st, serr := store.Open(storePath)
	if serr != nil {
		t.Fatalf("store.Open: %v", serr)
	}
	grants, gerr := st.LoadGrantOutcomes()
	if gerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", gerr)
	}
	if len(grants) != 1 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want exactly 1 (the recorded diagnosis)", len(grants))
	}
	if grants[0].Connector != "azure-prod" || grants[0].Resolved {
		t.Fatalf("grants[0] = %+v, want a MISS row for azure-prod", grants[0])
	}
	if grants[0].FailureClass != "missing read:audit_log scope" {
		t.Errorf("grants[0].FailureClass = %q, want the diagnosis summary", grants[0].FailureClass)
	}

	// --- (2) Simulate the operator applying the printed remediation. ---
	writeFile(t, stateFile, "healthy")

	var confirmOut string
	var confirmErr error
	confirmOut = captureStdout(t, func() {
		confirmErr = runDoctor([]string{"azure-prod", "--config", cfgPath, "--json", "--confirm", grantRef})
	})
	if confirmErr != nil {
		t.Fatalf("runDoctor --confirm after a successful fix: err = %v, want nil", confirmErr)
	}

	var confirmReport doctorConfirmReport
	if jerr := json.Unmarshal([]byte(confirmOut), &confirmReport); jerr != nil {
		t.Fatalf("--confirm --json output did not parse: %v\noutput: %s", jerr, confirmOut)
	}
	if !confirmReport.Resolved {
		t.Fatalf("confirmReport.Resolved = false, want true (the connector is now healthy)")
	}
	if confirmReport.Diagnosis.Summary != "credentials valid" {
		t.Errorf("confirmReport.Diagnosis.Summary = %q, want the re-probed healthy diagnosis", confirmReport.Diagnosis.Summary)
	}

	grantsAfterConfirm, gerr2 := st.LoadGrantOutcomes()
	if gerr2 != nil {
		t.Fatalf("LoadGrantOutcomes after confirm: %v", gerr2)
	}
	if len(grantsAfterConfirm) != 2 {
		t.Fatalf("LoadGrantOutcomes after confirm returned %d records, want 2 (original miss + resolution)", len(grantsAfterConfirm))
	}
	resolutionRow := grantsAfterConfirm[1]
	if !resolutionRow.Resolved || resolutionRow.ResolvedRef != grantRef {
		t.Fatalf("resolution row = %+v, want Resolved=true ResolvedRef=%q", resolutionRow, grantRef)
	}
	if resolutionRow.Connector != "azure-prod" {
		t.Errorf("resolution row Connector = %q, want %q", resolutionRow.Connector, "azure-prod")
	}

	// Resolvability, not just string round-tripping: ResolveGrantMiss must read
	// the ORIGINAL miss row back from the resolution's own ResolvedRef.
	resolved, rerr := st.ResolveGrantMiss(resolutionRow.ResolvedRef)
	if rerr != nil {
		t.Fatalf("ResolveGrantMiss(%q): %v", resolutionRow.ResolvedRef, rerr)
	}
	if resolved.Connector != "azure-prod" || resolved.FailureClass != "missing read:audit_log scope" {
		t.Fatalf("ResolveGrantMiss returned %+v, want the original miss row back", resolved)
	}
}

// TestRunDoctor_HealthyConnector_ExitZeroNoRemediation proves the standalone
// healthy path (no prior miss, no --confirm involved): Known:true with zero
// ranked remediation options is the kernel's own definition of "nothing to
// fix" (core/connect/diagnose.go's Remediation doc comment), and `mallcop
// doctor` must exit 0 for it, not the errFindings sentinel.
func TestRunDoctor_HealthyConnector_ExitZeroNoRemediation(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeSibling(t, dir, "doctor-sibling-healthy", doctorHealthySibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfig(t, cfgPath, storePath, "gcp-prod", bin)

	var err error
	out := captureStdout(t, func() {
		err = runDoctor([]string{"gcp-prod", "--config", cfgPath})
	})
	if err != nil {
		t.Fatalf("runDoctor over a healthy connector: err = %v, want nil", err)
	}
	if !strings.Contains(out, "HEALTHY") {
		t.Errorf("human-readable output = %q, want it to say HEALTHY", out)
	}

	st, serr := store.Open(storePath)
	if serr != nil {
		t.Fatalf("store.Open: %v", serr)
	}
	grants, gerr := st.LoadGrantOutcomes()
	if gerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", gerr)
	}
	if len(grants) != 1 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want 1 (a healthy status is still recorded history)", len(grants))
	}
}

// TestRunDoctor_UnknownConnector_ErrorsNamingConfigured proves the not-found
// path names which connectors DO support self-diagnosis, rather than a bare
// "not found".
func TestRunDoctor_UnknownConnector_ErrorsNamingConfigured(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeSibling(t, dir, "doctor-sibling", doctorHealthySibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfig(t, cfgPath, storePath, "azure-prod", bin)

	err := runDoctor([]string{"nonexistent-connector", "--config", cfgPath})
	if err == nil {
		t.Fatal("runDoctor over an unconfigured connector id returned nil, want an error")
	}
	if !strings.Contains(err.Error(), "azure-prod") {
		t.Errorf("error = %v, want it to name the configured connector(s)", err)
	}
}

// TestRunDoctor_NoConnectorsConfigured_Errors proves the guard: `mallcop
// doctor` refuses to run with no mallcop.yaml connectors: list to resolve
// against, rather than silently doing nothing.
func TestRunDoctor_NoConnectorsConfigured_Errors(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
  endpoint: ""
  key_env: MALLCOP_API_KEY
  model: mallcop-default
store:
  path: `+storePath+`
  baseline: ""
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
`)

	err := runDoctor([]string{"azure-prod", "--config", cfgPath})
	if err == nil {
		t.Fatal("runDoctor with no configured connectors returned nil, want an error")
	}
}

// --- Unit tests for the routing/presentation helpers (no process, no store) ---

// unitDiagnosable is a hand-rolled connect.Diagnosable/Connector double used
// ONLY to unit-test findDiagnosable's ROUTING logic (which sub-connector, by
// ID, among several wrapped in a real connect.Multi) — never to stand in for
// the doctor's primary diagnose/confirm workflow, which
// TestRunDoctor_DiagnoseThenConfirm_RealStoreGitPath above exercises through
// the real connect/exec.ExecConnector + real store + real git commit path.
type unitDiagnosable struct {
	id     string
	report connect.DiagnosisReport
}

func (u unitDiagnosable) Pull(_ context.Context) ([]event.Event, error) { return nil, nil }
func (u unitDiagnosable) ID() string                                    { return u.id }
func (u unitDiagnosable) Diagnose(_ context.Context) (connect.DiagnosisReport, error) {
	return u.report, nil
}

var (
	_ connect.Connector   = unitDiagnosable{}
	_ connect.Diagnosable = unitDiagnosable{}
)

// TestFindDiagnosable_MultiWrapped_FindsSubConnectorByID proves findDiagnosable
// reaches into a REAL connect.Multi(...) composition (the shape buildConnectors
// always returns, core/connect/multi.go's Diagnosables()) and selects the one
// sub-connector whose ID matches, among several.
func TestFindDiagnosable_MultiWrapped_FindsSubConnectorByID(t *testing.T) {
	a := unitDiagnosable{id: "aws-prod", report: connect.DiagnosisReport{ConnectorID: "aws-prod"}}
	b := unitDiagnosable{id: "azure-prod", report: connect.DiagnosisReport{ConnectorID: "azure-prod"}}
	multi := connect.Multi(a, b)

	got, err := findDiagnosable(multi, "azure-prod")
	if err != nil {
		t.Fatalf("findDiagnosable: %v", err)
	}
	if got.ID() != "azure-prod" {
		t.Errorf("findDiagnosable returned ID %q, want %q", got.ID(), "azure-prod")
	}
}

// TestFindDiagnosable_UnknownID_NamesConfiguredConnectors proves the
// not-found error names every connector that DOES support self-diagnosis.
func TestFindDiagnosable_UnknownID_NamesConfiguredConnectors(t *testing.T) {
	a := unitDiagnosable{id: "aws-prod"}
	multi := connect.Multi(a)

	_, err := findDiagnosable(multi, "nonexistent")
	if err == nil {
		t.Fatal("findDiagnosable over an unknown id returned nil error")
	}
	if !strings.Contains(err.Error(), "aws-prod") {
		t.Errorf("error = %v, want it to name aws-prod", err)
	}
}

func TestDiagnosisDeficient(t *testing.T) {
	cases := []struct {
		name string
		r    connect.DiagnosisReport
		want bool
	}{
		{"unknown_is_deficient", connect.DiagnosisReport{Diagnosis: connect.Diagnosis{Known: false}}, true},
		{"known_with_remediation_is_deficient", connect.DiagnosisReport{
			Diagnosis:   connect.Diagnosis{Known: true},
			Remediation: []connect.RemediationOption{{Command: "x"}},
		}, true},
		{"known_no_remediation_is_healthy", connect.DiagnosisReport{Diagnosis: connect.Diagnosis{Known: true}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := diagnosisDeficient(tc.r); got != tc.want {
				t.Errorf("diagnosisDeficient(%+v) = %v, want %v", tc.r, got, tc.want)
			}
		})
	}
}
