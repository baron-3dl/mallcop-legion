package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
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
elif [ "$state" = "still_deficient" ]; then
  printf '%s\n' '{"diagnosis":{"known":false,"summary":"still missing read:audit_log scope after applied fix","confidence":0.4}}'
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

// captureStdoutStderr is captureStdout (cli/status_test.go) plus a second
// redirect for os.Stderr into stderrBuf -- needed here because diagnoseAll's
// honest-omission warning (cli/doctor.go) is written to os.Stderr, not
// returned as part of the captured stdout JSON.
func captureStdoutStderr(t *testing.T, stderrBuf *bytes.Buffer, fn func()) string {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe (stdout): %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe (stderr): %v", err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	fn()
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	var outBuf bytes.Buffer
	io.Copy(&outBuf, rOut)
	io.Copy(stderrBuf, rErr)
	return outBuf.String()
}

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

// writeDoctorConfigMulti writes a mallcop.yaml naming several connectors: one
// kind:file connector (id "local-events", the NON-diagnosable kind — proves
// "a connector with no doctor support is skipped without failing the job")
// plus one kind:cloud connector per (id, binaryPath) pair in clouds.
func writeDoctorConfigMulti(t *testing.T, cfgPath, storePath string, clouds map[string]string) {
	t.Helper()
	body := `version: 1
inference:
  mode: offline
  endpoint: ""
  key_env: MALLCOP_API_KEY
  model: mallcop-default
store:
  path: ` + storePath + `
  baseline: ""
connectors:
  - kind: file
    id: local-events
    path: ` + filepath.Join(filepath.Dir(cfgPath), "events.jsonl") + `
`
	for id, bin := range clouds {
		body += `  - kind: cloud
    id: ` + id + `
    binary: ` + bin + `
`
	}
	body += `detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
`
	writeFile(t, cfgPath, body)
}

// TestRunDoctorAll_MixedConnectors_RealConfigRealSubprocess is the mallcoppro-62c
// headline acceptance proof for the aggregate form: against a REAL mallcop.yaml
// naming a non-diagnosable kind:file connector plus two REAL kind:cloud
// connectors (connect/exec.ExecConnector forking the real doctorFakeSibling /
// doctorHealthySibling scripts as subprocesses — the exact production shape
// buildConnectors() produces, not a hand-rolled Diagnosable stand-in),
// `mallcop doctor --all --json`:
//
//  1. emits an array with exactly ONE entry per DIAGNOSABLE connector (2, not
//     3 — the file connector never appears: "skipped without failing the job");
//  2. the array carries the real deficient diagnosis (with ranked remediation)
//     for one connector and the real healthy diagnosis for the other,
//     produced by two independently-invoked live subprocesses;
//  3. exits with the errFindings sentinel because at least one connector is
//     deficient (mirrors the single-connector form's own convention).
func TestRunDoctorAll_MixedConnectors_RealConfigRealSubprocess(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	writeFile(t, stateFile, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	deficientBin := writeFakeSibling(t, dir, "deficient-sibling", doctorFakeSibling)
	healthyBin := writeFakeSibling(t, dir, "healthy-sibling", doctorHealthySibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfigMulti(t, cfgPath, storePath, map[string]string{
		"azure-prod": deficientBin,
		"gcp-prod":   healthyBin,
	})

	var err error
	out := captureStdout(t, func() {
		err = runDoctor([]string{"--all", "--config", cfgPath, "--json"})
	})
	if !isFindingsError(err) {
		t.Fatalf("runDoctor --all with one deficient connector: err = %v, want the errFindings sentinel", err)
	}

	var reports []connect.DiagnosisReport
	if jerr := json.Unmarshal([]byte(out), &reports); jerr != nil {
		t.Fatalf("--all --json output did not parse as []DiagnosisReport: %v\noutput: %s", jerr, out)
	}
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want exactly 2 (one per DIAGNOSABLE connector — the kind:file connector must be absent, not fabricated): %+v", len(reports), reports)
	}

	byID := make(map[string]connect.DiagnosisReport, len(reports))
	for _, r := range reports {
		byID[r.ConnectorID] = r
	}
	if _, ok := byID["local-events"]; ok {
		t.Fatalf("the non-diagnosable kind:file connector must be absent from doctor.json, not present with a fabricated entry: %+v", reports)
	}
	deficient, ok := byID["azure-prod"]
	if !ok {
		t.Fatalf("azure-prod missing from reports: %+v", reports)
	}
	if !deficient.Diagnosis.Known || deficient.Diagnosis.Summary != "missing read:audit_log scope" || len(deficient.Remediation) != 1 {
		t.Fatalf("azure-prod report = %+v, want the classified deficiency with 1 ranked remediation from the fixture", deficient)
	}
	healthy, ok := byID["gcp-prod"]
	if !ok {
		t.Fatalf("gcp-prod missing from reports: %+v", reports)
	}
	if !healthy.Diagnosis.Known || len(healthy.Remediation) != 0 {
		t.Fatalf("gcp-prod report = %+v, want a healthy classified diagnosis with no remediation", healthy)
	}

	// --all must NEVER record to the grants stream (unlike the single-connector
	// form): doctor.json is an observability snapshot, not the interactive
	// remediation loop, and recording every scheduled run would flood the
	// grants stream with steady-state noise. The strongest proof of that is
	// that --all never even opens/inits the store (unlike runDoctor's plain
	// form, which calls openOrInitStore before anything else) -- so
	// storePath must not exist as a git repo at all after this run.
	if _, statErr := os.Stat(filepath.Join(storePath, ".git")); statErr == nil {
		t.Fatalf("storePath %q was initialized as a git repo -- 'doctor --all' must not touch the store at all, let alone write to the grants stream", storePath)
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("unexpected error stat'ing store path: %v", statErr)
	}
}

// TestRunDoctorAll_AllHealthy_ExitZero proves the all-healthy path exits 0
// (no errFindings) and still emits a well-formed JSON array, not merely the
// "at least one deficient" path above.
func TestRunDoctorAll_AllHealthy_ExitZero(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeSibling(t, dir, "healthy-sibling", doctorHealthySibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfigMulti(t, cfgPath, storePath, map[string]string{"gcp-prod": bin})

	var err error
	out := captureStdout(t, func() {
		err = runDoctor([]string{"--all", "--config", cfgPath, "--json"})
	})
	if err != nil {
		t.Fatalf("runDoctor --all, all healthy: err = %v, want nil", err)
	}
	var reports []connect.DiagnosisReport
	if jerr := json.Unmarshal([]byte(out), &reports); jerr != nil {
		t.Fatalf("--all --json output did not parse: %v\noutput: %s", jerr, out)
	}
	if len(reports) != 1 || reports[0].ConnectorID != "gcp-prod" {
		t.Fatalf("reports = %+v, want exactly 1 entry for gcp-prod", reports)
	}
}

// TestRunDoctorAll_NoConnectorsSupportDiagnosis_EmptyArrayNotFailure proves
// the degenerate case — a config with only non-diagnosable connectors —
// still emits a well-formed EMPTY array (never null, never a hard failure):
// "a scan must not die because one connector lacks a doctor" generalizes to
// "...or because NONE of them do."
func TestRunDoctorAll_NoConnectorsSupportDiagnosis_EmptyArrayNotFailure(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfigMulti(t, cfgPath, storePath, nil)

	var err error
	out := captureStdout(t, func() {
		err = runDoctor([]string{"--all", "--config", cfgPath, "--json"})
	})
	if err != nil {
		t.Fatalf("runDoctor --all with no diagnosable connectors: err = %v, want nil", err)
	}
	if strings.TrimSpace(out) != "[]" {
		t.Fatalf("output = %q, want a bare empty JSON array", out)
	}
}

// TestRunDoctorAll_UnconfiguredCloudConnector_OmittedAndReported_RealPath is
// the veracity-required real-path proof: a real mallcop.yaml naming a
// kind:cloud connector that is ID-ONLY -- neither `binary:` nor `source:` set
// -- alongside a healthy sibling. core/config's validate() does not require
// either field, so this config passes LoadEffective, and buildConnectors
// (cli/scan.go) constructs the ExecConnector for it unconditionally. Its real
// Diagnose call (connect/exec/exec.go's binaryName()) therefore returns a
// genuine non-nil error ("connector %q has neither binary nor source set"),
// driving the SAME runDoctorAll/diagnoseAll/doctor.json path
// TestRunDoctorAll_MixedConnectors_RealConfigRealSubprocess exercises for the
// mixed deficient/healthy case above -- no diagnoseAllFake double anywhere in
// this test. This is the case the veracity adversary demonstrated reachable
// from an ordinary config and the prior version of this file only proved via
// a hand-rolled Diagnosable fake (diagnoseAllFake, below), never through
// runDoctorAll/CLI/doctor.json itself.
//
// Asserts, at the doctor.json/CLI level:
//  1. the healthy sibling appears in the array;
//  2. the broken connector does NOT appear -- neither fabricated nor
//     present with a healthy-looking Known:true/no-remediation entry;
//  3. the omission is REPORTED on stderr (naming the connector and the real
//     "neither binary nor source set" error), not silently dropped;
//  4. runDoctor's process-level exit code reflects anyError via errFindings,
//     matching the single-error-path convention diagnoseAll already defines.
func TestRunDoctorAll_UnconfiguredCloudConnector_OmittedAndReported_RealPath(t *testing.T) {
	dir := t.TempDir()
	healthyBin := writeFakeSibling(t, dir, "healthy-sibling", doctorHealthySibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")

	// Hand-written (not writeDoctorConfigMulti, which always sets `binary:`):
	// "broken-conn" deliberately sets neither binary nor source.
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
    id: broken-conn
  - kind: cloud
    id: healthy-conn
    binary: `+healthyBin+`
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
`)

	// Confirm this config actually passes validation/loading -- the whole
	// point of the finding is that this is an ORDINARY reachable config, not
	// a hand-crafted invalid one.
	if _, _, cerr := config.LoadEffective(cfgPath); cerr != nil {
		t.Fatalf("config.LoadEffective on an id-only kind:cloud connector: %v, want nil (validate() does not require binary/source)", cerr)
	}

	var stderr bytes.Buffer
	var out string
	var err error
	out = captureStdoutStderr(t, &stderr, func() {
		err = runDoctor([]string{"--all", "--config", cfgPath, "--json"})
	})
	if !isFindingsError(err) {
		t.Fatalf("runDoctor --all with one connector whose Diagnose call errors: err = %v, want the errFindings sentinel", err)
	}

	var reports []connect.DiagnosisReport
	if jerr := json.Unmarshal([]byte(out), &reports); jerr != nil {
		t.Fatalf("--all --json output did not parse as []DiagnosisReport: %v\noutput: %s", jerr, out)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want exactly 1 (only healthy-conn; broken-conn's real Diagnose error must omit it, not fabricate an entry): %+v", len(reports), reports)
	}
	if reports[0].ConnectorID != "healthy-conn" {
		t.Fatalf("reports[0].ConnectorID = %q, want %q", reports[0].ConnectorID, "healthy-conn")
	}
	for _, r := range reports {
		if r.ConnectorID == "broken-conn" {
			t.Fatalf("broken-conn must NOT appear in doctor.json at all -- fabricated or healthy-looking -- got: %+v", reports)
		}
	}

	// The omission must be REPORTED, not silent: stderr names the connector
	// and carries the real config-shape error, not a synthetic message.
	stderrOut := stderr.String()
	if !strings.Contains(stderrOut, "broken-conn") {
		t.Fatalf("stderr = %q, want it to name broken-conn as the omitted connector", stderrOut)
	}
	if !strings.Contains(stderrOut, "neither binary nor source set") {
		t.Fatalf("stderr = %q, want it to carry the real binaryName() error explaining WHY broken-conn was never diagnosed", stderrOut)
	}

	// Confirm a reader of doctor.json genuinely cannot mistake "never
	// diagnosed" for "healthy": broken-conn is absent from the array entirely
	// (proven above), and the ONLY entry present (healthy-conn) is the real
	// classified healthy diagnosis, not a placeholder standing in for
	// broken-conn.
	if !reports[0].Diagnosis.Known || len(reports[0].Remediation) != 0 {
		t.Fatalf("reports[0] = %+v, want the real healthy classified diagnosis for healthy-conn", reports[0])
	}
}

// diagnoseAllFake is a minimal connect.Diagnosable test double used ONLY by
// TestDiagnoseAll_OneConnectorErrors below, to force a genuine Diagnose
// error deterministically. This is necessary because the REAL production
// Diagnosable (connect/exec.ExecConnector, exercised end-to-end by
// TestRunDoctorAll_MixedConnectors_RealConfigRealSubprocess above) is
// documented to almost NEVER return a non-nil error from Diagnose — a
// missing sibling binary, a sibling with no --doctor support, non-JSON
// output, or a subprocess timeout are ALL folded into a Known:false
// DiagnosisReport with a nil error (see connect/exec/exec.go's Diagnose doc);
// only a pre-flight ctx cancellation surfaces a real error, and forcing that
// through the CLI would cancel every connector's call uniformly, which
// cannot distinguish "some succeeded, one errored" from "all errored". A
// fake implementing the two-method Diagnosable interface directly is the
// only way to prove the omit-on-error / continue-past-one-failure branch
// against a MIX of successes and one failure.
type diagnoseAllFake struct {
	id     string
	report connect.DiagnosisReport
	err    error
}

func (f diagnoseAllFake) ID() string { return f.id }
func (f diagnoseAllFake) Diagnose(context.Context) (connect.DiagnosisReport, error) {
	return f.report, f.err
}

// TestDiagnoseAll_OneConnectorErrors_OmittedNotFabricated is a unit test on
// diagnoseAll (the pure aggregation helper runDoctorAll wraps): with 3 fake
// Diagnosables — one erroring, one healthy, one deficient — the erroring one
// must be OMITTED from the returned reports (never a fabricated placeholder
// entry, per the item's anti-lie contract), the warning must be written to
// errW, and both anyError and anyDeficient must be true.
func TestDiagnoseAll_OneConnectorErrors_OmittedNotFabricated(t *testing.T) {
	healthy := connect.DiagnosisReport{ConnectorID: "healthy-conn", Diagnosis: connect.Diagnosis{Known: true, Summary: "ok", Confidence: 1}}
	deficient := connect.DiagnosisReport{ConnectorID: "deficient-conn", Diagnosis: connect.Diagnosis{Known: true, Summary: "missing scope", Confidence: 0.8}, Remediation: []connect.RemediationOption{{Command: "fix it", BlastRadius: "reads metadata"}}}

	diags := []connect.Diagnosable{
		diagnoseAllFake{id: "erroring-conn", err: fmt.Errorf("boom: probe transport unreachable")},
		diagnoseAllFake{id: "healthy-conn", report: healthy},
		diagnoseAllFake{id: "deficient-conn", report: deficient},
	}

	var errBuf bytes.Buffer
	reports, anyDeficient, anyError := diagnoseAll(context.Background(), diags, &errBuf)

	if len(reports) != 2 {
		t.Fatalf("reports = %+v, want exactly 2 (erroring-conn must be omitted, not fabricated)", reports)
	}
	for _, r := range reports {
		if r.ConnectorID == "erroring-conn" {
			t.Fatalf("erroring-conn must NOT appear in reports at all: %+v", reports)
		}
	}
	if !anyError {
		t.Error("anyError = false, want true (one connector's Diagnose call returned an error)")
	}
	if !anyDeficient {
		t.Error("anyDeficient = false, want true (deficient-conn is present and deficient)")
	}
	if !strings.Contains(errBuf.String(), "erroring-conn") || !strings.Contains(errBuf.String(), "boom: probe transport unreachable") {
		t.Fatalf("errW = %q, want it to name the omitted connector and the underlying error (honest reporting, not silent)", errBuf.String())
	}
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

// TestRunDoctor_HumanReadableDiagnose_RendersRankedRemediation is the actual
// proof of this item's literal first acceptance clause — "`mallcop doctor
// <connector>` PRINTS the diagnosis plus ranked grants with blast-radius /
// dry-run / staleness" — against the HUMAN-READABLE renderer
// (printDiagnosisReport, cli/doctor.go's ranked-remediation loop), not the
// --json payload. TestRunDoctor_DiagnoseThenConfirm_RealStoreGitPath above
// only asserts the JSON shape; this test is the one that would catch a
// deleted KnownIssues loop or a deleted DryRun line in the human renderer.
func TestRunDoctor_HumanReadableDiagnose_RendersRankedRemediation(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	writeFile(t, stateFile, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	bin := writeFakeSibling(t, dir, "doctor-sibling", doctorFakeSibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfig(t, cfgPath, storePath, "azure-prod", bin)

	var err error
	out := captureStdout(t, func() {
		err = runDoctor([]string{"azure-prod", "--config", cfgPath})
	})
	if !isFindingsError(err) {
		t.Fatalf("runDoctor (human-readable) over a deficient connector: err = %v, want the errFindings sentinel", err)
	}

	const wantCommand = "az role assignment create --assignee OID --role Reader --scope SCOPE"
	if !strings.Contains(out, wantCommand) {
		t.Errorf("human-readable output missing the ranked remediation command %q\noutput:\n%s", wantCommand, out)
	}
	if !strings.Contains(out, "Blast radius:") || !strings.Contains(out, "Lets OID read metadata of every resource in the group.") {
		t.Errorf("human-readable output missing the Blast radius line\noutput:\n%s", out)
	}
	const wantDryRun = "az role assignment list --assignee OID --scope SCOPE -o table"
	if !strings.Contains(out, "Dry run:") || !strings.Contains(out, wantDryRun) {
		t.Errorf("human-readable output missing the Dry run preview %q\noutput:\n%s", wantDryRun, out)
	}
	if !strings.Contains(out, "Note:") || !strings.Contains(out, "PROPOSED BUT UNVERIFIED") {
		t.Errorf("human-readable output missing the staleness KnownIssues banner\noutput:\n%s", out)
	}
}

// TestRunDoctor_Confirm_StillDeficient_HumanReadableAndFreshMissRow covers
// printConfirmResult's STILL DEFICIENT branch (human-readable renderer) and
// the NEW-A19 fresh-miss row it records: an operator applies a fix that does
// NOT resolve the deficiency (the fixture's state file is left "deficient"),
// re-probes via --confirm, and both the printed "STILL DEFICIENT" line and a
// SECOND unresolved grants row (not a resolution referencing the original)
// must exist through the real git-backed store.
func TestRunDoctor_Confirm_StillDeficient_HumanReadableAndFreshMissRow(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	writeFile(t, stateFile, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	bin := writeFakeSibling(t, dir, "doctor-sibling", doctorFakeSibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfig(t, cfgPath, storePath, "azure-prod", bin)

	var jsonErr error
	jsonOut := captureStdout(t, func() {
		jsonErr = runDoctor([]string{"azure-prod", "--config", cfgPath, "--json"})
	})
	if !isFindingsError(jsonErr) {
		t.Fatalf("runDoctor initial diagnose: err = %v, want errFindings", jsonErr)
	}
	var report doctorReport
	if jerr := json.Unmarshal([]byte(jsonOut), &report); jerr != nil {
		t.Fatalf("--json output did not parse: %v\noutput: %s", jerr, jsonOut)
	}
	grantRef := report.GrantRef
	if grantRef == "" {
		t.Fatal("report.GrantRef is empty")
	}

	// The operator's applied fix did NOT work — flip the fixture to the
	// "still_deficient" state (Known:false: the re-probe can no longer even
	// classify it, the kernel's own NEW-A19 fresh-miss case) and re-probe via
	// --confirm, human-readable (no --json).
	writeFile(t, stateFile, "still_deficient")

	var confirmErr error
	confirmOut := captureStdout(t, func() {
		confirmErr = runDoctor([]string{"azure-prod", "--config", cfgPath, "--confirm", grantRef})
	})
	if !isFindingsError(confirmErr) {
		t.Fatalf("runDoctor --confirm still-deficient: err = %v, want errFindings", confirmErr)
	}
	if !strings.Contains(confirmOut, "STILL DEFICIENT") {
		t.Errorf("human-readable --confirm output missing STILL DEFICIENT\noutput:\n%s", confirmOut)
	}
	if !strings.Contains(confirmOut, "still missing read:audit_log scope after applied fix") {
		t.Errorf("human-readable --confirm output missing the re-probed diagnosis summary\noutput:\n%s", confirmOut)
	}
	if !strings.Contains(confirmOut, "fresh miss") {
		t.Errorf("human-readable --confirm output missing the fresh-miss framing of its own grant ref\noutput:\n%s", confirmOut)
	}

	st, serr := store.Open(storePath)
	if serr != nil {
		t.Fatalf("store.Open: %v", serr)
	}
	grants, gerr := st.LoadGrantOutcomes()
	if gerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", gerr)
	}
	if len(grants) != 2 {
		t.Fatalf("LoadGrantOutcomes after a still-deficient confirm returned %d records, want 2 (original miss + NEW-A19 fresh miss)", len(grants))
	}
	freshMiss := grants[1]
	if freshMiss.Resolved {
		t.Fatalf("freshMiss = %+v, want Resolved=false (a fresh miss, not a resolution)", freshMiss)
	}
	if freshMiss.Connector != "azure-prod" || freshMiss.FailureClass != "still missing read:audit_log scope after applied fix" {
		t.Errorf("freshMiss = %+v, want connector=azure-prod failure_class=%q", freshMiss, "still missing read:audit_log scope after applied fix")
	}
}

// TestRunDoctor_Confirm_KnownTrueWithRemediation_NotResolved_RealStoreGitPath
// is the mallcoppro-3fd9 regression proof: the re-probe --confirm drives
// lands on Known:true WITH a non-empty Remediation ladder still ranked — the
// EXACT shape the Azure doctor's defWrongPrincipal/defTokenExpired/
// defARMAuthorizationFailed/defResourceContextMode/defMissingWorkspaceGrant
// branches all produce, and this file's own diagnosisDeficient defines as
// STILL DEFICIENT (Known:true does not by itself mean healthy). The
// fixture's default/"deficient" state (doctorFakeSibling's else branch)
// already returns exactly that report shape, so this test simply leaves the
// state file UNCHANGED across the diagnose -> confirm calls (no operator fix
// simulated at all) and re-probes: the connector is REPORTING the identical
// still-deficient diagnosis it started with.
//
// runDoctorConfirm must:
//  1. NOT report Resolved (result.Resolved == false / "STILL DEFICIENT",
//     never "RESOLVED");
//  2. exit non-nil (the errFindings sentinel), never 0;
//  3. append a FRESH miss row to the real grants stream (Resolved=false),
//     never a resolution row (Resolved=true referencing the original
//     grant_ref) — a false resolution would corrupt the durable security
//     record and end the investigation the operator still needs to run.
//
// This test BITES: reverting runDoctorConfirm's Resolved computation from
// `!diagnosisDeficient(report)` back to the original `report.Diagnosis.Known`
// turns it red — confirmed by hand before restoring the fix (see
// test_decisions in this item's result).
func TestRunDoctor_Confirm_KnownTrueWithRemediation_NotResolved_RealStoreGitPath(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state")
	writeFile(t, stateFile, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	bin := writeFakeSibling(t, dir, "doctor-sibling", doctorFakeSibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeDoctorConfig(t, cfgPath, storePath, "azure-prod", bin)

	var jsonErr error
	jsonOut := captureStdout(t, func() {
		jsonErr = runDoctor([]string{"azure-prod", "--config", cfgPath, "--json"})
	})
	if !isFindingsError(jsonErr) {
		t.Fatalf("runDoctor initial diagnose: err = %v, want errFindings", jsonErr)
	}
	var report doctorReport
	if jerr := json.Unmarshal([]byte(jsonOut), &report); jerr != nil {
		t.Fatalf("--json output did not parse: %v\noutput: %s", jerr, jsonOut)
	}
	if !report.Diagnosis.Known || len(report.Remediation) == 0 {
		t.Fatalf("initial report = %+v, want Known:true with a non-empty Remediation ladder (the shape this regression covers)", report.DiagnosisReport)
	}
	grantRef := report.GrantRef
	if grantRef == "" {
		t.Fatal("report.GrantRef is empty")
	}

	// NO operator fix simulated: the state file is left exactly as it was.
	// The re-probe --confirm drives will land on the IDENTICAL Known:true +
	// non-empty-Remediation report as the initial diagnose.
	var confirmErr error
	confirmOut := captureStdout(t, func() {
		confirmErr = runDoctor([]string{"azure-prod", "--config", cfgPath, "--json", "--confirm", grantRef})
	})
	if !isFindingsError(confirmErr) {
		t.Fatalf("runDoctor --confirm over a re-probe still carrying a ranked Remediation: err = %v, want the errFindings sentinel (never nil/exit-0)", confirmErr)
	}

	var confirmReport doctorConfirmReport
	if jerr := json.Unmarshal([]byte(confirmOut), &confirmReport); jerr != nil {
		t.Fatalf("--confirm --json output did not parse: %v\noutput: %s", jerr, confirmOut)
	}
	if confirmReport.Resolved {
		t.Fatalf("confirmReport.Resolved = true, want false — Known:true with a non-empty Remediation ladder is STILL DEFICIENT, not resolved (mallcoppro-3fd9: this is the false-resolution defect)")
	}
	if len(confirmReport.Remediation) == 0 {
		t.Fatalf("confirmReport.Remediation = %+v, want the re-probe's ladder still present (proving this is genuinely the Known:true+remediation branch, not Known:false)", confirmReport.Remediation)
	}

	st, serr := store.Open(storePath)
	if serr != nil {
		t.Fatalf("store.Open: %v", serr)
	}
	grants, gerr := st.LoadGrantOutcomes()
	if gerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", gerr)
	}
	if len(grants) != 2 {
		t.Fatalf("LoadGrantOutcomes after this confirm returned %d records, want 2 (original miss + a FRESH miss)", len(grants))
	}
	row := grants[1]
	if row.Resolved {
		t.Fatalf("second grants row = %+v, want Resolved=false — recording Resolved=true here is exactly the false-resolution bug mallcoppro-3fd9 fixes: it would tell the operator the grant problem is fixed when the connector still has a ranked remediation to apply", row)
	}
	if row.ResolvedRef != "" {
		t.Fatalf("second grants row = %+v, want ResolvedRef empty — a fresh miss carries no resolved-ref, only an actual resolution row does", row)
	}
	if row.Connector != "azure-prod" {
		t.Errorf("second grants row Connector = %q, want %q", row.Connector, "azure-prod")
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
