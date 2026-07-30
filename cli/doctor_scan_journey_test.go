package cli

// doctor_scan_journey_test.go is the mallcoppro-d6c capstone: it proves the
// CLOSED DIAGNOSIS LOOP — diagnose -> emit -> apply -> confirm -> persist —
// COMPOSES end to end, not merely that each stage passes in isolation.
//
// Every stage already has its own test:
//   - TestRunDoctor_DiagnoseThenConfirm_RealStoreGitPath (doctor_test.go)
//     proves diagnose->emit->apply(simulated)->confirm->persist through
//     `mallcop doctor`, entirely within that one CLI verb.
//   - TestScanConfig_CloudConnectorDoctorLoop (scan_grantwiring_test.go)
//     proves miss->resolution->idempotent through `mallcop scan` alone,
//     entirely via the AUTOMATIC recordConnectorDiagnosis/confirmResolvedGrants
//     route (core/pipeline/grantwiring.go) — no `mallcop doctor` involved.
//
// Neither proves the untested seam this item exists to catch: that the
// resolution row ONE CLI verb (`mallcop doctor --confirm`) WRITES is the
// exact row a DIFFERENT CLI verb (`mallcop scan`, run later, by an operator
// who never re-invokes doctor) READS via pipeline's own Route-2 wiring
// (confirmResolvedGrants -> pendingGrantMiss) and correctly treats as
// already closed — no re-diagnose, no duplicate row. That is precisely the
// "a console reading a path the producer stopped writing" class of bug this
// dispatch has repeatedly found.
//
// A first version of this test asserted the seam ONLY via
// len(grantsAfterScan) != 2 / len(grantsAfterThirdScan) != 2. That assertion
// is equally satisfied by the scan doing NOTHING AT ALL with the grants
// stream — a "value did not change" assertion cannot distinguish "read it
// back" from "stopped reading it", which is exactly the bug class this item
// exists to catch. This version makes the seam OBSERVABLE instead of
// inferred, per the veracity rework:
//
//  1. journeySiblingScript's --doctor branch appends a line to a counter
//     file on EVERY invocation. Connector A (whose resolution `mallcop
//     doctor --confirm` already wrote) must show ZERO additional probes
//     across the two subsequent scans — a scan that ignores the persisted
//     resolution and re-probes on every run (severing pendingGrantMiss's
//     resolved-ref guard) turns this red.
//  2. A SECOND connector (connectorIDB) is left with an OPEN, unresolved
//     miss that only `mallcop doctor <id>` (never `--confirm`) ever
//     recorded. The first subsequent scan is the ONLY thing that ever closes
//     it — its own probe count must go 1 -> 2 and the grants stream must
//     gain a genuinely NEW resolution row (3 -> 4), not merely "stay the
//     same". A scan that never calls confirmResolvedGrants (severing Route
//     2 entirely) leaves connector B's miss open and its probe count frozen
//     at 1 — turns this red.
import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/store"
)

// journeySiblingScript renders a REAL, forked POSIX-sh sibling connector
// binary — the SAME DOCTOR_STATE_FILE shell-stub convention connect/exec/
// exec_test.go's doctorSibling and cli/doctor_test.go's doctorFakeSibling
// use (not an invented fake connector type). Unlike doctorFakeSibling (whose
// plain Pull always succeeds regardless of state), its plain Pull genuinely
// FAILS while deficient: "a connector fails to connect" is a real, observable
// fact about this fixture, not just a diagnosis narrative.
//
// stateVar and probeVar are environment variable NAMES (not values) baked
// literally into the script text at generation time — each connector in this
// test gets its OWN pair of names (config's `env:` list only forwards named
// values from the process environment, so two connectors sharing one name
// would alias each other's state). probeVar names a counter file the
// --doctor branch appends one line to on every invocation — the OBSERVABLE
// proof (required by the veracity rework, item mallcoppro-d6c) that a probe
// actually happened, rather than inferring it from a row count that could be
// equally explained by the scan doing nothing.
func journeySiblingScript(stateVar, probeVar string) string {
	tmpl := `#!/bin/sh
state=$(cat "$__STATE_VAR__" 2>/dev/null || echo deficient)
if [ "$1" = "--doctor" ]; then
  if [ -n "$__PROBE_VAR__" ]; then printf 'probe\n' >> "$__PROBE_VAR__"; fi
  if [ "$state" = "healthy" ]; then
    printf '%s\n' '{"diagnosis":{"known":true,"summary":"credentials valid","confidence":0.95}}'
  else
    printf '%s\n' '{"diagnosis":{"known":true,"summary":"service principal missing Reader role on the resource group","confidence":0.9},"remediation":[{"command":"az role assignment create --assignee OID --role Reader --scope SCOPE","blast_radius":"Lets the service principal READ metadata (never write, never data-plane) of every resource in the group.","known_issues":["PROPOSED BUT UNVERIFIED: mallcop CI eval has never proven this against a live account."],"dry_run":"az role assignment list --assignee OID --scope SCOPE -o table"}]}'
  fi
  exit 0
fi
if [ "$state" = "healthy" ]; then
  printf '%s\n' '{"id":"e-journey-1","source":"fake","type":"login","actor":"svc-journey"}'
  printf 'cursor: journey-tok-1\n' 1>&2
  exit 0
fi
echo "auth failed: AADSTS700082 refresh token expired" 1>&2
exit 1
`
	tmpl = strings.ReplaceAll(tmpl, "__STATE_VAR__", stateVar)
	tmpl = strings.ReplaceAll(tmpl, "__PROBE_VAR__", probeVar)
	return tmpl
}

// readProbeCount counts the lines journeySiblingScript's --doctor branch has
// appended to the counter file at path — the number of REAL --doctor
// subprocess invocations that connector has taken so far. A missing file
// (never probed) is 0, not an error.
func readProbeCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read probe counter %s: %v", path, err)
	}
	if len(data) == 0 {
		return 0
	}
	return len(strings.Split(strings.TrimRight(string(data), "\n"), "\n"))
}

// grantsFor filters a loaded grants stream down to the rows attributed to
// one connector, in stream order — lets the test reason about connector B's
// own history independent of connector A's interleaved rows.
func grantsFor(records []store.GrantOutcome, connectorID string) []store.GrantOutcome {
	var out []store.GrantOutcome
	for _, r := range records {
		if r.Connector == connectorID {
			out = append(out, r)
		}
	}
	return out
}

// writeJourneyConfig writes a mallcop.yaml naming TWO kind:cloud connectors
// (binaryPathA/binaryPathB), with budgets set explicitly so the SAME file is
// usable by both `mallcop doctor` (writeDoctorConfig's shape) and
// `mallcop scan` (scan_grantwiring_test.go's shape) — the whole point of
// this test is driving ONE config through BOTH CLI verbs. The second
// connector exists solely to prove the subsequent scan's grants-stream work
// is an observable STATE CHANGE (an open miss it alone closes), not just a
// non-change on the first connector.
func writeJourneyConfig(t *testing.T, cfgPath, storePath, connectorIDA, binaryPathA, connectorIDB, binaryPathB string) {
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
    id: `+connectorIDA+`
    binary: `+binaryPathA+`
    env: [DOCTOR_STATE_FILE, DOCTOR_PROBE_LOG]
  - kind: cloud
    id: `+connectorIDB+`
    binary: `+binaryPathB+`
    env: [DOCTOR_STATE_FILE_B, DOCTOR_PROBE_LOG_B]
detectors:
  builtin:
    enabled: true
    disable: []
learning:
  dir: detectors
  autonomy: non
budgets:
  max_findings: 25
  scan_timeout: 10m
`)
}

// TestClosedDiagnosisLoop_DiagnoseEmitApplyConfirmPersist_SubsequentScanReadsBack
// is this item's capstone acceptance test: it walks the WHOLE loop and would
// fail if any single link were broken, including a later stage silently
// ceasing to read what an earlier stage writes.
func TestClosedDiagnosisLoop_DiagnoseEmitApplyConfirmPersist_SubsequentScanReadsBack(t *testing.T) {
	dir := t.TempDir()

	// --- Connector A: the one whose resolution `mallcop doctor --confirm`
	// itself writes. A subsequent scan must read that resolution back and
	// NEVER re-probe it — proven below via probeLogA staying frozen at 2.
	stateFileA := filepath.Join(dir, "state-a")
	probeLogA := filepath.Join(dir, "probe-a")
	writeFile(t, stateFileA, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFileA)
	t.Setenv("DOCTOR_PROBE_LOG", probeLogA)
	binA := writeFakeSibling(t, dir, "journey-sibling-a", journeySiblingScript("DOCTOR_STATE_FILE", "DOCTOR_PROBE_LOG"))

	// --- Connector B: left with an OPEN, unresolved miss that ONLY
	// `mallcop doctor <id>` (never `--confirm`) ever recorded. The first
	// subsequent scan is the ONLY thing that ever closes it, proven below via
	// its own row count growing (1 -> 2) and its own probe count growing
	// (1 -> 2) on that scan, then staying frozen at 2 across the next one.
	stateFileB := filepath.Join(dir, "state-b")
	probeLogB := filepath.Join(dir, "probe-b")
	writeFile(t, stateFileB, "deficient")
	t.Setenv("DOCTOR_STATE_FILE_B", stateFileB)
	t.Setenv("DOCTOR_PROBE_LOG_B", probeLogB)
	binB := writeFakeSibling(t, dir, "journey-sibling-b", journeySiblingScript("DOCTOR_STATE_FILE_B", "DOCTOR_PROBE_LOG_B"))

	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	const connectorID = "azure-sp-prod"
	const connectorIDB = "azure-sp-staging"
	writeJourneyConfig(t, cfgPath, storePath, connectorID, binA, connectorIDB, binB)

	// --- (0) "a connector fails to connect" is a REAL, observable fact, not
	// narrated in a comment. Build the connector through the EXACT production
	// composition root (buildConnectors -> connect.Multi(...), never a bare
	// Diagnosable) and Pull it directly: it must genuinely fail while
	// deficient (both A and B start deficient). Pull itself never touches
	// the grants stream (only pipeline.Run's post-failure hook does), so
	// this leaves the store untouched — a clean baseline for the row-count
	// assertions below.
	cfg, cfgFilePath, cerr := config.LoadEffective(cfgPath)
	if cerr != nil {
		t.Fatalf("config.LoadEffective: %v", cerr)
	}
	if cfgFilePath == "" {
		t.Fatalf("config.LoadEffective did not find %s", cfgPath)
	}
	conn, berr := buildConnectors(cfg, storePath, nil)
	if berr != nil {
		t.Fatalf("buildConnectors: %v", berr)
	}
	if _, pullErr := conn.Pull(context.Background()); pullErr == nil {
		t.Fatalf("Pull over the deficient connectors returned nil error, want a genuine connect failure")
	}

	// --- (1) DIAGNOSE + EMIT (connector A): `mallcop doctor <id>` classifies
	// the failure and prints a ranked, least-privilege remediation the
	// operator can read and copy (BlastRadius + DryRun + staleness
	// KnownIssues banner) — driven through the SAME connect.Multi-wrapped
	// shape buildConnectors always returns, via a REAL forked sibling
	// process.
	var diagOut string
	var diagErr error
	diagOut = captureStdout(t, func() {
		diagErr = runDoctor([]string{connectorID, "--config", cfgPath, "--json"})
	})
	if !isFindingsError(diagErr) {
		t.Fatalf("runDoctor over a deficient connector: err = %v, want the errFindings sentinel", diagErr)
	}
	if got := readProbeCount(t, probeLogA); got != 1 {
		t.Fatalf("connector A probe count after its own diagnose = %d, want 1 (exactly one real --doctor invocation)", got)
	}

	var report doctorReport
	if jerr := json.Unmarshal([]byte(diagOut), &report); jerr != nil {
		t.Fatalf("--json output did not parse as doctorReport: %v\noutput: %s", jerr, diagOut)
	}
	if !report.Diagnosis.Known {
		t.Fatalf("report.Diagnosis.Known = false, want a CLASSIFIED failure — this loop proves the classified/remediable path (the unclassified GRANT-MISS/E1 path is scan_grantwiring_test.go's own coverage)")
	}
	if len(report.Remediation) != 1 {
		t.Fatalf("report.Remediation = %+v, want exactly 1 ranked least-privilege option to read and copy", report.Remediation)
	}
	opt := report.Remediation[0]
	if opt.BlastRadius == "" {
		t.Error("remediation option has no BlastRadius — an operator cannot judge an ask with no blast-radius text")
	}
	if opt.DryRun == nil || *opt.DryRun == "" {
		t.Error("remediation option has no DryRun preview")
	}
	if report.GrantRef == "" {
		t.Fatal("report.GrantRef is empty — need it to drive --confirm")
	}
	grantRef := report.GrantRef

	st, serr := store.Open(storePath)
	if serr != nil {
		t.Fatalf("store.Open: %v", serr)
	}
	grantsAfterDiagnose, gerr := st.LoadGrantOutcomes()
	if gerr != nil {
		t.Fatalf("LoadGrantOutcomes after diagnose: %v", gerr)
	}
	if len(grantsAfterDiagnose) != 1 {
		t.Fatalf("LoadGrantOutcomes after diagnose = %d records, want exactly 1 (the GRANT-MISS)", len(grantsAfterDiagnose))
	}
	if grantsAfterDiagnose[0].Resolved || grantsAfterDiagnose[0].ResolvedRef != "" {
		t.Fatalf("miss row = %+v, want Resolved=false ResolvedRef=\"\"", grantsAfterDiagnose[0])
	}

	// --- (2) APPLY (simulated): the operator runs the emitted `az` command
	// out of band. Neither this test nor the product ever runs it — the ONLY
	// thing that changes is the fixture's state file (emit-only, no grant or
	// elevated right is executed by anything here).
	writeFile(t, stateFileA, "healthy")

	// --- (3) CONFIRM + PERSIST (connector A): `mallcop doctor <id> --confirm
	// <ref>` re-probes the REAL sibling and records the resolution through
	// the real git-backed store as a SECOND appended row, never a mutation.
	var confirmOut string
	var confirmErr error
	confirmOut = captureStdout(t, func() {
		confirmErr = runDoctor([]string{connectorID, "--config", cfgPath, "--json", "--confirm", grantRef})
	})
	if confirmErr != nil {
		t.Fatalf("runDoctor --confirm after the simulated fix: err = %v, want nil", confirmErr)
	}
	if got := readProbeCount(t, probeLogA); got != 2 {
		t.Fatalf("connector A probe count after doctor --confirm = %d, want 2 (diagnose + confirm, exactly one real --doctor invocation each)", got)
	}
	var confirmReport doctorConfirmReport
	if jerr := json.Unmarshal([]byte(confirmOut), &confirmReport); jerr != nil {
		t.Fatalf("--confirm --json output did not parse: %v\noutput: %s", jerr, confirmOut)
	}
	if !confirmReport.Resolved {
		t.Fatalf("confirmReport.Resolved = false, want true (the connector is now healthy)")
	}

	grantsAfterConfirm, gerr2 := st.LoadGrantOutcomes()
	if gerr2 != nil {
		t.Fatalf("LoadGrantOutcomes after confirm: %v", gerr2)
	}
	if len(grantsAfterConfirm) != 2 {
		t.Fatalf("LoadGrantOutcomes after confirm = %d records, want exactly 2 (miss + resolution, NEVER a mutation)", len(grantsAfterConfirm))
	}
	if grantsAfterConfirm[0].Resolved {
		t.Fatalf("the ORIGINAL miss row was mutated in place: %+v", grantsAfterConfirm[0])
	}
	resolutionRow := grantsAfterConfirm[1]
	if !resolutionRow.Resolved || resolutionRow.ResolvedRef != grantRef {
		t.Fatalf("resolution row = %+v, want Resolved=true ResolvedRef=%q (the ORIGINAL GRANT-MISS's own ref)", resolutionRow, grantRef)
	}
	resolvedBack, rerr := st.ResolveGrantMiss(resolutionRow.ResolvedRef)
	if rerr != nil {
		t.Fatalf("ResolveGrantMiss(%q): %v", resolutionRow.ResolvedRef, rerr)
	}
	if resolvedBack.Connector != connectorID || resolvedBack.Resolved {
		t.Fatalf("ResolveGrantMiss returned %+v, want the ORIGINAL unresolved miss row back", resolvedBack)
	}

	// --- (3b) SECOND CONNECTOR LEFT OPEN: diagnose connector B while it is
	// still deficient — recording an unresolved GRANT-MISS row for B — but,
	// unlike A, `mallcop doctor --confirm` is NEVER run for it. Only the
	// scan below is ever asked to close it: this is what turns the
	// subsequent scan's grants-stream work into an OBSERVABLE STATE CHANGE
	// (an open miss it alone closes) instead of a mere non-change on A.
	var diagBOut string
	var diagBErr error
	diagBOut = captureStdout(t, func() {
		diagBErr = runDoctor([]string{connectorIDB, "--config", cfgPath, "--json"})
	})
	if !isFindingsError(diagBErr) {
		t.Fatalf("runDoctor over deficient connector B: err = %v, want the errFindings sentinel", diagBErr)
	}
	if got := readProbeCount(t, probeLogB); got != 1 {
		t.Fatalf("connector B probe count after its own diagnose = %d, want 1", got)
	}
	var reportB doctorReport
	if jerr := json.Unmarshal([]byte(diagBOut), &reportB); jerr != nil {
		t.Fatalf("connector B --json output did not parse as doctorReport: %v\noutput: %s", jerr, diagBOut)
	}
	if reportB.GrantRef == "" {
		t.Fatal("connector B's report.GrantRef is empty")
	}
	// Apply B's simulated fix too, but deliberately do NOT confirm it via
	// `mallcop doctor --confirm` — the whole point is that nothing but a
	// later scan ever closes this one.
	writeFile(t, stateFileB, "healthy")

	grantsBeforeScan, gerrB := st.LoadGrantOutcomes()
	if gerrB != nil {
		t.Fatalf("LoadGrantOutcomes before the subsequent scan: %v", gerrB)
	}
	if len(grantsBeforeScan) != 3 {
		t.Fatalf("LoadGrantOutcomes before the subsequent scan = %d records, want exactly 3 (A's miss+resolution, B's still-open miss)", len(grantsBeforeScan))
	}
	bBeforeScan := grantsFor(grantsBeforeScan, connectorIDB)
	if len(bBeforeScan) != 1 || bBeforeScan[0].Resolved {
		t.Fatalf("connector B's rows before the scan = %+v, want exactly 1 unresolved miss", bBeforeScan)
	}

	// --- (4) THE UNTESTED SEAM: a SUBSEQUENT `mallcop scan` — a DIFFERENT
	// CLI verb than the one that wrote A's resolution above, through
	// cli/scan.go's REAL buildConnectors (connect.Multi-wrapped) path. Both
	// connectors are now healthy (Pull succeeds), so pipeline.Run's
	// confirmResolvedGrants (core/pipeline/grantwiring.go) runs its Route-2
	// wiring over EACH reachable Diagnosable:
	//
	//   - connector A already has a resolution row (written by `mallcop
	//     doctor --confirm` above) — pendingGrantMiss must find NOTHING
	//     outstanding for it, so it must NOT be re-probed at all. Asserted
	//     below as probeLogA staying frozen at 2 (an OBSERVABLE non-event,
	//     not merely "the row count didn't change").
	//   - connector B still has an OPEN miss that ONLY this scan has ever
	//     been asked to close — pendingGrantMiss must find it, pay for
	//     exactly one live re-Diagnose, and append a genuinely NEW
	//     resolution row. Asserted below as probeLogB growing 1 -> 2 AND
	//     the grants stream growing 3 -> 4 with a real new resolution row
	//     for B — an OBSERVABLE POSITIVE consequence, not an unchanged
	//     count that a no-op scan would satisfy just as well.
	var scanErr error
	_ = captureStdout(t, func() {
		scanErr = runScan([]string{"--config", cfgPath, "--json"})
	})
	if scanErr != nil && !isFindingsError(scanErr) {
		t.Fatalf("subsequent `mallcop scan` over the now-healthy connectors: unexpected error %v", scanErr)
	}

	if got := readProbeCount(t, probeLogA); got != 2 {
		t.Fatalf("connector A probe count after the subsequent scan = %d, want STILL 2 — "+
			"the scan must READ the doctor-CLI-written resolution back and NOT re-probe an already-resolved connector", got)
	}
	if got := readProbeCount(t, probeLogB); got != 2 {
		t.Fatalf("connector B probe count after the subsequent scan = %d, want 2 (1 -> 2) — "+
			"the scan itself must pay for exactly one live re-Diagnose to close B's still-open miss", got)
	}

	grantsAfterScan, gerr3 := st.LoadGrantOutcomes()
	if gerr3 != nil {
		t.Fatalf("LoadGrantOutcomes after the subsequent scan: %v", gerr3)
	}
	if len(grantsAfterScan) != 4 {
		t.Fatalf("LoadGrantOutcomes after the subsequent scan = %d records, want exactly 4 "+
			"(A's 2 rows unchanged + B's now-closed miss+resolution)", len(grantsAfterScan))
	}
	aAfterScan := grantsFor(grantsAfterScan, connectorID)
	if len(aAfterScan) != 2 {
		t.Fatalf("connector A's own rows after the scan = %+v, want still exactly 2 (untouched)", aAfterScan)
	}
	bAfterScan := grantsFor(grantsAfterScan, connectorIDB)
	if len(bAfterScan) != 2 {
		t.Fatalf("connector B's own rows after the scan = %+v, want exactly 2 (its miss, now CLOSED by this scan)", bAfterScan)
	}
	if bAfterScan[0].Resolved {
		t.Fatalf("connector B's ORIGINAL miss row was mutated in place: %+v", bAfterScan[0])
	}
	bResolution := bAfterScan[1]
	if !bResolution.Resolved || bResolution.ResolvedRef != reportB.GrantRef {
		t.Fatalf("connector B's resolution row = %+v, want Resolved=true ResolvedRef=%q (B's ORIGINAL GRANT-MISS's own ref) — "+
			"this is the scan's own live re-Diagnose closing an open miss, not a doctor-CLI-written row", bResolution, reportB.GrantRef)
	}

	// --- (5) IDEMPOTENCY ACROSS A THIRD SCAN: this is not a one-time
	// coincidence of the first read-back — running `mallcop scan` again over
	// the same now-fully-resolved connectors must not grow the history OR
	// the probe counts any further, for EITHER connector.
	var scanErr2 error
	_ = captureStdout(t, func() {
		scanErr2 = runScan([]string{"--config", cfgPath, "--json"})
	})
	if scanErr2 != nil && !isFindingsError(scanErr2) {
		t.Fatalf("third scan over the still-healthy connectors: unexpected error %v", scanErr2)
	}
	if got := readProbeCount(t, probeLogA); got != 2 {
		t.Fatalf("connector A probe count after the THIRD scan = %d, want still 2 (no re-probe of an already-resolved connector)", got)
	}
	if got := readProbeCount(t, probeLogB); got != 2 {
		t.Fatalf("connector B probe count after the THIRD scan = %d, want still 2 (B's resolution from the prior scan must ALSO be read back, not re-probed)", got)
	}
	grantsAfterThirdScan, gerr4 := st.LoadGrantOutcomes()
	if gerr4 != nil {
		t.Fatalf("LoadGrantOutcomes after the third scan: %v", gerr4)
	}
	if len(grantsAfterThirdScan) != 4 {
		t.Fatalf("LoadGrantOutcomes after a THIRD scan = %d records, want still 4 (idempotent across re-scans, both connectors)", len(grantsAfterThirdScan))
	}
}
