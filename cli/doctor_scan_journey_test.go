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
import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/store"
)

// journeySibling is a REAL, forked POSIX-sh sibling connector binary — the
// SAME DOCTOR_STATE_FILE shell-stub convention connect/exec/exec_test.go's
// doctorSibling and cli/doctor_test.go's doctorFakeSibling use (not an
// invented fake connector type). Unlike doctorFakeSibling (whose plain Pull
// always succeeds regardless of state), journeySibling's plain Pull
// genuinely FAILS while deficient: "a connector fails to connect" is a real,
// observable fact about this fixture, not just a diagnosis narrative.
const journeySibling = `#!/bin/sh
state=$(cat "$DOCTOR_STATE_FILE" 2>/dev/null || echo deficient)
if [ "$1" = "--doctor" ]; then
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

// writeJourneyConfig writes a mallcop.yaml naming ONE kind:cloud connector at
// binaryPath, with budgets set explicitly so the SAME file is usable by both
// `mallcop doctor` (writeDoctorConfig's shape) and `mallcop scan`
// (scan_grantwiring_test.go's shape) — the whole point of this test is
// driving ONE config through BOTH CLI verbs.
func writeJourneyConfig(t *testing.T, cfgPath, storePath, connectorID, binaryPath string) {
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
	stateFile := filepath.Join(dir, "state")
	writeFile(t, stateFile, "deficient")
	t.Setenv("DOCTOR_STATE_FILE", stateFile)

	bin := writeFakeSibling(t, dir, "journey-sibling", journeySibling)
	storePath := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	const connectorID = "azure-sp-prod"
	writeJourneyConfig(t, cfgPath, storePath, connectorID, bin)

	// --- (0) "a connector fails to connect" is a REAL, observable fact, not
	// narrated in a comment. Build the connector through the EXACT production
	// composition root (buildConnectors -> connect.Multi(...), never a bare
	// Diagnosable) and Pull it directly: it must genuinely fail while
	// deficient. Pull itself never touches the grants stream (only
	// pipeline.Run's post-failure hook does), so this leaves the store
	// untouched — a clean baseline for the row-count assertions below.
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
		t.Fatalf("Pull over the deficient connector returned nil error, want a genuine connect failure")
	}

	// --- (1) DIAGNOSE + EMIT: `mallcop doctor <id>` classifies the failure
	// and prints a ranked, least-privilege remediation the operator can read
	// and copy (BlastRadius + DryRun + staleness KnownIssues banner) — driven
	// through the SAME connect.Multi-wrapped shape buildConnectors always
	// returns, via a REAL forked sibling process.
	var diagOut string
	var diagErr error
	diagOut = captureStdout(t, func() {
		diagErr = runDoctor([]string{connectorID, "--config", cfgPath, "--json"})
	})
	if !isFindingsError(diagErr) {
		t.Fatalf("runDoctor over a deficient connector: err = %v, want the errFindings sentinel", diagErr)
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
	writeFile(t, stateFile, "healthy")

	// --- (3) CONFIRM + PERSIST: `mallcop doctor <id> --confirm <ref>`
	// re-probes the REAL sibling and records the resolution through the real
	// git-backed store as a SECOND appended row, never a mutation.
	var confirmOut string
	var confirmErr error
	confirmOut = captureStdout(t, func() {
		confirmErr = runDoctor([]string{connectorID, "--config", cfgPath, "--json", "--confirm", grantRef})
	})
	if confirmErr != nil {
		t.Fatalf("runDoctor --confirm after the simulated fix: err = %v, want nil", confirmErr)
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

	// --- (4) THE UNTESTED SEAM: a SUBSEQUENT `mallcop scan` — a DIFFERENT
	// CLI verb than the one that wrote the resolution above, through
	// cli/scan.go's REAL buildConnectors (connect.Multi-wrapped) path. The
	// connector is now healthy (Pull succeeds), so pipeline.Run's
	// confirmResolvedGrants (core/pipeline/grantwiring.go) runs its Route-2
	// wiring: it must read the grants stream, see the miss is ALREADY
	// resolved — by `mallcop doctor`, not by itself — and do NOTHING: no
	// live re-Diagnose call, no duplicate row. This proves the artifact one
	// CLI verb writes is the artifact a genuinely different one reads.
	var scanErr error
	_ = captureStdout(t, func() {
		scanErr = runScan([]string{"--config", cfgPath, "--json"})
	})
	if scanErr != nil && !isFindingsError(scanErr) {
		t.Fatalf("subsequent `mallcop scan` over the now-healthy connector: unexpected error %v", scanErr)
	}

	grantsAfterScan, gerr3 := st.LoadGrantOutcomes()
	if gerr3 != nil {
		t.Fatalf("LoadGrantOutcomes after the subsequent scan: %v", gerr3)
	}
	if len(grantsAfterScan) != 2 {
		t.Fatalf("LoadGrantOutcomes after the subsequent scan = %d records, want STILL 2 "+
			"(the scan must READ the doctor-CLI-written resolution back, not re-diagnose or duplicate it)", len(grantsAfterScan))
	}

	// --- (5) IDEMPOTENCY ACROSS A THIRD SCAN: this is not a one-time
	// coincidence of the first read-back — running `mallcop scan` again over
	// the same already-resolved connector must not grow the history further.
	var scanErr2 error
	_ = captureStdout(t, func() {
		scanErr2 = runScan([]string{"--config", cfgPath, "--json"})
	})
	if scanErr2 != nil && !isFindingsError(scanErr2) {
		t.Fatalf("third scan over the still-healthy connector: unexpected error %v", scanErr2)
	}
	grantsAfterThirdScan, gerr4 := st.LoadGrantOutcomes()
	if gerr4 != nil {
		t.Fatalf("LoadGrantOutcomes after the third scan: %v", gerr4)
	}
	if len(grantsAfterThirdScan) != 2 {
		t.Fatalf("LoadGrantOutcomes after a THIRD scan = %d records, want still 2 (idempotent across re-scans)", len(grantsAfterThirdScan))
	}
}
