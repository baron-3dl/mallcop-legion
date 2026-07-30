package cli

// scan_grantwiring_test.go is the end-to-end proof mallcoppro-d3f's veracity
// rework demands: a config-driven `mallcop scan` through cli/scan.go's REAL
// buildConnectors() path — which ALWAYS wraps every configured connector,
// even a single kind:cloud one, in connect.Multi(...) (cli/scan.go:558) —
// must actually produce (Route 1) and later close (Route 2) a GrantOutcome
// row on the git-backed store, driven by the SAME production code path a
// customer's `mallcop scan` runs, not merely a unit test that hands
// pipeline.Run a hand-built Diagnosable connector directly.
//
// The fake sibling below is the SAME real, forked, self-contained POSIX-sh
// process connect/exec/exec_test.go's own doctorSibling fixture uses — a
// live child process this test's own process execs, not a mock of
// connect.Diagnosable. Its --doctor branch is a genuine second invocation of
// the real connect/exec.ExecConnector.Diagnose, which itself forks a REAL
// process and parses REAL stdout JSON; nothing about the diagnosis path is
// faked here.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
)

// brokenDoctorSibling simulates an expired/invalid credential: a normal pull
// fails (non-zero exit, stderr message), but --doctor is supported and
// reports Known:false — an unclassified GRANT-MISS with no ranked
// remediation to try, exactly the case Route 1's E1 ask exists for.
const brokenDoctorSibling = `#!/bin/sh
if [ "$1" = "--doctor" ]; then
  printf '%s\n' '{"diagnosis":{"known":false,"summary":"credentials rejected: token invalid","confidence":0.2},"remediation":[]}'
  exit 0
fi
echo "auth failed: invalid token" 1>&2
exit 1
`

// fixedDoctorSibling is the SAME connector after an operator applied a fix
// out of band: Pull now succeeds (one git-oops event + a cursor line) and
// --doctor reports Known:true.
const fixedDoctorSibling = `#!/bin/sh
if [ "$1" = "--doctor" ]; then
  printf '%s\n' '{"diagnosis":{"known":true,"summary":"credentials valid","confidence":0.95},"remediation":[]}'
  exit 0
fi
printf '%s\n' '{"id":"c1","source":"github","type":"push","actor":"ops","payload":{"forced":true,"ref":"refs/heads/main"}}'
printf 'cursor: tok-1\n' 1>&2
`

// writeSibling (over)writes an executable fake sibling binary at path.
func writeSibling(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write sibling %s: %v", path, err)
	}
}

// TestScanConfig_CloudConnectorDoctorLoop drives three successive
// `mallcop scan` runs over ONE config-declared kind:cloud connector:
//
//  1. the sibling is broken → Pull fails → a GrantOutcome MISS row, carrying
//     the E1 ask, must land on the grants stream (Route 1);
//  2. the operator fixes it out of band (the sibling binary is swapped) →
//     Pull succeeds → a RESOLUTION row closing the ORIGINAL miss must land,
//     with no separate CLI verb or test-only call involved (Route 2);
//  3. a third scan over the now-healthy connector must not duplicate the
//     resolution — idempotent across re-scans.
func TestScanConfig_CloudConnectorDoctorLoop(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	siblingPath := filepath.Join(binDir, "mallcop-connector-fake")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfgStore := filepath.Join(dir, "store")
	cfgPath := filepath.Join(dir, "mallcop.yaml")
	writeFile(t, cfgPath, `version: 1
inference:
  mode: offline
store:
  path: `+cfgStore+`
connectors:
  - kind: cloud
    id: fake-cloud
    source: fake
detectors:
  builtin:
    enabled: true
learning:
  dir: detectors
budgets:
  max_findings: 25
  scan_timeout: 10m
`)

	// --- (1) BROKEN sibling: Pull fails, --doctor reports Known:false. ---
	writeSibling(t, siblingPath, brokenDoctorSibling)
	err := runScan([]string{"--config", cfgPath})
	if err == nil || isFindingsError(err) {
		t.Fatalf("first scan (broken sibling): want a genuine connect error, got %v", err)
	}

	st, serr := store.Open(cfgStore)
	if serr != nil {
		t.Fatalf("open store: %v", serr)
	}
	grants, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes: %v", lerr)
	}
	if len(grants) != 1 {
		t.Fatalf("after the broken-sibling scan, LoadGrantOutcomes = %d records, want exactly 1 "+
			"(the GRANT-MISS produced through the REAL buildConnectors -> connect.Multi -> pipeline.Run path)", len(grants))
	}
	miss := grants[0]
	if miss.Connector != "fake-cloud" {
		t.Fatalf("miss.Connector = %q, want %q (the config's connector id)", miss.Connector, "fake-cloud")
	}
	if miss.Resolved {
		t.Fatalf("miss row already Resolved=true, want a fresh MISS")
	}
	if miss.DecisionKind != "grant" || miss.BlastRadius == "" || miss.Question == "" {
		t.Fatalf("miss row = %+v, want the E1 SecurityDecision ask populated (Diagnosis.Known was false)", miss)
	}

	// --- (2) FIXED sibling: the operator's out-of-band fix. Pull succeeds. ---
	writeSibling(t, siblingPath, fixedDoctorSibling)
	err = runScan([]string{"--config", cfgPath, "--json"})
	if err != nil && !isFindingsError(err) {
		t.Fatalf("second scan (fixed sibling): unexpected error %v", err)
	}

	grants2, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes after fix: %v", lerr)
	}
	if len(grants2) != 2 {
		t.Fatalf("after the fixed-sibling scan, LoadGrantOutcomes = %d records, want 2 "+
			"(the original miss + a resolution — the REAL cli/scan.go path must have called RecordConfirmOutcome)", len(grants2))
	}
	resolution := grants2[1]
	if !resolution.Resolved {
		t.Fatalf("second row = %+v, want Resolved=true", resolution)
	}
	if resolution.Connector != "fake-cloud" {
		t.Fatalf("resolution.Connector = %q, want %q", resolution.Connector, "fake-cloud")
	}

	// The resolution must genuinely close the FIRST miss row, not a
	// coincidental one — resolvable back through the store.
	backToMiss, rerr := st.ResolveGrantMiss(resolution.ResolvedRef)
	if rerr != nil {
		t.Fatalf("ResolveGrantMiss(%q): %v", resolution.ResolvedRef, rerr)
	}
	if backToMiss.Connector != "fake-cloud" || backToMiss.Resolved {
		t.Fatalf("ResolveGrantMiss(resolution.ResolvedRef) = %+v, want the original fake-cloud MISS row", backToMiss)
	}

	// --- (3) THIRD scan over the still-healthy connector: idempotent. ---
	err = runScan([]string{"--config", cfgPath, "--json"})
	if err != nil && !isFindingsError(err) {
		t.Fatalf("third scan: unexpected error %v", err)
	}
	grants3, lerr := st.LoadGrantOutcomes()
	if lerr != nil {
		t.Fatalf("LoadGrantOutcomes after third scan: %v", lerr)
	}
	if len(grants3) != 2 {
		t.Fatalf("after a THIRD scan over an already-resolved connector, LoadGrantOutcomes = %d records, want still 2 "+
			"(idempotent — mallcoppro-d3f's acceptance criterion: \"the NEXT SCAN READS\" it, it does not re-write it)", len(grants3))
	}
}
