package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
)

// initStatusRepo creates a REAL git-backed store dir (matching
// core/store's own initRepo test helper) so runStatus exercises the actual
// git plumbing, not a fake.
func initStatusRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "test"},
		{"config", "user.email", "test@example.com"},
		{"config", "commit.gpgsign", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	seed := exec.Command("git", "commit", "-q", "--allow-empty", "-m", "root")
	seed.Dir = dir
	seed.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if out, err := seed.CombinedOutput(); err != nil {
		t.Fatalf("seed commit: %v\n%s", err, out)
	}
	return dir
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// TestRunStatus_DecisionsWording proves `mallcop status` labels the total
// recorded-resolutions count "Decisions:", not "Resolved:" — the terminology
// fix that disambiguates it from `mallcop scan`'s per-run "Resolved: N"
// summary line (which counts only the non-escalate subset of ONE scan, not
// every decision ever recorded in the store).
func TestRunStatus_DecisionsWording(t *testing.T) {
	repo := initStatusRepo(t)

	st, err := store.Open(repo)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	// Two resolutions recorded, both escalations (so a scan over this data
	// would itself report "Resolved: 0" while status still has decisions to
	// show — the exact confusion the wording fix resolves).
	for i := 0; i < 2; i++ {
		if _, err := st.Append(store.KindResolutions, map[string]string{
			"finding_id": "f-1", "action": "escalate",
		}); err != nil {
			t.Fatalf("append resolution: %v", err)
		}
	}

	out := captureStdout(t, func() {
		if err := runStatus([]string{"--store", filepath.Clean(repo)}); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !bytes.Contains([]byte(out), []byte("Decisions:  2 recorded")) {
		t.Errorf("expected %q in output, got:\n%s", "Decisions:  2 recorded", out)
	}
	if bytes.Contains([]byte(out), []byte("Resolved:")) {
		t.Errorf("status output must not say \"Resolved:\" (ambiguous with scan's per-run summary word); got:\n%s", out)
	}
}

// TestRunStatus_SurfacesReportedMissRecallRed proves `mallcop status` surfaces the
// store-pure coverage gaps and flags a RECALL RED when the operator has recorded a
// report-miss (mallcop feedback report-miss) — the self-heal loop's per-operator
// detected-miss visibility.
func TestRunStatus_SurfacesReportedMissRecallRed(t *testing.T) {
	repo := initStatusRepo(t)
	st, err := store.Open(repo)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	meta := []byte(`{"source":"github","event_type":"github.permission.grant","actor":"mallory"}`)
	if _, err := st.Append(store.KindDirectives, store.Directive{
		Op: "report-miss", Pattern: "github/github.permission.grant/mallory",
		Reason: "operator note", Actor: "baron", Meta: meta,
	}); err != nil {
		t.Fatalf("append report-miss directive: %v", err)
	}

	out := captureStdout(t, func() {
		if err := runStatus([]string{"--store", filepath.Clean(repo)}); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !bytes.Contains([]byte(out), []byte("Coverage gaps:")) {
		t.Errorf("expected a Coverage gaps line, got:\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("1 reported miss")) {
		t.Errorf("expected \"1 reported miss\" in output, got:\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("Recall reds:")) {
		t.Errorf("expected a Recall reds line flagging the miss, got:\n%s", out)
	}
	// The operator's free-text audit note must NOT be surfaced in status output.
	if bytes.Contains([]byte(out), []byte("operator note")) {
		t.Errorf("status must not surface the raw operator description, got:\n%s", out)
	}
}

// TestRunStatus_EmptyStore_CasesZeroOpenLine proves a store that has never
// had a scan write cases.json (ReadSnapshot's documented "not found" case)
// still prints an HONEST "Cases: 0 open" line — the section is never simply
// absent (mallcoppro-a51's done condition).
func TestRunStatus_EmptyStore_CasesZeroOpenLine(t *testing.T) {
	repo := initStatusRepo(t)

	out := captureStdout(t, func() {
		if err := runStatus([]string{"--store", filepath.Clean(repo)}); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	if !bytes.Contains([]byte(out), []byte("Cases:      0 open\n")) {
		t.Errorf("expected an honest \"Cases: 0 open\" line on an empty store, got:\n%s", out)
	}
	if bytes.Contains([]byte(out), []byte("recurring)")) {
		t.Errorf("empty store must not print a recurring parenthetical, got:\n%s", out)
	}
}

// TestRunStatus_CasesSection_MatchesSharedSummarize proves `mallcop status`'s
// Cases section is byte-identical to what core/cases.Summarize computes over
// the SAME cases.json a real `mallcop scan` run wrote — the R4 dual-audience
// requirement (mallcoppro-a51) that status must never re-derive or re-cluster
// its own count. It runs 3 real scans over gitOopsEventWithID (cli/cases_test.go's
// fixture — same actor, same detector, distinct event ids) so ONE case
// recurs to Count 3/Status "recurring" in a REAL git-backed store, reads
// store/cases.json back with the exact same helper cli/cases_test.go's own
// assertions use, computes the expected Summary by calling cases.Summarize
// on that read-back slice directly (the SAME shared function status.go
// calls internally — this test derives its expectation from the shared
// function's own output, never a hand-typed number), and asserts runStatus's
// printed output matches it exactly.
func TestRunStatus_CasesSection_MatchesSharedSummarize(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "store")
	baselinePath := filepath.Join(dir, "baseline.json")
	writeKnownActorsBaseline(t, baselinePath, "dev")

	ids := []string{"g1", "g2", "g3"}
	stamps := []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "2026-01-01T02:00:00Z"}
	for i, id := range ids {
		eventsPath := filepath.Join(dir, "events-"+id+".jsonl")
		writeFile(t, eventsPath, gitOopsEventWithID(id, stamps[i]))
		err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath, "--baseline", baselinePath})
		if !isFindingsError(err) {
			t.Fatalf("scan %d (%s): want findings sentinel, got %v", i+1, id, err)
		}
	}

	// Read back the REAL committed cases.json (same helper cli/cases_test.go
	// uses to assert Collapse's own output) and derive the expectation from
	// the SAME shared function status.go calls — cases.Summarize.
	gotCases := readCasesJSON(t, storePath)
	want := cases.Summarize(gotCases)
	if want.Open != 1 || want.Recurring != 1 {
		t.Fatalf("test fixture assumption broke: want 1 open/1 recurring case from cases.Summarize, got %+v (cases=%+v)", want, gotCases)
	}

	out := captureStdout(t, func() {
		if err := runStatus([]string{"--store", filepath.Clean(storePath)}); err != nil {
			t.Fatalf("runStatus: %v", err)
		}
	})

	wantHeader := fmt.Sprintf("Cases:      %d open (%d recurring)\n", want.Open, want.Recurring)
	if !bytes.Contains([]byte(out), []byte(wantHeader)) {
		t.Errorf("want header %q in status output, got:\n%s", wantHeader, out)
	}
	if len(want.Lines) != 1 {
		t.Fatalf("test fixture assumption broke: want exactly 1 case line, got %v", want.Lines)
	}
	for _, line := range want.Lines {
		if !bytes.Contains([]byte(out), []byte(line+"\n")) {
			t.Errorf("want case line %q in status output, got:\n%s", line, out)
		}
	}
}
