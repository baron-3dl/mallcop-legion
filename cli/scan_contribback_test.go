package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
)

// TestScan_ContributeBackPoll_MergedUpdatesRecordOnNextScan is the primary
// user-workflow proof for mallcoppro-003: `mallcop scan` (via runScan, the
// REAL CLI entry point) picks up an already-opened contribute-back record
// with State=="open", asks a fake GitHub API (a REAL local httptest.Server —
// nothing about the HTTP round trip is mocked, only the far end is
// redirected to localhost via $MALLCOP_GITHUB_API_BASE) whether the PR
// merged, and appends a FRESH State=="merged" row to the SAME real
// git-backed store the scan itself just wrote findings/resolutions to.
//
// This proves the full "next scan" wiring end-to-end: real store
// (openOrInitStore + git commit), real runScan pipeline invocation, real
// HTTP fetch — only the network's far end (github.com) is a local double.
func TestScan_ContributeBackPoll_MergedUpdatesRecordOnNextScan(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)
	storePath := filepath.Join(dir, "store")

	// Seed the contribute-back record BEFORE the scan runs — this is what a
	// prior `gh pr create` under the operator's own identity would already
	// have durably written (selfext/contribback.PollOutcomes is proven
	// against this exact record shape in selfext/contribback/poll_test.go;
	// this test proves the CLI actually calls it on a real scan).
	st, err := openOrInitStore(storePath)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	seed := store.ContribBackRecord{
		Fingerprint: "cli-wiring-fp",
		PRURL:       "https://github.com/mallcop-app/mallcop/pull/777",
		State:       store.ContribBackOpen,
		OpenedAt:    time.Now().UTC().Add(-96 * time.Hour),
		UpdatedAt:   time.Now().UTC().Add(-96 * time.Hour),
	}
	if _, err := st.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append(KindContribBack): %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/mallcop-app/mallcop/pulls/777" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("scan's contribute-back poll sent an Authorization header — the shared-repo read must stay unauthenticated")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "closed", "merged": true})
	}))
	defer srv.Close()

	t.Setenv(envGitHubAPIBase, srv.URL)

	err = runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("runScan: want findings sentinel (gitOopsEvent always fires), got %v", err)
	}

	reopened, err := store.Open(storePath)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	recs, err := reopened.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("LoadContribBackRecords = %d rows after one scan, want 2 (seeded open + the scan's new merged row)", len(recs))
	}
	if recs[0].State != store.ContribBackOpen {
		t.Errorf("seeded row mutated by the scan: %+v", recs[0])
	}
	if recs[1].State != store.ContribBackMerged || recs[1].PRURL != seed.PRURL {
		t.Fatalf("scan's new row = %+v, want State=merged for %s", recs[1], seed.PRURL)
	}

	// A second scan must be a no-op for this record: it is no longer "open",
	// so the poll must not touch it again (mallcoppro-42e idempotency
	// discipline — no duplicate rows, no churn across re-scans). The event
	// itself is a duplicate of the first scan's (same id), so the pipeline
	// reports zero NEW findings this time (nil, not the findings sentinel).
	err = runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if err != nil {
		t.Fatalf("second runScan: want nil (the event is a dedup no-op; only the contribback record matters here), got %v", err)
	}
	recs2, err := reopened.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords after second scan: %v", err)
	}
	if len(recs2) != 2 {
		t.Fatalf("LoadContribBackRecords after a SECOND scan = %d rows, want still 2 (no churn on an already-merged record)", len(recs2))
	}
}

// TestScan_ContributeBackPoll_UnreachableAPIDoesNotFailScan proves the
// non-fatal acceptance criterion at the CLI layer: a scan whose
// contribute-back poll cannot reach GitHub's API still completes and reports
// its findings sentinel exactly as it would with no contribback records at
// all — the poll's failure must never surface as a scan failure.
func TestScan_ContributeBackPoll_UnreachableAPIDoesNotFailScan(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)
	storePath := filepath.Join(dir, "store")

	st, err := openOrInitStore(storePath)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	seed := store.ContribBackRecord{
		PRURL:     "https://github.com/mallcop-app/mallcop/pull/1",
		State:     store.ContribBackOpen,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := st.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append(KindContribBack): %v", err)
	}

	// Point the poll at a dead port: every request fails at the transport
	// level, the closest analogue to "GitHub is unreachable this hour."
	deadSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := deadSrv.URL
	deadSrv.Close()
	t.Setenv(envGitHubAPIBase, deadURL)

	err = runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("runScan with an unreachable contribute-back API: want the ordinary findings sentinel (poll failure must not fail the scan), got %v", err)
	}

	reopened, rerr := store.Open(storePath)
	if rerr != nil {
		t.Fatalf("re-open store: %v", rerr)
	}
	recs, err := reopened.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].State != store.ContribBackOpen {
		t.Fatalf("recs = %+v, want the original untouched open row (honest degrade)", recs)
	}
}
