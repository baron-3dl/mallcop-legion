package contribback

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
)

// initRepo creates a REAL git repo in a temp dir, mirroring core/store's own
// test helper (initRepo in core/store/store_test.go) — the poll must be
// proven against the actual git-backed store, not a fake.
func initRepo(t *testing.T) string {
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

// openStore opens a REAL store on a fresh initRepo temp dir.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(initRepo(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return s
}

// ghPullResponse is the (trimmed) shape of GitHub's real
// GET /repos/<owner>/<repo>/pulls/<n> response — only the fields
// githubFetcher reads.
type ghPullResponse struct {
	State  string `json:"state"`
	Merged bool   `json:"merged"`
}

// fakeGitHubAPI stands in for GitHub's public REST API: a REAL local HTTP
// server (httptest.NewServer) that the production githubFetcher makes a REAL
// HTTP round trip against — nothing about the fetch path itself is mocked or
// faked, only the far end of the network is redirected to localhost, exactly
// the precedent pkg/notify/discord_test.go already sets for this codebase's
// other "notify an external HTTP endpoint" features.
func fakeGitHubAPI(t *testing.T, byPath map[string]ghPullResponse) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, ok := byPath[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("fakeGitHubAPI: request to %s carried an Authorization header %q — the poll must be unauthenticated", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestParsePRURL(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		wantOwner string
		wantRepo  string
		wantNum   int
		wantErr   bool
	}{
		{"valid", "https://github.com/mallcop-app/mallcop/pull/42", "mallcop-app", "mallcop", 42, false},
		{"valid single digit", "https://github.com/acme/widget/pull/7", "acme", "widget", 7, false},
		{"not github", "https://gitlab.com/acme/widget/pull/7", "", "", 0, true},
		{"not a PR path", "https://github.com/acme/widget/issues/7", "", "", 0, true},
		{"non-numeric", "https://github.com/acme/widget/pull/abc", "", "", 0, true},
		{"trailing slash rejected", "https://github.com/acme/widget/pull/7/", "", "", 0, true},
		{"trailing garbage rejected", "https://github.com/acme/widget/pull/7?tab=files", "", "", 0, true},
		{"empty", "", "", "", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			owner, repo, num, err := ParsePRURL(c.url)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParsePRURL(%q) = (%q,%q,%d,nil), want an error", c.url, owner, repo, num)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePRURL(%q): %v", c.url, err)
			}
			if owner != c.wantOwner || repo != c.wantRepo || num != c.wantNum {
				t.Fatalf("ParsePRURL(%q) = (%q,%q,%d), want (%q,%q,%d)", c.url, owner, repo, num, c.wantOwner, c.wantRepo, c.wantNum)
			}
		})
	}
}

// TestPollOutcomes_MergedUpdatesRecord proves the primary user workflow: a
// contribute-back record with an open PR URL, polled against a PR the fake
// GitHub API reports merged, gets a FRESH row appended with State=merged —
// through the REAL store (real git commit) and a REAL HTTP round trip to a
// local server.
func TestPollOutcomes_MergedUpdatesRecord(t *testing.T) {
	s := openStore(t)
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{
		"/repos/mallcop-app/mallcop/pulls/42": {State: "closed", Merged: true},
	})

	openedAt := time.Now().UTC().Add(-72 * time.Hour)
	seed := store.ContribBackRecord{
		Fingerprint: "abcdef0123456789",
		PRURL:       "https://github.com/mallcop-app/mallcop/pull/42",
		State:       store.ContribBackOpen,
		OpenedAt:    openedAt,
		UpdatedAt:   openedAt,
	}
	if _, err := s.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	sum, err := PollOutcomes(context.Background(), s, NewGitHubFetcher(srv.URL))
	if err != nil {
		t.Fatalf("PollOutcomes: %v", err)
	}
	if sum.Considered != 1 || sum.Updated != 1 || sum.Failed != 0 {
		t.Fatalf("PollOutcomes summary = %+v, want {Considered:1 Updated:1 Failed:0}", sum)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadContribBackRecords = %d rows, want 2 (opened + merged, never mutated in place)", len(got))
	}
	if got[0].State != store.ContribBackOpen {
		t.Errorf("original opened row mutated: %+v", got[0])
	}
	if got[1].State != store.ContribBackMerged {
		t.Errorf("second row State = %q, want %q", got[1].State, store.ContribBackMerged)
	}
	if got[1].PRURL != seed.PRURL || !got[1].OpenedAt.Equal(openedAt) {
		t.Errorf("second row = %+v, want PRURL=%s OpenedAt=%v preserved", got[1], seed.PRURL, openedAt)
	}
}

// TestPollOutcomes_ClosedUnmergedUpdatesRecord proves the second acceptance
// path: a PR closed WITHOUT merging becomes State=closed.
func TestPollOutcomes_ClosedUnmergedUpdatesRecord(t *testing.T) {
	s := openStore(t)
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{
		"/repos/mallcop-app/mallcop/pulls/9": {State: "closed", Merged: false},
	})

	seed := store.ContribBackRecord{
		PRURL:     "https://github.com/mallcop-app/mallcop/pull/9",
		State:     store.ContribBackOpen,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := s.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	sum, err := PollOutcomes(context.Background(), s, NewGitHubFetcher(srv.URL))
	if err != nil {
		t.Fatalf("PollOutcomes: %v", err)
	}
	if sum.Updated != 1 {
		t.Fatalf("PollOutcomes summary = %+v, want Updated=1", sum)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 2 || got[1].State != store.ContribBackClosed {
		t.Fatalf("rows = %+v, want 2 rows with the second State=%q", got, store.ContribBackClosed)
	}
}

// TestPollOutcomes_StillOpen_NoChurn proves the idempotency half of the
// mallcoppro-42e discipline: a re-poll that observes the SAME state (still
// open) appends NOTHING — no duplicate row, no churn.
func TestPollOutcomes_StillOpen_NoChurn(t *testing.T) {
	s := openStore(t)
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{
		"/repos/mallcop-app/mallcop/pulls/3": {State: "open", Merged: false},
	})

	seed := store.ContribBackRecord{
		PRURL:     "https://github.com/mallcop-app/mallcop/pull/3",
		State:     store.ContribBackOpen,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := s.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	fetcher := NewGitHubFetcher(srv.URL)
	for i := 0; i < 3; i++ {
		sum, err := PollOutcomes(context.Background(), s, fetcher)
		if err != nil {
			t.Fatalf("PollOutcomes call %d: %v", i, err)
		}
		if sum.Updated != 0 {
			t.Fatalf("PollOutcomes call %d summary = %+v, want Updated=0 (still open)", i, sum)
		}
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadContribBackRecords = %d rows after 3 no-op polls, want 1 (no churn)", len(got))
	}
}

// TestPollOutcomes_MergedThenIdempotentAcrossRescans proves idempotency
// across the FULL lifecycle: once a record has flipped to merged, a later
// re-scan no longer even considers it (it is no longer State==open), so
// re-polling appends nothing further — mirroring mallcoppro-42e's "a genuine
// re-run stays idempotent" guarantee.
func TestPollOutcomes_MergedThenIdempotentAcrossRescans(t *testing.T) {
	s := openStore(t)
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{
		"/repos/mallcop-app/mallcop/pulls/42": {State: "closed", Merged: true},
	})
	fetcher := NewGitHubFetcher(srv.URL)

	seed := store.ContribBackRecord{
		PRURL:     "https://github.com/mallcop-app/mallcop/pull/42",
		State:     store.ContribBackOpen,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := s.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	if sum, err := PollOutcomes(context.Background(), s, fetcher); err != nil || sum.Updated != 1 {
		t.Fatalf("first PollOutcomes = %+v, err=%v, want Updated=1 nil-err", sum, err)
	}
	// Second scan: the record is now State==merged, no longer "open" — the
	// poll must not even consider it, let alone append again.
	sum, err := PollOutcomes(context.Background(), s, fetcher)
	if err != nil {
		t.Fatalf("second PollOutcomes: %v", err)
	}
	if sum.Considered != 0 || sum.Updated != 0 {
		t.Fatalf("second PollOutcomes summary = %+v, want {Considered:0 Updated:0} (merged record no longer polled)", sum)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadContribBackRecords = %d rows after 2 scans, want 2 (opened + merged, no further churn)", len(got))
	}
}

// TestPollOutcomes_UnreachableDegradesHonestly proves the failure-mode
// acceptance criterion: an unreachable/deleted/404 PR degrades HONESTLY (the
// record is left in its truthful last-known state, nothing is fabricated)
// and PollOutcomes returns no error — a scan that otherwise succeeded must
// never fail over this.
func TestPollOutcomes_UnreachableDegradesHonestly(t *testing.T) {
	s := openStore(t)
	// fakeGitHubAPI with NO matching path == every request 404s, exactly
	// like a deleted PR or a typo'd number would against the real API.
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{})

	seed := store.ContribBackRecord{
		PRURL:     "https://github.com/mallcop-app/mallcop/pull/404",
		State:     store.ContribBackOpen,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := s.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	sum, err := PollOutcomes(context.Background(), s, NewGitHubFetcher(srv.URL))
	if err != nil {
		t.Fatalf("PollOutcomes must not return an error on a 404: %v", err)
	}
	if sum.Failed != 1 || sum.Updated != 0 {
		t.Fatalf("PollOutcomes summary = %+v, want {Failed:1 Updated:0}", sum)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 1 || got[0].State != store.ContribBackOpen {
		t.Fatalf("rows = %+v, want exactly the original untouched open row (honest degrade, no fabricated outcome)", got)
	}
}

// TestPollOutcomes_NetworkDownDoesNotError proves the same honesty guarantee
// against a fully unreachable server (connection refused), not just a 404 —
// the closest analogue to "network failure must not break a scan that
// otherwise succeeded."
func TestPollOutcomes_NetworkDownDoesNotError(t *testing.T) {
	s := openStore(t)
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{
		"/repos/mallcop-app/mallcop/pulls/1": {State: "open"},
	})
	deadURL := srv.URL
	srv.Close() // close it immediately: every request now hits a dead port.

	seed := store.ContribBackRecord{
		PRURL:     "https://github.com/mallcop-app/mallcop/pull/1",
		State:     store.ContribBackOpen,
		OpenedAt:  time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if _, err := s.Append(store.KindContribBack, seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	sum, err := PollOutcomes(context.Background(), s, NewGitHubFetcher(deadURL))
	if err != nil {
		t.Fatalf("PollOutcomes must not return an error on a network failure: %v", err)
	}
	if sum.Failed != 1 {
		t.Fatalf("PollOutcomes summary = %+v, want Failed=1", sum)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 1 || got[0].State != store.ContribBackOpen {
		t.Fatalf("rows = %+v, want the original untouched open row", got)
	}
}

// TestPollOutcomes_MultipleRecords_OnlyOpenOnesConsidered proves PollOutcomes
// leaves already-terminal records (merged/closed) alone, and folds the stream
// to the latest row per PRURL, when multiple PRs are tracked at once.
func TestPollOutcomes_MultipleRecords_OnlyOpenOnesConsidered(t *testing.T) {
	s := openStore(t)
	srv := fakeGitHubAPI(t, map[string]ghPullResponse{
		"/repos/mallcop-app/mallcop/pulls/1": {State: "open"},
		"/repos/mallcop-app/mallcop/pulls/2": {State: "closed", Merged: true},
	})

	now := time.Now().UTC()
	alreadyMerged := store.ContribBackRecord{PRURL: "https://github.com/mallcop-app/mallcop/pull/1", State: store.ContribBackMerged, OpenedAt: now, UpdatedAt: now}
	openB := store.ContribBackRecord{PRURL: "https://github.com/mallcop-app/mallcop/pull/2", State: store.ContribBackOpen, OpenedAt: now, UpdatedAt: now}

	for _, r := range []store.ContribBackRecord{alreadyMerged, openB} {
		if _, err := s.Append(store.KindContribBack, r); err != nil {
			t.Fatalf("seed Append: %v", err)
		}
	}

	sum, err := PollOutcomes(context.Background(), s, NewGitHubFetcher(srv.URL))
	if err != nil {
		t.Fatalf("PollOutcomes: %v", err)
	}
	// Only PR #2 (openB) was State==open; PR #1's latest row was already
	// merged, so it must not be considered at all.
	if sum.Considered != 1 || sum.Updated != 1 {
		t.Fatalf("PollOutcomes summary = %+v, want {Considered:1 Updated:1} (only the open PR #2 polled)", sum)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("LoadContribBackRecords = %d rows, want 3 (2 seeded + 1 new merged row for PR #2)", len(got))
	}
	if got[2].PRURL != openB.PRURL || got[2].State != store.ContribBackMerged {
		t.Fatalf("new row = %+v, want PR #2 merged", got[2])
	}
}

// TestPollOutcomes_NilStoreOrFetcher_NoPanic proves the nil-safe defaults: a
// caller that hasn't wired a store or fetcher gets a zero Summary and no
// error, never a panic.
func TestPollOutcomes_NilStoreOrFetcher_NoPanic(t *testing.T) {
	if sum, err := PollOutcomes(context.Background(), nil, NewGitHubFetcher("")); err != nil || sum != (PollSummary{}) {
		t.Fatalf("PollOutcomes(nil store) = %+v, %v, want zero Summary, nil error", sum, err)
	}
	s := openStore(t)
	if sum, err := PollOutcomes(context.Background(), s, nil); err != nil || sum != (PollSummary{}) {
		t.Fatalf("PollOutcomes(nil fetcher) = %+v, %v, want zero Summary, nil error", sum, err)
	}
}

// TestNewGitHubFetcher_NeverAuthenticates proves the production fetcher sends
// no credential of any kind — the shared repo is public and this is a design
// invariant (R8), not an incidental property.
func TestNewGitHubFetcher_NeverAuthenticates(t *testing.T) {
	var sawAuth, sawCookie bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		if r.Header.Get("Cookie") != "" {
			sawCookie = true
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"state":"open","merged":false}`)
	}))
	defer srv.Close()

	if _, err := NewGitHubFetcher(srv.URL).FetchPRState(context.Background(), "acme", "widget", 1); err != nil {
		t.Fatalf("FetchPRState: %v", err)
	}
	if sawAuth || sawCookie {
		t.Fatalf("githubFetcher sent a credential (Authorization=%v Cookie=%v) — the shared repo read must be unauthenticated", sawAuth, sawCookie)
	}
}

// TestNewGitHubFetcher_DefaultsToRealAPIBase proves the empty-string default
// resolves to the real GitHub API host, not an empty/broken URL — verified by
// inspecting the constructed request path shape via a non-empty override
// vs the documented constant, since we must not make a live network call in
// a unit test.
func TestNewGitHubFetcher_DefaultsToRealAPIBase(t *testing.T) {
	f, ok := NewGitHubFetcher("").(*githubFetcher)
	if !ok {
		t.Fatalf("NewGitHubFetcher(\"\") did not return *githubFetcher")
	}
	if f.apiBase != defaultGitHubAPIBase {
		t.Fatalf("NewGitHubFetcher(\"\").apiBase = %q, want %q", f.apiBase, defaultGitHubAPIBase)
	}
}

// TestLatestByURL_FoldsToMostRecentRowPerURL is a focused unit test of the
// fold helper the mallcoppro-42e idempotency discipline depends on.
func TestLatestByURL_FoldsToMostRecentRowPerURL(t *testing.T) {
	recs := []store.ContribBackRecord{
		{PRURL: "https://github.com/a/b/pull/1", State: store.ContribBackOpen},
		{PRURL: "https://github.com/a/b/pull/2", State: store.ContribBackOpen},
		{PRURL: "https://github.com/a/b/pull/1", State: store.ContribBackMerged},
	}
	got := latestByURL(recs)
	if len(got) != 2 {
		t.Fatalf("latestByURL returned %d records, want 2 (one per distinct URL)", len(got))
	}
	byURL := map[string]store.ContribBackRecord{}
	for _, r := range got {
		byURL[r.PRURL] = r
	}
	if byURL["https://github.com/a/b/pull/1"].State != store.ContribBackMerged {
		t.Fatalf("latestByURL kept the STALE row for pull/1, want the later merged row: %+v", got)
	}
	if byURL["https://github.com/a/b/pull/2"].State != store.ContribBackOpen {
		t.Fatalf("latestByURL wrong state for pull/2: %+v", got)
	}
}
