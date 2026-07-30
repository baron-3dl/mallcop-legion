package contribback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
)

// fakePR is a PROpener that records OpenPR calls AND exposes a Merge method the
// production Opener can never reach (PROpener has no Merge). The test asserts
// mergeCalls stays 0 at every dial — proving by construction that contribute-back
// never merges regardless of the autonomy dial.
type fakePR struct {
	openCalls  int
	mergeCalls int
	lastReq    PRRequest
	url        string
	err        error
}

func (f *fakePR) OpenPR(_ context.Context, req PRRequest) (PRResult, error) {
	f.openCalls++
	f.lastReq = req
	if f.err != nil {
		return PRResult{}, f.err
	}
	url := f.url
	if url == "" {
		url = "https://github.com/mallcop-app/mallcop/pull/1"
	}
	return PRResult{URL: url}, nil
}

// Merge is deliberately NOT part of the PROpener interface. It exists only so the
// test can prove the Opener never invokes any merge path: if a future change ever
// wired merging in, this counter would have to move, and the invariant test would
// fail. Today it can never be called through the Opener.
func (f *fakePR) Merge(context.Context, PRRequest) error {
	f.mergeCalls++
	return nil
}

func eligibleArtifact() Artifact {
	return Artifact{
		Fingerprint: "abcdef0123456789",
		Consented:   true,
		Universal:   true,
		Title:       "selfext(contribute-back): universal detection widen",
		Body:        "body",
	}
}

// enabledOpener wires a REAL store (openStore, poll_test.go's helper: a real
// `git init` temp repo, real git-commit Append) — Contribute persists the
// opened-PR record through this exact handle, so every test that reaches a
// successful OpenPR is exercising the real store-append path, not a fake.
func enabledOpener(t *testing.T, pr PROpener) *Opener {
	t.Helper()
	return &Opener{
		Config: Config{Enabled: true, Repo: "mallcop-app/mallcop"},
		PR:     pr,
		Store:  openStore(t),
	}
}

// (a) Contribute-back is OFF BY DEFAULT: the zero-value Config is disabled, so an
// eligible, consented, universal artifact opens NO shared-OSS PR.
func TestContributeOffByDefault(t *testing.T) {
	pr := &fakePR{}
	// Zero-value Config — the operator did nothing to opt in.
	o := &Opener{PR: pr}
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if out.Opened || out.Attempted {
		t.Fatalf("default-off Opener opened/attempted a PR: %+v", out)
	}
	if pr.openCalls != 0 {
		t.Fatalf("default-off Opener called OpenPR %d times, want 0", pr.openCalls)
	}
	if !strings.Contains(out.SkipReason, "disabled") {
		t.Errorf("SkipReason = %q, want a 'disabled' reason", out.SkipReason)
	}
}

// (b) At EVERY dial — including the most-autonomous "fully"/yolo tier and even an
// unrecognized "more autonomous than fully" value — an enabled + eligible
// contribute-back OPENS the shared-OSS PR but NEVER merges it.
func TestContributeOpensButNeverMergesAtEveryDial(t *testing.T) {
	dials := []autonomy.Dial{
		autonomy.NonAutonomy,
		autonomy.SemiAutonomy,
		autonomy.FullyAutonomy,            // the most-autonomous defined tier == "yolo"
		autonomy.Dial("yolo"),             // the R3 name for the top tier, unrecognized here
		autonomy.Dial("ultra-permissive"), // a hypothetical value beyond the dial
	}
	for _, dial := range dials {
		t.Run(string(dial), func(t *testing.T) {
			pr := &fakePR{}
			o := enabledOpener(t, pr)
			out, err := o.Contribute(context.Background(), dial, eligibleArtifact())
			if err != nil {
				t.Fatalf("Contribute(dial=%q): %v", dial, err)
			}
			if !out.Opened {
				t.Fatalf("dial=%q: PR not opened: %+v", dial, out)
			}
			if pr.openCalls != 1 {
				t.Fatalf("dial=%q: OpenPR called %d times, want 1", dial, pr.openCalls)
			}
			// THE HARD LINE: no merge, at any dial.
			if pr.mergeCalls != 0 {
				t.Fatalf("dial=%q: contribute-back MERGED the shared-OSS PR (mergeCalls=%d) — hard-line violation", dial, pr.mergeCalls)
			}
			if out.PRURL == "" {
				t.Errorf("dial=%q: opened PR has no URL", dial)
			}
		})
	}
}

// (c) DISABLED → no shared PR, even for a fully-eligible artifact at the top dial.
func TestContributeDisabledNoSharedPR(t *testing.T) {
	pr := &fakePR{}
	o := &Opener{Config: Config{Enabled: false, Repo: "mallcop-app/mallcop"}, PR: pr}
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.openCalls != 0 || out.Opened {
		t.Fatalf("disabled Opener opened a PR: openCalls=%d out=%+v", pr.openCalls, out)
	}
}

// Defense in depth: even enabled, a non-consented artifact opens no PR.
func TestContributeNotConsentedNoPR(t *testing.T) {
	pr := &fakePR{}
	o := enabledOpener(t, pr)
	art := eligibleArtifact()
	art.Consented = false
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.openCalls != 0 || out.Opened {
		t.Fatalf("non-consented artifact opened a PR: %+v", out)
	}
	if !strings.Contains(out.SkipReason, "consent") {
		t.Errorf("SkipReason = %q, want a 'consent' reason", out.SkipReason)
	}
}

// Defense in depth: a tenant-specific (non-universal) widen opens no PR.
func TestContributeNotUniversalNoPR(t *testing.T) {
	pr := &fakePR{}
	o := enabledOpener(t, pr)
	art := eligibleArtifact()
	art.Universal = false
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.openCalls != 0 || out.Opened {
		t.Fatalf("non-universal artifact opened a PR: %+v", out)
	}
	if !strings.Contains(out.SkipReason, "universal") {
		t.Errorf("SkipReason = %q, want a 'universal' reason", out.SkipReason)
	}
}

// The Opener passes the configured target repo + branch through to the PR opener.
func TestContributeUsesConfiguredRepoAndBranch(t *testing.T) {
	pr := &fakePR{}
	o := &Opener{Config: Config{Enabled: true, Repo: "mallcop-app/mallcop", BaseBranch: "trunk"}, PR: pr, Store: openStore(t)}
	if _, err := o.Contribute(context.Background(), autonomy.SemiAutonomy, eligibleArtifact()); err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if pr.lastReq.Repo != "mallcop-app/mallcop" {
		t.Errorf("repo = %q, want mallcop-app/mallcop", pr.lastReq.Repo)
	}
	if pr.lastReq.BaseBranch != "trunk" {
		t.Errorf("base = %q, want trunk", pr.lastReq.BaseBranch)
	}
	if pr.lastReq.HeadBranch != "contribback/abcdef012345" {
		t.Errorf("head = %q, want contribback/abcdef012345", pr.lastReq.HeadBranch)
	}
}

// ghArgs never carries a token/credential flag — the operator's ambient gh auth
// opens the PR (R8: no standing write credential).
func TestGHArgsCarriesNoCredential(t *testing.T) {
	args := ghArgs(PRRequest{
		Repo: "mallcop-app/mallcop", BaseBranch: "main", HeadBranch: "contribback/x",
		Title: "t", Body: "b",
	})
	joined := strings.ToLower(strings.Join(args, " "))
	for _, banned := range []string{"token", "--auth", "password", "credential", "gh_token", "github_token"} {
		if strings.Contains(joined, banned) {
			t.Errorf("gh args contain a credential-ish flag %q: %v", banned, args)
		}
	}
	// Sanity: the essential PR flags are present.
	for _, want := range []string{"pr", "create", "--repo", "--base", "--head", "--title", "--body"} {
		if !containsArg(args, want) {
			t.Errorf("gh args missing %q: %v", want, args)
		}
	}
}

// ghOpener parses the PR URL from gh's output and never merges.
func TestGHOpenerParsesURL(t *testing.T) {
	g := &ghOpener{run: func(_ context.Context, _ string, _ ...string) (string, error) {
		return "https://github.com/mallcop-app/mallcop/pull/42\n", nil
	}}
	res, err := g.OpenPR(context.Background(), PRRequest{Repo: "mallcop-app/mallcop", BaseBranch: "main", HeadBranch: "contribback/x", Title: "t", Body: "b"})
	if err != nil {
		t.Fatalf("OpenPR: %v", err)
	}
	if res.URL != "https://github.com/mallcop-app/mallcop/pull/42" {
		t.Errorf("URL = %q", res.URL)
	}
}

// LoadArtifact distills a router-emitted OSS-PR artifact into an eligible
// Artifact (Consented + Universal), wiring the router's output to the opener.
func TestLoadArtifactFromRouterEmission(t *testing.T) {
	// Shape mirrors router.ossArtifact's on-disk JSON (proposal/gate/provenance/note).
	raw := map[string]any{
		"proposal": map[string]any{
			"kind": "mapping",
			"mapping": map[string]any{
				"source": "github", "raw_action": "repo.rename", "event_type": "config_change",
			},
			"universal":   true,
			"fingerprint": "deadbeefcafebabe0001",
			"model":       "investigate",
		},
		"note": "OSS contribute-back proposal.",
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "oss-pr-deadbeefcafe-20260713-000000.json")
	data, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	art, err := LoadArtifact(path)
	if err != nil {
		t.Fatalf("LoadArtifact: %v", err)
	}
	if !art.Consented {
		t.Error("loaded artifact must be Consented (router only emits on consent)")
	}
	if !art.Universal {
		t.Error("loaded artifact must be Universal")
	}
	if art.Fingerprint != "deadbeefcafebabe0001" {
		t.Errorf("fingerprint = %q", art.Fingerprint)
	}
	if !strings.Contains(art.Title, "config_change") {
		t.Errorf("title = %q, want the mapping target", art.Title)
	}
	if !strings.Contains(art.Body, "NOT auto-merged") {
		t.Errorf("body must state the PR is not auto-merged: %q", art.Body)
	}
	if art.HeadBranch() != "contribback/deadbeefcafe" {
		t.Errorf("head branch = %q", art.HeadBranch())
	}

	// End-to-end wiring: the loaded artifact opens a PR (not merged) when enabled.
	pr := &fakePR{}
	o := enabledOpener(t, pr)
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute(loaded): %v", err)
	}
	if !out.Opened || pr.mergeCalls != 0 {
		t.Fatalf("loaded artifact: opened=%v merges=%d, want opened + zero merges", out.Opened, pr.mergeCalls)
	}
	// mallcoppro-003 veracity rework: Contribute must have PERSISTED a
	// ContribBackRecord through the real store — nothing in this test hand-
	// seeds one.
	recs, err := o.Store.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("LoadContribBackRecords = %d records, want exactly 1 persisted by Contribute itself", len(recs))
	}
	if recs[0].PRURL != out.PRURL || recs[0].State != store.ContribBackOpen || recs[0].Fingerprint != art.Fingerprint {
		t.Errorf("persisted record = %+v, want PRURL=%s State=open Fingerprint=%s", recs[0], out.PRURL, art.Fingerprint)
	}
	if recs[0].OpenedAt.IsZero() || recs[0].UpdatedAt.IsZero() {
		t.Errorf("persisted record has zero OpenedAt/UpdatedAt: %+v", recs[0])
	}
}

// LoadCodeArtifact distills a CODE-lane authored-detector artifact into an
// eligible Artifact (Consented + Universal, Lane=code), maps each customer-repo
// file to its OSS core/detect/authored/<name>/ destination, and composes a PR
// body that states the promotion must pass the OSS repo's own exam.yml +
// CODEOWNERS review and is never auto-merged. (the code lane
// had no artifact at all.)
func TestLoadCodeArtifact_MapsToPRRequest(t *testing.T) {
	raw := map[string]any{
		"kind": "authored_detector",
		"detector": map[string]any{
			"name": "deploy-burst",
			"files": []string{
				"detectors/deploy-burst/detector.go",
				"detectors/deploy-burst/detector_test.go",
				"detectors/deploy-burst/scenarios/burst.jsonl",
			},
		},
		"provenance": map[string]any{
			"fingerprint": "c0ffee1234567890abcd",
			"gate_ref":    "headsha-abc123",
		},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "code-pr-c0ffee123456-20260714-000000.json")
	data, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	art, err := LoadCodeArtifact(path)
	if err != nil {
		t.Fatalf("LoadCodeArtifact: %v", err)
	}
	if art.Lane != LaneCode {
		t.Errorf("lane = %q, want %q", art.Lane, LaneCode)
	}
	if !art.Consented || !art.Universal {
		t.Errorf("code artifact must be Consented+Universal: %+v", art)
	}
	if art.DetectorName != "deploy-burst" {
		t.Errorf("detector name = %q", art.DetectorName)
	}
	if art.GateRef != "headsha-abc123" {
		t.Errorf("gate ref = %q", art.GateRef)
	}
	// Every promoted file maps detectors/<name>/... -> core/detect/authored/<name>/...
	wantDest := map[string]string{
		"detectors/deploy-burst/detector.go":           "core/detect/authored/deploy-burst/detector.go",
		"detectors/deploy-burst/detector_test.go":      "core/detect/authored/deploy-burst/detector_test.go",
		"detectors/deploy-burst/scenarios/burst.jsonl": "core/detect/authored/deploy-burst/scenarios/burst.jsonl",
	}
	if len(art.Files) != len(wantDest) {
		t.Fatalf("promoted %d files, want %d: %+v", len(art.Files), len(wantDest), art.Files)
	}
	for _, f := range art.Files {
		if wantDest[f.Src] != f.Dest {
			t.Errorf("file %q -> %q, want %q", f.Src, f.Dest, wantDest[f.Src])
		}
	}
	// Deterministic head branch stays contribback/<short-fp> (idempotent re-run).
	if art.HeadBranch() != "contribback/c0ffee123456" {
		t.Errorf("head branch = %q", art.HeadBranch())
	}
	if !strings.Contains(art.Title, "deploy-burst") || !strings.Contains(art.Title, "promote") {
		t.Errorf("title = %q, want the promotion + detector name", art.Title)
	}
	for _, want := range []string{"NOT auto-merged", "exam.yml", "CODEOWNERS", "c0ffee1234567890abcd", "core/detect/authored/deploy-burst"} {
		if !strings.Contains(art.Body, want) {
			t.Errorf("body missing %q:\n%s", want, art.Body)
		}
	}

	// End-to-end: the loaded code artifact maps to a PRRequest and opens a PR
	// (NOT merged) when enabled, at the top dial.
	pr := &fakePR{}
	o := enabledOpener(t, pr)
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, art)
	if err != nil {
		t.Fatalf("Contribute(code): %v", err)
	}
	if !out.Opened || pr.mergeCalls != 0 {
		t.Fatalf("code artifact: opened=%v merges=%d, want opened + zero merges", out.Opened, pr.mergeCalls)
	}
	if pr.lastReq.HeadBranch != "contribback/c0ffee123456" {
		t.Errorf("PRRequest head branch = %q", pr.lastReq.HeadBranch)
	}
	if pr.lastReq.Title != art.Title {
		t.Errorf("PRRequest title = %q, want %q", pr.lastReq.Title, art.Title)
	}
	// mallcoppro-003 veracity rework: the CODE lane persists exactly like the
	// DATA lane — Contribute is lane-agnostic about the persist step.
	recs, err := o.Store.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(recs) != 1 || recs[0].PRURL != out.PRURL || recs[0].State != store.ContribBackOpen {
		t.Fatalf("persisted records = %+v, want exactly 1 open record for %s", recs, out.PRURL)
	}
	if recs[0].Fingerprint != art.Fingerprint {
		t.Errorf("persisted fingerprint = %q, want %q", recs[0].Fingerprint, art.Fingerprint)
	}
}

// A code artifact with the wrong kind (a DATA-lane file) is rejected — the two
// lanes never cross-load.
func TestLoadCodeArtifact_RejectsWrongKind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oss-pr.json")
	if err := os.WriteFile(path, []byte(`{"proposal":{"kind":"mapping","fingerprint":"abc"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCodeArtifact(path); err == nil {
		t.Fatal("expected LoadCodeArtifact to reject a non-authored_detector file")
	}
}

// TestContribute_ThenPollOutcomes_FullLoopFromRealPersist is the primary
// mallcoppro-003 veracity-rework proof: it exercises the ENTIRE contribute-
// back loop -- open, persist, poll, update -- with NO hand-seeded
// ContribBackRecord anywhere in this test. Contribute must persist the
// opened-PR record itself (the defect the rework closes: OpenPR returning a
// URL is not the same as writing it anywhere); PollOutcomes then reads that
// SAME real store and a real local HTTP server (standing in for GitHub's
// public API) to observe the PR merged, and appends the updated row.
func TestContribute_ThenPollOutcomes_FullLoopFromRealPersist(t *testing.T) {
	s := openStore(t)
	pr := &fakePR{url: "https://github.com/mallcop-app/mallcop/pull/999"}
	o := &Opener{
		Config: Config{Enabled: true, Repo: "mallcop-app/mallcop"},
		PR:     pr,
		Store:  s,
	}

	// (1) OPEN: Contribute opens the PR and must persist the record ITSELF --
	// this test never calls s.Append(KindContribBack, ...) directly.
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err != nil {
		t.Fatalf("Contribute: %v", err)
	}
	if !out.Opened || out.PRURL != pr.url {
		t.Fatalf("Contribute out = %+v, want Opened with PRURL=%s", out, pr.url)
	}

	preRecs, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords after open: %v", err)
	}
	if len(preRecs) != 1 || preRecs[0].State != store.ContribBackOpen || preRecs[0].PRURL != pr.url {
		t.Fatalf("post-open records = %+v, want exactly 1 open record for %s persisted by Contribute itself", preRecs, pr.url)
	}

	// (2) POLL: a later scan asks a real local HTTP server (the GitHub
	// public-API stand-in) whether the PR merged.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/mallcop-app/mallcop/pulls/999" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "closed", "merged": true})
	}))
	defer srv.Close()

	sum, err := PollOutcomes(context.Background(), s, NewGitHubFetcher(srv.URL))
	if err != nil {
		t.Fatalf("PollOutcomes: %v", err)
	}
	if sum.Considered != 1 || sum.Updated != 1 || sum.Failed != 0 {
		t.Fatalf("poll summary = %+v, want Considered=1 Updated=1 Failed=0", sum)
	}

	// (3) VERIFY: the outcome flowed back -- the fire-and-forget gap this
	// item closes.
	postRecs, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords after poll: %v", err)
	}
	if len(postRecs) != 2 {
		t.Fatalf("post-poll records = %d, want 2 (opened + merged rows, never mutated in place)", len(postRecs))
	}
	if postRecs[0].State != store.ContribBackOpen {
		t.Errorf("first row mutated: %+v", postRecs[0])
	}
	if postRecs[1].State != store.ContribBackMerged || postRecs[1].PRURL != pr.url {
		t.Errorf("second row = %+v, want State=merged PRURL=%s", postRecs[1], pr.url)
	}
}

// TestContribute_NilStore_FailsBeforeOpeningNotAfter proves the Store-wiring
// guard fires BEFORE any PR is opened: an enabled Opener with no Store wired
// is a configuration bug (mallcoppro-003: the operator forgot to wire the
// handle that makes the opened PR pollable), and it must fail closed rather
// than open an orphan PR nothing can ever poll.
func TestContribute_NilStore_FailsBeforeOpeningNotAfter(t *testing.T) {
	pr := &fakePR{}
	o := &Opener{Config: Config{Enabled: true, Repo: "mallcop-app/mallcop"}, PR: pr}
	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err == nil {
		t.Fatal("Contribute: want an error when Store is nil (enabled but not wired), got nil")
	}
	if out.Opened {
		t.Errorf("out.Opened = true, want false -- a nil Store must be caught before OpenPR is ever called")
	}
	if pr.openCalls != 0 {
		t.Errorf("OpenPR called %d times with a nil Store, want 0 (fail before opening an unpollable orphan PR)", pr.openCalls)
	}
}

// TestContribute_StoreAppendFailure_ReportsErrorNotSilentLoss proves the
// opposite failure mode never regresses: if persisting the opened-PR record
// fails, Contribute returns an error (rather than silently reporting success
// while the record never lands) -- the exact silent-loss shape this rework
// closes, now made impossible even under a REAL git-plumbing failure (the
// repo's object store made unwritable), not a fake error injected via an
// interface.
func TestContribute_StoreAppendFailure_ReportsErrorNotSilentLoss(t *testing.T) {
	dir := initRepo(t)
	s, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	objDir := filepath.Join(dir, ".git", "objects")
	if err := os.Chmod(objDir, 0o500); err != nil {
		t.Fatalf("chmod objects dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(objDir, 0o700) }) // let t.TempDir() clean up

	pr := &fakePR{}
	o := &Opener{Config: Config{Enabled: true, Repo: "mallcop-app/mallcop"}, PR: pr, Store: s}

	out, err := o.Contribute(context.Background(), autonomy.FullyAutonomy, eligibleArtifact())
	if err == nil {
		t.Fatal("Contribute: want an error when the store append fails (unwritable object store), got nil")
	}
	if !out.Opened {
		t.Errorf("out.Opened = false, want true (the PR itself DID open on GitHub before the persist failed)")
	}
	if !strings.Contains(err.Error(), "persist") {
		t.Errorf("error = %q, want it to name the persist failure", err.Error())
	}
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
