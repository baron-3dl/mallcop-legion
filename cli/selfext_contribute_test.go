package cli

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/contribback"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"github.com/mallcop-app/mallcop/selfext/router"
)

// silentLogger discards log output so tests don't spam stderr.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakePROpener is a contribback.PROpener test double that records calls and
// returns a canned PR URL. It never shells out to a real `gh` — this is the
// injection point contributeArtifacts exposes precisely so a test can assert
// against it without a live GitHub credential.
type fakePROpener struct {
	calls   int
	lastReq contribback.PRRequest
	url     string
	err     error
}

func (f *fakePROpener) OpenPR(_ context.Context, req contribback.PRRequest) (contribback.PRResult, error) {
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return contribback.PRResult{}, f.err
	}
	url := f.url
	if url == "" {
		url = "https://github.com/mallcop-app/mallcop/pull/42"
	}
	return contribback.PRResult{URL: url}, nil
}

// fakePRStateFetcher is a contribback.PRStateFetcher test double for driving
// PollOutcomes without a live GitHub API call.
type fakePRStateFetcher struct {
	state contribback.PRState
}

func (f fakePRStateFetcher) FetchPRState(context.Context, string, string, int) (contribback.PRState, error) {
	return f.state, nil
}

// realRoutedArtifact drives the REAL selfext/router package (Router.Route) to
// emit a genuine oss-pr-*.json contribute-back artifact into
// <artifactBase>/oss — the exact shape and location `mallcop selfext
// --propose --consent` produces in production. Tests use this instead of
// hand-authoring artifact JSON so the discovery+load path is proven against
// what the router actually writes, not an approximation of it.
func realRoutedArtifact(t *testing.T, artifactBase, fingerprint string) router.Decision {
	t.Helper()
	rejects, err := engine.LoadRejectSet(t.TempDir())
	if err != nil {
		t.Fatalf("engine.LoadRejectSet: %v", err)
	}
	rt := &router.Router{
		KnownEventTypes: map[string]bool{"config_change": true},
		OverlayDir:      filepath.Join(t.TempDir(), "overlay"),
		ArtifactDir:     filepath.Join(artifactBase, "oss"),
		ProvenanceDir:   filepath.Join(t.TempDir(), "prov"),
		Fingerprints:    rejects,
		Autonomy:        autonomy.SemiAutonomy,
	}
	prop := proposer.Proposal{
		Kind:        proposer.KindMapping,
		Mapping:     &proposer.MappingProposal{Source: "github", RawAction: "repo.rename", EventType: "config_change"},
		Universal:   true,
		Fingerprint: fingerprint,
		Model:       "investigate",
		Endpoint:    "https://forge.example.test",
	}
	gate := engine.GateResult{Passed: true, CoveragePlus: 1, BaseSHA: "b0", HeadSHA: "h0"}
	dec, err := rt.Route(prop, gate, true) // tenantConsent=true, Universal=true -> OSS-CONTRIB
	if err != nil {
		t.Fatalf("router.Route: %v", err)
	}
	if dec.Destination != router.DestOSSContribBack || dec.ArtifactPath == "" {
		t.Fatalf("test fixture: router.Route did not emit an OSS artifact: %+v", dec)
	}
	return dec
}

// runGitT runs one git command in dir and fails the test on error, returning
// combined output for the (rare) caller that wants to inspect it.
func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

// newBareOSSRemote creates a REAL bare git repo on disk — standing in for the
// shared OSS repo's remote, exactly as the STILL BINDING constraint on this
// item requires ("do not push a contribute-back PR to mallcop-app/mallcop as
// a side effect of testing — use a local bare repo"). pushContribBranch
// clones this exact filesystem path with a plain `git clone`; production
// clones an https://github.com/... URL instead, but it is the SAME code path
// (contribPushRunner shells out to the SAME `git clone/checkout/commit/push`
// sequence either way) — this is not a parallel fake mechanism.
//
// It seeds a "main" branch with one file first, mirroring a real repo (never
// empty at HEAD) so pushContribBranch's `git checkout main` has a real branch
// to land on before branching off it.
func newBareOSSRemote(t *testing.T) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "oss-remote.git")
	if out, err := exec.Command("git", "init", "--quiet", "--bare", "-b", "main", bare).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	seed := t.TempDir()
	runGitT(t, seed, "init", "--quiet", "-b", "main")
	runGitT(t, seed, "config", "user.email", "seed@test.example")
	runGitT(t, seed, "config", "user.name", "seed")
	runGitT(t, seed, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitT(t, seed, "add", "README.md")
	runGitT(t, seed, "commit", "--quiet", "-m", "seed")
	runGitT(t, seed, "remote", "add", "origin", bare)
	runGitT(t, seed, "push", "--quiet", "origin", "main")
	return bare
}

// verifyPushedHeadBranch proves, by cloning bareRepo FRESH into a brand-new
// directory (never reusing pushContribBranch's own scratch clone), that
// headBranch genuinely exists on the remote with a real, non-empty commit
// ahead of "main" carrying wantFile — the exact three things mallcoppro-a6c's
// veracity finding said were never true in production ("Head sha can't be
// blank", "No commits between main and contribback/...", "Head ref must be a
// branch").
func verifyPushedHeadBranch(t *testing.T, bareRepo, headBranch, wantFile string) {
	t.Helper()
	clone := t.TempDir()
	runGitT(t, "", "clone", "--quiet", bareRepo, clone)
	// The branch ref must exist on the remote at all (a missing head branch
	// is exactly the "Head ref must be a branch" failure mode).
	branches := runGitT(t, clone, "branch", "-r")
	if !strings.Contains(branches, "origin/"+headBranch) {
		t.Fatalf("remote has no branch %q; branches:\n%s", headBranch, branches)
	}
	// The branch must be genuinely ahead of main — a real commit, not an
	// empty one ("No commits between main and contribback/..." was the exact
	// production failure).
	ahead := strings.TrimSpace(runGitT(t, clone, "rev-list", "--count", "main..origin/"+headBranch))
	if ahead == "0" || ahead == "" {
		t.Fatalf("origin/%s has %s commits ahead of main, want >=1 (an empty branch reproduces the veracity finding)", headBranch, ahead)
	}
	// The file the artifact was materialized as must actually be present in
	// that commit's tree ("Head sha can't be blank" reproduces when nothing
	// was ever committed at all).
	diffFiles := runGitT(t, clone, "diff", "--name-only", "main", "origin/"+headBranch)
	if !strings.Contains(diffFiles, wantFile) {
		t.Fatalf("origin/%s diff vs main does not include %q; diff --name-only:\n%s", headBranch, wantFile, diffFiles)
	}
}

// TestContributeArtifacts_OpensRealPRAndPersistsThroughRealStore is the
// acceptance test for mallcoppro-a6c: from a store containing a
// ROUTER-EMITTED contribute-back artifact (never hand-seeded), invoking the
// new entry point (contributeArtifacts) opens the PR through the Opener and
// PERSISTS a ContribBackRecord(State=open) with the real PR URL through the
// REAL store path — then a later poll (contribback.PollOutcomes, unchanged
// production code from mallcoppro-003) observes it merge, closing the full
// loop through the SAME store this call wrote to.
func TestContributeArtifacts_OpensRealPRAndPersistsThroughRealStore(t *testing.T) {
	artifactBase := t.TempDir()
	fp := "fp-real-router-emit-1"
	realRoutedArtifact(t, artifactBase, fp)
	headBranch := contribback.Artifact{Fingerprint: fp}.HeadBranch()

	storeDir := t.TempDir()
	st, err := openOrInitStore(storeDir)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}

	// A REAL local bare git repo stands in for the shared OSS remote (STILL
	// BINDING constraint: never push a real PR to mallcop-app/mallcop as a
	// side effect of testing). pushContribBranch runs its real
	// clone/checkout/commit/push sequence against this exact path.
	bareRemote := newBareOSSRemote(t)

	pr := &fakePROpener{url: "https://github.com/mallcop-app/mallcop/pull/777"}
	sum, err := contributeArtifacts(context.Background(), contributeArgs{
		artifactDir: artifactBase,
		storeRepo:   storeDir,
		ossRepo:     "mallcop-app/mallcop",
		autonomy:    autonomy.FullyAutonomy, // proves the dial never gates opening a PR
		cloneSpec:   bareRemote,
	}, st, pr, silentLogger())
	if err != nil {
		t.Fatalf("contributeArtifacts: %v", err)
	}
	if sum.Considered != 1 || sum.Opened != 1 || sum.Failed != 0 || sum.Skipped != 0 {
		t.Fatalf("summary = %+v, want {Considered:1 Opened:1}", sum)
	}
	if pr.calls != 1 {
		t.Fatalf("fakePROpener.OpenPR called %d times, want 1", pr.calls)
	}
	if pr.lastReq.Repo != "mallcop-app/mallcop" {
		t.Errorf("PRRequest.Repo = %q, want mallcop-app/mallcop", pr.lastReq.Repo)
	}
	if pr.lastReq.HeadBranch != headBranch {
		t.Errorf("PRRequest.HeadBranch = %q, want %q", pr.lastReq.HeadBranch, headBranch)
	}

	// THE VERACITY-FINDING PROOF: the head branch was REALLY created,
	// REALLY committed to, and REALLY pushed to the remote — checked by
	// cloning the bare repo fresh (not reusing pushContribBranch's own
	// scratch clone) and inspecting it with real git commands.
	verifyPushedHeadBranch(t, bareRemote, headBranch, "contrib-back/"+fp+".json")

	// PERSISTED THROUGH THE REAL STORE — reopen it fresh (a new handle on the
	// same on-disk git repo) to prove the record is durable, not merely held
	// in the Opener's in-memory struct.
	st2, err := store.Open(storeDir)
	if err != nil {
		t.Fatalf("re-open store: %v", err)
	}
	recs, err := st2.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d contribback records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.State != store.ContribBackOpen {
		t.Errorf("record.State = %q, want %q", rec.State, store.ContribBackOpen)
	}
	if rec.PRURL != "https://github.com/mallcop-app/mallcop/pull/777" {
		t.Errorf("record.PRURL = %q, want the real OpenPR-returned URL", rec.PRURL)
	}
	if rec.Fingerprint == "" {
		t.Errorf("record.Fingerprint is empty")
	}

	// Full loop: a LATER scan's poll (mallcoppro-003, unmodified) observes this
	// exact record merge — proving contributeArtifacts wrote something
	// PollOutcomes can actually act on, not merely something shaped like it.
	psum, perr := contribback.PollOutcomes(context.Background(), st2, fakePRStateFetcher{
		state: contribback.PRState{State: "closed", Merged: true},
	})
	if perr != nil {
		t.Fatalf("PollOutcomes: %v", perr)
	}
	if psum.Updated != 1 {
		t.Fatalf("PollOutcomes.Updated = %d, want 1", psum.Updated)
	}
	recs2, err := st2.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords (post-poll): %v", err)
	}
	if len(recs2) != 2 {
		t.Fatalf("got %d contribback records after poll, want 2 (open + merged)", len(recs2))
	}
	if recs2[len(recs2)-1].State != store.ContribBackMerged {
		t.Errorf("latest record.State = %q, want %q", recs2[len(recs2)-1].State, store.ContribBackMerged)
	}
}

// TestContributeArtifacts_SkipsAlreadyRecordedFingerprint proves the
// fingerprint-keyed dedupe: a re-run over an artifact directory whose
// fingerprint the store ALREADY has a ContribBackRecord for (open, merged, or
// closed) must never re-attempt OpenPR. This test deliberately pre-seeds a
// record (via the real store, not a hand-rolled struct in a map) — that is the
// scenario under test, distinct from the main acceptance test above which
// does not pre-seed anything.
func TestContributeArtifacts_SkipsAlreadyRecordedFingerprint(t *testing.T) {
	artifactBase := t.TempDir()
	fp := "fp-already-recorded"
	realRoutedArtifact(t, artifactBase, fp)

	storeDir := t.TempDir()
	st, err := openOrInitStore(storeDir)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	if _, err := st.Append(store.KindContribBack, store.ContribBackRecord{
		Fingerprint: fp,
		PRURL:       "https://github.com/mallcop-app/mallcop/pull/1",
		State:       store.ContribBackOpen,
	}); err != nil {
		t.Fatalf("seed existing record: %v", err)
	}

	pr := &fakePROpener{}
	sum, err := contributeArtifacts(context.Background(), contributeArgs{
		artifactDir: artifactBase,
		storeRepo:   storeDir,
		ossRepo:     "mallcop-app/mallcop",
		autonomy:    autonomy.NonAutonomy,
	}, st, pr, silentLogger())
	if err != nil {
		t.Fatalf("contributeArtifacts: %v", err)
	}
	if sum.Skipped != 1 || sum.Opened != 0 {
		t.Fatalf("summary = %+v, want {Skipped:1 Opened:0}", sum)
	}
	if pr.calls != 0 {
		t.Fatalf("fakePROpener.OpenPR called %d times, want 0 (already recorded)", pr.calls)
	}
}

// TestContributeArtifacts_NoArtifactDir_IsNotAnError proves a missing
// --artifact-dir/oss (nothing has been --propose'd with --consent yet) is a
// legitimate empty run, not a failure.
func TestContributeArtifacts_NoArtifactDir_IsNotAnError(t *testing.T) {
	storeDir := t.TempDir()
	st, err := openOrInitStore(storeDir)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}
	pr := &fakePROpener{}
	sum, err := contributeArtifacts(context.Background(), contributeArgs{
		artifactDir: filepath.Join(t.TempDir(), "never-written"),
		storeRepo:   storeDir,
		ossRepo:     "mallcop-app/mallcop",
	}, st, pr, silentLogger())
	if err != nil {
		t.Fatalf("contributeArtifacts: %v", err)
	}
	if sum.Considered != 0 || sum.Opened != 0 {
		t.Fatalf("summary = %+v, want all-zero", sum)
	}
	if pr.calls != 0 {
		t.Fatalf("OpenPR called %d times, want 0", pr.calls)
	}
}

// TestContributeArtifacts_OpenPRFailure_IsReportedNotSwallowed proves a
// per-artifact OpenPR failure surfaces as an error (and is tallied Failed),
// rather than being silently dropped.
func TestContributeArtifacts_OpenPRFailure_IsReportedNotSwallowed(t *testing.T) {
	artifactBase := t.TempDir()
	realRoutedArtifact(t, artifactBase, "fp-open-fails")

	storeDir := t.TempDir()
	st, err := openOrInitStore(storeDir)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}

	pr := &fakePROpener{err: errGHFake}
	sum, err := contributeArtifacts(context.Background(), contributeArgs{
		artifactDir: artifactBase,
		storeRepo:   storeDir,
		ossRepo:     "mallcop-app/mallcop",
		cloneSpec:   newBareOSSRemote(t), // push must SUCCEED so this test isolates the OpenPR failure, not a push failure
	}, st, pr, silentLogger())
	if err == nil {
		t.Fatal("expected an error when OpenPR fails")
	}
	if sum.Failed != 1 {
		t.Fatalf("summary.Failed = %d, want 1", sum.Failed)
	}
	// A failed OpenPR must persist NOTHING (Contribute never gets to the
	// Store.Append step when OpenPR itself errors).
	recs, lerr := st.LoadContribBackRecords()
	if lerr != nil {
		t.Fatalf("LoadContribBackRecords: %v", lerr)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d contribback records after a failed OpenPR, want 0", len(recs))
	}
}

// TestPushContribBranch_CreatesRealCommitAndPushesIt is a focused, direct
// test of pushContribBranch (mallcoppro-a6c's core fix): given a real bare
// remote and a real Artifact, it must leave the head branch really created,
// really committed to, and really pushed — verified by cloning the remote
// fresh, exactly the veracity finding's three named failure modes ("Head sha
// can't be blank", "No commits between main and contribback/...", "Head ref
// must be a branch").
func TestPushContribBranch_CreatesRealCommitAndPushesIt(t *testing.T) {
	bare := newBareOSSRemote(t)
	art := contribback.Artifact{
		Fingerprint: "direct-push-fp",
		Consented:   true,
		Universal:   true,
		Title:       "selfext(contribute-back): test widen",
		Body:        "body text",
	}
	if err := pushContribBranch(context.Background(), bare, "main", art); err != nil {
		t.Fatalf("pushContribBranch: %v", err)
	}
	verifyPushedHeadBranch(t, bare, art.HeadBranch(), "contrib-back/direct-push-fp.json")
}

// TestPushContribBranch_ReRunIsIdempotentViaForcePush proves a SECOND call for
// the SAME fingerprint (the retry-after-partial-failure scenario: an earlier
// run pushed the branch but OpenPR then errored) succeeds rather than failing
// on a stale non-fast-forward against its own prior attempt.
func TestPushContribBranch_ReRunIsIdempotentViaForcePush(t *testing.T) {
	bare := newBareOSSRemote(t)
	art := contribback.Artifact{Fingerprint: "retry-fp", Title: "t", Body: "b"}
	if err := pushContribBranch(context.Background(), bare, "main", art); err != nil {
		t.Fatalf("first pushContribBranch: %v", err)
	}
	if err := pushContribBranch(context.Background(), bare, "main", art); err != nil {
		t.Fatalf("second pushContribBranch (retry): %v", err)
	}
	verifyPushedHeadBranch(t, bare, art.HeadBranch(), "contrib-back/retry-fp.json")
}

// TestPushContribBranch_FailsOnUnreachableRemote proves the failure path is
// reported, not silently swallowed as success: an unreachable clone target
// must return an error, reproducing (at the push step, where it now surfaces
// LOUDLY and early) the exact "nothing was ever created" condition the
// veracity finding described. This is the regression-proof half of REQUIRED
// #2: had pushContribBranch never been wired into contributeArtifacts (or
// been a no-op), this failure would instead surface downstream as gh's
// "Head sha can't be blank" — this test pins the failure at the source.
func TestPushContribBranch_FailsOnUnreachableRemote(t *testing.T) {
	unreachable := filepath.Join(t.TempDir(), "does-not-exist.git")
	art := contribback.Artifact{Fingerprint: "unreachable-fp", Title: "t", Body: "b"}
	if err := pushContribBranch(context.Background(), unreachable, "main", art); err == nil {
		t.Fatal("pushContribBranch: expected an error cloning a nonexistent remote, got nil")
	}
}

// TestContributeArtifacts_PushFailure_NeverCallsOpenPR is the end-to-end proof
// that contributeArtifacts (mallcoppro-a6c's production entry point) treats a
// push failure as fatal for that artifact BEFORE ever reaching OpenPR or
// persisting anything — i.e. the ordering fix (push, then Contribute) is
// wired all the way through the CLI layer, not just provable at the
// pushContribBranch unit level. Confirmed to bite: with the
// `if perr := pushContribBranch(...); perr != nil { ... continue }` guard
// removed (verified by hand during development), this test fails because
// fakePROpener.calls becomes 1 and sum.Failed becomes 0 — the exact silent
// regression this test exists to catch.
func TestContributeArtifacts_PushFailure_NeverCallsOpenPR(t *testing.T) {
	artifactBase := t.TempDir()
	realRoutedArtifact(t, artifactBase, "fp-push-fails")

	storeDir := t.TempDir()
	st, err := openOrInitStore(storeDir)
	if err != nil {
		t.Fatalf("openOrInitStore: %v", err)
	}

	pr := &fakePROpener{}
	sum, err := contributeArtifacts(context.Background(), contributeArgs{
		artifactDir: artifactBase,
		storeRepo:   storeDir,
		ossRepo:     "mallcop-app/mallcop",
		cloneSpec:   filepath.Join(t.TempDir(), "no-such-remote.git"), // unreachable -> push must fail
	}, st, pr, silentLogger())
	if err == nil {
		t.Fatal("expected an error when the head-branch push fails")
	}
	if sum.Failed != 1 || sum.Opened != 0 {
		t.Fatalf("summary = %+v, want {Failed:1 Opened:0}", sum)
	}
	if pr.calls != 0 {
		t.Fatalf("fakePROpener.OpenPR called %d times, want 0 (a failed push must never reach OpenPR)", pr.calls)
	}
	recs, lerr := st.LoadContribBackRecords()
	if lerr != nil {
		t.Fatalf("LoadContribBackRecords: %v", lerr)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d contribback records after a failed push, want 0", len(recs))
	}
}

var errGHFake = &fakeGHError{}

type fakeGHError struct{}

func (e *fakeGHError) Error() string { return "gh pr create: simulated failure (not authenticated)" }

// TestRunSelfext_ContributeRequiresStoreRepoAndOssRepo proves the CLI-level
// flag wiring: --contribute REQUIRES --store-repo and --oss-repo, matching
// Config.Repo/Opener.Store being "required when Enabled" in
// selfext/contribback.
func TestRunSelfext_ContributeRequiresStoreRepoAndOssRepo(t *testing.T) {
	t.Run("missing both", func(t *testing.T) {
		if err := runSelfext([]string{"--contribute"}); err == nil {
			t.Fatal("expected error: --store-repo and --oss-repo both missing")
		}
	})
	t.Run("missing oss-repo", func(t *testing.T) {
		err := runSelfext([]string{"--contribute", "--store-repo", t.TempDir()})
		if err == nil {
			t.Fatal("expected error: --oss-repo missing")
		}
	})
	t.Run("--contribute counts toward the mode XOR", func(t *testing.T) {
		if err := runSelfext([]string{"--contribute", "--run"}); err == nil {
			t.Fatal("expected error: --contribute and --run are mutually exclusive")
		}
	})
}
