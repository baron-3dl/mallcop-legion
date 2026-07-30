package store

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// initRepo creates a REAL git repo in a temp dir. Every persistence and
// concurrency test hits this — not an in-memory fake — so the tests prove the
// git repo ALONE reconstructs full state.
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
	// A repo with no commits has no HEAD; seed an empty root commit so HEAD
	// resolves from the first Append onward (matches how the CLI seeds a repo).
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

// TestWriteSnapshotOverwritesAndDedupes proves WriteSnapshot commits a full-content
// JSON document (not an append), overwrites on the next call, and skips a byte-identical
// write — the property the browser depends on (deduped current state, not the append log).
func TestWriteSnapshotOverwrites(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// First snapshot: two records.
	if _, err := s.WriteSnapshot("findings.json", []map[string]any{{"id": "a"}, {"id": "b"}}); err != nil {
		t.Fatalf("WriteSnapshot 1: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(committedBytes(t, repo, "findings.json"), &got); err != nil {
		t.Fatalf("snapshot 1 not valid JSON array: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("snapshot 1 = %d records, want 2", len(got))
	}

	// Second snapshot with ONE record must OVERWRITE (not append) — the file is a
	// single document, so the count goes down, unlike the append-only stream.
	if _, err := s.WriteSnapshot("findings.json", []map[string]any{{"id": "c"}}); err != nil {
		t.Fatalf("WriteSnapshot 2: %v", err)
	}
	if err := json.Unmarshal(committedBytes(t, repo, "findings.json"), &got); err != nil {
		t.Fatalf("snapshot 2 not valid JSON array: %v", err)
	}
	if len(got) != 1 || got[0]["id"] != "c" {
		t.Fatalf("snapshot 2 = %v, want single record id=c (overwrite, not append)", got)
	}

	// A byte-identical re-write must NOT create a new commit.
	before := len(gitLog(t, repo))
	if _, err := s.WriteSnapshot("findings.json", []map[string]any{{"id": "c"}}); err != nil {
		t.Fatalf("WriteSnapshot 3 (identical): %v", err)
	}
	if after := len(gitLog(t, repo)); after != before {
		t.Fatalf("identical snapshot created a commit: log %d -> %d", before, after)
	}
}

func gitLog(t *testing.T, repo string) []string {
	t.Helper()
	cmd := exec.Command("git", "log", "--format=%H %s")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git log: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines
}

// committedBytes reads a stream file's content from the git OBJECT STORE at
// HEAD, bypassing the store package, so the test asserts on the literal
// committed content (the store materializes records into git objects, not the
// work tree). An absent blob (stream never written) returns empty bytes.
func committedBytes(t *testing.T, repo, file string) []byte {
	t.Helper()
	cmd := exec.Command("git", "cat-file", "-p", "HEAD:"+file)
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		// Missing path → empty (no records yet).
		return nil
	}
	return out
}

func TestOpenRejectsNonGitDir(t *testing.T) {
	dir := t.TempDir() // NOT a git repo
	if _, err := Open(dir); err == nil {
		t.Fatal("Open on a non-git dir should fail, got nil error")
	}
}

func TestOpenRejectsMissingPath(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("Open on a missing path should fail, got nil error")
	}
}

// TestAppendAndLoadRoundTrip proves a record appended is replayed verbatim, and
// that the git repo alone holds it (we re-Open a fresh handle).
func TestAppendAndLoadRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rec := map[string]any{"id": "e1", "type": "login"}
	sha, err := s.Append(KindEvents, rec)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if sha == "" {
		t.Fatal("Append returned empty sha")
	}

	// Fresh handle — reconstruct from the repo, not from in-process memory.
	s2, err := Open(repo)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	got, err := s2.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record, got %d", len(got))
	}
	var back map[string]any
	if err := json.Unmarshal(got[0], &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["id"] != "e1" || back["type"] != "login" {
		t.Fatalf("record round-trip mismatch: %v", back)
	}
}

// TestLoadMissingStreamIsEmpty proves a never-written stream is empty, not an
// error — a valid reconstructed state.
func TestLoadMissingStreamIsEmpty(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)
	got, err := s.Load(KindFindings)
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0, got %d", len(got))
	}
}

// TestAppendOnlyHistoryPreserved is the APPEND-ONLY proof: every prior record
// stays byte-for-byte where it was; the file only grows; nothing is rewritten
// in place. We assert (a) each Load result is a strict prefix-extension of the
// last, and (b) every git commit's diff is pure addition (no deletions).
func TestAppendOnlyHistoryPreserved(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)

	var prevBytes []byte
	var shas []string
	for i := 0; i < 5; i++ {
		rec := map[string]any{"n": i, "msg": fmt.Sprintf("record-%d", i)}
		sha, err := s.Append(KindFindings, rec)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		shas = append(shas, sha)

		cur := committedBytes(t, repo, KindFindings.file())
		// (a) The new on-disk content must START WITH the previous content —
		// proving no in-place mutation of earlier bytes.
		if i > 0 && !strings.HasPrefix(string(cur), string(prevBytes)) {
			t.Fatalf("append %d mutated prior bytes; prev was not a prefix of current", i)
		}
		if i > 0 && len(cur) <= len(prevBytes) {
			t.Fatalf("append %d did not grow the file (%d <= %d)", i, len(cur), len(prevBytes))
		}
		prevBytes = cur
	}

	// (b) Each store commit's diff must be addition-only: no removed lines.
	for _, sha := range shas {
		cmd := exec.Command("git", "show", "--format=", "--unified=0", sha)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git show %s: %v\n%s", sha, err, out)
		}
		for _, ln := range strings.Split(string(out), "\n") {
			// A real deletion line starts with "-" but not the "---" file
			// header. Its presence would mean a prior record was rewritten.
			if strings.HasPrefix(ln, "-") && !strings.HasPrefix(ln, "---") {
				t.Fatalf("commit %s contains a deletion (not append-only): %q", sha, ln)
			}
		}
	}

	// Final reconstruction from the repo alone: 5 records, in order.
	got, err := s.Load(KindFindings)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 records, got %d", len(got))
	}
	for i, raw := range got {
		var r map[string]any
		_ = json.Unmarshal(raw, &r)
		if int(r["n"].(float64)) != i {
			t.Fatalf("record %d out of order: %v", i, r)
		}
	}
}

// TestDirectivesFirstClassCrossProcess is the keystone proof: a directive
// written via Append by ONE Open is returned by a FRESH Open().LoadDirectives()
// — i.e. the next scan would load and obey it. We make the two Opens model two
// processes by using entirely independent Store handles; the only shared state
// is the git repo on disk.
func TestDirectivesFirstClassCrossProcess(t *testing.T) {
	repo := initRepo(t)

	// "Process 1": operator writes a suppress directive.
	writer, err := Open(repo)
	if err != nil {
		t.Fatalf("writer Open: %v", err)
	}
	d := Directive{
		Op:      "suppress",
		Pattern: "detector:rate-anomaly",
		Reason:  "known batch job, false positives",
		Actor:   "operator",
	}
	if _, err := writer.Append(KindDirectives, d); err != nil {
		t.Fatalf("append directive: %v", err)
	}

	// "Process 2": a fresh scan boots, Opens the repo, loads directives.
	scanner, err := Open(repo)
	if err != nil {
		t.Fatalf("scanner Open: %v", err)
	}
	dirs, err := scanner.LoadDirectives()
	if err != nil {
		t.Fatalf("LoadDirectives: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("want 1 directive obeyed by next scan, got %d", len(dirs))
	}
	if dirs[0].Op != "suppress" || dirs[0].Pattern != "detector:rate-anomaly" {
		t.Fatalf("directive not faithfully reconstructed: %+v", dirs[0])
	}
	if dirs[0].Reason != "known batch job, false positives" {
		t.Fatalf("directive reason lost: %+v", dirs[0])
	}
}

// TestConversationFirstClassCrossProcess proves conversation is durable and
// replayed by a fresh Open — the agent loop resumes from the repo alone.
func TestConversationFirstClassCrossProcess(t *testing.T) {
	repo := initRepo(t)
	w, _ := Open(repo)
	turns := []Turn{
		{Role: "user", Content: "scan the org"},
		{Role: "assistant", Content: "running 13 detectors"},
		{Role: "tool", ToolName: "detect", ToolResult: json.RawMessage(`{"findings":3}`)},
	}
	for i, tn := range turns {
		if _, err := w.Append(KindConversation, tn); err != nil {
			t.Fatalf("append turn %d: %v", i, err)
		}
	}

	r, _ := Open(repo)
	got, err := r.LoadConversation()
	if err != nil {
		t.Fatalf("LoadConversation: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 turns, got %d", len(got))
	}
	if got[0].Role != "user" || got[0].Content != "scan the org" {
		t.Fatalf("turn 0 mismatch: %+v", got[0])
	}
	if got[2].ToolName != "detect" || string(got[2].ToolResult) != `{"findings":3}` {
		t.Fatalf("tool turn mismatch: %+v", got[2])
	}
}

// TestGitRepoAloneReconstructsState is the GROUND-SOURCE proof: write to one
// repo, then `git clone` it to a brand-new directory and Open the clone. If the
// clone reconstructs every stream, the git repo ALONE is the source of truth —
// no out-of-band state exists.
func TestGitRepoAloneReconstructsState(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)
	if _, err := s.Append(KindEvents, map[string]any{"id": "e1"}); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if _, err := s.Append(KindFindings, map[string]any{"id": "f1"}); err != nil {
		t.Fatalf("append finding: %v", err)
	}
	if _, err := s.Append(KindDirectives, Directive{Op: "focus", Pattern: "exfil"}); err != nil {
		t.Fatalf("append directive: %v", err)
	}

	clone := filepath.Join(t.TempDir(), "clone")
	cmd := exec.Command("git", "clone", "-q", repo, clone)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}

	cs, err := Open(clone)
	if err != nil {
		t.Fatalf("Open clone: %v", err)
	}
	ev, _ := cs.Load(KindEvents)
	fd, _ := cs.Load(KindFindings)
	dirs, _ := cs.LoadDirectives()
	if len(ev) != 1 || len(fd) != 1 || len(dirs) != 1 {
		t.Fatalf("clone did not reconstruct full state: events=%d findings=%d directives=%d",
			len(ev), len(fd), len(dirs))
	}
	if dirs[0].Op != "focus" || dirs[0].Pattern != "exfil" {
		t.Fatalf("clone directive mismatch: %+v", dirs[0])
	}
}

// TestConcurrentWritersNoLostWrite is the CONCURRENCY proof. Many goroutines
// append to the same stream through INDEPENDENT Store handles. Every append must
// land (no lost write), the git log must be deterministic (one commit per
// append, linear history), and reconstruction from the repo must return exactly
// N records with no duplicates.
func TestConcurrentWritersNoLostWrite(t *testing.T) {
	repo := initRepo(t)

	const writers = 12
	baseCommits := len(gitLog(t, repo)) // root commit

	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Independent handle per goroutine — they share only the repo.
			s, err := Open(repo)
			if err != nil {
				errs[n] = err
				return
			}
			_, errs[n] = s.Append(KindEvents, map[string]any{"writer": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d failed: %v", i, err)
		}
	}

	// No lost write: exactly `writers` records reconstructed from the repo.
	s, _ := Open(repo)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("lost write: want %d records, got %d", writers, len(got))
	}

	// Each writer's record present exactly once — no duplication, no drop.
	seen := map[int]int{}
	for _, raw := range got {
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("corrupt record after concurrent write: %v", err)
		}
		seen[int(r["writer"].(float64))]++
	}
	if len(seen) != writers {
		t.Fatalf("want %d distinct writers, got %d (%v)", writers, len(seen), seen)
	}
	for w, c := range seen {
		if c != 1 {
			t.Fatalf("writer %d landed %d times (want exactly 1)", w, c)
		}
	}

	// Deterministic merged log: exactly one new commit per append, linear.
	log := gitLog(t, repo)
	if got, want := len(log)-baseCommits, writers; got != want {
		t.Fatalf("want %d store commits, got %d (log has %d lines)", want, got, len(log))
	}
	for _, ln := range log[:writers] { // newest `writers` entries are ours
		if !strings.Contains(ln, "store: append events") {
			t.Fatalf("unexpected commit in merged log: %q", ln)
		}
	}
}

// noopSerializer grants the lock to everyone immediately — it provides NO
// mutual exclusion. Passing it to OpenWith strips away the in-process mutex so
// concurrent goroutines genuinely race at the git layer, the way two separate
// OS PROCESSES would. This is the real stress test for the rebase-retry: if the
// retry logic is wrong, this test loses or duplicates writes.
type noopSerializer struct{}

func (noopSerializer) Lock(string) (func(), error) { return func() {}, nil }

// TestRebaseRetryUnderTrueRace drives the cross-process race path. With no
// shared in-process lock, N goroutines append to the same stream and the only
// thing preventing a lost write is commitAppend's sync-append-commit rebase
// loop. We assert exactly N records, each exactly once, and a linear log.
func TestRebaseRetryUnderTrueRace(t *testing.T) {
	repo := initRepo(t)
	baseCommits := len(gitLog(t, repo))

	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s, err := OpenWith(repo, noopSerializer{})
			if err != nil {
				errs[n] = err
				return
			}
			_, errs[n] = s.Append(KindEvents, map[string]any{"w": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racing writer %d failed: %v", i, err)
		}
	}

	s, _ := Open(repo)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("true-race lost/duplicated writes: want %d records, got %d", writers, len(got))
	}
	seen := map[int]int{}
	for _, raw := range got {
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("corrupt record: %v", err)
		}
		seen[int(r["w"].(float64))]++
	}
	for w := 0; w < writers; w++ {
		if seen[w] != 1 {
			t.Fatalf("writer %d landed %d times under true race (want exactly 1); full map %v", w, seen[w], seen)
		}
	}

	// Deterministic merged log: one commit per append, all linear (each commit
	// has exactly one parent — no merge commits introduced by the retry).
	log := gitLog(t, repo)
	if got, want := len(log)-baseCommits, writers; got != want {
		t.Fatalf("want %d store commits under true race, got %d", want, got)
	}
	mp := exec.Command("git", "log", "--merges", "--format=%H")
	mp.Dir = repo
	mout, _ := mp.CombinedOutput()
	if strings.TrimSpace(string(mout)) != "" {
		t.Fatalf("rebase-retry produced merge commits (non-linear log):\n%s", mout)
	}
}

// TestSerializerHookIsUsed proves the per-tenant write-serialization HOOK is a
// real seam: a custom Serializer passed to OpenWith is invoked around every
// Append, and its release runs. This is the interface the managed (aztables)
// side implements later; here we just prove the seam exists and is honored.
func TestSerializerHookIsUsed(t *testing.T) {
	repo := initRepo(t)

	hook := &countingSerializer{inner: defaultMutex}
	s, err := OpenWith(repo, hook)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Append(KindResolutions, map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if hook.locks != 3 {
		t.Fatalf("serializer hook Lock called %d times, want 3", hook.locks)
	}
	if hook.releases != 3 {
		t.Fatalf("serializer hook release called %d times, want 3", hook.releases)
	}
}

type countingSerializer struct {
	inner    Serializer
	mu       sync.Mutex
	locks    int
	releases int
}

func (c *countingSerializer) Lock(repoPath string) (func(), error) {
	rel, err := c.inner.Lock(repoPath)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.locks++
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.releases++
		c.mu.Unlock()
		rel()
	}, nil
}

// TestBootstrapOnEmptyRepo proves the FIRST Append on a freshly `git init`'d
// repo with ZERO commits works — the store bootstraps a root commit. The
// consumer (CLI) may hand the store a repo it just inited without seeding a
// root; the store must not require a pre-existing HEAD.
func TestBootstrapOnEmptyRepo(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "t"},
		{"config", "user.email", "t@e"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	// No root commit seeded — HEAD is unborn.
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	sha, err := s.Append(KindDirectives, Directive{Op: "suppress", Pattern: "x"})
	if err != nil {
		t.Fatalf("bootstrap Append: %v", err)
	}
	if sha == "" {
		t.Fatal("bootstrap Append returned empty sha")
	}
	// Fresh handle reconstructs the directive from the repo alone.
	s2, _ := Open(dir)
	dirs, err := s2.LoadDirectives()
	if err != nil {
		t.Fatalf("LoadDirectives: %v", err)
	}
	if len(dirs) != 1 || dirs[0].Op != "suppress" {
		t.Fatalf("bootstrap directive not reconstructed: %+v", dirs)
	}
}

// TestBootstrapRaceNoDoubleRoot proves that when MANY writers race to be the
// first Append on an unborn-HEAD repo, the zero-value CAS lets exactly one win
// the root and the rest rebase onto it — no forked history, no lost write.
func TestBootstrapRaceNoDoubleRoot(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.name", "t"}, {"config", "user.email", "t@e"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	const writers = 10
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s, err := OpenWith(dir, noopSerializer{})
			if err != nil {
				errs[n] = err
				return
			}
			_, errs[n] = s.Append(KindEvents, map[string]any{"w": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("bootstrap-race writer %d: %v", i, err)
		}
	}

	s, _ := Open(dir)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != writers {
		t.Fatalf("bootstrap race lost/dup writes: want %d, got %d", writers, len(got))
	}
	// Linear history rooted at a single root commit.
	mp := exec.Command("git", "rev-list", "--max-parents=0", "HEAD")
	mp.Dir = dir
	rout, _ := mp.CombinedOutput()
	if roots := strings.Fields(string(rout)); len(roots) != 1 {
		t.Fatalf("want exactly 1 root commit, got %d (%v)", len(roots), roots)
	}
}

// TestAppendBatchSingleCommitOrderRoundTrip proves the headline AppendBatch
// property: N records land as EXACTLY ONE new commit (git rev-list --count
// grows by 1, not N), the returned sha is that commit, and Load replays every
// record back in order.
func TestAppendBatchSingleCommitOrderRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	before := revListCount(t, repo)

	const n = 20
	recs := make([]any, n)
	for i := 0; i < n; i++ {
		recs[i] = map[string]any{"n": i, "msg": fmt.Sprintf("batch-record-%d", i)}
	}
	sha, err := s.AppendBatch(KindEvents, recs)
	if err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}
	if sha == "" {
		t.Fatal("AppendBatch returned empty sha")
	}

	after := revListCount(t, repo)
	if after-before != 1 {
		t.Fatalf("AppendBatch of %d records grew the log by %d commits, want exactly 1", n, after-before)
	}

	head, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	if strings.TrimSpace(string(head)) != sha {
		t.Fatalf("AppendBatch sha %s does not match new HEAD %s", sha, strings.TrimSpace(string(head)))
	}

	// Fresh handle — reconstruct from the repo alone.
	s2, err := Open(repo)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	got, err := s2.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != n {
		t.Fatalf("want %d records, got %d", n, len(got))
	}
	for i, raw := range got {
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("unmarshal record %d: %v", i, err)
		}
		if int(r["n"].(float64)) != i {
			t.Fatalf("record %d out of order: %v", i, r)
		}
	}

	// The commit message carries the batch count (n>1 format).
	msg := gitLog(t, repo)[0]
	if !strings.Contains(msg, "store: append events (n=20)") {
		t.Fatalf("commit message = %q, want it to contain \"store: append events (n=20)\"", msg)
	}
}

// TestAppendBatchEmptyIsNoop proves an empty batch is a documented no-op: it
// returns ("", nil) and creates NO commit.
func TestAppendBatchEmptyIsNoop(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)

	before := revListCount(t, repo)
	sha, err := s.AppendBatch(KindEvents, nil)
	if err != nil {
		t.Fatalf("AppendBatch(empty): %v", err)
	}
	if sha != "" {
		t.Fatalf("AppendBatch(empty) sha = %q, want empty", sha)
	}
	if after := revListCount(t, repo); after != before {
		t.Fatalf("AppendBatch(empty) created a commit: %d -> %d", before, after)
	}
}

// TestAppendBatchMarshalFailureIsAtomic proves a single unmarshalable record
// (a channel, at index k) rejects the WHOLE batch — naming index k in the
// error — and leaves the repo untouched: no commit, not even a partial one for
// the records before k.
func TestAppendBatchMarshalFailureIsAtomic(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)

	before := revListCount(t, repo)
	const badIndex = 2
	recs := []any{
		map[string]any{"n": 0},
		map[string]any{"n": 1},
		map[string]any{"bad": make(chan int)}, // unmarshalable — index 2
		map[string]any{"n": 3},
	}
	_, err := s.AppendBatch(KindEvents, recs)
	if err == nil {
		t.Fatal("AppendBatch with an unmarshalable record should fail")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("record %d", badIndex)) {
		t.Fatalf("error %q does not name the failing index %d", err, badIndex)
	}

	if after := revListCount(t, repo); after != before {
		t.Fatalf("failed AppendBatch created a commit: %d -> %d", before, after)
	}
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("failed AppendBatch left %d records committed, want 0 (all-or-nothing)", len(got))
	}
}

// TestAppendBatchConcurrentWithAppendNoLostWrite races AppendBatch and Append
// writers against the SAME store: every record from every writer must survive
// exactly once, and the merged log must be linear (the CAS/rebase-retry must
// hold for batches exactly as it does for single appends).
func TestAppendBatchConcurrentWithAppendNoLostWrite(t *testing.T) {
	repo := initRepo(t)
	baseCommits := revListCount(t, repo)

	const batchWriters = 6
	const batchSize = 5
	const singleWriters = 10

	var wg sync.WaitGroup
	errs := make([]error, batchWriters+singleWriters)

	for i := 0; i < batchWriters; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s, err := OpenWith(repo, noopSerializer{})
			if err != nil {
				errs[n] = err
				return
			}
			recs := make([]any, batchSize)
			for j := 0; j < batchSize; j++ {
				recs[j] = map[string]any{"batch": n, "j": j}
			}
			_, errs[n] = s.AppendBatch(KindEvents, recs)
		}(i)
	}
	for i := 0; i < singleWriters; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s, err := OpenWith(repo, noopSerializer{})
			if err != nil {
				errs[batchWriters+n] = err
				return
			}
			_, errs[batchWriters+n] = s.Append(KindEvents, map[string]any{"single": n})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d failed: %v", i, err)
		}
	}

	s, _ := Open(repo)
	got, err := s.Load(KindEvents)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wantTotal := batchWriters*batchSize + singleWriters
	if len(got) != wantTotal {
		t.Fatalf("mixed-race lost/duplicated writes: want %d records, got %d", wantTotal, len(got))
	}

	batchSeen := map[int]map[int]int{}
	singleSeen := map[int]int{}
	for _, raw := range got {
		var r map[string]any
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("corrupt record: %v", err)
		}
		if bn, ok := r["batch"]; ok {
			n := int(bn.(float64))
			j := int(r["j"].(float64))
			if batchSeen[n] == nil {
				batchSeen[n] = map[int]int{}
			}
			batchSeen[n][j]++
		} else if sn, ok := r["single"]; ok {
			singleSeen[int(sn.(float64))]++
		}
	}
	for n := 0; n < batchWriters; n++ {
		for j := 0; j < batchSize; j++ {
			if batchSeen[n][j] != 1 {
				t.Fatalf("batch %d record %d landed %d times, want exactly 1", n, j, batchSeen[n][j])
			}
		}
	}
	for n := 0; n < singleWriters; n++ {
		if singleSeen[n] != 1 {
			t.Fatalf("single writer %d landed %d times, want exactly 1", n, singleSeen[n])
		}
	}

	// Linear history: no merge commits introduced by the retry loop.
	mp := exec.Command("git", "log", "--merges", "--format=%H")
	mp.Dir = repo
	mout, _ := mp.CombinedOutput()
	if strings.TrimSpace(string(mout)) != "" {
		t.Fatalf("mixed-race AppendBatch/Append produced merge commits (non-linear log):\n%s", mout)
	}

	// Commit count: one per batch writer + one per single writer.
	wantCommits := batchWriters + singleWriters
	if got := revListCount(t, repo) - baseCommits; got != wantCommits {
		t.Fatalf("want %d new commits (one per writer, batched or not), got %d", wantCommits, got)
	}
}

// revListCount returns the total commit count reachable from HEAD.
func revListCount(t *testing.T, repo string) int {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-list", "--count", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-list --count: %v", err)
	}
	n := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n); err != nil {
		t.Fatalf("parse rev-list count %q: %v", out, err)
	}
	return n
}

func TestAppendRejectsUnknownKind(t *testing.T) {
	repo := initRepo(t)
	s, _ := Open(repo)
	if _, err := s.Append(Kind("bogus"), map[string]any{}); err == nil {
		t.Fatal("Append with unknown kind should fail")
	}
	if _, err := s.Load(Kind("bogus")); err == nil {
		t.Fatal("Load with unknown kind should fail")
	}
}

// TestKindsCoverage guards the closed set: Kinds() returns exactly the nine
// streams and every one is valid.
func TestKindsCoverage(t *testing.T) {
	ks := Kinds()
	if len(ks) != 9 {
		t.Fatalf("want 9 kinds, got %d", len(ks))
	}
	for _, k := range ks {
		if !k.valid() {
			t.Fatalf("Kinds() returned invalid kind %q", k)
		}
	}
}

// TestSyncWorkTreePreservesDirtySidecarState reproduces the live cursor-freeze
// defect: a deployment COMMITS .mallcop/cursors/<id> into the store branch
// (making it tracked), a later scan's connector advances the cursor with a
// plain file write mid-scan, and the first store commit's syncWorkTree
// (`read-tree --reset -u HEAD`) silently reverted the dirty tracked file to
// HEAD's content — freezing the cursor at its first committed value forever.
// The sidecar snapshot/restore must keep the in-flight write.
func TestSyncWorkTreePreservesDirtySidecarState(t *testing.T) {
	dir := initRepo(t)

	// A deployment commits the cursor (tracked in HEAD from here on).
	cursorPath := filepath.Join(dir, ".mallcop", "cursors", "aws-3dl")
	if err := os.MkdirAll(filepath.Dir(cursorPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorPath, []byte("mark-old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", ".mallcop"}, {"commit", "-q", "-m", "cursors: persist"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	// Mid-scan, the connector advances the cursor (plain write, uncommitted)
	// and drops a brand-new untracked sidecar file next to it.
	if err := os.WriteFile(cursorPath, []byte("mark-new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	untrackedPath := filepath.Join(dir, ".mallcop", "cursors", "mercury-3dl")
	if err := os.WriteFile(untrackedPath, []byte("mark-fresh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Any store write triggers syncWorkTree.
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Append(KindEvents, map[string]any{"id": "e1"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("read cursor after sync: %v", err)
	}
	if string(got) != "mark-new\n" {
		t.Fatalf("tracked-dirty cursor after syncWorkTree = %q, want %q (in-flight write clobbered)", got, "mark-new\n")
	}
	got, err = os.ReadFile(untrackedPath)
	if err != nil {
		t.Fatalf("read untracked cursor after sync: %v", err)
	}
	if string(got) != "mark-fresh\n" {
		t.Fatalf("untracked cursor after syncWorkTree = %q, want %q", got, "mark-fresh\n")
	}

	// And a batch write (the other syncWorkTree caller) must preserve it too.
	if err := os.WriteFile(cursorPath, []byte("mark-newer\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AppendBatch(KindEvents, []any{map[string]any{"id": "e2"}, map[string]any{"id": "e3"}}); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}
	got, _ = os.ReadFile(cursorPath)
	if string(got) != "mark-newer\n" {
		t.Fatalf("cursor after batch syncWorkTree = %q, want %q", got, "mark-newer\n")
	}
}
