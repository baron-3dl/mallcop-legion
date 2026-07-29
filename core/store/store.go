// Package store is the git-repo source of truth for mallcop's eight append-only
// streams: events, findings, resolutions, baseline, conversation, directives,
// scans, and selfext_dispatches.
//
// ONE-BRAIN keystone. Every other core subsystem (the agent loop, the scan
// pipeline) CONSUMES this package; this package consumes nothing from them. The
// store has exactly one job: durably append records to a git repository such
// that the git repository ALONE can reconstruct the full state of the system.
// There is no separate database. The git history is the database.
//
// Each stream is a JSON-Lines file at the repo root (events.jsonl,
// findings.jsonl, …). Append serializes a record to one line, appends it to the
// stream file, stages, and commits. Reads replay the file. Because every write
// is a commit, `git log` is the audit trail and `git checkout <sha>` is
// time-travel.
//
// Directives and conversation are first-class streams, not afterthoughts. A
// directive written by one process (e.g. {"op":"suppress","pattern":"…"}) is
// loaded and obeyed by the next process that Opens the same repo — this is how
// an operator steers future scans. Conversation is the durable transcript that
// the agent loop appends to and replays.
//
// Concurrency model (OSS, single repo, no remote): a process-wide serialization
// hook guards the critical section, and every commit is performed on top of the
// current HEAD with a rebase-retry on the rare interleaving that still races.
// No write is ever lost; the merged log is deterministic (ordered by commit).
//
// IMPORT DISCIPLINE: this package imports NO channel, campfire, inference, or
// connect packages. It is the bottom of the dependency graph. See
// imports_test.go, which fails the build if that ever changes.
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind identifies one of the eight append-only streams. The string value is
// also the on-disk basename (Kind+".jsonl").
type Kind string

// maxStreamBytes is the sanity ceiling for a single stream blob and for one
// appended chunk (1 TiB). Bounding both operands of the pre-allocation size
// arithmetic below a fixed constant makes the sum provably overflow-free; a
// stream anywhere near this size is corruption, not data.
const maxStreamBytes = 1 << 40

const (
	// KindEvents is the normalized security-event stream.
	KindEvents Kind = "events"
	// KindFindings is the detector-output stream.
	KindFindings Kind = "findings"
	// KindResolutions is the actor-decision stream.
	KindResolutions Kind = "resolutions"
	// KindBaseline is the baseline-snapshot stream (append-only: each new
	// baseline is a new record; prior baselines are preserved as history).
	KindBaseline Kind = "baseline"
	// KindConversation is the durable agent-loop transcript stream.
	KindConversation Kind = "conversation"
	// KindDirectives is the operator-steering stream (suppressions, focus,
	// policy). Loaded and obeyed by the next scan.
	KindDirectives Kind = "directives"
	// KindScans is the scan-run register (mallcoppro-e3c): one record per
	// completed `mallcop scan` invocation (findings or not), appended by
	// core/pipeline.Run at the end of every run. It is the durable,
	// rotation-surviving source detection-time investigation correlates
	// recurrence timing against ("this fires ~2min after every scheduled
	// scan"): unlike KindEvents/KindBaseline, a store rotation (mallcoppro-ee3)
	// never needs to truncate it, and CommitTimesFor supplies a historical
	// fallback for scan times that predate this stream's introduction. Purely
	// additive — an older binary that has never heard of KindScans reads every
	// other stream unaffected.
	KindScans Kind = "scans"
	// KindSelfextDispatches is the self-extension dispatch-request stream
	// (mallcoppro-0d95): one record per `dispatch_selfext` chat-tool call that
	// actually COMMITTED (an "auto" autonomy dial read; a "non"/propose-only
	// read returns a proposal to the model and appends nothing — see
	// core/investigate/selfexttool.go). It is the SAME durable-record pattern
	// as KindScans (mallcoppro-e3c): purely additive, so an older binary that
	// has never heard of it reads every other stream unaffected. This is the
	// outcome-level parity point with mallcop-pro's UI dispatch endpoint — the
	// privileged mallcop-pro side later consumes this stream rather than the
	// chat loop making an HTTP call (core/investigate is net/http-banned; see
	// imports_test.go).
	KindSelfextDispatches Kind = "selfext_dispatches"
)

// kinds is the closed set of valid streams. Append/Load reject anything else so
// a typo can never create a rogue, unreplayed file in the repo.
var kinds = map[Kind]bool{
	KindEvents:            true,
	KindFindings:          true,
	KindResolutions:       true,
	KindBaseline:          true,
	KindConversation:      true,
	KindDirectives:        true,
	KindScans:             true,
	KindSelfextDispatches: true,
}

// Kinds returns the eight stream kinds in deterministic order. Useful for
// callers that want to enumerate or snapshot every stream.
func Kinds() []Kind {
	return []Kind{
		KindEvents, KindFindings, KindResolutions,
		KindBaseline, KindConversation, KindDirectives, KindScans,
		KindSelfextDispatches,
	}
}

func (k Kind) valid() bool { return kinds[k] }

func (k Kind) file() string { return string(k) + ".jsonl" }

// Serializer is the per-tenant write-serialization HOOK. The OSS store uses an
// in-process mutex (procMutex); the managed/multi-tenant side implements this
// against a durable lock (e.g. an Azure Table lease) so that writers in
// different processes — or different machines — cannot interleave commits to
// the same tenant repo.
//
// Lock must block until the caller holds exclusive write access for repoPath,
// and return a release func that the store calls (deferred) when the append's
// commit has landed. An implementation MAY ignore repoPath if its lock is
// already tenant-scoped. Lock returns an error only when the lock cannot be
// acquired at all (e.g. lease backend unreachable); a transient contention is
// the implementation's problem to retry internally.
//
// This package deliberately does NOT implement an aztables serializer. That
// belongs to the managed side, which will provide its own Serializer to
// OpenWith.
type Serializer interface {
	Lock(repoPath string) (release func(), err error)
}

// procMutex is the default OSS Serializer: a process-wide mutex keyed by
// absolute repo path. It guarantees that two *Store handles (or two goroutines)
// in the SAME process never commit concurrently to the same repo. Cross-process
// safety on a single machine is provided additionally by the rebase-retry in
// commitAppend; cross-machine safety is the managed Serializer's job.
type procMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

var defaultMutex = &procMutex{locks: map[string]*sync.Mutex{}}

func (p *procMutex) Lock(repoPath string) (func(), error) {
	p.mu.Lock()
	m, ok := p.locks[repoPath]
	if !ok {
		m = &sync.Mutex{}
		p.locks[repoPath] = m
	}
	p.mu.Unlock()
	m.Lock()
	return m.Unlock, nil
}

// Store is a handle to the git-repo source of truth at a single repo path. It
// is safe for concurrent use by multiple goroutines; appends are serialized by
// the Serializer.
type Store struct {
	repoPath   string
	serializer Serializer
	authorName string
	authorMail string
}

// Open opens (and, on a fresh repo, initializes the streams in) the git
// repository rooted at repoPath. repoPath must already be a git work tree —
// callers run `git init` first (the store does not create repos; tests and the
// CLI own that lifecycle). Open uses the default in-process Serializer.
//
// Open is cheap and side-effect-light: it verifies the repo, but does NOT read
// or rewrite any stream. State is reconstructed lazily by Load*/LoadDirectives.
func Open(repoPath string) (*Store, error) {
	return OpenWith(repoPath, defaultMutex)
}

// OpenWith is Open with an explicit Serializer. The managed side passes its
// durable, tenant-scoped lock here. A nil serializer falls back to the default
// in-process mutex.
func OpenWith(repoPath string, s Serializer) (*Store, error) {
	if s == nil {
		s = defaultMutex
	}
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("store: resolve repo path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("store: repo path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("store: repo path %q is not a directory", abs)
	}
	if _, err := os.Stat(filepath.Join(abs, ".git")); err != nil {
		return nil, fmt.Errorf("store: %q is not a git repository (run git init first): %w", abs, err)
	}
	return &Store{
		repoPath:   abs,
		serializer: s,
		authorName: "mallcop-store",
		authorMail: "store@mallcop.app",
	}, nil
}

// Path returns the absolute repo path this store writes to.
func (s *Store) Path() string { return s.repoPath }

// Append serializes record to a single JSON line and appends it to the kind's
// stream, then commits. The write is APPEND-ONLY: prior records in the file are
// never read, parsed, or rewritten — the new line is concatenated to the
// existing bytes, so history is preserved verbatim. The commit is taken under
// the Serializer lock and retried via rebase if a concurrent committer moved
// HEAD between staging and commit, so no write is ever lost.
//
// record may be any JSON-serializable value (a typed struct such as
// finding.Finding, or a map[string]any directive). Append returns the resulting
// commit SHA.
func (s *Store) Append(kind Kind, record any) (sha string, err error) {
	if !kind.valid() {
		return "", fmt.Errorf("store: unknown stream kind %q", kind)
	}
	line, err := marshalLine(kind, record)
	if err != nil {
		return "", err
	}

	release, err := s.serializer.Lock(s.repoPath)
	if err != nil {
		return "", fmt.Errorf("store: acquire write lock: %w", err)
	}
	defer release()

	chunk := append(append([]byte(nil), line...), '\n')
	return s.commitAppend(kind, chunk, 1)
}

// AppendBatch serializes and commits MULTIPLE records to kind's stream as a
// SINGLE commit, instead of one commit per record.
//
// WHY THIS EXISTS: commitAppend's plumbing (see its doc comment) re-reads and
// re-hashes the ENTIRE stream blob on every call — that is the price of the
// work-tree-free CAS design, and it is fine at the granularity of "one commit
// per Append call". It stops being fine when a caller drives thousands of
// Appends back to back (a scan ingesting a large connector pull): the cost of
// N single-record commits against a stream of size F is O(N * F), because
// each commit re-hashes the (growing) whole file. In production this produced
// thousands of commits per scan, each writing a multi-MB blob into the object
// store — tens of gigabytes of loose-object churn that exhausted CI runner
// disk (mallcoppro-ee3). AppendBatch collapses the whole batch into ONE
// commitAppend call — one blob re-hash, one commit — so the cost for a
// same-size batch drops to O(F) regardless of N.
//
// ATOMICITY CONTRACT: AppendBatch is all-or-nothing. Every record is
// marshaled and JSONL-validated (one record, no bare newline) BEFORE the
// Serializer lock is acquired and before anything is written to the object
// store. If any record at index k fails to marshal or contains a newline, the
// WHOLE batch is rejected with an error naming index k, and NOTHING is
// committed — not even the records before k. Once validation passes, the
// batch is committed as a single atomic commitAppend call: there is no
// intermediate state where only part of the batch has landed.
//
// EMPTY BATCH: len(records) == 0 is a documented no-op. It returns ("", nil)
// without taking the Serializer lock or creating a commit — there is nothing
// to append, so there is nothing to charge a commit for.
//
// Append (the per-record path) remains correct and is the right choice for
// low-volume streams where the batching overhead isn't worth it (e.g.
// KindConversation, KindDirectives, or any single-record write) — it is not
// deprecated by this addition.
func (s *Store) AppendBatch(kind Kind, records []any) (sha string, err error) {
	if !kind.valid() {
		return "", fmt.Errorf("store: unknown stream kind %q", kind)
	}
	if len(records) == 0 {
		return "", nil
	}

	// Marshal + validate EVERY record up front, before the lock and before any
	// write — a bad record anywhere in the batch must reject the whole batch,
	// leaving the store untouched.
	var chunk bytes.Buffer
	for i, rec := range records {
		line, err := marshalLine(kind, rec)
		if err != nil {
			return "", fmt.Errorf("store: batch %s record %d: %w", kind, i, err)
		}
		chunk.Write(line)
		chunk.WriteByte('\n')
	}

	release, err := s.serializer.Lock(s.repoPath)
	if err != nil {
		return "", fmt.Errorf("store: acquire write lock: %w", err)
	}
	defer release()

	return s.commitAppend(kind, chunk.Bytes(), len(records))
}

// marshalLine serializes record to a single JSONL line (no trailing newline)
// and enforces the one-record-one-line invariant Append/AppendBatch both
// depend on: json.Marshal never emits a bare newline itself, but this guards
// the invariant explicitly so a future encoder change can't silently corrupt
// the stream format.
func marshalLine(kind Kind, record any) ([]byte, error) {
	line, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("store: marshal %s record: %w", kind, err)
	}
	if bytes.ContainsRune(line, '\n') {
		return nil, fmt.Errorf("store: marshaled %s record contains a newline", kind)
	}
	return line, nil
}

// commitAppend performs the append-and-commit critical section: REBASE-RETRY on
// conflict via a git ref compare-and-swap. The caller holds the Serializer lock,
// which serializes writers in the SAME process; this function additionally
// makes the write safe against a SECOND OS PROCESS (or a managed Serializer that
// scopes per-tenant rather than per-repo) WITHOUT relying on the shared work
// tree or index at all.
//
// A naive "append to the work-tree file, then git add && git commit" is unsafe
// under true concurrency: two processes share one work tree and one index.lock,
// so their file appends and commits interleave into lost writes, duplicated
// records, or hard "File exists" failures. We sidestep the work tree entirely
// and operate on the git OBJECT STORE with plumbing:
//
//  1. Read the current HEAD (oldHead) and the committed content of the stream
//     blob at HEAD.
//  2. Append our chunk (one or more already newline-terminated JSONL lines)
//     to that content in memory and write a NEW BLOB (git hash-object -w).
//  3. Build a NEW TREE from HEAD's tree with our blob swapped in
//     (read-tree + update-index in a TEMPORARY, per-attempt index file — never
//     the shared index — then write-tree).
//  4. Create the commit (git commit-tree -p oldHead).
//  5. Atomically advance the ref: git update-ref HEAD <newCommit> <oldHead>.
//     This is a COMPARE-AND-SWAP — it fails iff HEAD moved since step 1. On
//     failure we loop (rebase onto the new tip). On success our write is the
//     unique child of oldHead.
//
// Because the CAS rejects any commit whose expected-old-value is stale, no
// concurrent writer can be overwritten: every winner advances HEAD by exactly
// one commit, every loser retries against the new HEAD. The result is a linear,
// deterministic, commit-ordered log with NO lost write and NO duplicate, proven
// by TestRebaseRetryUnderTrueRace.
//
// Steps 1-5 above deliberately never touch the repo's REAL index/work tree —
// only the CAS winner's per-attempt temp index. Once the CAS lands, the
// winner reconciles the real index/work tree to HEAD (syncWorkTree) so the
// repo never sits, even transiently, in the drifted state where an ordinary
// `git status` sees every stream file as staged-deleted (mallcoppro-4fe).
//
// chunk is one-or-more COMPLETE, newline-terminated JSONL lines (the caller —
// Append for one record, AppendBatch for many — has already validated and
// terminated every line); commitAppend never parses or re-splits it, it only
// concatenates: next = prev + chunk. count is the number of records chunk
// carries, purely for the commit message: exactly 1 keeps the historical
// "store: append <kind>" format (existing greps/tests depend on this exact
// string), anything else appends "(n=<count>)" so `git log` shows the batch
// size without breaking the single-record format.
func (s *Store) commitAppend(kind Kind, chunk []byte, count int) (string, error) {
	const maxRetries = 128
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff(attempt)
		}

		// oldHead is the tip we rebase onto, or "" if the repo has no commits
		// yet (a freshly `git init`'d repo). The first Append bootstraps a root
		// commit; thereafter every Append builds on the prior tip.
		oldHead, _ := s.head() // err ⇒ no HEAD ⇒ oldHead == ""

		// (1) Current committed content of the stream at HEAD ("" if the blob
		// does not exist yet, or no HEAD). We read from the OBJECT STORE, not
		// the work tree, so a peer's in-flight work-tree state cannot taint us.
		var prev []byte
		if oldHead != "" {
			var err error
			prev, err = s.blobAt(oldHead, kind.file())
			if err != nil {
				lastErr = err
				continue
			}
		}

		// (2) Append our chunk (already newline-terminated, one-or-more
		// lines) in memory and write the new blob. Bound BOTH operands
		// against a fixed ceiling before the capacity arithmetic: prev comes
		// from a repo blob a hostile clone could have made pathological, and
		// an absurd length must fail loud here — not overflow the make()
		// capacity or panic in the allocator. A stream anywhere near a TiB
		// is corruption, not data (the whole file is re-hashed per commit).
		if len(prev) > maxStreamBytes || len(chunk) > maxStreamBytes {
			return "", fmt.Errorf("store: %s stream too large to append to (%d + %d bytes, ceiling %d)",
				kind, len(prev), len(chunk), maxStreamBytes)
		}
		next := make([]byte, 0, len(prev)+len(chunk))
		next = append(next, prev...)
		next = append(next, chunk...)
		blobSHA, err := s.hashObject(next)
		if err != nil {
			lastErr = err
			continue
		}

		// (3) Build the new tree (off HEAD's tree, or the empty tree on
		// bootstrap) with our blob swapped in, using a per-attempt temp index
		// so we never touch the shared index.
		treeSHA, err := s.buildTree(oldHead, kind.file(), blobSHA)
		if err != nil {
			lastErr = err
			continue
		}

		// (4) Commit the tree on top of oldHead (no parent on bootstrap).
		// count==1 keeps the historical "store: append <kind>" message
		// exactly as before (existing greps/tests depend on this literal
		// string); a batch of more than one record appends "(n=<count>)" so
		// `git log` shows the batch size.
		message := fmt.Sprintf("store: append %s", kind)
		if count != 1 {
			message = fmt.Sprintf("store: append %s (n=%d)", kind, count)
		}
		commitSHA, err := s.commitTree(treeSHA, oldHead, message)
		if err != nil {
			lastErr = err
			continue
		}

		// (5) CAS the ref. On bootstrap, require the ref to NOT yet exist (a
		// zero old-value) so two racing first-writers can't both create it;
		// otherwise require it to still equal oldHead. Either way a stale CAS
		// is retryable contention.
		var casArgs []string
		if oldHead == "" {
			// 40 zeros = "ref must not currently exist".
			casArgs = []string{"update-ref", "HEAD", commitSHA, strings.Repeat("0", 40)}
		} else {
			casArgs = []string{"update-ref", "HEAD", commitSHA, oldHead}
		}
		if _, err := s.git(casArgs...); err != nil {
			lastErr = err // expected under contention — rebase and retry
			continue
		}
		// The commit that just landed was built entirely against the
		// PER-ATTEMPT temp index above (buildTree) — the repo's REAL index
		// (.git/index) was never touched. Left alone, it silently drifts out
		// of sync with HEAD forever: the real index still reflects whatever
		// it held when the repo was `git init`'d (nothing, for a fresh repo),
		// while HEAD's tree gains a stream file on every Append. Reconcile it
		// now, as an integral part of this write, so the repo is NEVER left
		// in the drifted state between commits (see syncWorkTree).
		if err := s.syncWorkTree(); err != nil {
			return "", err
		}
		return commitSHA, nil
	}
	return "", fmt.Errorf("store: commit %s gave up after %d rebase retries: %w", kind, maxRetries, lastErr)
}

// syncWorkTree reconciles the repo's REAL index and work tree to CURRENT HEAD
// (re-resolved here, never the sha the caller just produced) after a
// successful commit. It is the fix for mallcoppro-4fe: commitAppend and
// WriteSnapshot build every commit through a per-attempt TEMPORARY index
// (GIT_INDEX_FILE) so concurrent writers racing the CAS never contend on the
// repo's shared index/lock — but that means a successful append NEVER updates
// the real .git/index. Left unreconciled, the real index permanently reflects
// whatever it held at `git init` time (empty, for every repo this CLI
// creates) while HEAD's tree accumulates the stream files. Any git command
// that DOES look at the real index (`git status`, or a customer's
// `git add -A && git commit`) then sees every stream file as staged-DELETED
// (index lacks the path, HEAD has it) and physically missing (the work tree
// was never written either) — and a follow-on commit in that state COMMITS
// the deletion, replacing real history with git's empty tree.
//
// `git read-tree --reset -u HEAD` atomically replaces the real index AND the
// work-tree contents with HEAD's tree in one step: it is idempotent and
// monotonic (re-resolving HEAD instead of taking a specific sha means a
// slower concurrent writer's sync can never regress a faster one's — whatever
// order concurrent syncs land in, each converges the repo to whatever HEAD
// currently holds, never backward). It does not disturb untracked paths
// outside HEAD's tree, because those were never part of any index to begin
// with.
//
// SIDECAR STATE (.mallcop/): the CLI keeps sidecar files INSIDE the store
// repo — most importantly the cloud connectors' incremental cursors at
// .mallcop/cursors/<id>, written as plain files mid-scan and committed by the
// deployment AFTER the scan. While such a path is untracked the reset leaves
// it alone, but the moment a deployment commits it, it is part of HEAD's tree
// — and a later in-scan write to it would be silently REVERTED by the reset
// below (observed live: aws-3dl's committed cursor froze at its first value
// forever, every scan re-pulling the full window). syncWorkTree therefore
// snapshots every regular file under .mallcop/cursors/ before the reset and
// rewrites it after: in-flight cursor state always survives reconciliation,
// tracked or not. A failed restore is a hard error — silently losing a
// cursor means silently re-pulling (or worse, skipping) a window on the next
// scan. NOTE: unlike the stream reconcile above, the sidecar restore is
// last-write-wins and NOT monotonic across concurrent same-store processes —
// acceptable because cursors are only ever written by the single scan
// process that owns the store in every supported deployment.
//
// Contention on the real index lock (a second writer's sync running at the
// same instant) is expected only under true multi-process/goroutine
// concurrency against the SAME store — never in the single-writer path
// `mallcop scan` uses — so it is retried with the same backoff as the CAS
// loop rather than failing outright.
func (s *Store) syncWorkTree() error {
	sidecar, err := s.snapshotSidecar()
	if err != nil {
		return err
	}
	const maxRetries = 32
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff(attempt)
		}
		if _, err := s.git("read-tree", "--reset", "-u", "HEAD"); err != nil {
			lastErr = err
			continue
		}
		return s.restoreSidecar(sidecar)
	}
	return fmt.Errorf("store: sync work tree gave up after %d retries: %w", maxRetries, lastErr)
}

// sidecarCursorsDir is the CLI-owned directory inside the store repo whose
// in-flight file state (connector cursors) must survive syncWorkTree's
// reset. Deliberately NARROW — .mallcop/cursors/, not all of .mallcop/ — so
// a hostile or misconfigured store clone cannot make the per-commit snapshot
// read arbitrarily large unrelated content (e.g. a wasm cache) into memory.
const sidecarCursorsDir = ".mallcop/cursors"

// snapshotSidecar reads every regular file under <repo>/.mallcop/cursors
// into memory. A missing directory is the common case (nothing to preserve)
// and returns an empty map. The directory is small by construction (a
// handful of sub-KB cursor files), so reading it wholesale per sync is
// trivially cheap.
func (s *Store) snapshotSidecar() (map[string][]byte, error) {
	root := filepath.Join(s.repoPath, filepath.FromSlash(sidecarCursorsDir))
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			// A cursor removed between the walk listing and this read is a
			// skip, not a failure — there is simply nothing to preserve.
			if os.IsNotExist(rerr) {
				return nil
			}
			return rerr
		}
		files[path] = b
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: snapshot sidecar state: %w", err)
	}
	return files, nil
}

// restoreSidecar rewrites the snapshotted sidecar files after the work-tree
// reset. Restoring is unconditional (byte-identical rewrites are harmless)
// and MUST succeed: a lost cursor silently widens or gaps the next scan.
func (s *Store) restoreSidecar(files map[string][]byte) error {
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("store: restore sidecar dir for %s: %w", path, err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return fmt.Errorf("store: restore sidecar file %s: %w", path, err)
		}
	}
	return nil
}

// WriteSnapshot commits a full-content JSON document named `name` at the repo
// root, using the same work-tree-free plumbing + CAS-retry as commitAppend.
// Unlike Append (which appends one line to a JSONL stream), a snapshot REPLACES
// the whole file with the caller's complete record set — the current, deduped,
// non-suppressed view. It is the browser-readable projection of the scan: a
// consumer (e.g. the web chat) reads this single document instead of replaying
// the append-only findings.jsonl, which accumulates historical + suppressed
// records across scans. A snapshot byte-identical to HEAD's is a no-op (no empty
// commit). Returns the new (or unchanged) commit SHA.
func (s *Store) WriteSnapshot(name string, records any) (string, error) {
	content, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return "", fmt.Errorf("store: marshal snapshot %s: %w", name, err)
	}
	content = append(content, '\n')

	release, err := s.serializer.Lock(s.repoPath)
	if err != nil {
		return "", fmt.Errorf("store: acquire write lock: %w", err)
	}
	defer release()

	const maxRetries = 128
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff(attempt)
		}
		oldHead, _ := s.head()
		if oldHead != "" {
			if prev, err := s.blobAt(oldHead, name); err == nil && bytes.Equal(prev, content) {
				return oldHead, nil // unchanged — skip the empty commit
			}
		}
		blobSHA, err := s.hashObject(content)
		if err != nil {
			lastErr = err
			continue
		}
		treeSHA, err := s.buildTree(oldHead, name, blobSHA)
		if err != nil {
			lastErr = err
			continue
		}
		commitSHA, err := s.commitTree(treeSHA, oldHead, "store: snapshot "+name)
		if err != nil {
			lastErr = err
			continue
		}
		var casArgs []string
		if oldHead == "" {
			casArgs = []string{"update-ref", "HEAD", commitSHA, strings.Repeat("0", 40)}
		} else {
			casArgs = []string{"update-ref", "HEAD", commitSHA, oldHead}
		}
		if _, err := s.git(casArgs...); err != nil {
			lastErr = err
			continue
		}
		// See syncWorkTree's doc comment (called identically from
		// commitAppend) — this commit's tree, like every commitAppend
		// commit, was built against a temp index only; reconcile the real
		// index/work tree to it now, not later.
		if err := s.syncWorkTree(); err != nil {
			return "", err
		}
		return commitSHA, nil
	}
	return "", fmt.Errorf("store: snapshot %s gave up after %d retries: %w", name, maxRetries, lastErr)
}

// ReadSnapshot returns the current committed bytes of a full-document file at
// HEAD — a snapshot written by WriteSnapshot (findings.json,
// investigations/<finding-id>.json, …) or any other path present in the repo's
// tree. It is a thin PUBLIC wrapper over the same blobAt(HEAD, name) plumbing
// WriteSnapshot already uses internally for its own byte-identical no-op check,
// exposed so a consumer (core/inquest's idempotency check, prior-investigation
// lookup) can read a snapshot back without reaching into the store's private
// git plumbing. A path that does not exist at HEAD (including "the repo has no
// commits yet") returns (nil, nil) — not found is not an error, exactly like
// Load's empty-stream case.
func (s *Store) ReadSnapshot(name string) ([]byte, error) {
	head, err := s.head()
	if err != nil {
		// No HEAD (repo with zero commits) → nothing has ever been written.
		return nil, nil
	}
	return s.blobAt(head, name)
}

// CommitTimesFor returns the commit timestamps (RFC3339, git's %cI) of every
// commit that touched ANY of the given repo-root-relative paths, ascending. It
// is the HISTORICAL fallback for scan-cadence correlation on a store that
// predates the KindScans register (mallcoppro-e3c): every commitAppend/
// WriteSnapshot call this store's sole writer (`mallcop scan`) makes is ITSELF
// a scan-run timestamp, so the git log of the streams a scan always touches
// (events.jsonl, baseline.jsonl, resolutions.jsonl) recovers scan cadence back
// to the repo's very first commit with zero additional bookkeeping — this is
// what lets correlation see "hourly, since March" on a store whose KindScans
// register only started today.
//
// No dedup across paths: commitAppend/WriteSnapshot's per-commit plumbing
// swaps in exactly ONE file per commit (buildTree), so two DIFFERENT paths
// never share a commit — deduping by timestamp would wrongly collapse two
// genuinely distinct commits that happen to land within the same
// second-resolution %cI value (routine under a fast test or a burst of
// scans), undercounting scan_count.
//
// A repo with zero commits, or a path never committed, is not an error — it
// contributes no timestamps.
func (s *Store) CommitTimesFor(paths ...string) ([]time.Time, error) {
	var out []time.Time
	for _, p := range paths {
		raw, err := s.git("log", "--format=%cI", "--", p)
		if err != nil {
			if strings.Contains(err.Error(), "does not have any commits yet") ||
				strings.Contains(err.Error(), "unknown revision or path") ||
				strings.Contains(err.Error(), "bad revision") {
				continue
			}
			return nil, fmt.Errorf("store: commit times for %s: %w", p, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			t, terr := time.Parse(time.RFC3339, line)
			if terr != nil {
				continue // a malformed log line is skipped, not fatal
			}
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out, nil
}

// blobAt returns the bytes of the file blob at the given commit, or empty bytes
// if the file does not exist in that commit's tree.
func (s *Store) blobAt(commit, file string) ([]byte, error) {
	out, err := s.gitRaw("cat-file", "-p", commit+":"+file)
	if err != nil {
		// Missing path is not an error: the stream simply has no records yet.
		if strings.Contains(err.Error(), "does not exist") ||
			strings.Contains(err.Error(), "Not a valid object name") ||
			strings.Contains(err.Error(), "exists on disk, but not in") {
			return nil, nil
		}
		return nil, fmt.Errorf("store: read blob %s:%s: %w", commit, file, err)
	}
	return out, nil
}

// hashObject writes content as a blob into the object store and returns its sha.
func (s *Store) hashObject(content []byte) (string, error) {
	out, err := s.gitStdin(content, "hash-object", "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("store: hash-object: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// buildTree produces a new tree identical to baseCommit's tree but with file
// pointing at blobSHA. It uses a TEMPORARY index file unique to this attempt so
// concurrent writers never contend on the repo's shared index.
func (s *Store) buildTree(baseCommit, file, blobSHA string) (string, error) {
	tmpIndex, err := os.CreateTemp("", "mallcop-store-index-*")
	if err != nil {
		return "", fmt.Errorf("store: temp index: %w", err)
	}
	idxPath := tmpIndex.Name()
	if err := tmpIndex.Close(); err != nil {
		return "", fmt.Errorf("store: close temp index: %w", err)
	}
	// Remove the empty placeholder: git rejects a 0-byte file as a corrupt
	// index ("smaller than expected"). It must create the index fresh at this
	// path. We only needed CreateTemp to reserve a collision-free name.
	if err := os.Remove(idxPath); err != nil {
		return "", fmt.Errorf("store: clear temp index: %w", err)
	}
	defer os.Remove(idxPath)

	env := append(s.gitEnv(), "GIT_INDEX_FILE="+idxPath)

	// Seed the temp index from the base commit's tree. On bootstrap (no base
	// commit) the temp index starts empty, so we skip read-tree.
	if baseCommit != "" {
		if out, err := s.gitEnvCmd(env, nil, "read-tree", baseCommit); err != nil {
			return "", fmt.Errorf("store: read-tree %s: %v: %s", baseCommit, err, out)
		}
	}
	// Swap in our blob at the stream path (regular file mode 100644).
	if out, err := s.gitEnvCmd(env, nil, "update-index", "--add", "--cacheinfo", "100644", blobSHA, file); err != nil {
		return "", fmt.Errorf("store: update-index %s: %v: %s", file, err, out)
	}
	// Write the resulting tree.
	out, err := s.gitEnvCmd(env, nil, "write-tree")
	if err != nil {
		return "", fmt.Errorf("store: write-tree: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// commitTree creates a commit object for tree and returns its sha. parent is
// the single parent, or "" to create a root (parentless) commit on bootstrap.
// No ref is moved here — that is the CAS step in commitAppend.
func (s *Store) commitTree(tree, parent, message string) (string, error) {
	args := []string{"commit-tree", tree, "-m", message}
	if parent != "" {
		args = []string{"commit-tree", tree, "-p", parent, "-m", message}
	}
	out, err := s.git(args...)
	if err != nil {
		return "", fmt.Errorf("store: commit-tree: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// Load replays the kind's stream and returns each record as a raw JSON message,
// oldest first. State is reconstructed from the git OBJECT STORE at HEAD — the
// committed blob, not the work-tree file — so a Load always reflects durable,
// committed records and never a peer's in-flight write. This is what makes the
// git repo ALONE the source of truth: `git clone` carries every record, and a
// work tree is not even required.
//
// A stream with no committed records (never appended to, or a repo with no
// commits) is not an error — it returns an empty slice, because "the system has
// emitted zero of these" is a valid reconstructed state. Blank lines are
// skipped so a partially-flushed record degrades gracefully.
func (s *Store) Load(kind Kind) ([]json.RawMessage, error) {
	if !kind.valid() {
		return nil, fmt.Errorf("store: unknown stream kind %q", kind)
	}
	head, err := s.head()
	if err != nil {
		// No HEAD (repo with zero commits) → no records yet.
		return nil, nil
	}
	content, err := s.blobAt(head, kind.file())
	if err != nil {
		return nil, fmt.Errorf("store: load %s: %w", kind, err)
	}
	if len(content) == 0 {
		return nil, nil
	}

	var out []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(content))
	// Allow long lines (large payloads/evidence blobs).
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		// Validate it is well-formed JSON so a corrupt line surfaces here,
		// not three layers up in a consumer.
		if !json.Valid(raw) {
			return nil, fmt.Errorf("store: %s line %d is not valid JSON", kind, lineNo)
		}
		cp := make(json.RawMessage, len(raw))
		copy(cp, raw)
		out = append(out, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("store: scan %s: %w", kind, err)
	}
	return out, nil
}

// --- git plumbing -----------------------------------------------------------

func (s *Store) head() (string, error) {
	out, err := s.git("rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// backoff sleeps a short, jittered interval that grows with the attempt count,
// so a contended set of writers de-synchronizes on a CAS loss instead of
// livelocking. Capped so a hot repo still drains quickly.
func backoff(attempt int) {
	base := time.Duration(attempt) * 2 * time.Millisecond
	if base > 50*time.Millisecond {
		base = 50 * time.Millisecond
	}
	jitter := time.Duration(rand.Int63n(int64(2*time.Millisecond) + 1))
	time.Sleep(base + jitter)
}

// git runs a git subcommand in the repo and returns trimmed-free stdout as a
// string. It sets a deterministic identity and disables any user/global
// hooks/config bleed so the store's commits are reproducible regardless of the
// operator's environment.
func (s *Store) git(args ...string) (string, error) {
	out, err := s.gitEnvCmd(s.gitEnv(), nil, args...)
	return string(out), err
}

// gitRaw is git but returns raw stdout bytes (no string conversion churn) for
// reading blob content verbatim.
func (s *Store) gitRaw(args ...string) ([]byte, error) {
	return s.gitEnvCmd(s.gitEnv(), nil, args...)
}

// gitStdin runs git feeding stdin from in, returning raw stdout.
func (s *Store) gitStdin(in []byte, args ...string) ([]byte, error) {
	return s.gitEnvCmd(s.gitEnv(), in, args...)
}

// gitEnvCmd is the single exec chokepoint: runs git with an explicit env and
// optional stdin, returning raw stdout. Routing every git call through one
// function keeps stderr formatting and env handling consistent.
func (s *Store) gitEnvCmd(env []string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = s.repoPath
	cmd.Env = env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("git %s: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (s *Store) gitEnv() []string {
	env := os.Environ()
	env = append(env,
		"GIT_AUTHOR_NAME="+s.authorName,
		"GIT_AUTHOR_EMAIL="+s.authorMail,
		"GIT_COMMITTER_NAME="+s.authorName,
		"GIT_COMMITTER_EMAIL="+s.authorMail,
		// Keep the store hermetic: ignore global/system config that could
		// inject signing, hooks, or alternate identities.
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
	return env
}
