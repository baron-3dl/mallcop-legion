package store

import (
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

// seedlessInit git-inits dir WITHOUT the root seed commit initRepo uses —
// a genuinely zero-commit repo (no HEAD), so ReadSnapshot/CommitTimesFor's
// "no HEAD yet" branch is exercised directly rather than only their
// "path never touched" branch.
func seedlessInit(t *testing.T, dir string) {
	t.Helper()
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
}

// TestKindScansAppendAndLoadRoundTrip proves the seventh stream round-trips
// exactly like the existing six: Append + Load recovers the typed records in
// commit order, and LoadScans decodes them onto ScanRecord.
func TestKindScansAppendAndLoadRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t1 := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	recs := []ScanRecord{
		{StartedAt: t1, FinishedAt: t1.Add(2 * time.Second), EventsScanned: 5, FindingsDetected: 1, Escalated: 1, MallcopVersion: "v0.15.0"},
		{StartedAt: t2, FinishedAt: t2.Add(3 * time.Second), EventsScanned: 3, FindingsDetected: 0, Escalated: 0, MallcopVersion: "v0.15.0"},
	}
	for _, r := range recs {
		if _, err := s.Append(KindScans, r); err != nil {
			t.Fatalf("Append(KindScans): %v", err)
		}
	}

	got, err := s.LoadScans()
	if err != nil {
		t.Fatalf("LoadScans: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadScans returned %d records, want 2", len(got))
	}
	if !got[0].StartedAt.Equal(t1) || got[0].EventsScanned != 5 || got[0].Escalated != 1 {
		t.Errorf("first scan record = %+v, want StartedAt=%v EventsScanned=5 Escalated=1", got[0], t1)
	}
	if !got[1].StartedAt.Equal(t2) || got[1].FindingsDetected != 0 {
		t.Errorf("second scan record = %+v, want StartedAt=%v FindingsDetected=0", got[1], t2)
	}

	// A store that has never appended a scan record returns an empty slice,
	// not an error — mirrors LoadDirectives/LoadConversation's contract.
	freshRepo := initRepo(t)
	fresh, err := Open(freshRepo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	none, err := fresh.LoadScans()
	if err != nil {
		t.Fatalf("LoadScans on empty stream: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("LoadScans on a store with no scans = %d records, want 0", len(none))
	}
}

// TestKindSelfextDispatchesAppendAndLoadRoundTrip proves the eighth stream
// (mallcoppro-0d95) round-trips exactly like KindScans did for the seventh:
// Append + Load recovers the typed records in commit order, and
// LoadSelfextDispatches decodes them onto SelfextDispatchRecord.
func TestKindSelfextDispatchesAppendAndLoadRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	t1 := time.Date(2026, 7, 29, 9, 0, 0, 0, time.UTC)
	recs := []SelfextDispatchRecord{
		{RequestedAt: t1, Lane: "heal", DetectorID: "authored-deploy-burst", EventType: "github.deployment", Severity: "medium", Reason: "operator asked to cover this gap", Autonomy: "fully"},
		{RequestedAt: t1.Add(time.Hour), Lane: "investigate", DetectorID: "authored-payments-scope", EventType: "cloud.iam", Actor: "svc-payments", Source: "aws", Autonomy: "semi"},
	}
	for _, r := range recs {
		if _, err := s.Append(KindSelfextDispatches, r); err != nil {
			t.Fatalf("Append(KindSelfextDispatches): %v", err)
		}
	}

	got, err := s.LoadSelfextDispatches()
	if err != nil {
		t.Fatalf("LoadSelfextDispatches: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadSelfextDispatches returned %d records, want 2", len(got))
	}
	if got[0].DetectorID != "authored-deploy-burst" || got[0].Autonomy != "fully" {
		t.Errorf("first dispatch record = %+v, want DetectorID=authored-deploy-burst Autonomy=fully", got[0])
	}
	if got[1].Actor != "svc-payments" || got[1].Autonomy != "semi" {
		t.Errorf("second dispatch record = %+v, want Actor=svc-payments Autonomy=semi", got[1])
	}

	// A store that has never appended a selfext dispatch record returns an
	// empty slice, not an error — mirrors LoadScans/LoadDirectives' contract.
	freshRepo := initRepo(t)
	fresh, err := Open(freshRepo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	none, err := fresh.LoadSelfextDispatches()
	if err != nil {
		t.Fatalf("LoadSelfextDispatches on empty stream: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("LoadSelfextDispatches on a store with no dispatches = %d records, want 0", len(none))
	}
}

// TestReadSnapshotRoundTrip proves ReadSnapshot recovers exactly what
// WriteSnapshot committed, including a NESTED path (investigations/<id>.json)
// — the shape core/inquest depends on to write beside findings.json without a
// store-schema change — and reports (nil, nil) for a path that was never
// written, and for a store with zero commits.
func TestReadSnapshotRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	type doc struct {
		Verdict string `json:"verdict"`
	}
	if _, err := s.WriteSnapshot("investigations/finding-abc123.json", doc{Verdict: "benign"}); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	got, err := s.ReadSnapshot("investigations/finding-abc123.json")
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	var d doc
	if err := json.Unmarshal(got, &d); err != nil {
		t.Fatalf("unmarshal snapshot: %v (raw=%s)", err, got)
	}
	if d.Verdict != "benign" {
		t.Errorf("ReadSnapshot verdict = %q, want %q", d.Verdict, "benign")
	}

	// A findings.json snapshot written to the repo ROOT must coexist with the
	// nested investigations/ path — proves buildTree's read-tree-then-swap
	// preserves sibling tree entries rather than clobbering the whole tree.
	if _, err := s.WriteSnapshot("findings.json", []int{1, 2, 3}); err != nil {
		t.Fatalf("WriteSnapshot findings.json: %v", err)
	}
	stillThere, err := s.ReadSnapshot("investigations/finding-abc123.json")
	if err != nil || len(stillThere) == 0 {
		t.Fatalf("investigations/finding-abc123.json lost after writing a sibling snapshot: err=%v len=%d", err, len(stillThere))
	}

	// Missing path -> (nil, nil), not an error.
	missing, err := s.ReadSnapshot("investigations/finding-does-not-exist.json")
	if err != nil {
		t.Fatalf("ReadSnapshot missing path: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("ReadSnapshot missing path returned %d bytes, want 0", len(missing))
	}

	// Zero-commit repo -> (nil, nil), not an error (mirrors Load's empty-stream
	// contract). initRepo seeds a root commit, so build a truly bare one here.
	bareDir := t.TempDir()
	seedlessInit(t, bareDir)
	bare, err := Open(bareDir)
	if err != nil {
		t.Fatalf("Open bare: %v", err)
	}
	zero, err := bare.ReadSnapshot("anything.json")
	if err != nil {
		t.Fatalf("ReadSnapshot on zero-commit repo: %v", err)
	}
	if len(zero) != 0 {
		t.Fatalf("ReadSnapshot on zero-commit repo returned %d bytes, want 0", len(zero))
	}
}

// TestCommitTimesForRecoversHistory proves CommitTimesFor returns the commit
// timestamps of every commit that touched the named path(s), ascending and
// deduplicated — the historical fallback core/inquest's scan-schedule
// correlation uses on a store that predates the KindScans register: every
// Append to events.jsonl this store's sole writer (`mallcop scan`) makes IS a
// scan-run timestamp.
func TestCommitTimesForRecoversHistory(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Three separate "scans": each appends to events.jsonl (a commit).
	for i := 0; i < 3; i++ {
		if _, err := s.Append(KindEvents, map[string]any{"id": i}); err != nil {
			t.Fatalf("Append(KindEvents) %d: %v", i, err)
		}
	}
	// A commit to a DIFFERENT stream must not be picked up when querying only
	// events.jsonl.
	if _, err := s.Append(KindDirectives, map[string]any{"op": "focus"}); err != nil {
		t.Fatalf("Append(KindDirectives): %v", err)
	}

	times, err := s.CommitTimesFor("events.jsonl")
	if err != nil {
		t.Fatalf("CommitTimesFor: %v", err)
	}
	if len(times) != 3 {
		t.Fatalf("CommitTimesFor(events.jsonl) returned %d timestamps, want 3", len(times))
	}
	for i := 1; i < len(times); i++ {
		if times[i].Before(times[i-1]) {
			t.Errorf("CommitTimesFor did not return ascending order: %v before %v", times[i], times[i-1])
		}
	}

	// Multiple paths union without duplicating a commit that touched both in
	// the SAME AppendBatch call — but here they're separate commits, so the
	// union should just be a superset.
	union, err := s.CommitTimesFor("events.jsonl", "directives.jsonl")
	if err != nil {
		t.Fatalf("CommitTimesFor(multi): %v", err)
	}
	if len(union) != 4 {
		t.Fatalf("CommitTimesFor(events.jsonl, directives.jsonl) returned %d timestamps, want 4", len(union))
	}

	// A path never committed contributes nothing, and is not an error.
	none, err := s.CommitTimesFor("never-written.jsonl")
	if err != nil {
		t.Fatalf("CommitTimesFor(never-written): %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("CommitTimesFor(never-written) returned %d timestamps, want 0", len(none))
	}

	// A store with zero commits is not an error either.
	bareDir := t.TempDir()
	seedlessInit(t, bareDir)
	bare, err := Open(bareDir)
	if err != nil {
		t.Fatalf("Open bare: %v", err)
	}
	zero, err := bare.CommitTimesFor("events.jsonl")
	if err != nil {
		t.Fatalf("CommitTimesFor on zero-commit repo: %v", err)
	}
	if len(zero) != 0 {
		t.Fatalf("CommitTimesFor on zero-commit repo returned %d timestamps, want 0", len(zero))
	}
}
