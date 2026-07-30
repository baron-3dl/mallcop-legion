package store

import (
	"bytes"
	"testing"
	"time"
)

// TestKindGrantsAppendAndLoadRoundTrip proves the ninth stream (mallcoppro-62b)
// round-trips exactly like KindScans/KindSelfextDispatches: Append + Load
// recovers the typed records in commit order, through the REAL store
// append+git-commit path (initRepo is a real `git init` temp repo; Append
// shells out to real git plumbing — no fake/in-memory store is used
// anywhere in this file), and LoadGrantOutcomes decodes them onto
// GrantOutcome.
func TestKindGrantsAppendAndLoadRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	missAt := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)
	miss := GrantOutcome{
		Connector:    "aws-cloudtrail",
		Cloud:        "aws",
		AccessMode:   "read-only",
		FailureClass: "missing-scope",
		GrantCommand: "aws iam attach-role-policy --role-name mallcop-scan --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess",
		DetectedAt:   missAt,
		Resolved:     false,
	}
	missSHA, err := s.Append(KindGrants, miss)
	if err != nil {
		t.Fatalf("Append(KindGrants) miss: %v", err)
	}
	if missSHA == "" {
		t.Fatalf("Append(KindGrants) miss returned empty commit SHA")
	}

	got, err := s.LoadGrantOutcomes()
	if err != nil {
		t.Fatalf("LoadGrantOutcomes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadGrantOutcomes returned %d records, want 1", len(got))
	}
	if got[0].Connector != "aws-cloudtrail" || got[0].Resolved || got[0].ResolvedRef != "" {
		t.Errorf("miss row = %+v, want Connector=aws-cloudtrail Resolved=false ResolvedRef=\"\"", got[0])
	}
	if got[0].FailureClass != "missing-scope" || got[0].GrantCommand == "" {
		t.Errorf("miss row = %+v, want FailureClass=missing-scope and a non-empty GrantCommand", got[0])
	}

	// CRITICAL SCHEMA CHECK: a resolution is a SECOND appended row carrying
	// ResolvedRef pointing at the original miss row — never a mutation of the
	// first. ResolvedRef is NOT a synthetic/free-form key: it is the real
	// commit SHA Store.Append returned for the miss row above. That SHA is a
	// genuinely resolvable identity (see ResolveGrantMiss's doc comment) —
	// proven below by actually reading the original row back through it,
	// not merely asserting the string round-trips.
	resolution := GrantOutcome{
		Connector:   miss.Connector,
		Cloud:       miss.Cloud,
		AccessMode:  miss.AccessMode,
		DetectedAt:  missAt.Add(10 * time.Minute),
		Resolved:    true,
		ResolvedRef: missSHA,
	}
	if _, err := s.Append(KindGrants, resolution); err != nil {
		t.Fatalf("Append(KindGrants) resolution: %v", err)
	}

	got, err = s.LoadGrantOutcomes()
	if err != nil {
		t.Fatalf("LoadGrantOutcomes after resolution: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadGrantOutcomes returned %d records after resolution, want 2 (miss + resolution, never mutated in place)", len(got))
	}
	// The original miss row must be UNCHANGED — proves the resolution did not
	// mutate it.
	if got[0].Connector != "aws-cloudtrail" || got[0].Resolved || got[0].FailureClass != "missing-scope" {
		t.Errorf("original miss row mutated by resolution append: %+v", got[0])
	}
	// The second row is the resolution, pointing back at the original.
	if !got[1].Resolved {
		t.Fatalf("second row Resolved = false, want true (it is the resolution row)")
	}
	if got[1].ResolvedRef != missSHA {
		t.Errorf("resolution row ResolvedRef = %q, want %q (the miss row's Append commit SHA)", got[1].ResolvedRef, missSHA)
	}

	// PROVE resolvability, not just string round-tripping: dereference
	// ResolvedRef through ResolveGrantMiss and confirm it hands back the
	// EXACT original miss row's content — a consumer really can resolve the
	// resolution back to the diagnosis it closes.
	resolved, err := s.ResolveGrantMiss(got[1].ResolvedRef)
	if err != nil {
		t.Fatalf("ResolveGrantMiss(%q): %v", got[1].ResolvedRef, err)
	}
	if resolved.Connector != miss.Connector ||
		resolved.Cloud != miss.Cloud ||
		resolved.AccessMode != miss.AccessMode ||
		resolved.FailureClass != miss.FailureClass ||
		resolved.GrantCommand != miss.GrantCommand ||
		resolved.Resolved ||
		!resolved.DetectedAt.Equal(miss.DetectedAt) {
		t.Fatalf("ResolveGrantMiss(%q) = %+v, want the original miss row %+v", got[1].ResolvedRef, resolved, miss)
	}

	// A store that has never appended a grant record returns an empty slice,
	// not an error — mirrors LoadScans/LoadSelfextDispatches' contract.
	freshRepo := initRepo(t)
	fresh, err := Open(freshRepo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	none, err := fresh.LoadGrantOutcomes()
	if err != nil {
		t.Fatalf("LoadGrantOutcomes on empty stream: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("LoadGrantOutcomes on a store with no grant records = %d records, want 0", len(none))
	}
}

// TestLoadGrantOutcomesWithRefs_RecoversEachRowsOwnSHA proves the recovery
// path mallcoppro-d3f's Route 2 wiring needs: a reader that was NOT the
// process that originally called Append (a later `mallcop scan`, or the same
// process re-reading the stream a scan later) can still recover each row's
// own commit SHA — the exact same value Append itself returned when that row
// was written — purely by replaying the grants stream's commit history.
// Three real Append calls against a real git temp repo; no fake/in-memory
// store or synthetic SHA anywhere in this test.
func TestLoadGrantOutcomesWithRefs_RecoversEachRowsOwnSHA(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	sha1, err := s.Append(KindGrants, GrantOutcome{Connector: "aws-prod", FailureClass: "missing-scope", DetectedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	sha2, err := s.Append(KindGrants, GrantOutcome{Connector: "aws-prod", Resolved: true, ResolvedRef: sha1, DetectedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	sha3, err := s.Append(KindGrants, GrantOutcome{Connector: "github-audit", FailureClass: "missing read:audit_log scope", DetectedAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("Append 3: %v", err)
	}

	recs, err := s.LoadGrantOutcomesWithRefs()
	if err != nil {
		t.Fatalf("LoadGrantOutcomesWithRefs: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("LoadGrantOutcomesWithRefs returned %d records, want 3", len(recs))
	}
	wantSHAs := []string{sha1, sha2, sha3}
	for i, want := range wantSHAs {
		if recs[i].SHA != want {
			t.Errorf("record %d SHA = %q, want %q (Append's own return value for that row)", i, recs[i].SHA, want)
		}
	}
	if recs[0].Connector != "aws-prod" || recs[0].Resolved {
		t.Errorf("record 0 = %+v, want the aws-prod MISS row", recs[0])
	}
	if !recs[1].Resolved || recs[1].ResolvedRef != sha1 {
		t.Errorf("record 1 = %+v, want the resolution row pointing at sha1", recs[1])
	}
	if recs[2].Connector != "github-audit" {
		t.Errorf("record 2 = %+v, want the github-audit MISS row", recs[2])
	}

	// Prove the recovered SHA is genuinely resolvable, not merely a
	// plausible-looking string: hand it back through ResolveGrantMiss and
	// confirm it reads the SAME row LoadGrantOutcomesWithRefs already decoded.
	back, err := s.ResolveGrantMiss(recs[2].SHA)
	if err != nil {
		t.Fatalf("ResolveGrantMiss(%q): %v", recs[2].SHA, err)
	}
	if back.Connector != "github-audit" {
		t.Fatalf("ResolveGrantMiss(recovered SHA) = %+v, want the github-audit row", back)
	}

	// A store that has never appended to KindGrants returns an empty slice,
	// not an error — mirrors LoadGrantOutcomes' own contract.
	freshRepo := initRepo(t)
	fresh, err := Open(freshRepo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	none, err := fresh.LoadGrantOutcomesWithRefs()
	if err != nil {
		t.Fatalf("LoadGrantOutcomesWithRefs on empty stream: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("LoadGrantOutcomesWithRefs on a store with no grant records = %d records, want 0", len(none))
	}
}

// TestKindGrantsForwardCompat_UnknownStreamInertAndPreserved proves the
// ACTUAL forward-compatibility property the acceptance criterion needs: an
// older binary that has never heard of KindGrants (or ANY future stream)
// treats an unrecognized stream file as INERT — every known-kind Load still
// returns correct data with it present, and a subsequent known-kind Append
// preserves it byte-for-byte in the resulting tree.
//
// A prior version of this test used the SAME (fully KindGrants-aware) binary
// and simply didn't call grants code — that proves stream-FILE isolation
// within one binary, not forward compatibility of a reader whose kinds map
// genuinely lacks "grants". It would pass unchanged even if a future
// manifest or full-tree walk broke old readers, because nothing in it ever
// puts a kind-less blob in front of Load/Append.
//
// This test instead writes a stream file named for NO Kind this binary's
// closed `kinds` map contains — future_kind.jsonl — directly into the git
// tree, using the store's own real object-store plumbing (hashObject /
// buildTree / commitTree / update-ref / syncWorkTree — the exact primitives
// commitAppend itself is built from, see store.go). That is deliberate, not
// a shortcut: Append/AppendBatch REJECT any kind outside the closed map
// (TestAppendRejectsUnknownKind), which is precisely why an unknown future
// stream can only be simulated by dropping to the same low-level plumbing a
// genuinely newer binary's commitAppend would have used to create it. Nothing
// here is mocked or faked — every call below hits the real git binary against
// a real temp repo, identically to every other test in this package.
func TestKindGrantsForwardCompat_UnknownStreamInertAndPreserved(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Seed a known stream BEFORE the unknown blob exists, so we can prove it
	// survives the unknown blob's arrival.
	if _, err := s.Append(KindScans, ScanRecord{StartedAt: time.Now().UTC(), MallcopVersion: "v0.19.0"}); err != nil {
		t.Fatalf("Append(KindScans) seed: %v", err)
	}

	// Write an UNKNOWN-kind stream file directly into the tree via the
	// store's real low-level plumbing — bypassing Append's kind validation
	// entirely, because that validation is exactly what would block us from
	// ever creating this file through the public API. This is what a stream
	// a genuinely newer binary invented, and this binary has never heard of,
	// looks like on disk.
	futureContent := []byte(`{"future_field":"a stream kind this binary's kinds map does not contain"}` + "\n")
	oldHead, err := s.head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	blobSHA, err := s.hashObject(futureContent)
	if err != nil {
		t.Fatalf("hashObject: %v", err)
	}
	treeSHA, err := s.buildTree(oldHead, "future_kind.jsonl", blobSHA)
	if err != nil {
		t.Fatalf("buildTree: %v", err)
	}
	commitSHA, err := s.commitTree(treeSHA, oldHead, "simulate: unknown future stream write")
	if err != nil {
		t.Fatalf("commitTree: %v", err)
	}
	if _, err := s.git("update-ref", "HEAD", commitSHA, oldHead); err != nil {
		t.Fatalf("update-ref: %v", err)
	}
	if err := s.syncWorkTree(); err != nil {
		t.Fatalf("syncWorkTree: %v", err)
	}

	// (a) Every known-kind Load still returns correct data with the unknown
	// stream present in the tree.
	scans, err := s.LoadScans()
	if err != nil {
		t.Fatalf("LoadScans with unknown-kind stream present: %v", err)
	}
	if len(scans) != 1 || scans[0].MallcopVersion != "v0.19.0" {
		t.Fatalf("LoadScans disturbed by an unrelated unknown-kind stream file: %+v", scans)
	}

	// Append to a known stream (grants itself) alongside the unknown one, and
	// confirm ITS Load is unaffected too.
	if _, err := s.Append(KindGrants, GrantOutcome{
		Connector:  "github",
		Cloud:      "github",
		AccessMode: "read-only",
		DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Append(KindGrants) with unknown-kind stream present: %v", err)
	}
	grants, err := s.LoadGrantOutcomes()
	if err != nil {
		t.Fatalf("LoadGrantOutcomes with unknown-kind stream present: %v", err)
	}
	if len(grants) != 1 || grants[0].Connector != "github" {
		t.Fatalf("LoadGrantOutcomes disturbed by an unrelated unknown-kind stream file: %+v", grants)
	}

	// (b) The known-kind Append above must have preserved the unknown blob
	// BYTE-FOR-BYTE in the resulting tree — proving commitAppend's
	// swap-one-file tree-building (buildTree) never touches, drops, or
	// corrupts sibling files it doesn't know about.
	newHead, err := s.head()
	if err != nil {
		t.Fatalf("head after known-kind append: %v", err)
	}
	got, err := s.blobAt(newHead, "future_kind.jsonl")
	if err != nil {
		t.Fatalf("blobAt future_kind.jsonl after known-kind append: %v", err)
	}
	if !bytes.Equal(got, futureContent) {
		t.Fatalf("unknown-kind stream blob was NOT preserved byte-for-byte across a known-kind Append.\n got:  %q\nwant: %q", got, futureContent)
	}

	// Kinds()/valid() sanity: KindGrants itself is additive too, same as
	// before — nothing removed or renamed from the closed set.
	found := false
	for _, k := range Kinds() {
		if k == KindGrants {
			found = true
		}
	}
	if !found {
		t.Fatalf("Kinds() does not include KindGrants: %v", Kinds())
	}
	if !KindGrants.valid() {
		t.Fatalf("KindGrants.valid() = false, want true")
	}
}
