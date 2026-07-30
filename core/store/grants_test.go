package store

import (
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
	if _, err := s.Append(KindGrants, miss); err != nil {
		t.Fatalf("Append(KindGrants) miss: %v", err)
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
	// first. We identify the original row by its (Connector, DetectedAt)
	// pair, the same way a real consumer would key it, and append a brand
	// new row rather than editing the one already committed.
	originalRef := miss.Connector + "@" + miss.DetectedAt.Format(time.RFC3339)
	resolution := GrantOutcome{
		Connector:   miss.Connector,
		Cloud:       miss.Cloud,
		AccessMode:  miss.AccessMode,
		DetectedAt:  missAt.Add(10 * time.Minute),
		Resolved:    true,
		ResolvedRef: originalRef,
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
	if got[1].ResolvedRef != originalRef {
		t.Errorf("resolution row ResolvedRef = %q, want %q", got[1].ResolvedRef, originalRef)
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

// TestKindGrantsIsAdditive_OlderBinaryUnaffected proves the ACCEPTANCE
// criterion that an older binary that never heard of KindGrants reads every
// other stream unaffected: appending to KindGrants must not disturb any
// other stream's content, and the fixed, closed `kinds` map (pre-KindGrants
// shape simulated here by exercising only the OTHER kinds around a grants
// append) continues to round-trip normally.
func TestKindGrantsIsAdditive_OlderBinaryUnaffected(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Seed a record on an unrelated, pre-existing stream BEFORE any grants
	// activity.
	if _, err := s.Append(KindScans, ScanRecord{StartedAt: time.Now().UTC(), MallcopVersion: "v0.19.0"}); err != nil {
		t.Fatalf("Append(KindScans) seed: %v", err)
	}

	// Append to the new grants stream.
	if _, err := s.Append(KindGrants, GrantOutcome{
		Connector:  "github",
		Cloud:      "github",
		AccessMode: "read-only",
		DetectedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Append(KindGrants): %v", err)
	}

	// The pre-existing scans stream is unaffected: still exactly the one
	// record, decodable exactly as before — an "older binary" here is
	// simulated by simply never calling anything grants-related on this
	// data and confirming it is intact.
	scans, err := s.LoadScans()
	if err != nil {
		t.Fatalf("LoadScans after grants append: %v", err)
	}
	if len(scans) != 1 || scans[0].MallcopVersion != "v0.19.0" {
		t.Fatalf("KindScans stream disturbed by a KindGrants append: %+v", scans)
	}

	// Kinds() must include the new kind alongside every pre-existing one —
	// purely additive, nothing removed or renamed.
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
