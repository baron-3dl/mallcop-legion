package store

import (
	"testing"
	"time"
)

// TestKindContribBackAppendAndLoadRoundTrip proves the tenth stream
// (mallcoppro-003) round-trips exactly like KindGrants/KindScans/
// KindSelfextDispatches: Append + Load recovers the typed records in commit
// order, through the REAL store append+git-commit path (initRepo is a real
// `git init` temp repo; Append shells out to real git plumbing — no fake/
// in-memory store anywhere in this file).
func TestKindContribBackAppendAndLoadRoundTrip(t *testing.T) {
	repo := initRepo(t)
	s, err := Open(repo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	openedAt := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)
	opened := ContribBackRecord{
		Fingerprint: "abcdef0123456789",
		PRURL:       "https://github.com/mallcop-app/mallcop/pull/42",
		State:       ContribBackOpen,
		OpenedAt:    openedAt,
		UpdatedAt:   openedAt,
	}
	if _, err := s.Append(KindContribBack, opened); err != nil {
		t.Fatalf("Append(KindContribBack) opened: %v", err)
	}

	got, err := s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadContribBackRecords returned %d records, want 1", len(got))
	}
	if got[0].State != ContribBackOpen || got[0].PRURL != opened.PRURL {
		t.Errorf("opened row = %+v, want State=open PRURL=%s", got[0], opened.PRURL)
	}

	// CRITICAL SCHEMA CHECK: a state change is a SECOND appended row — never
	// a mutation of the first. Same append-only discipline KindGrants uses
	// for its miss/resolution pair.
	merged := opened
	merged.State = ContribBackMerged
	merged.UpdatedAt = openedAt.Add(48 * time.Hour)
	if _, err := s.Append(KindContribBack, merged); err != nil {
		t.Fatalf("Append(KindContribBack) merged: %v", err)
	}

	got, err = s.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords after merge: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadContribBackRecords returned %d records after merge, want 2 (opened + merged, never mutated in place)", len(got))
	}
	if got[0].State != ContribBackOpen {
		t.Errorf("original opened row mutated: %+v", got[0])
	}
	if got[1].State != ContribBackMerged || got[1].PRURL != opened.PRURL {
		t.Errorf("second row = %+v, want State=merged PRURL=%s (same PR, new state)", got[1], opened.PRURL)
	}
	if !got[1].OpenedAt.Equal(openedAt) {
		t.Errorf("merged row OpenedAt = %v, want preserved %v", got[1].OpenedAt, openedAt)
	}

	// A store that has never appended a contribback record returns an empty
	// slice, not an error — mirrors LoadGrantOutcomes'/LoadScans' contract.
	freshRepo := initRepo(t)
	fresh, err := Open(freshRepo)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	none, err := fresh.LoadContribBackRecords()
	if err != nil {
		t.Fatalf("LoadContribBackRecords on empty stream: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("LoadContribBackRecords on a store with no contribback records = %d records, want 0", len(none))
	}
}

// TestKindContribBackIsAdditive proves KindContribBack is registered in the
// closed kinds set and enumerated by Kinds() — the same forward-compatibility
// bar every other stream meets.
func TestKindContribBackIsAdditive(t *testing.T) {
	if !KindContribBack.valid() {
		t.Fatalf("KindContribBack.valid() = false, want true")
	}
	found := false
	for _, k := range Kinds() {
		if k == KindContribBack {
			found = true
		}
	}
	if !found {
		t.Fatalf("Kinds() does not include KindContribBack: %v", Kinds())
	}
}
