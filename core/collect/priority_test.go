package collect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// TestDetectorGaps_PrioritizeDirective_TargetSourceReordersOutput proves the
// item's DONE condition: a 'prioritize' directive with target_kind="source"
// reorders gapSortKey's ranking for a real gap set. Without any directive,
// two reported_miss gaps on sources "detector:aaa" and "detector:zzz" sort
// alphabetically (aaa first, per gapSortKey). A prioritize directive naming
// "detector:zzz" must move it to the front.
func TestDetectorGaps_PrioritizeDirective_TargetSourceReordersOutput(t *testing.T) {
	st := openStore(t)

	metaA, _ := json.Marshal(map[string]any{"source": "detector:aaa", "event_type": "login"})
	appendRec(t, st, store.KindDirectives, store.Directive{Op: reportMissOp, Meta: metaA})
	metaZ, _ := json.Marshal(map[string]any{"source": "detector:zzz", "event_type": "login"})
	appendRec(t, st, store.KindDirectives, store.Directive{Op: reportMissOp, Meta: metaZ})

	// Baseline: no prioritize directive — deterministic alphabetical order.
	gaps, err := DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}
	if len(gaps) != 2 || gaps[0].Source != "detector:aaa" || gaps[1].Source != "detector:zzz" {
		t.Fatalf("baseline order = %+v, want [aaa, zzz]", gaps)
	}

	// Now issue a prioritize directive on the zzz source and re-run against a
	// FRESH store carrying the same two gaps plus the prioritize directive —
	// mirrors how a directive appended between scans steers the next run.
	st2 := openStore(t)
	appendRec(t, st2, store.KindDirectives, store.Directive{Op: reportMissOp, Meta: metaA})
	appendRec(t, st2, store.KindDirectives, store.Directive{Op: reportMissOp, Meta: metaZ})
	metaPrio, _ := json.Marshal(map[string]any{"target_kind": "source", "weight": 5.0})
	appendRec(t, st2, store.KindDirectives, store.Directive{
		Op: "prioritize", Pattern: "detector:zzz", Actor: "operator",
		Reason: "focus on the payments connector", Meta: metaPrio,
	})

	prioritized, err := DetectorGaps(st2, nil)
	if err != nil {
		t.Fatalf("DetectorGaps (prioritized): %v", err)
	}
	if len(prioritized) != 2 || prioritized[0].Source != "detector:zzz" || prioritized[1].Source != "detector:aaa" {
		t.Fatalf("prioritized order = %+v, want [zzz, aaa] (prioritize directive should surface zzz first)", prioritized)
	}

	// ADDITIVE, no verdict effect (R9): the same two gaps exist in both runs
	// (same kinds, same evidence) — only their ORDER changed.
	baselineByID := map[string]GapCandidate{}
	for _, g := range gaps {
		baselineByID[g.Source] = g
	}
	for _, g := range prioritized {
		base, ok := baselineByID[g.Source]
		if !ok {
			t.Fatalf("prioritize directive introduced a gap not present in the baseline: %+v", g)
		}
		if mustJSON(t, base.Evidence) != mustJSON(t, g.Evidence) {
			t.Fatalf("prioritize directive changed gap evidence for %s: %+v vs %+v", g.Source, base.Evidence, g.Evidence)
		}
	}
}

// TestDetectorGaps_PrioritizeDirective_TargetGapKeyReordersOutput proves the
// "gap-key" target_kind variant: a directive naming the override_fp kind plus
// a specific finding id reorders two override_fp gaps that would otherwise
// sort by finding id.
func TestDetectorGaps_PrioritizeDirective_TargetGapKeyReordersOutput(t *testing.T) {
	st := openStore(t)

	seedOverrideFP(t, st, "find-a", "detector:aaa")
	seedOverrideFP(t, st, "find-b", "detector:bbb")

	metaPrio, _ := json.Marshal(map[string]any{"target_kind": "gap-key", "weight": 3.0})
	appendRec(t, st, store.KindDirectives, store.Directive{
		Op: "criticality", Pattern: "override_fp|find-b", Meta: metaPrio,
	})

	gaps, err := DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}
	if len(gaps) != 2 {
		t.Fatalf("want 2 gaps, got %d: %+v", len(gaps), gaps)
	}
	if gaps[0].FindingIDs[0] != "find-b" {
		t.Fatalf("gap-key prioritize directive did not surface find-b first: %+v", gaps)
	}
}

// TestDetectorGaps_PrioritizeDirective_DefaultWeight proves a prioritize
// directive with NO explicit Meta.weight still boosts a matching gap ahead
// of a non-matching one — "focus on X" with no weight given must not be a
// silent no-op.
func TestDetectorGaps_PrioritizeDirective_DefaultWeight(t *testing.T) {
	st := openStore(t)

	seedOverrideFP(t, st, "find-a", "detector:aaa")
	seedOverrideFP(t, st, "find-z", "detector:zzz")

	metaPrio, _ := json.Marshal(map[string]any{"target_kind": "source"})
	appendRec(t, st, store.KindDirectives, store.Directive{
		Op: "prioritize", Pattern: "detector:zzz", Meta: metaPrio, // no weight field
	})

	gaps, err := DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}
	if len(gaps) != 2 || gaps[0].Source != "detector:zzz" {
		t.Fatalf("default-weight prioritize directive did not reorder: %+v", gaps)
	}
}

// TestDetectorGaps_PrioritizeDirective_NonMatchingPatternIsInert proves a
// prioritize directive whose pattern matches NOTHING in this gap set has
// zero effect — the output is byte-identical to having no directive at all.
func TestDetectorGaps_PrioritizeDirective_NonMatchingPatternIsInert(t *testing.T) {
	st := openStore(t)
	seedOverrideFP(t, st, "find-a", "detector:aaa")
	seedOverrideFP(t, st, "find-z", "detector:zzz")
	baseline, err := DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}

	st2 := openStore(t)
	seedOverrideFP(t, st2, "find-a", "detector:aaa")
	seedOverrideFP(t, st2, "find-z", "detector:zzz")
	metaPrio, _ := json.Marshal(map[string]any{"target_kind": "source", "weight": 9.0})
	appendRec(t, st2, store.KindDirectives, store.Directive{
		Op: "prioritize", Pattern: "detector:nonexistent", Meta: metaPrio,
	})
	withDirective, err := DetectorGaps(st2, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}

	if mustJSON(t, baseline) != mustJSON(t, withDirective) {
		t.Fatalf("non-matching prioritize directive changed output:\nbaseline=%s\nwith=%s",
			mustJSON(t, baseline), mustJSON(t, withDirective))
	}
}

// seedOverrideFP appends the resolution + suppress-directive pair that
// DetectorGaps turns into ONE GapOverrideFP gap, keyed by findingID/source.
func seedOverrideFP(t *testing.T, st *store.Store, findingID, source string) {
	t.Helper()
	appendRec(t, st, store.KindResolutions, resolution.Resolution{
		FindingID: findingID, Action: "escalate", Reason: "clean escalate, no dissent",
		Actor: "mallory", Severity: "high", Source: source,
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	})
	meta, _ := json.Marshal(map[string]any{"finding_id": findingID, "verb": "resolve"})
	appendRec(t, st, store.KindDirectives, store.Directive{
		Op: "suppress", Pattern: source, Meta: meta,
	})
}
