// priority.go — the Gap E2 consumer for this package: an operator
// 'prioritize' (alias 'criticality') directive with Meta.target_kind="source"
// weights investigation ATTENTION — which escalated findings RunAll spends
// its metered narrate budget on first. ADDITIVE ONLY (R9): this only
// reorders findings already selected for investigation by the cascade; it
// never adds, drops, or reclassifies a finding, and it has zero effect on
// committee verdicts (a re-sort of who gets investigated first when
// MaxPerScan can't cover everyone this scan, nothing more).
//
// This intentionally does NOT import core/collect's PriorityDispatcher (same
// registry shape, different consumer) — core/inquest's closed import
// allowlist (imports_test.go) bars a dependency on any sibling core package
// other than core/agent/core/store/core/tools, so the tiny match+accumulate
// logic is duplicated here rather than shared. Both copies read the same
// store.DirectiveMeta wire shape (target_kind/weight), so an operator
// directive steers both the gap queue (core/collect) and investigation
// attention (here) with one write.
package inquest

import (
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/store"
)

// prioritizeAttentionOps are the directive Op values this consumer answers
// to (Design §Gap E2: "a 'prioritize'/'criticality' directive").
var prioritizeAttentionOps = map[string]bool{
	"prioritize":  true,
	"criticality": true,
}

// defaultAttentionWeight is the boost a matching directive contributes when
// its Meta.Weight is unset — mirrors core/collect's defaultPrioritizeWeight
// so "focus on the payments connector" with no explicit weight still moves
// that source's findings ahead, not silently 0.
const defaultAttentionWeight = 1.0

// attentionWeight sums every 'prioritize'/'criticality' directive whose
// Meta.TargetKind is "source" and whose Pattern matches f.Source — "*"
// matches every source, an exact string matches that source only. A finding
// with no matching directive gets weight 0, preserving the pre-existing
// finding-ID order.
func attentionWeight(f EscalatedFinding, directives []store.Directive) float64 {
	var w float64
	for _, d := range directives {
		if !prioritizeAttentionOps[d.Op] {
			continue
		}
		meta, err := d.ParseMeta()
		if err != nil || meta.TargetKind != "source" {
			continue
		}
		pattern := strings.TrimSpace(d.Pattern)
		if pattern == "" {
			continue
		}
		if pattern != "*" && pattern != f.Finding.Source {
			continue
		}
		if meta.Weight == 0 {
			w += defaultAttentionWeight
			continue
		}
		w += meta.Weight
	}
	return w
}

// sortByAttention orders findings by accumulated E2 directive weight,
// descending, and preserves the INCOMING order on any tie (both the
// zero-directives case and any weight tie) rather than re-deciding ties by
// finding-ID itself. This composes with RunAll's Gap C attention-weight sort
// (mallcoppro-4da) that runs immediately before this one: that sort already
// establishes a deterministic order (its own weight, descending, ID as its
// tiebreak), so a stable no-reorder-on-tie here means "no matching E2
// directive" is a true no-op on top of Gap C's ordering — not a silent
// re-sort back to plain finding-ID order that would discard a focus/
// watch-closer weight whenever no prioritize/criticality directive also
// exists. directives may be nil (no store directives, or the caller couldn't
// load them) — every finding then weighs 0 and this call changes nothing.
func sortByAttention(findings []EscalatedFinding, directives []store.Directive) {
	weights := make(map[string]float64, len(findings))
	for _, f := range findings {
		weights[f.Finding.ID] = attentionWeight(f, directives)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return weights[findings[i].Finding.ID] > weights[findings[j].Finding.ID]
	})
}
