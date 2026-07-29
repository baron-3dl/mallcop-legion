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

// sortByAttention orders findings by accumulated directive weight,
// descending, with the pre-existing deterministic finding-ID order as the
// tiebreak (both the zero-directives case and any weight tie). directives
// may be nil (no store directives, or the caller couldn't load them) — every
// finding then weighs 0 and the order is byte-identical to the pre-E2
// finding-ID sort.
func sortByAttention(findings []EscalatedFinding, directives []store.Directive) {
	weights := make(map[string]float64, len(findings))
	for _, f := range findings {
		weights[f.Finding.ID] = attentionWeight(f, directives)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		wi, wj := weights[findings[i].Finding.ID], weights[findings[j].Finding.ID]
		if wi != wj {
			return wi > wj
		}
		return findings[i].Finding.ID < findings[j].Finding.ID
	})
}
