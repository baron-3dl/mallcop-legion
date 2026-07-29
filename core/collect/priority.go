// priority.go — the Gap E2 consumer: an operator 'prioritize' (alias
// 'criticality') directive reorders DetectorGaps' output so the gap the
// operator called out surfaces first, WITHOUT changing which gaps exist or
// their evidence. ADDITIVE ONLY (R9): this is a re-sort, never a filter — no
// GapCandidate is added, dropped, or reclassified by a prioritize directive,
// and it has zero effect on committee verdicts (gaps are a post-scan,
// operator-facing learning signal, not a detection-time decision).
//
// This mirrors core/pipeline's DirectiveDispatcher shape (Register a
// consumer per Op, replay every directive, accumulate an effect) but is its
// own small registry local to this package: core/pipeline's dispatcher
// mutates a FindingVerdict for a pkg/finding.Finding match, which has no
// notion of a GapCandidate or its (kind, source, detector-family) identity.
// Duplicating the tiny registry shape here — rather than stretching the
// finding-shaped dispatcher to cover gaps, or having collect import pipeline
// — keeps each package's directive consumer honest about what it can steer.
package collect

import (
	"strings"

	"github.com/mallcop-app/mallcop/core/store"
)

// defaultPrioritizeWeight is the boost a matching prioritize directive
// contributes when its Meta.Weight is unset (the zero value). "Focus on the
// payments connector" with no explicit weight must still move that gap ahead
// of everything else — a directive that matches but contributes 0 would be
// silently inert, which defeats the point of issuing it.
const defaultPrioritizeWeight = 1.0

// PriorityConsumer accumulates ONE directive's contribution to a
// GapCandidate's ranking weight. w is the running weight for this gap; d is
// the directive being applied (already confirmed to match this gap by
// gapDirectiveMatches).
type PriorityConsumer func(w *float64, d store.Directive, g GapCandidate)

// PriorityDispatcher routes each directive whose Op is registered to its
// consumer, accumulating a total ranking weight per GapCandidate. Unlike
// core/pipeline's DirectiveDispatcher (drop/keep), every consumer here is
// additive-only by construction: Weight only ever ADDS to the running total,
// it can never remove a gap from the output.
type PriorityDispatcher struct {
	consumers map[string]PriorityConsumer
}

// NewPriorityDispatcher returns a dispatcher pre-registered with the
// prioritize/criticality weight consumer. Other callers may Register
// additional Ops on top (e.g. a future deprioritize verb) without touching
// this file.
func NewPriorityDispatcher() *PriorityDispatcher {
	pd := &PriorityDispatcher{consumers: make(map[string]PriorityConsumer)}
	pd.Register("prioritize", prioritizeConsumer)
	pd.Register("criticality", prioritizeConsumer)
	return pd
}

// Register wires a consumer for the given Op. Registering the same Op twice
// replaces the prior consumer (last registration wins) — callers own not
// double-registering.
func (pd *PriorityDispatcher) Register(op string, c PriorityConsumer) {
	pd.consumers[op] = c
}

func prioritizeConsumer(w *float64, d store.Directive, _ GapCandidate) {
	meta, err := d.ParseMeta()
	if err != nil || meta.Weight == 0 {
		*w += defaultPrioritizeWeight
		return
	}
	*w += meta.Weight
}

// gapDirectiveMatches reports whether directive d (already known to have a
// registered Op) targets GapCandidate g. Meta.TargetKind selects what
// Pattern names:
//
//   - "source"  — Pattern matches g.Source verbatim, or g.DetectorFamily
//     (with or without a "detector:" prefix) — a detect_miss gap has no
//     Source, so targeting by family is the only way to reach it.
//   - "gap-key" — Pattern matches (a prefix of) gapSortKey(g), split on '|'
//     the same segment-wise way core/pipeline's matchPattern reads
//     "<source>/<type>/<actor>": a '*' segment matches anything, a directive
//     naming fewer segments than the key matches on the segments it names.
//   - anything else (including empty/absent TargetKind) — no match. A
//     prioritize directive with no target_kind is unactionable here (there
//     is no default finding-key semantics for a gap the way pipeline's
//     matchPattern has for a finding).
func gapDirectiveMatches(d store.Directive, g GapCandidate) bool {
	meta, err := d.ParseMeta()
	if err != nil {
		return false
	}
	pattern := strings.TrimSpace(d.Pattern)
	if pattern == "" {
		return false
	}
	switch meta.TargetKind {
	case "source":
		if pattern == "*" {
			return true
		}
		if pattern == g.Source {
			return true
		}
		family := strings.TrimPrefix(strings.TrimSpace(pattern), "detector:")
		return g.DetectorFamily != "" && family == g.DetectorFamily
	case "gap-key":
		return matchSegments(pattern, gapSortKey(g))
	default:
		return false
	}
}

// matchSegments implements the same prefix/wildcard segment match as
// core/pipeline's matchPattern, generalized to gapSortKey's '|' separator
// (pipeline's is fixed to '/'). A pattern with fewer segments than the key
// matches on the segments it names (a prefix match); more segments than the
// key never matches.
func matchSegments(pattern, key string) bool {
	keyParts := strings.Split(key, "|")
	patParts := strings.Split(pattern, "|")
	if len(patParts) > len(keyParts) {
		return false
	}
	for i, p := range patParts {
		if p == "*" {
			continue
		}
		if p != keyParts[i] {
			return false
		}
	}
	return true
}

// defaultPriorityDispatcher is the package-level singleton DetectorGaps
// applies. A caller that needs additional prioritization Ops builds its own
// via NewPriorityDispatcher + Register, same convention as
// core/pipeline.defaultDirectiveDispatcher.
var defaultPriorityDispatcher = NewPriorityDispatcher()

// weightGaps computes each GapCandidate's ranking weight by replaying
// directives against it: every directive whose Op is registered on pd AND
// whose target matches g contributes (accumulates, never subtracts). A gap
// with no matching directive gets weight 0 — the pre-existing, purely
// deterministic gapSortKey order.
//
// Keyed by gapSortKey(g) rather than slice index: the caller sorts the same
// []GapCandidate this map was built from, and sort.SliceStable mutates the
// slice in place (swaps elements between indices), so an index-keyed map
// would silently attach the wrong weight to the wrong gap mid-sort. gapSortKey
// is already the collector's own deterministic identity for a GapCandidate
// (kind|primary-id|source|event_type), so it doubles as a stable map key
// here with no new identity concept introduced.
func weightGaps(pd *PriorityDispatcher, gaps []GapCandidate, directives []store.Directive) map[string]float64 {
	weights := make(map[string]float64, len(gaps))
	for _, g := range gaps {
		var w float64
		for _, d := range directives {
			consumer, ok := pd.consumers[d.Op]
			if !ok {
				continue
			}
			if !gapDirectiveMatches(d, g) {
				continue
			}
			consumer(&w, d, g)
		}
		weights[gapSortKey(g)] = w
	}
	return weights
}
