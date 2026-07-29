// consumer_attention.go — the Gap C attention consumers (mallcoppro-4da):
// focus/watch-closer (an attention WEIGHT that feeds finding ranking and
// core/inquest's investigation-depth budget) and severity (a LABEL override
// on finding.Severity). Registered on the shared defaultDirectiveDispatcher
// via an init() Register() call, per the same pattern other Gap-C ops
// (mute-TTL, cases) register their own consumers — this file never edits
// directives.go's dispatch loop, matching, or the suppress/unsuppress
// consumers.
//
// R9 (hard invariant): both consumers here are naming/weighting/annotation
// ONLY. Neither ever sets FindingVerdict.Suppressed, and neither is called
// anywhere near core/agent's committee vote — Weight and SeverityOverride
// are read by ranking/budget/display code strictly AFTER a finding's
// escalate/quiet disposition has already been decided and persisted. A
// focus or severity directive can make a finding get MORE investigation
// attention or a different displayed label; it can never flip a verdict.
package pipeline

import (
	"sort"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// defaultFocusWeight is the attention bump a focus/watch-closer directive
// contributes when its Meta carries no explicit Weight (e.g. `mallcop
// feedback <id> watch` issued with no --weight flag). A bare "pay more
// attention to this" directive must still move the needle, so an absent/
// non-positive Weight falls back to this constant rather than contributing
// zero (which would make the directive a silent no-op).
const defaultFocusWeight = 1.0

func init() {
	defaultDirectiveDispatcher.Register("focus", attentionWeightConsumer)
	defaultDirectiveDispatcher.Register("watch-closer", attentionWeightConsumer)
	defaultDirectiveDispatcher.Register("severity", severityOverrideConsumer)
}

// attentionWeightConsumer implements focus/watch-closer: "raise" is the only
// direction (the opposite of suppress, which drops outright) — there is no
// "un-focus" op in the documented vocabulary, so this only ever ADDS weight.
// Multiple matching focus/watch-closer directives on the same finding
// accumulate (replay order doesn't matter for a pure sum), which is the
// intended semantic: two independent operator signals to watch something
// closer should watch it closer than either alone.
func attentionWeightConsumer(v *FindingVerdict, d store.Directive, _ finding.Finding) {
	meta, err := d.ParseMeta()
	if err != nil {
		// Malformed Meta: annotation-only op, so degrade to a no-op rather
		// than propagate an error through the dispatch loop (Apply/callers
		// have no error return to carry it).
		return
	}
	w := meta.Weight
	if w <= 0 {
		w = defaultFocusWeight
	}
	v.Weight += w
}

// severityOverrideConsumer implements "severity": the LAST matching
// directive in replay order wins (directives replay oldest-first, so a later
// severity directive for the same Pattern supersedes an earlier one) —
// consistent with unsuppress-cancels-suppress's last-word-wins semantic
// elsewhere in this package. An empty/absent Meta.Severity (malformed or
// pre-Meta directive) leaves the accumulated override untouched rather than
// clearing it.
func severityOverrideConsumer(v *FindingVerdict, d store.Directive, _ finding.Finding) {
	meta, err := d.ParseMeta()
	if err != nil || meta.Severity == "" {
		return
	}
	v.SeverityOverride = meta.Severity
}

// AttentionVerdicts replays directives against findings using d's registered
// consumers and returns the accumulated FindingVerdict per finding, keyed by
// finding.ID. It is the read side of the same per-finding accumulation
// Apply performs internally — Apply only inspects Suppressed and discards
// the rest; this exposes Weight and SeverityOverride to callers that need
// them (finding ranking, the severity-override consumer, core/inquest's
// depth budget). A finding absent from directives entirely still gets an
// entry (the zero FindingVerdict), so callers can index unconditionally.
func (d *DirectiveDispatcher) AttentionVerdicts(findings []finding.Finding, directives []store.Directive) map[string]FindingVerdict {
	out := make(map[string]FindingVerdict, len(findings))
	for _, f := range findings {
		v := FindingVerdict{}
		for _, dir := range directives {
			if !matchPattern(dir.Pattern, f) {
				continue
			}
			if consumer, ok := d.consumers[dir.Op]; ok {
				consumer(&v, dir, f)
			}
		}
		out[f.ID] = v
	}
	return out
}

// AttentionWeights is AttentionVerdicts narrowed to just the Weight, keyed
// by finding.ID — the shape core/inquest.Input.AttentionWeights and
// RankFindings both consume. A finding with no matching focus/watch-closer
// directive gets weight 0 (the zero value), which sorts after any
// positively-weighted finding and never reorders relative to other
// zero-weight findings beyond the ID tiebreak.
func (d *DirectiveDispatcher) AttentionWeights(findings []finding.Finding, directives []store.Directive) map[string]float64 {
	verdicts := d.AttentionVerdicts(findings, directives)
	out := make(map[string]float64, len(verdicts))
	for id, v := range verdicts {
		out[id] = v.Weight
	}
	return out
}

// RankFindings returns findings reordered by descending attention weight
// (focus/watch-closer), breaking ties by finding ID for determinism — a
// re-run over the same findings+directives always produces the same order.
// This is the "finding ranking" half of Gap C's attention consumer; it never
// drops or mutates a finding, only reorders the slice (a copy — the input
// is left untouched).
func (d *DirectiveDispatcher) RankFindings(findings []finding.Finding, directives []store.Directive) []finding.Finding {
	weights := d.AttentionWeights(findings, directives)
	ranked := make([]finding.Finding, len(findings))
	copy(ranked, findings)
	sort.SliceStable(ranked, func(i, j int) bool {
		wi, wj := weights[ranked[i].ID], weights[ranked[j].ID]
		if wi != wj {
			return wi > wj
		}
		return ranked[i].ID < ranked[j].ID
	})
	return ranked
}

// ApplySeverityOverrides returns findings with Severity replaced per any
// matching "severity" directive (a copy — the input slice/findings are left
// untouched). R9: this changes ONLY the displayed finding.Severity label; it
// runs after core/agent's committee has already resolved escalate/quiet for
// every finding in the set, and it never feeds back into that vote.
func (d *DirectiveDispatcher) ApplySeverityOverrides(findings []finding.Finding, directives []store.Directive) []finding.Finding {
	verdicts := d.AttentionVerdicts(findings, directives)
	out := make([]finding.Finding, len(findings))
	for i, f := range findings {
		out[i] = f
		if sv := verdicts[f.ID].SeverityOverride; sv != "" {
			out[i].Severity = sv
		}
	}
	return out
}
