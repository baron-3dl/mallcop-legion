package pipeline

import (
	"strings"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// findingKey is the STABLE identity a directive Pattern matches a finding by.
// It is "<source>/<type>/<actor>" — the triple that names "this kind of finding
// about this actor from this detector". The CLI derives a suppress Pattern from
// a concrete finding using exactly this key (see cmd/mallcop/feedback.go), so a
// directive written for one finding suppresses every future finding with the
// same source/type/actor — which is the whole point: the operator dismisses a
// CLASS of finding, not a single transient ID.
//
// The key is deterministic and depends only on durable finding fields, never on
// the per-run finding ID (which embeds the event ID and is not stable across
// scans). An empty segment is preserved (kept as "") so the arity is always
// three and a '*' glob in the directive can still match it.
func findingKey(f finding.Finding) string {
	return f.Source + "/" + f.Type + "/" + f.Actor
}

// matchPattern reports whether a directive Pattern matches a finding key. The
// match is segment-wise over the "<source>/<type>/<actor>" triple:
//
//   - The pattern is split on '/' into at most three segments.
//   - A '*' segment matches ANY value for that position (a wildcard).
//   - Any other segment must equal the corresponding key segment exactly.
//   - A pattern with FEWER than three segments matches on the segments it does
//     name (a prefix match) — e.g. "detector:secrets-exposure" matches every
//     finding from that source regardless of type/actor. A pattern with MORE
//     than three segments never matches (it over-specifies the triple).
//
// The matching is deterministic and case-sensitive — directives are written by
// the CLI from real finding fields, so the casing always lines up.
func matchPattern(pattern string, f finding.Finding) bool {
	if pattern == "" {
		return false
	}
	keyParts := []string{f.Source, f.Type, f.Actor}
	patParts := strings.Split(pattern, "/")
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

// FindingVerdict accumulates the effect of every matching directive on ONE
// finding as the directive stream replays in order (oldest first). Op
// consumers registered on a DirectiveDispatcher mutate it; the dispatcher
// decides what to do with the accumulated verdict once all directives have
// been applied (today: drop it if Suppressed).
//
// New fields land here as later items register new consumers (C2 mute-TTL,
// C3 focus/severity weighting, C5/A/E2 case + prioritization ops) — this is
// the extension point the item's DONE condition calls "a registry other
// stages hook into". Adding a field is never a behavior change on its own:
// only a registered consumer that reads it changes what happens to a finding.
type FindingVerdict struct {
	// Suppressed is true when the net effect of matching directives is "drop
	// this finding". Mirrors the pre-refactor suppress/unsuppress behavior
	// byte-for-byte: suppress sets it, unsuppress clears it, replay order
	// decides the last word.
	Suppressed bool
}

// DirectiveConsumer mutates a finding's verdict for ONE directive that
// matched that finding's Pattern. d is the directive being applied; f is the
// finding it matched (read-only — a consumer that needs finding fields, e.g.
// a future severity-override consumer, reads them here rather than mutating
// f directly, since Apply only ever returns kept/dropped findings unchanged).
type DirectiveConsumer func(v *FindingVerdict, d store.Directive, f finding.Finding)

// DirectiveDispatcher routes each directive to the consumer REGISTERED for
// its Op. This is the load-bearing seam that makes persisted feedback INERT
// no longer: a 'suppress' directive written by `mallcop feedback <id>
// dismiss` drops every future finding whose key matches the directive
// Pattern — and other pipeline stages (mute TTL, focus weighting, severity
// override, case-close) hook in by registering their own Op consumer instead
// of editing this file.
//
// An Op with no registered consumer is a no-op for Apply: it matches
// findings but has no drop/weight/severity effect here. That preserves the
// pre-refactor behavior for "focus" and "mute", which were documented verbs
// but never implemented as drop ops.
type DirectiveDispatcher struct {
	consumers map[string]DirectiveConsumer
}

// NewDirectiveDispatcher returns a dispatcher pre-registered with the
// existing suppress/unsuppress drop behavior. Other stages call Register to
// add their own Op consumers on top of this baseline.
func NewDirectiveDispatcher() *DirectiveDispatcher {
	d := &DirectiveDispatcher{consumers: make(map[string]DirectiveConsumer)}
	d.Register("suppress", suppressConsumer)
	d.Register("unsuppress", unsuppressConsumer)
	return d
}

// Register wires a consumer for the given Op. Registering the same Op twice
// replaces the prior consumer (last registration wins) — callers own not
// double-registering.
func (d *DirectiveDispatcher) Register(op string, c DirectiveConsumer) {
	d.consumers[op] = c
}

func suppressConsumer(v *FindingVerdict, _ store.Directive, _ finding.Finding) {
	v.Suppressed = true
}

func unsuppressConsumer(v *FindingVerdict, _ store.Directive, _ finding.Finding) {
	v.Suppressed = false
}

// Apply filters findings against the operator-steering directive stream.
//
// Semantics (deterministic, order-sensitive replay of the append-only
// stream) — UNCHANGED from the pre-refactor applyDirectives:
//
//   - suppress   — a finding matching Pattern is DROPPED.
//   - unsuppress — CANCELS a prior suppress for the same Pattern: a later
//     unsuppress wins, so the finding is kept again. (Replay order is the
//     directive stream order — oldest first — so the last word on a Pattern
//     wins.)
//   - Any Op with no registered consumer — not a drop verb here; left to
//     other consumers (notification muting, prioritization). It never
//     removes a finding, so it is a no-op for this filter.
//
// Returns the kept findings in their original order. A finding is kept unless
// the net effect of all directives that match it is "suppressed".
func (d *DirectiveDispatcher) Apply(findings []finding.Finding, directives []store.Directive) []finding.Finding {
	if len(directives) == 0 {
		return findings
	}
	kept := make([]finding.Finding, 0, len(findings))
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
		if !v.Suppressed {
			kept = append(kept, f)
		}
	}
	return kept
}

// defaultDirectiveDispatcher is the dispatcher applyDirectives uses. It is a
// package-level singleton (not per-call) so pipeline.go and callers that only
// need suppress/unsuppress semantics don't have to construct a dispatcher
// themselves; a caller that needs additional consumers (mute TTL, focus
// weighting, ...) builds its own via NewDirectiveDispatcher + Register.
var defaultDirectiveDispatcher = NewDirectiveDispatcher()

// applyDirectives filters findings against the operator-steering directive
// stream using the default (suppress/unsuppress-only) dispatcher. Kept as a
// thin wrapper for existing callers (core/pipeline/pipeline.go and this
// package's characterization tests) — behavior is byte-identical to the
// pre-refactor implementation; see DirectiveDispatcher.Apply for the
// semantics.
func applyDirectives(findings []finding.Finding, directives []store.Directive) []finding.Finding {
	return defaultDirectiveDispatcher.Apply(findings, directives)
}
