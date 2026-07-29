package pipeline

import (
	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
)

// CaseConsumer mutates a case SET for one directive whose Op targets a case,
// not a finding — there is no finding.Finding to hand a
// DirectiveConsumer (directives.go) for a "close-case"/"recurrence-fine"
// directive, so it gets its own, parallel op->consumer registry rather than
// forcing a case-shaped Op through the finding-shaped DirectiveDispatcher.
type CaseConsumer func(existing []cases.Case, d store.Directive) []cases.Case

// caseConsumers is the registry case-targeting directive Ops resolve
// against — the SAME "op -> consumer, Register to add one" seam
// DirectiveDispatcher.Register uses for finding-targeting ops (suppress,
// unsuppress, and whatever mute/focus/severity consumers register in their
// own files), mirrored here for the case-projection stage.
var caseConsumers = map[string]CaseConsumer{}

// RegisterCaseConsumer wires a consumer for the given Op against the case
// directive registry. Registering the same Op twice replaces the prior
// consumer (last registration wins) — callers own not double-registering,
// same contract as DirectiveDispatcher.Register.
func RegisterCaseConsumer(op string, c CaseConsumer) {
	caseConsumers[op] = c
}

func init() {
	RegisterCaseConsumer("close-case", closeCaseConsumer)
	RegisterCaseConsumer("recurrence-fine", recurrenceFineConsumer)
}

// caseDirectivePattern reports whether directive d's Pattern names case c —
// an EXACT match (unlike matchPattern's glob-triple matching for findings):
// case IDs are content-derived hashes (cases.caseID), not a "/"-segmented
// source/type/actor key, so there is no meaningful wildcard/prefix
// vocabulary to reuse from matchPattern here.
func caseDirectivePattern(d store.Directive, id string) bool {
	return d.Pattern != "" && d.Pattern == id
}

func closeCaseConsumer(existing []cases.Case, d store.Directive) []cases.Case {
	for _, c := range existing {
		if caseDirectivePattern(d, c.CaseID) {
			return cases.SetStatus(existing, c.CaseID, cases.StatusClosed)
		}
	}
	return existing
}

func recurrenceFineConsumer(existing []cases.Case, d store.Directive) []cases.Case {
	for _, c := range existing {
		if caseDirectivePattern(d, c.CaseID) {
			return cases.SetStatus(existing, c.CaseID, cases.StatusAged)
		}
	}
	return existing
}

// ApplyCaseDirectives replays directives against a case set in stream order
// (oldest first — same replay-order contract DirectiveDispatcher.Apply uses
// for findings), routing each directive to its registered Op consumer. A
// directive whose Op has no registered consumer, or whose Pattern names no
// case in the current set, is a no-op — mirrors DirectiveDispatcher.Apply's
// "unregistered Op does nothing" behavior.
//
// This is the enforcement seam: a persisted 'close-case'/'recurrence-fine'
// directive (issued via `mallcop case close <id>` or the chat write-tool,
// Gap A) is INERT until something replays it against the case set — this
// function is that replay, called from cli's collapseCases before the
// merged case set is written back to cases.json, so the transition survives
// past the scan that issued the directive AND every scan after it (the
// directive stream is append-only and replayed in full each time).
func ApplyCaseDirectives(existing []cases.Case, directives []store.Directive) []cases.Case {
	for _, d := range directives {
		consumer, ok := caseConsumers[d.Op]
		if !ok {
			continue
		}
		existing = consumer(existing, d)
	}
	return existing
}
