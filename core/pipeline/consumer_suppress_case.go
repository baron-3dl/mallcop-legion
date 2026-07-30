package pipeline

import (
	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// consumer_suppress_case.go closes the over-broad-suppression defect
// (mallcoppro-419, the opus security review of the suppression surface): the
// operator console derives a 'suppress' directive's Pattern as
// "<source>/<type>/<actor>" (findingKey, directives.go) — Entity is dropped —
// but core/cases clusters escalated findings on (Type, Actor, ENTITY)
// (core/cases/collapse.go's Key). core/cases' own
// TestCollapse_DistinctEntity_DistinctCases proves two findings sharing
// type/actor but differing only by entity are DISTINCT cases. So silencing
// the case the operator was actually shown ALSO silenced every sibling case
// under a different entity — a permanent blind spot that looks exactly like
// quiet on a security product.
//
// 'suppress-case' is a NEW directive Op whose Pattern is a CaseID
// (core/cases.CaseID's 12-hex-char content hash of Type+Actor+Entity) —
// exactly as narrow as the case the console showed the operator, because
// Entity is baked into the hash. It is consumed HERE, at the finding stage,
// via its OWN equality match (ApplySuppressCase below) rather than through
// DirectiveDispatcher.Apply's matchPattern: matchPattern's contract is the
// "<source>/<type>/<actor>" segment-glob triple that suppress/unsuppress/mute
// all share, and a CaseID is not a value in that triple (Entity, which the
// hash is partly derived from, has no segment there at all). Extending
// matchPattern with a 4th segment to carry Entity was explicitly rejected
// (mallcoppro-419 orchestrator ruling): it would change an already-shipped
// matcher's contract and risk every suppress directive a customer has
// already committed to the store. So 'suppress-case' gets its own,
// independent equality match instead — the SAME pattern
// core/pipeline/consumer_case.go already established for the OTHER
// case-targeting ops (close-case/recurrence-fine): those mutate the case
// SET via caseDirectivePattern's exact `d.Pattern == c.CaseID` compare;
// ApplySuppressCase below is the finding-stage twin, matching a finding's
// OWN CaseID (recomputed per finding, the same way pipeline.go's escalation
// loop already does) the identical way.
//
// The existing suppress/unsuppress/mute ops, matchPattern, and
// DirectiveDispatcher.Apply are completely untouched by this file — this is
// an ADDITIONAL filter applied alongside applyDirectives, not a
// modification of it.
//
// CONSENSUS INVARIANT: this is a suppression the pipeline honours, same as
// 'suppress' — it drops findings BEFORE they reach the committee cascade,
// it never overrides a committee verdict already reached. A finding whose
// case has no matching 'suppress-case' directive is untouched.

// suppressedCaseIDs returns the set of CaseIDs named by any 'suppress-case'
// directive in the stream. The directive stream is append-only and this
// reads the WHOLE stream every time (mirrors applyDirectives' own full
// replay) — there is no 'unsuppress-case' counterpart in this item's scope
// (mirrors consumer_case.go's close-case/recurrence-fine, which likewise
// have no "reopen" verb yet); a directive naming a CaseID suppresses it for
// every future scan that replays this stream.
func suppressedCaseIDs(directives []store.Directive) map[string]bool {
	ids := make(map[string]bool)
	for _, d := range directives {
		if d.Op == "suppress-case" && d.Pattern != "" {
			ids[d.Pattern] = true
		}
	}
	return ids
}

// findingCaseID computes the SAME clustering hash pipeline.go's escalation
// loop and core/cases.Collapse use for this exact (Type, Actor, Entity)
// triple — core/cases.CaseID, never re-derived independently (a second
// clustering path computing its own notion of "the same case" is exactly
// the drift bug that hash exists to prevent). Computable for ANY finding,
// escalated or not: CaseID depends only on Type/Actor/Evidence, none of
// which require a cascade resolution to exist.
func findingCaseID(f finding.Finding) string {
	return cases.CaseID(cases.Key{
		Type:   f.Type,
		Actor:  f.Actor,
		Entity: cases.ExtractEntity(f.Evidence),
	})
}

// ApplySuppressCase drops every finding whose case (findingCaseID) is named
// by a 'suppress-case' directive, and keeps every other finding untouched —
// in particular, a SIBLING case sharing Type/Actor but differing only by
// Entity computes a DIFFERENT CaseID and is never suppressed by this
// function: that is the whole point (mallcoppro-419 acceptance criterion).
// A recurring cluster under a different entity keeps firing after the
// operator silences one entity — a DIFFERENT entity is a different case the
// operator has not judged, and firing is the honest outcome; silently
// suppressing it would be the harm this item exists to prevent.
//
// Called from Run alongside applyDirectives (either order is equivalent: a
// finding dropped by one is simply absent from what the other evaluates,
// and neither reads the other's output). nil/empty directives is a
// cheap no-op — returns findings unchanged without allocating.
func ApplySuppressCase(findings []finding.Finding, directives []store.Directive) []finding.Finding {
	caseIDs := suppressedCaseIDs(directives)
	if len(caseIDs) == 0 {
		return findings
	}
	kept := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if caseIDs[findingCaseID(f)] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}
