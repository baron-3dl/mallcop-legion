package cases

// Status values Collapse's lifecycle does NOT produce on its own. Collapse
// (collapse.go) only ever moves a Case between "open" and "recurring" — by
// its own doc comment, closing/aging a case out is explicitly OUT of that
// function's scope. SetStatus below is the missing verb (mallcoppro-48d):
// an operator decision, driven by a directive (Gap C, mallcoppro-a1c), not
// something the consensus-driven clustering function decides for itself.
const (
	// StatusClosed marks a case the operator has resolved: it may still
	// recur (a future Collapse call can still add to it), but the operator
	// has recorded that the CURRENT cluster is handled.
	StatusClosed = "closed"
	// StatusAged marks a case the operator has acknowledged as an accepted,
	// tolerated recurrence — "this keeps happening and that's fine" (the
	// 'recurrence-fine' directive verb) — distinct from StatusClosed, which
	// says the case is done, not merely expected.
	StatusAged = "aged"
)

// SetStatus returns a COPY of existing with the Case whose CaseID equals id
// transitioned to status. Pure, like Collapse: a deterministic function of
// its arguments that never mutates existing's backing array, so calling it
// twice with identical arguments reproduces the identical result — the same
// property store.Store.WriteSnapshot's no-op check depends on elsewhere in
// this package.
//
// An id that names no case in existing is a no-op: SetStatus never errors on
// an unknown CaseID (mirrors Collapse/computeCadence's fail-open style) — the
// returned slice has the same cases, none altered.
func SetStatus(existing []Case, id, status string) []Case {
	out := make([]Case, len(existing))
	copy(out, existing)
	for i := range out {
		if out[i].CaseID == id {
			out[i].Status = status
		}
	}
	return out
}
