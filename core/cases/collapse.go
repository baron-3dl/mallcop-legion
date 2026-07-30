package cases

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// findingIDRingCap is the max number of contributing finding IDs a Case
// retains. On overflow the OLDEST id is dropped (FIFO) — the ring exists so
// cases.json stays bounded on a long-running store, not to be a complete
// audit trail (findings.jsonl already is that).
const findingIDRingCap = 50

// cadenceWindow is the max number of most-recent contributing findings whose
// timestamps feed the median inter-arrival computation.
const cadenceWindow = 20

// Escalation is the ONLY shape Collapse consumes: one already-escalated
// finding occurrence, projected down to exactly what clustering needs.
// Deliberately excludes Reason/Confidence/Action — see the package doc's
// consensus-invariant note. This type cannot carry a disposition because it
// has no field to hold one.
type Escalation struct {
	FindingID string
	Type      string
	Actor     string
	Severity  string
	Entity    string
	Timestamp time.Time
}

// severityRank orders severities for the "max seen" rule. Unknown strings
// rank below every known severity (0), so a case's severity is never
// downgraded by a malformed/empty value.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// caseID derives the short, deterministic case identifier for a cluster Key:
// the first 12 hex characters of sha256(type + NUL + actor + NUL + entity).
// Deterministic and collision-negligible at project scale (mirrors
// core/eval/corpus.go's sha256/hex hashing idiom).
func caseID(k Key) string {
	sum := sha256.Sum256([]byte(k.Type + "\x00" + k.Actor + "\x00" + k.Entity))
	return hex.EncodeToString(sum[:])[:12]
}

// CaseID is the EXPORTED twin of caseID — the SHARED clustering hash any
// caller outside this package must use to resolve which case a (type, actor,
// entity) triple belongs to, so a second, independently-derived clustering
// path never has a chance to drift from Collapse's own grouping
// (mallcoppro-42e: core/inquest's case-keyed investigation records resolve a
// finding's case ID this way — core/inquest cannot import this package
// itself, per its closed import allowlist, so its caller, core/pipeline,
// which already imports core/cases for directive replay, computes CaseID
// once per escalated finding and threads it through). Identical output to
// caseID for the same Key; kept as two names only so the internal callers in
// this file keep their original, unexported spelling.
func CaseID(k Key) string {
	return caseID(k)
}

// Collapse projects newEsc — this scan's already-escalated occurrences — onto
// existing, clustering each by (Type, Actor, Entity), and returns the FULL
// updated case set. It is PURE: a deterministic function of its arguments
// (timestampOf resolves a finding ID to its ORIGINAL occurrence timestamp,
// e.g. via a closure over an already-loaded findings snapshot — never
// time.Now()), so calling Collapse twice with identical arguments produces
// byte-identical output, including array order (sorted by CaseID) — the
// property store.Store.WriteSnapshot's byte-identical no-op check relies on.
//
// A new cluster starts "open" with Count 1. A cluster Collapse has already
// seen (in existing, or earlier in this same newEsc batch) flips to
// "recurring", takes the max severity ever seen, and grows Count/FindingIDs/
// LastSeen. Collapse never removes a Case and never sets any status other
// than "open"/"recurring" — closing/aging a case is explicitly out of this
// item's scope.
func Collapse(existing []Case, newEsc []Escalation, timestampOf func(findingID string) (time.Time, bool)) []Case {
	byID := make(map[string]Case, len(existing))
	for _, c := range existing {
		byID[c.CaseID] = c
	}

	for _, e := range newEsc {
		id := caseID(Key{Type: e.Type, Actor: e.Actor, Entity: e.Entity})
		c, ok := byID[id]
		if !ok {
			c = Case{
				SchemaVersion: SchemaVersion,
				CaseID:        id,
				Key:           Key{Type: e.Type, Actor: e.Actor, Entity: e.Entity},
				Status:        "open",
				Severity:      e.Severity,
				FirstSeen:     e.Timestamp,
				LastSeen:      e.Timestamp,
			}
		} else {
			c.Status = "recurring"
			if severityRank(e.Severity) > severityRank(c.Severity) {
				c.Severity = e.Severity
			}
			if e.Timestamp.After(c.LastSeen) {
				c.LastSeen = e.Timestamp
			}
		}
		c.Count++
		c.FindingIDs = appendCapped(c.FindingIDs, e.FindingID, findingIDRingCap)
		c.CadenceSecs = computeCadence(c.FindingIDs, timestampOf)
		byID[id] = c
	}

	out := make([]Case, 0, len(byID))
	for _, c := range byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CaseID < out[j].CaseID })
	return out
}

// appendCapped appends id to the FIFO ring ids, dropping the oldest entry
// when the result would exceed maxLen.
func appendCapped(ids []string, id string, maxLen int) []string {
	out := append(ids, id)
	if len(out) > maxLen {
		out = out[len(out)-maxLen:]
	}
	return out
}

// computeCadence returns the median inter-arrival time, in seconds, over the
// last (up to) cadenceWindow contributing IDs whose timestamp timestampOf can
// resolve, sorted ascending. 0 when fewer than 2 timestamps resolve — never
// an error (mirrors ExtractEntity's fail-open style).
func computeCadence(ids []string, timestampOf func(string) (time.Time, bool)) float64 {
	if timestampOf == nil {
		return 0
	}
	start := 0
	if len(ids) > cadenceWindow {
		start = len(ids) - cadenceWindow
	}
	var stamps []time.Time
	for _, id := range ids[start:] {
		if t, ok := timestampOf(id); ok {
			stamps = append(stamps, t)
		}
	}
	if len(stamps) < 2 {
		return 0
	}
	sort.Slice(stamps, func(i, j int) bool { return stamps[i].Before(stamps[j]) })

	deltas := make([]float64, 0, len(stamps)-1)
	for i := 1; i < len(stamps); i++ {
		deltas = append(deltas, stamps[i].Sub(stamps[i-1]).Seconds())
	}
	sort.Float64s(deltas)
	n := len(deltas)
	if n%2 == 1 {
		return deltas[n/2]
	}
	return (deltas[n/2-1] + deltas[n/2]) / 2
}
