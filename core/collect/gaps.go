package collect

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/eval"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// dissentReasonMarker is the ISOLATED, BRITTLE-PARSE hook onto the unstructured
// consensus-dissent signal. Consensus dissent is NOT a structured field today —
// the fanout merge (core/agent/fanout.go) only records it as free text inside a
// Resolution.Reason, in two forms:
//
//	"… Dissent (<names>) cited; confidence penalized 0.10."   (majority-resolve)
//	"…; dissent (<names>) cited"                              (majority-escalate)
//
// The substring ") cited" is common to BOTH and survives the "(%s)" name
// expansion, so a Reason containing it carries a dissent signal. This is a v1
// brittle parse: it is isolated HERE so a future structured dissent field on the
// resolution can replace this single constant, and TestDissentMarkerDriftGuard
// FAILS if the marker ever leaves fanout.go's source (drift caught at build time,
// not silently in production).
const dissentReasonMarker = ") cited"

// GapKind enumerates the three detection-gap flavors DetectorGaps surfaces.
type GapKind string

const (
	// GapDetectMiss is a real production false-negative: an expected-escalate
	// scenario where detect emitted ZERO findings (exam-detect DETECT-MISS).
	GapDetectMiss GapKind = "detect_miss"
	// GapOverrideFP is a human-override disagreement: a suppress directive whose
	// human verb differs from the agent's stored decision on the same finding.
	GapOverrideFP GapKind = "override_fp"
	// GapDissent is a consensus-dissent cluster: a resolution whose reason carries
	// the fanout dissent marker (the panel did not agree unanimously).
	GapDissent GapKind = "dissent"
	// GapReportedMiss is an OPERATOR-REPORTED false-NEGATIVE: an operator ran
	// `mallcop feedback report-miss` to assert the loop MISSED something it should
	// have flagged (a (source, event_type[, actor]) the scan let through). It is a
	// recall gap sourced from a report-miss directive on the directives stream —
	// distinct from GapOverrideFP (a false-POSITIVE the operator suppressed). The
	// operator's free-text description is deliberately NOT carried here (see
	// DetectorGaps): only the structured (source, event_type, actor, window)
	// fields cross into a proposal, so a report-miss cannot smuggle raw operator
	// text downstream.
	GapReportedMiss GapKind = "reported_miss"
)

// reportMissOp is the directive Op `mallcop feedback report-miss` writes to record
// an operator-reported false-negative. Kept in one place so the CLI writer and this
// collector's reader stay coupled.
const reportMissOp = "report-miss"

// IsRecallRed reports whether a gap is a RECALL RED — a MISSED known attack the
// loop should have caught. Exactly two kinds are recall reds: a real exam-detect
// false-negative (GapDetectMiss) and an operator-reported miss (GapReportedMiss).
// The precision-side kinds (GapOverrideFP, GapDissent) are NOT recall reds — a
// false-positive the operator suppressed, or a panel that merely disagreed, are
// precision signals that warn but must never FAIL a scheduled scan (Baron
// FAIL-ON-MISS ruling: only a recall red fails the scan, at every autonomy dial).
func (g GapCandidate) IsRecallRed() bool {
	return g.Kind == GapDetectMiss || g.Kind == GapReportedMiss
}

// GapEvidence is the STRUCTURED, enumerated evidence attached to a GapCandidate.
// It carries only derived / classifier-controlled fields — NEVER raw untrusted
// free text (a resolution reason, a raw payload) — so a proposal built from it
// cannot smuggle attacker-influenced content downstream.
type GapEvidence struct {
	// detect_miss provenance (from the exam-detect fidelity row).
	ScenarioID       string   `json:"scenario_id,omitempty"`
	ExpectedAction   string   `json:"expected_action,omitempty"`
	ExpectedActor    string   `json:"expected_actor,omitempty"`
	EmittedDetectors []string `json:"emitted_detectors,omitempty"`
	// override_fp provenance: the canonical (escalate|resolve) verbs that disagreed.
	HumanVerb   string `json:"human_verb,omitempty"`
	AgentAction string `json:"agent_action,omitempty"`
	// dissent provenance: the marker constant that matched (NOT the raw reason).
	DissentMarker string `json:"dissent_marker,omitempty"`
	// reported_miss provenance: the optional time window the operator scoped the
	// miss to (a structured, operator-chosen token like "24h" or "off-hours" —
	// NOT free text derived from a payload). The reported actor, when given, rides
	// ExpectedActor above (reused: "the actor the gap concerns"). The operator's
	// free-text --description is intentionally absent from GapEvidence entirely.
	Window string `json:"window,omitempty"`
}

// GapCandidate is a proposer-ready detection-gap record. Plain data with json
// tags — it crosses the module boundary into mallcop-pro's proposer unchanged,
// which turns it into an add-only proposal (a new detector rule, a widened gate,
// a re-vote). It carries no raw untrusted free text; all evidence is structured.
type GapCandidate struct {
	// Kind is which gap flavor this is.
	Kind GapKind `json:"kind"`
	// Source is the finding/detector source id (e.g. "detector:unusual-login").
	// Empty for a detect_miss (no finding was emitted).
	Source string `json:"source,omitempty"`
	// EventType is the event type the gap concerns, when known. Empty when the
	// upstream signal (a fidelity row, a resolution) does not carry it.
	EventType string `json:"event_type,omitempty"`
	// DetectorFamily is the detector family the gap concerns (e.g. "unusual-login",
	// "priv-escalation" — the expected family on a miss, the finding's family
	// otherwise).
	DetectorFamily string `json:"detector_family,omitempty"`
	// Severity is the finding severity, when a finding exists. Empty on detect_miss.
	Severity string `json:"severity,omitempty"`
	// FindingIDs are the finding ids this gap references. Empty on detect_miss.
	FindingIDs []string `json:"finding_ids,omitempty"`
	// SampleEventIDs are event ids for provenance, when available.
	SampleEventIDs []string `json:"sample_event_ids,omitempty"`
	// Evidence is the structured, no-free-text evidence for this gap.
	Evidence GapEvidence `json:"evidence"`
}

// DetectorGaps combines three offline, deterministic gap sources into one ranked
// slice of GapCandidate:
//
//	(a) DETECT-MISS rows on expected-escalate scenarios (real false-negatives) —
//	    from the passed-in exam-detect fidelity rows;
//	(b) human_override != agent_decision FPs — join each suppress directive's
//	    Meta.finding_id/verb to the resolution stream by FindingID/Action;
//	(c) consensus-dissent clusters — resolutions whose Reason carries the fanout
//	    dissent marker.
//	(d) operator-reported misses — report-miss directives (mallcop feedback
//	    report-miss): the operator asserting a false-NEGATIVE, surfaced from the
//	    directive's STRUCTURED meta only (never its free-text description).
//
// It is a pure read of st (resolutions + directives) plus the caller's rows — no
// inference, no network. Output ordering is deterministic (see gapSortKey).
func DetectorGaps(st *store.Store, rows []eval.DetectFidelityRow) ([]GapCandidate, error) {
	var out []GapCandidate

	// (a) Real false-negatives: exam-detect DETECT-MISS on an expected-escalate
	// scenario (a DETECT-MISS on an expected-resolve is the CORRECT "nothing
	// flagged" outcome and is not a gap).
	for _, r := range rows {
		if r.Outcome != eval.OutcomeDetectMiss || !expectsEscalate(r.ExpectedAction) {
			continue
		}
		out = append(out, GapCandidate{
			Kind:           GapDetectMiss,
			DetectorFamily: r.ExpectedDetector,
			Evidence: GapEvidence{
				ScenarioID:       r.ScenarioID,
				ExpectedAction:   r.ExpectedAction,
				ExpectedActor:    r.ExpectedActor,
				EmittedDetectors: r.EmittedDetectors,
			},
		})
	}

	// Load the resolution stream once (shared by (b) and (c)).
	resRaw, err := st.Load(store.KindResolutions)
	if err != nil {
		return nil, fmt.Errorf("collect: load resolutions: %w", err)
	}
	resolutions := make([]resolution.Resolution, 0, len(resRaw))
	for i, raw := range resRaw {
		var res resolution.Resolution
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("collect: decode resolution %d: %w", i, err)
		}
		resolutions = append(resolutions, res)
	}
	// First resolution wins per finding id (deterministic; the store replays
	// oldest-first).
	byFinding := make(map[string]resolution.Resolution, len(resolutions))
	for _, r := range resolutions {
		if _, ok := byFinding[r.FindingID]; !ok {
			byFinding[r.FindingID] = r
		}
	}

	// (b) Human-override false-positives: a suppress directive references a
	// finding via Meta.finding_id; if the human verb disagrees with the agent's
	// stored decision, that is an override the loop should learn from.
	dirs, err := st.LoadDirectives()
	if err != nil {
		return nil, fmt.Errorf("collect: load directives: %w", err)
	}
	for _, d := range dirs {
		if !strings.EqualFold(strings.TrimSpace(d.Op), "suppress") {
			continue
		}
		var meta struct {
			FindingID string `json:"finding_id"`
			Verb      string `json:"verb"`
		}
		if len(d.Meta) > 0 {
			_ = json.Unmarshal(d.Meta, &meta)
		}
		if meta.FindingID == "" {
			continue
		}
		res, ok := byFinding[meta.FindingID]
		if !ok {
			continue // directive references a finding not in this scan's stream
		}
		human := canonVerb(meta.Verb)
		if human == "" {
			human = "resolve" // a suppress directive is, by default, "dismiss/benign"
		}
		agentVerb := canonVerb(res.Action)
		if human == agentVerb {
			continue // human and agent agree — no gap
		}
		out = append(out, GapCandidate{
			Kind:           GapOverrideFP,
			Source:         res.Source,
			DetectorFamily: familyFromSource(res.Source),
			Severity:       res.Severity,
			FindingIDs:     []string{meta.FindingID},
			Evidence:       GapEvidence{HumanVerb: human, AgentAction: agentVerb},
		})
	}

	// (c) Consensus-dissent clusters: resolutions whose reason carries the fanout
	// dissent marker. We surface the finding, NOT the raw reason (no free text).
	//
	// DEDUPED BY FindingID (mallcoppro-9015): a consensus re-vote appends a
	// SECOND resolution row for the same finding — observed live in prod
	// gaps.json, two byte-identical dissent candidates for
	// finding-evt_5628196043f0 — so a naive one-candidate-per-RESOLUTION-ROW
	// loop (the pre-fix shape) emits a duplicate "panel did not fully agree"
	// notice per re-vote. Keep exactly one candidate per FindingID: the MOST
	// RECENT dissenting resolution (resolutions replays oldest-first per the
	// store's append-only contract — see byFinding's own "first wins" comment
	// above — so the LAST write into dissentByFinding during this forward scan
	// is the most recent one).
	dissentByFinding := make(map[string]resolution.Resolution)
	var dissentOrder []string
	for _, r := range resolutions {
		if !strings.Contains(r.Reason, dissentReasonMarker) {
			continue
		}
		if _, seen := dissentByFinding[r.FindingID]; !seen {
			dissentOrder = append(dissentOrder, r.FindingID)
		}
		dissentByFinding[r.FindingID] = r
	}
	for _, fid := range dissentOrder {
		r := dissentByFinding[fid]
		out = append(out, GapCandidate{
			Kind:           GapDissent,
			Source:         r.Source,
			DetectorFamily: familyFromSource(r.Source),
			Severity:       r.Severity,
			FindingIDs:     []string{r.FindingID},
			Evidence:       GapEvidence{DissentMarker: dissentReasonMarker},
		})
	}

	// (d) Operator-reported misses: a report-miss directive is the operator saying
	// "the loop MISSED this — a (source, event_type[, actor]) it should have
	// flagged". Surface ONLY the structured fields the operator supplied; the
	// directive's Reason (the free-text --description) is deliberately dropped so a
	// report-miss cannot smuggle raw operator text into a downstream proposal
	// (same no-free-text posture as GapEvidence everywhere else).
	for _, d := range dirs {
		if !strings.EqualFold(strings.TrimSpace(d.Op), reportMissOp) {
			continue
		}
		var meta struct {
			Source    string `json:"source"`
			EventType string `json:"event_type"`
			Actor     string `json:"actor"`
			Window    string `json:"window"`
		}
		if len(d.Meta) > 0 {
			_ = json.Unmarshal(d.Meta, &meta)
		}
		// A report-miss with no structured source/event_type is un-actionable — the
		// proposer has nothing to map. Skip it rather than emit an empty gap.
		if meta.Source == "" && meta.EventType == "" {
			continue
		}
		out = append(out, GapCandidate{
			Kind:           GapReportedMiss,
			Source:         meta.Source,
			EventType:      meta.EventType,
			DetectorFamily: familyFromSource(meta.Source),
			Evidence:       GapEvidence{ExpectedActor: meta.Actor, Window: meta.Window},
		})
	}

	// Gap E2: an operator prioritize/criticality directive re-sorts (never
	// filters) the ranked output — a higher accumulated weight surfaces
	// first; gaps tied on weight (the common case: zero directives, or none
	// matching) keep the original deterministic gapSortKey order. dirs is
	// already loaded above for (b)/(d); reused here so this costs no extra
	// store read.
	weights := weightGaps(defaultPriorityDispatcher, out, dirs)
	sort.SliceStable(out, func(i, j int) bool {
		wi, wj := weights[gapSortKey(out[i])], weights[gapSortKey(out[j])]
		if wi != wj {
			return wi > wj
		}
		return gapSortKey(out[i]) < gapSortKey(out[j])
	})
	return out, nil
}

// gapSortKey builds a stable, total ordering key for a GapCandidate:
// kind | primary-id | source | event_type. The primary id is the first finding
// id, or the scenario id for a detect_miss (which has no finding). event_type is
// the final tiebreaker so a reported_miss gap (which carries neither a finding id
// nor a scenario id) still totally orders by its (source, event_type).
func gapSortKey(g GapCandidate) string {
	id := g.Evidence.ScenarioID
	if len(g.FindingIDs) > 0 {
		id = g.FindingIDs[0]
	}
	return string(g.Kind) + "|" + id + "|" + g.Source + "|" + g.EventType
}

// expectsEscalate reports whether an expected chain_action demands an escalate
// (mirrors eval.actionIsEscalate, reimplemented here to avoid exporting it).
func expectsEscalate(action string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	return a == "escalated" || a == "escalate-or-stronger"
}

// canonVerb collapses the store/directive action vocabularies onto the two
// canonical decisions the gap join compares: "escalate" and "resolve". An
// unrecognized verb is returned lowered/trimmed (so a novel verb still compares
// consistently, it just never spuriously matches escalate/resolve).
func canonVerb(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "escalate", "escalated", "escalate-or-stronger", "alert", "block":
		return "escalate"
	case "resolve", "resolved", "suppress", "ignore", "benign", "proceed":
		return "resolve"
	default:
		return strings.ToLower(strings.TrimSpace(a))
	}
}

// familyFromSource strips the "detector:" prefix off a finding source to yield
// the bare detector family token (e.g. "detector:unusual-login" -> "unusual-login").
func familyFromSource(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "detector:")
}
