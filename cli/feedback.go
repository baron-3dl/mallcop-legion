package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// runFeedback implements `mallcop feedback <finding_id> approve|dismiss`.
//
// This is the OPERATOR FEEDBACK seam: an operator who has seen a finding (in the
// scan output, or in a Discord post) records a decision that the NEXT scan
// honors. The decision is persisted as a Directive on the store's directives
// stream; pipeline.Run replays that stream and drops suppressed findings.
//
// Both verbs persist a 'suppress' directive (the operator is telling mallcop
// "stop flagging this"), but they record the verb distinctly for the audit
// trail:
//
//	dismiss — operator says the finding is noise / not actionable.
//	approve — operator says the underlying activity is known-good / sanctioned.
//
// A fourth verb, mute, persists a TIME-BOXED 'mute' directive instead of an
// indefinite 'suppress': `mallcop feedback <id> mute --ttl 30d`. It is for
// "stop flagging this for now" (e.g. a known maintenance window) rather than
// "this is permanently fine" — core/pipeline's mute consumer
// (core/pipeline/consumer_mute.go) drops matching findings until
// Meta.expires_at, then automatically resumes flagging on the first scan
// after that instant, with no separate unmute step required.
//
// The suppress Pattern is derived from the finding's stable key
// "<source>/<type>/<actor>" so the directive suppresses the CLASS of finding,
// not just one transient per-run finding ID (which is not stable across scans).
//
// A THIRD verb, report-miss, is the FALSE-NEGATIVE seam — the mirror of
// approve|dismiss (both false-POSITIVE suppression). Instead of a finding the
// operator has seen, report-miss records a gap the operator KNOWS the loop should
// have flagged but did not: a (source, event_type[, actor]) the scan let through.
// It takes no finding_id (there is no finding — that is the whole point); it
// persists a report-miss directive whose STRUCTURED fields (source, event_type,
// actor, window) core/collect surfaces as a GapReportedMiss GapCandidate, and
// whose free-text --description is recorded for the operator's own audit but is
// NEVER forwarded raw into a proposal (see collect.DetectorGaps).
//
// Usage:
//
//	mallcop feedback <finding_id> approve|dismiss --store <dir> [--reason "..."] [--by <operator>]
//	mallcop feedback <finding_id> mute --ttl 30d --store <dir> [--reason "..."] [--by <operator>]
//	mallcop feedback report-miss --store <dir> --source <src> --event-type <type> [--actor <a>] [--window <w>] [--description "..."] [--by <operator>]
func runFeedback(args []string) error {
	// report-miss takes NO positional finding_id (there is no finding). Route it
	// before the approve|dismiss positional parsing below.
	if len(args) >= 1 && args[0] == "report-miss" {
		return runFeedbackReportMiss(args[1:])
	}

	// The two positional args (finding_id, action) come FIRST, before any flags,
	// so the operator writes `mallcop feedback <id> dismiss --store <dir>`. Go's
	// flag package stops at the first non-flag token, so we peel the positionals
	// off the front ourselves and parse the remainder as flags.
	if len(args) < 2 {
		return fmt.Errorf("feedback: usage: mallcop feedback <finding_id> approve|dismiss --store <dir> [--reason \"...\"] [--by <operator>]\n       mallcop feedback <finding_id> mute --ttl 30d --store <dir> [--reason \"...\"] [--by <operator>]\n       mallcop feedback report-miss --store <dir> --source <src> --event-type <type> [--actor <a>] [--window <w>] [--description \"...\"]")
	}
	findingID := args[0]
	verb := args[1]

	fs := flag.NewFlagSet("feedback", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store written by 'mallcop scan' (required)")
	reason := fs.String("reason", "", "Operator rationale for this decision (free text, recorded for audit)")
	by := fs.String("by", "", "Operator identity (defaults to $USER)")
	ttl := fs.String("ttl", "", "Mute duration (e.g. \"30d\", \"12h\") — required for the mute verb; ignored otherwise")

	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	switch verb {
	case "approve", "dismiss", "mute":
	default:
		return fmt.Errorf("feedback: unknown action %q (want approve|dismiss|mute)", verb)
	}

	if *storePath == "" {
		return fmt.Errorf("feedback: --store is required (the git-repo path written by 'mallcop scan')")
	}

	var muteTTL time.Duration
	if verb == "mute" {
		if *ttl == "" {
			return fmt.Errorf("feedback: --ttl is required for mute (e.g. --ttl 30d)")
		}
		var err error
		muteTTL, err = parseTTL(*ttl)
		if err != nil {
			return fmt.Errorf("feedback: --ttl %q: %w", *ttl, err)
		}
		if muteTTL <= 0 {
			return fmt.Errorf("feedback: --ttl %q must be a positive duration", *ttl)
		}
	}

	operator := *by
	if operator == "" {
		operator = os.Getenv("USER")
	}
	if operator == "" {
		operator = "operator"
	}

	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("feedback: open store %q: %w", *storePath, err)
	}

	// Resolve the finding by ID from the durable findings stream.
	f, err := findFindingByID(st, findingID)
	if err != nil {
		return err
	}

	// Derive the stable suppress Pattern from the finding's source/type/actor.
	pattern := f.Source + "/" + f.Type + "/" + f.Actor

	// Record the verb + rationale distinctly in Meta for the audit trail, while
	// the always-works mechanism is the persisted directive (suppress, or a
	// time-boxed mute below). recordedAt anchors the mute TTL to issuance time
	// (not the eventual replay clock), so --ttl is relative to "now" at the
	// moment the operator ran the command.
	recordedAt := time.Now().UTC()
	metaFields := map[string]string{
		"verb":       verb,
		"finding_id": f.ID,
		"recorded":   recordedAt.Format(time.RFC3339),
	}
	op := "suppress"
	var expiresAt time.Time
	if verb == "mute" {
		op = "mute"
		expiresAt = recordedAt.Add(muteTTL)
		// "expires_at" is the exact key core/store.DirectiveMeta.ParseMeta
		// (core/store/records.go) decodes and core/pipeline's mute consumer
		// (core/pipeline/consumer_mute.go) reads.
		metaFields["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	meta, err := json.Marshal(metaFields)
	if err != nil {
		return fmt.Errorf("feedback: encode meta: %w", err)
	}

	reasonText := *reason
	if reasonText == "" {
		switch verb {
		case "approve":
			reasonText = "operator approved: activity known-good"
		case "mute":
			reasonText = fmt.Sprintf("operator muted for %s: finding paused, not dismissed", *ttl)
		default:
			reasonText = "operator dismissed: finding not actionable"
		}
	}

	d := store.Directive{
		Op:      op,
		Pattern: pattern,
		Reason:  reasonText,
		Actor:   operator,
		Meta:    json.RawMessage(meta),
	}

	if _, err := st.Append(store.KindDirectives, d); err != nil {
		return fmt.Errorf("feedback: append directive: %w", err)
	}

	fmt.Printf("Recorded %s for finding %s\n", verb, f.ID)
	fmt.Printf("  %s pattern: %s\n", op, pattern)
	fmt.Printf("  Operator:         %s\n", operator)
	fmt.Printf("  Reason:           %s\n", reasonText)
	if verb == "mute" {
		fmt.Printf("  Expires:          %s\n", expiresAt.Format(time.RFC3339))
		fmt.Printf("Scans before this time will suppress matching findings; scans after it will resume flagging them.\n")
	} else {
		fmt.Printf("The next scan will suppress findings matching this pattern.\n")
	}
	// A dismiss is exactly the moment 'mallcop scenario capture --must-not-fire'
	// exists for (mallcoppro-65c4): the operator just confirmed this finding's
	// underlying activity was a FALSE ALARM. Point at the pairing command so
	// growing the local benign-twin corpus is one copy-paste away, not a
	// separate discovery. f.Actor/f.Type are always populated on a resolved
	// finding (see pkg/finding.Finding), so this suggestion never needs
	// hedging for an empty value.
	if verb == "dismiss" && f.Actor != "" && f.Type != "" {
		fmt.Printf("Tip: capture this as a benign-twin scenario for your local corpus --\n")
		fmt.Printf("  mallcop scenario capture --store %s --actor %s --window 24h --must-not-fire %s\n", *storePath, f.Actor, f.Type)
	}
	return nil
}

// runFeedbackReportMiss implements `mallcop feedback report-miss`: record an
// operator-asserted FALSE-NEGATIVE — a (source, event_type[, actor]) the loop
// should have flagged but did not. It persists a report-miss directive on the
// directives stream; the NEXT `mallcop collect` surfaces it as a GapReportedMiss
// GapCandidate (a recall gap the proposer can close), and `mallcop status`
// counts it. The free-text --description is stored in the directive's Reason for
// the operator's own audit trail, but the collector NEVER forwards it into a
// proposal — only the structured meta crosses that boundary.
func runFeedbackReportMiss(args []string) error {
	fs := flag.NewFlagSet("feedback report-miss", flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store written by 'mallcop scan' (required)")
	source := fs.String("source", "", "Source id the miss concerns (e.g. \"github\", \"detector:priv-escalation\") (required)")
	eventType := fs.String("event-type", "", "Event/action type the loop should have flagged (e.g. \"github.permission.grant\") (required)")
	actor := fs.String("actor", "", "Optional actor the miss concerns")
	window := fs.String("window", "", "Optional structured time window the miss was scoped to (e.g. \"24h\", \"off-hours\")")
	description := fs.String("description", "", "Optional free-text rationale (recorded for AUDIT only — never forwarded into a proposal)")
	by := fs.String("by", "", "Operator identity (defaults to $USER)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *storePath == "" {
		return fmt.Errorf("feedback report-miss: --store is required (the git-repo path written by 'mallcop scan')")
	}
	// A report-miss with no structured target is un-actionable: the proposer would
	// have nothing to map. Require at least one of source/event-type, and reject a
	// report that carries ONLY a free-text description (which never crosses into a
	// proposal) — that would be a silent no-op gap.
	if *source == "" && *eventType == "" {
		return fmt.Errorf("feedback report-miss: at least one of --source or --event-type is required (a bare --description is recorded for audit but produces no actionable gap)")
	}

	operator := *by
	if operator == "" {
		operator = os.Getenv("USER")
	}
	if operator == "" {
		operator = "operator"
	}

	st, err := store.Open(*storePath)
	if err != nil {
		return fmt.Errorf("feedback report-miss: open store %q: %w", *storePath, err)
	}

	// Structured meta is the ONLY thing collect forwards into a proposal — never
	// the free-text description below.
	meta, err := json.Marshal(struct {
		Source    string `json:"source"`
		EventType string `json:"event_type"`
		Actor     string `json:"actor,omitempty"`
		Window    string `json:"window,omitempty"`
		Recorded  string `json:"recorded"`
	}{
		Source:    *source,
		EventType: *eventType,
		Actor:     *actor,
		Window:    *window,
		Recorded:  time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("feedback report-miss: encode meta: %w", err)
	}

	// Pattern is a stable, human-readable key of the miss target for the audit
	// trail (source/event_type/actor). Reason carries the operator's free-text
	// description for THEIR audit — collect drops it, so it never reaches a proposal.
	pattern := *source + "/" + *eventType + "/" + *actor
	d := store.Directive{
		Op:      "report-miss",
		Pattern: pattern,
		Reason:  *description,
		Actor:   operator,
		Meta:    json.RawMessage(meta),
	}
	if _, err := st.Append(store.KindDirectives, d); err != nil {
		return fmt.Errorf("feedback report-miss: append directive: %w", err)
	}

	fmt.Printf("Recorded a reported miss (operator false-negative)\n")
	fmt.Printf("  Source:     %s\n", *source)
	fmt.Printf("  Event type: %s\n", *eventType)
	if *actor != "" {
		fmt.Printf("  Actor:      %s\n", *actor)
	}
	if *window != "" {
		fmt.Printf("  Window:     %s\n", *window)
	}
	fmt.Printf("  Operator:   %s\n", operator)
	fmt.Printf("'mallcop collect' will surface this as a recall gap; 'mallcop status' counts it.\n")
	return nil
}

// findFindingByID replays the findings stream and returns the finding with the
// given ID. It returns a clear error if no finding matches — a bad finding-id
// must fail cleanly, not silently no-op.
func findFindingByID(st *store.Store, id string) (finding.Finding, error) {
	raws, err := st.Load(store.KindFindings)
	if err != nil {
		return finding.Finding{}, fmt.Errorf("feedback: load findings: %w", err)
	}
	for _, raw := range raws {
		var f finding.Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			// A malformed stored finding is a corruption, surface it.
			return finding.Finding{}, fmt.Errorf("feedback: decode stored finding: %w", err)
		}
		if f.ID == id {
			return f, nil
		}
	}
	return finding.Finding{}, fmt.Errorf("feedback: finding %q not found in store (run 'mallcop status --store ...' to list)", id)
}

// parseTTL parses a mute duration. time.ParseDuration already handles
// "h"/"m"/"s" (and combinations); this adds a "d" (days) unit on top since
// operator-facing mute windows are naturally day-scoped ("30d") and Go's
// stdlib has no day unit. A bare integer+"d" suffix (e.g. "30d") is parsed
// as N*24h; anything else falls through to time.ParseDuration unchanged.
func parseTTL(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		numPart := s[:len(s)-1]
		var days float64
		if _, err := fmt.Sscanf(numPart, "%g", &days); err != nil {
			return 0, fmt.Errorf("invalid day count %q: %w", numPart, err)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}
