package cases

import "fmt"

// Summary is the dual-audience report over an already-collapsed case set: the
// CLI (`mallcop status`) and any future console call THIS SAME function
// rather than each re-deriving their own counts/formatting from []Case — the
// exact drift mallcoppro-a51 exists to prevent. Summarize never re-clusters;
// it is a pure, read-only view over the Case slice Collapse/ApplyCaseDirectives
// already produced (and cli/cases.go's collapseCases already committed to
// store/cases.json).
type Summary struct {
	// Open is every case NOT closed/aged — i.e. still live, whether it has
	// recurred yet or not. This is the "N" in "N open (M recurring)".
	Open int
	// Recurring is the subset of Open whose Status is specifically
	// "recurring" (Collapse has seen its cluster more than once). This is
	// the "M" in "N open (M recurring)".
	Recurring int
	// Lines is one human-readable line per Open case (closed/aged cases are
	// summarized in the counts elsewhere, not repeated per-line here), in the
	// same order as the input slice (Collapse/ReadSnapshot leave that sorted
	// by CaseID).
	Lines []string
}

// Summarize computes the CLI/console-agnostic case report over cs. It does
// not read a store, cluster a finding, or apply a directive — those are
// Collapse/ApplyCaseDirectives/collapseCases's job. Summarize only formats
// what is already there, so a call site can never disagree with cases.json
// about what's open, what's recurring, or how a case reads on one line.
func Summarize(cs []Case) Summary {
	var s Summary
	for _, c := range cs {
		if c.Status == StatusClosed || c.Status == StatusAged {
			continue
		}
		s.Open++
		if c.Status == "recurring" {
			s.Recurring++
		}
		s.Lines = append(s.Lines, FormatLine(c))
	}
	return s
}

// FormatLine renders one Case as the single human-readable line both the CLI
// and any future console print — type, entity, count, humanized cadence, and
// status, in that order. Kept as its own exported function (not inlined into
// Summarize) so a consumer that already has one Case (e.g. a future `mallcop
// case show <id>`) can reuse the identical formatting instead of re-deriving it.
func FormatLine(c Case) string {
	entity := c.Key.Entity
	if entity == "" {
		entity = "(no entity)"
	}
	return fmt.Sprintf("  %s  entity=%s  count=%d  cadence=%s  status=%s",
		c.Key.Type, entity, c.Count, HumanizeCadence(c.CadenceSecs), c.Status)
}

// HumanizeCadence renders a Case's CadenceSecs (median inter-arrival seconds,
// see collapse.go's computeCadence) as an approximate, human-scale duration.
// 0 (fewer than 2 resolvable timestamps — see computeCadence's doc) is
// reported honestly as "no established cadence", never "~0s", which would
// misread as "recurring instantly."
func HumanizeCadence(secs float64) string {
	if secs <= 0 {
		return "no established cadence"
	}
	switch {
	case secs < 60:
		return fmt.Sprintf("~%ds", int(secs))
	case secs < 3600:
		return fmt.Sprintf("~%dm", int(secs/60))
	case secs < 86400:
		return fmt.Sprintf("~%dh", int(secs/3600))
	default:
		return fmt.Sprintf("~%dd", int(secs/86400))
	}
}
