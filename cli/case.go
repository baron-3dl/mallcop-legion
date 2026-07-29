package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/store"
)

// runCase implements `mallcop case close|age <case_id>` — the ISSUANCE half
// of Gap C's case-close consumer (mallcoppro-a1c). It persists a
// 'close-case'/'recurrence-fine' Directive on the same append-only
// directives stream `mallcop feedback` writes to; the directive is INERT
// until the next `mallcop scan` replays it (cli/cases.go's collapseCases,
// via core/pipeline.ApplyCaseDirectives) against store/cases.json. Same
// two-step "persist now, apply on next replay" shape as feedback's
// suppress/unsuppress — no direct write to cases.json from here, so the
// projection stays a pure function of (Collapse output, directive stream)
// with exactly one writer (collapseCases).
//
// Usage:
//
//	mallcop case close <case_id> --store <dir> [--reason "..."] [--by <operator>]
//	mallcop case age   <case_id> --store <dir> [--reason "..."] [--by <operator>]
func runCase(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("case: usage: mallcop case close|age <case_id> --store <dir> [--reason \"...\"] [--by <operator>]")
	}
	verb := args[0]
	caseID := args[1]

	var op string
	switch verb {
	case "close":
		op = "close-case"
	case "age":
		op = "recurrence-fine"
	default:
		return fmt.Errorf("case: unknown action %q (want close|age)", verb)
	}

	fs := flag.NewFlagSet("case "+verb, flag.ContinueOnError)
	storePath := fs.String("store", "", "Path to the git-repo store written by 'mallcop scan' (required)")
	reason := fs.String("reason", "", "Operator rationale for this decision (free text, recorded for audit)")
	by := fs.String("by", "", "Operator identity (defaults to $USER)")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if *storePath == "" {
		return fmt.Errorf("case: --store is required (the git-repo path written by 'mallcop scan')")
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
		return fmt.Errorf("case: open store %q: %w", *storePath, err)
	}

	// Validate the case ID resolves to a real, already-projected case before
	// persisting a directive for it — same "resolve the target from the
	// durable stream first" discipline runFeedback applies to finding_id.
	// This never blocks the directive on a case that recurs LATER (the
	// directive stream replay handles that on the next scan, same as
	// suppress) — it only catches an operator typo/copy-paste of the wrong
	// case ID up front.
	raw, err := st.ReadSnapshot(casesSnapshotName)
	if err != nil {
		return fmt.Errorf("case: read %s: %w", casesSnapshotName, err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("case: no cases recorded yet in this store (run 'mallcop scan' first)")
	}
	var existing []cases.Case
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fmt.Errorf("case: decode %s: %w", casesSnapshotName, err)
	}
	found := false
	for _, c := range existing {
		if c.CaseID == caseID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("case: no case with id %q in %s", caseID, casesSnapshotName)
	}

	reasonText := *reason
	if reasonText == "" {
		if verb == "close" {
			reasonText = "operator closed: case resolved"
		} else {
			reasonText = "operator aged: recurrence acknowledged as expected"
		}
	}

	d := store.Directive{
		Op:      op,
		Pattern: caseID,
		Reason:  reasonText,
		Actor:   operator,
	}
	if _, err := st.Append(store.KindDirectives, d); err != nil {
		return fmt.Errorf("case: append directive: %w", err)
	}

	fmt.Printf("Recorded %s for case %s\n", op, caseID)
	fmt.Printf("  Operator: %s\n", operator)
	fmt.Printf("  Reason:   %s\n", reasonText)
	fmt.Printf("The next scan will apply this to store/%s.\n", casesSnapshotName)
	return nil
}
