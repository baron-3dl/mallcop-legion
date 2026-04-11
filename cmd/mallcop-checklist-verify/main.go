// Command mallcop-checklist-verify is a veracity-gate hook CLI that blocks a
// disposition from closing a bead unless it has emitted all required Pre-Resolution
// Checklist items to the engagement campfire.
//
// # Hook contract
//
// This binary is declared in charts/exam.toml.tmpl via:
//
//	[[hooks]]
//	point   = "pre_bead_close"
//	type    = "veracity_gate"
//	command = "mallcop-checklist-verify"
//
// Legion's `command=` field is a future hook invocation mechanism (G2 workaround,
// see docs/design/quality-on-legion.md §Gap 4). Until legion wires external
// command invocation through HookEngine.RunHooks, this binary is called directly
// by the exam pipeline or CI gate with explicit flags.
//
// # Usage
//
//	mallcop-checklist-verify \
//	  --campfire <id-or-fs-path> \
//	  --bead-id <bead-id> \
//	  --checklist-count <5|7>
//
// # Disposition checklist counts
//
//   - triage  (exam:scenario, task:triage): 5 items
//     1. EVIDENCE       — what events triggered the finding
//     2. ADVERSARY      — who/what is the threat actor
//     3. DISCONFIRM     — evidence that could rule out malicious intent
//     4. BOUNDARY       — scope of the incident (blast radius)
//     5. STAKES         — what is at risk if this is a real attack
//
//   - investigate (task:investigate): 7 items (the 5 above plus 2 more)
//     6. CORRELATION    — cross-source evidence links
//     7. CONFIDENCE     — stated confidence in the resolution with rationale
//
// Source: agents/investigate/POST.md and agents/triage/POST.md in this repo.
// The strict 7/7 requirement for investigate is noted in the disposition table
// at docs/design/quality-on-legion.md §The disposition surface.
//
// # Verification rules per item
//
//  1. A campfire message tagged checklist:item:<N> exists (N in 1..count)
//  2. The message payload is non-empty after trimming whitespace
//  3. The message body contains at least one evidence citation matching one of:
//     - transcript:line-<digits>  (e.g. transcript:line-42)
//     - event:<alphanumeric-id>   (e.g. event:evt-abc123)
//     - evt-<alphanumeric>        (bare event ID shorthand)
//
// Exit 0 on pass. Exit 1 on any rule failure with a clear diagnostic to stderr.
// Exit 2 on configuration/infrastructure errors (campfire unreachable, etc.).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// evidenceCitationRe matches at least one concrete evidence anchor in a
// checklist item body. Anchors recognised:
//
//   - transcript:line-<digits>   (e.g. transcript:line-42)
//   - event:<word>               (e.g. event:evt-abc123, event:login-007)
//   - evt-<word>                 (bare event ID shorthand, e.g. evt-003)
var evidenceCitationRe = regexp.MustCompile(
	`(?i)(transcript:line-\d+|event:[A-Za-z0-9_-]+|evt-[A-Za-z0-9_-]+)`,
)

// cfMessage is a partial unmarshal of the JSON returned by `cf read --json --all`.
type cfMessage struct {
	ID      string   `json:"id"`
	Payload string   `json:"payload"`
	Tags    []string `json:"tags"`
}

func main() {
	campfire := flag.String("campfire", "", "campfire ID or filesystem path (required)")
	beadID := flag.String("bead-id", "", "bead ID being closed (used for context in error messages)")
	checklistCount := flag.Int("checklist-count", 0, "number of checklist items required (5 for triage, 7 for investigate; required)")
	flag.Parse()

	if *campfire == "" {
		fmt.Fprintln(os.Stderr, "mallcop-checklist-verify: --campfire is required")
		os.Exit(2)
	}
	if *checklistCount == 0 {
		fmt.Fprintln(os.Stderr, "mallcop-checklist-verify: --checklist-count is required (5 for triage, 7 for investigate)")
		os.Exit(2)
	}
	if *checklistCount != 5 && *checklistCount != 7 {
		fmt.Fprintf(os.Stderr, "mallcop-checklist-verify: --checklist-count must be 5 or 7, got %d\n", *checklistCount)
		os.Exit(2)
	}

	msgs, err := readChecklistMessages(*campfire)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-checklist-verify: reading campfire %q: %v\n", *campfire, err)
		os.Exit(2)
	}

	if err := verifyChecklist(msgs, *checklistCount, *beadID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(0)
}

// readChecklistMessages shells out to `cf read <campfire> --json --all`
// and returns all messages whose tags include checklist:item:<N> for some N.
//
// We read all messages and filter client-side because `cf read --tag X` performs
// exact tag matching — there is no prefix-match syntax in cf 0.16.
// Filtering on the checklist:item: prefix in Go avoids reading the full message
// body for unrelated messages while still catching all checklist:item:<N> tags.
func readChecklistMessages(campfire string) ([]cfMessage, error) {
	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return nil, fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	cmd := exec.Command(cfBin, "read", campfire, "--json", "--all")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if ok := errors_as(err, &exitErr); ok {
			return nil, fmt.Errorf("cf read: %w\n%s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("cf read: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var all []cfMessage
	if err := json.Unmarshal(out, &all); err != nil {
		return nil, fmt.Errorf("parse cf read output: %w", err)
	}

	// Filter to only messages that carry at least one checklist:item:<N> tag.
	const checklistPrefix = "checklist:item:"
	var msgs []cfMessage
	for _, m := range all {
		for _, tag := range m.Tags {
			if strings.HasPrefix(tag, checklistPrefix) {
				msgs = append(msgs, m)
				break
			}
		}
	}
	return msgs, nil
}

// errors_as is a thin wrapper so we can avoid importing "errors" just for As.
func errors_as(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// itemNumber extracts N from a tag of the form "checklist:item:<N>".
// Returns 0 if the tag does not match the expected format.
func itemNumber(tag string) int {
	const prefix = "checklist:item:"
	if !strings.HasPrefix(tag, prefix) {
		return 0
	}
	suffix := tag[len(prefix):]
	n, err := strconv.Atoi(suffix)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// verifyChecklist checks that all items 1..count are present, non-empty,
// and contain at least one evidence citation.
//
// beadID is used only for error message context and may be empty.
func verifyChecklist(msgs []cfMessage, count int, beadID string) error {
	// Build a map: item number → message body.
	// If multiple messages carry the same item tag, the last one wins
	// (most recent wins semantics — agents may revise).
	itemBodies := make(map[int]string, count)
	for _, msg := range msgs {
		for _, tag := range msg.Tags {
			n := itemNumber(tag)
			if n > 0 {
				itemBodies[n] = msg.Payload
			}
		}
	}

	var failures []string

	for i := 1; i <= count; i++ {
		body, present := itemBodies[i]

		if !present {
			ctx := ""
			if beadID != "" {
				ctx = fmt.Sprintf(" (bead %s)", beadID)
			}
			failures = append(failures,
				fmt.Sprintf("checklist:item:%d missing%s — disposition must emit this tag before closing", i, ctx))
			continue
		}

		trimmed := strings.TrimSpace(body)
		if trimmed == "" {
			failures = append(failures,
				fmt.Sprintf("checklist:item:%d present but body is empty — non-empty content required", i))
			continue
		}

		if !evidenceCitationRe.MatchString(trimmed) {
			failures = append(failures,
				fmt.Sprintf("checklist:item:%d body has no evidence citation — "+
					"body must contain transcript:line-<N>, event:<id>, or evt-<id> (got: %q)", i, truncate(trimmed, 80)))
		}
	}

	if len(failures) > 0 {
		header := fmt.Sprintf("mallcop-checklist-verify: %d/%d checklist items failed:", len(failures), count)
		return fmt.Errorf("%s\n  %s", header, strings.Join(failures, "\n  "))
	}

	return nil
}

// truncate shortens s to at most n bytes for display in error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
