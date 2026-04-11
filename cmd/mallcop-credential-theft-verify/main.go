// Command mallcop-credential-theft-verify is a veracity-gate hook binary that
// enforces the Credential Theft Test rule from the investigate disposition.
//
// Rule source: mallcop/src/mallcop/actors/investigate/POST.md §Credential Theft Test
//
// # Credential Theft Test
//
// Before resolving, the investigate agent must ask: "If these credentials were
// stolen, would this activity look identical?" The agent must look for evidence
// that ONLY a legitimate user would produce — consistent source IP across
// sessions, expected device fingerprint, actions requiring physical presence.
// If nothing distinguishes legitimate use from credential misuse, the finding
// must be escalated.
//
// This hook enforces that rule at pre_bead_close time by verifying the closing
// disposition emitted at least one campfire message tagged
// "credential-theft-test:considered" with a body that:
//
//  1. Is valid JSON with a non-empty "event_ids" []string field (≥1 entry)
//     citing the events the agent considered as distinguishing signals.
//  2. Contains distinguish-text of ≥40 characters addressing "what would
//     distinguish legitimate from compromised?" (a note of "n/a" or similar
//     vacuous text is rejected).
//
// Tag matching is case-sensitive ("credential-theft-test:considered" only).
//
// # Hook contract
//
// Legion invokes this binary at pre_bead_close. Context is provided via
// environment variables:
//
//	MALLCOP_BEAD_ID       — the bead being closed
//	MALLCOP_CAMPFIRE_ID   — the engagement campfire ID
//	MALLCOP_DISPOSITION   — the closing disposition label
//
// Exit 0 → bead close allowed.
// Exit non-zero → bead close blocked; reason on stderr.
//
// The binary shells out to `cf read <campfire-id> --tag credential-theft-test:considered
// --json --all` to query the campfire, matching the idiom used by other hook
// binaries in this repo (e.g. mallcop-exam-report).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	requiredTag          = "credential-theft-test:considered"
	minDistinguishLength = 40
)

// ctMessage is a partial unmarshal of a campfire message JSON object.
type ctMessage struct {
	Payload string   `json:"payload"`
	Tags    []string `json:"tags"`
}

// ctBody is the expected JSON body of a credential-theft-test:considered message.
type ctBody struct {
	EventIDs []string `json:"event_ids"`
	Note     string   `json:"note"`
}

func main() {
	campfireID := os.Getenv("MALLCOP_CAMPFIRE_ID")
	if campfireID == "" {
		fmt.Fprintln(os.Stderr, "mallcop-credential-theft-verify: MALLCOP_CAMPFIRE_ID not set")
		os.Exit(2)
	}

	if err := run(campfireID); err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-credential-theft-verify: %v\n", err)
		os.Exit(1)
	}
}

func run(campfireID string) error {
	msgs, err := readMessages(campfireID)
	if err != nil {
		return err
	}

	// Filter to messages with the required tag (case-sensitive).
	var candidates []ctMessage
	for _, msg := range msgs {
		for _, tag := range msg.Tags {
			if tag == requiredTag {
				candidates = append(candidates, msg)
				break
			}
		}
	}

	if len(candidates) == 0 {
		return fmt.Errorf("no message tagged %q found — agent did not perform the Credential Theft Test", requiredTag)
	}

	// Validate each candidate. Any passing candidate is sufficient.
	var errs []string
	for i, msg := range candidates {
		if err := validateBody(msg.Payload); err != nil {
			errs = append(errs, fmt.Sprintf("message[%d]: %v", i, err))
			continue
		}
		return nil // valid message found
	}

	return fmt.Errorf("credential-theft-test:considered message(s) failed validation:\n  %s",
		strings.Join(errs, "\n  "))
}

// validateBody checks a single message payload against the Credential Theft Test rules.
func validateBody(payload string) error {
	var body ctBody
	if err := json.Unmarshal([]byte(payload), &body); err != nil {
		return fmt.Errorf("JSON parse error: %w", err)
	}

	if len(body.EventIDs) == 0 {
		return fmt.Errorf("event_ids is empty — must cite at least one distinguishing event")
	}

	// Assess distinguish-text: concatenate note + any other string content.
	// The primary prose carrier is the Note field. If the body was parsed from
	// JSON the raw payload is the full text source for prose length checks.
	// We measure human-readable distinguish-text as anything beyond the JSON
	// scaffolding — concretely the full payload length minus the JSON key/value
	// overhead is a reasonable proxy, but checking Note length directly is
	// simpler and matches the spec intent.
	if len(strings.TrimSpace(body.Note)) < minDistinguishLength {
		return fmt.Errorf("distinguish-text too short (%d chars, need ≥%d) — vacuous note rejected",
			len(strings.TrimSpace(body.Note)), minDistinguishLength)
	}

	return nil
}

// readMessages shells out to `cf read <campfire-id> --tag credential-theft-test:considered
// --json --all` and returns the decoded messages.
func readMessages(campfireID string) ([]ctMessage, error) {
	cfBin, err := exec.LookPath("cf")
	if err != nil {
		return nil, fmt.Errorf("cf binary not found on PATH: %w", err)
	}

	cmd := exec.Command(cfBin, "read", campfireID, "--tag", requiredTag, "--json", "--all")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("cf read: %w", err)
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	var msgs []ctMessage
	if err := json.Unmarshal(out, &msgs); err != nil {
		return nil, fmt.Errorf("parse cf read output: %w", err)
	}

	return msgs, nil
}
