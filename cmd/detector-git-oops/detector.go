package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// secretPatterns match secret-looking strings in commit messages.
// These are conservative patterns that flag high-entropy tokens and
// known key prefixes.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                           // AWS access key
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),                        // GitHub PAT
	regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),                        // GitHub OAuth
	regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),                        // GitHub App token
	regexp.MustCompile(`xox[bpsa]-[0-9]{10,}-[a-zA-Z0-9]+`),         // Slack token
	regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`),                   // Stripe live key
	regexp.MustCompile(`(?i)(password|secret|api.?key)\s*[=:]\s*\S{8,}`), // generic assignment
}

// gitOopsPayload is the expected payload structure for git events.
type gitOopsPayload struct {
	Forced        bool   `json:"forced"`
	Deleted       bool   `json:"deleted"`
	Ref           string `json:"ref"`
	CommitMessage string `json:"commit_message"`
	HeadCommit    string `json:"head_commit"`
}

// evaluate returns zero or more Findings for a git event. Multiple findings
// may be returned when a commit message triggers several secret patterns.
// Returns nil slice when the event is benign or not a git event.
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, _ *baseline.Baseline) []finding.Finding {
	// Only process git push/delete events.
	if ev.Source != "github" && ev.Source != "gitlab" && ev.Source != "bitbucket" {
		// Accept generic "git" source too for testing.
		if ev.Source != "git" {
			return nil
		}
	}
	if ev.Type != "push" && ev.Type != "branch_delete" && ev.Type != "tag_delete" {
		return nil
	}

	var pp gitOopsPayload
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &pp)
	}

	var findings []finding.Finding

	// Rule 1: force push to any branch.
	if pp.Forced {
		branch := branchFromRef(pp.Ref)
		severity := "high"
		if isProtectedBranch(branch) {
			severity = "critical"
		}
		evidence, _ := json.Marshal(map[string]string{
			"actor":  ev.Actor,
			"ref":    pp.Ref,
			"branch": branch,
			"rule":   "force-push",
		})
		findings = append(findings, finding.Finding{
			ID:        "finding-" + ev.ID + "-force",
			Source:    "detector:git-oops",
			Severity:  severity,
			Type:      "git-oops",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("force push to branch %q by %q", branch, ev.Actor),
			Evidence:  evidence,
		})
	}

	// Rule 2: branch or tag deletion.
	if pp.Deleted || ev.Type == "branch_delete" || ev.Type == "tag_delete" {
		ref := pp.Ref
		if ref == "" {
			ref = "(unknown)"
		}
		evidence, _ := json.Marshal(map[string]string{
			"actor": ev.Actor,
			"ref":   ref,
			"rule":  "branch-delete",
		})
		findings = append(findings, finding.Finding{
			ID:        "finding-" + ev.ID + "-delete",
			Source:    "detector:git-oops",
			Severity:  "medium",
			Type:      "git-oops",
			Actor:     ev.Actor,
			Timestamp: ev.Timestamp,
			Reason:    fmt.Sprintf("branch/tag deleted: %q by %q", ref, ev.Actor),
			Evidence:  evidence,
		})
	}

	// Rule 3: secret-looking strings in commit message.
	if pp.CommitMessage != "" {
		for _, re := range secretPatterns {
			if re.MatchString(pp.CommitMessage) {
				patternName := secretPatternName(re)
				evidence, _ := json.Marshal(map[string]string{
					"actor":   ev.Actor,
					"pattern": patternName,
					"rule":    "secret-in-commit-message",
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-secret-" + patternName,
					Source:    "detector:git-oops",
					Severity:  "critical",
					Type:      "git-oops",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    fmt.Sprintf("commit message by %q may contain a secret (%s pattern)", ev.Actor, patternName),
					Evidence:  evidence,
				})
				break // one finding per commit message (first pattern match wins)
			}
		}
	}

	return findings
}

// branchFromRef extracts the branch name from a git ref like "refs/heads/main".
func branchFromRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")
	if ref == "" {
		return "(unknown)"
	}
	return ref
}

// isProtectedBranch returns true for well-known protected branch names.
func isProtectedBranch(branch string) bool {
	switch strings.ToLower(branch) {
	case "main", "master", "production", "prod", "release":
		return true
	}
	return false
}

// secretPatternName returns a short human-readable name for a compiled pattern.
func secretPatternName(re *regexp.Regexp) string {
	s := re.String()
	switch {
	case strings.HasPrefix(s, "AKIA"):
		return "aws-access-key"
	case strings.HasPrefix(s, "ghp_"):
		return "github-pat"
	case strings.HasPrefix(s, "gho_"):
		return "github-oauth"
	case strings.HasPrefix(s, "ghs_"):
		return "github-app-token"
	case strings.HasPrefix(s, "xox"):
		return "slack-token"
	case strings.HasPrefix(s, "sk_live_"):
		return "stripe-key"
	default:
		return "generic-secret"
	}
}
