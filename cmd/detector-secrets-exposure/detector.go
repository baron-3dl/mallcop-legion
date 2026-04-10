package main

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// secretRule represents a pattern to detect and its classification.
type secretRule struct {
	re       *regexp.Regexp
	name     string
	severity string // "critical" = confirmed format; "high" = likely secret
}

// secretRules are ordered most-specific first. First match per text wins.
var secretRules = []secretRule{
	// AWS credentials.
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws-access-key-id", "critical"},
	{regexp.MustCompile(`(?i)aws[_\-. ]?secret[_\-. ]?access[_\-. ]?key\s*[=:]\s*[A-Za-z0-9/+]{40}`), "aws-secret-access-key", "critical"},
	// GitHub tokens.
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "github-pat", "critical"},
	{regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`), "github-oauth-token", "critical"},
	{regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`), "github-app-token", "critical"},
	{regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{82}`), "github-fine-grained-pat", "critical"},
	// Slack tokens.
	{regexp.MustCompile(`xox[bpsar]-[0-9a-zA-Z\-]{10,}`), "slack-token", "critical"},
	// Stripe keys.
	{regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "stripe-live-key", "critical"},
	{regexp.MustCompile(`rk_live_[a-zA-Z0-9]{24,}`), "stripe-restricted-key", "critical"},
	// Twilio.
	{regexp.MustCompile(`SK[a-f0-9]{32}`), "twilio-api-key", "critical"},
	// Sendgrid.
	{regexp.MustCompile(`SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`), "sendgrid-api-key", "critical"},
	// Anthropic / OpenAI keys.
	{regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{90,}`), "anthropic-api-key", "critical"},
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{48,}`), "openai-api-key", "critical"},
	// Forge / mallcop keys.
	{regexp.MustCompile(`forge-sk-[a-zA-Z0-9\-_]{32,}`), "forge-api-key", "critical"},
	{regexp.MustCompile(`mallcop-sk-[a-zA-Z0-9\-_]{32,}`), "mallcop-api-key", "critical"},
	// Private keys (PEM blocks).
	{regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "private-key-pem", "critical"},
	// JWT tokens (header.payload.signature).
	{regexp.MustCompile(`eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+`), "jwt-token", "high"},
	// Generic credential assignments.
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api[_\-. ]?key|access[_\-. ]?token|auth[_\-. ]?token)\s*[=:]\s*["']?[^\s"',;]{8,}["']?`), "generic-credential", "high"},
	// Connection strings with embedded credentials.
	{regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@`), "connection-string-with-creds", "critical"},
	// Bearer tokens in field values.
	{regexp.MustCompile(`(?i)\bbearer\s+[a-zA-Z0-9\-_\.]{20,}`), "bearer-token", "high"},
}

// evaluate scans all string fields in the event payload for secret patterns.
// Returns one finding per matched rule (first match per rule, per event).
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, _ *baseline.Baseline) []finding.Finding {
	if len(ev.Payload) == 0 {
		return nil
	}

	texts := extractStrings(ev.Payload)
	if len(texts) == 0 {
		return nil
	}

	var findings []finding.Finding
	seen := map[string]bool{}

	for _, rule := range secretRules {
		if seen[rule.name] {
			continue
		}
		for _, text := range texts {
			if rule.re.MatchString(text) {
				// Redact: don't include the actual secret value in the finding.
				evidence, _ := json.Marshal(map[string]string{
					"actor":    ev.Actor,
					"pattern":  rule.name,
					"field":    "payload",
					"rule":     "secret-in-payload",
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-secret-" + rule.name,
					Source:    "detector:secrets-exposure",
					Severity:  rule.severity,
					Type:      "secrets-exposure",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    "secret detected in event payload: " + rule.name,
					Evidence:  evidence,
				})
				seen[rule.name] = true
				break
			}
		}
	}

	return findings
}

// extractStrings recursively extracts all string values from a JSON value,
// including object keys. This ensures we catch secrets embedded in key names too.
func extractStrings(raw json.RawMessage) []string {
	var out []string

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for k, v := range obj {
			// Include the key=value pair as a combined string for generic patterns.
			var sv string
			if err := json.Unmarshal(v, &sv); err == nil && sv != "" {
				out = append(out, k+"="+sv)
				out = append(out, sv)
			}
			out = append(out, extractStrings(v)...)
		}
		return out
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, v := range arr {
			out = append(out, extractStrings(v)...)
		}
		return out
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		out = append(out, s)
	}
	return out
}

// knownTestValues are placeholder values used in tests and examples that
// should not trigger findings. Listed here for documentation — currently
// handled by pattern specificity (patterns require sufficient length/format).
var _ = []string{
	"changeme",
	"password123",
	"example",
}

// isSafeToRedact checks if a string looks like a real secret (not a placeholder).
// Currently unused — kept for future false-positive suppression.
func isSafeToRedact(s string) bool {
	lower := strings.ToLower(s)
	placeholders := []string{"example", "placeholder", "changeme", "xxxxx", "your-", "insert-", "<"}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return true
}
