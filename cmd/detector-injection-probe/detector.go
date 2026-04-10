package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/thirdiv/mallcop-legion/pkg/baseline"
	"github.com/thirdiv/mallcop-legion/pkg/event"
	"github.com/thirdiv/mallcop-legion/pkg/finding"
)

// injectionPatterns are compiled regexes for known prompt injection signals.
// SECURITY-CRITICAL: these patterns must be comprehensive and conservatively
// tuned to avoid false negatives on adversarial inputs.
var injectionPatterns = []injectionRule{
	// Direct instruction overrides — highest severity.
	{
		re:       regexp.MustCompile(`(?i)\bignore\s+(all\s+)?previous\s+instructions?\b`),
		name:     "ignore-previous-instructions",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bforget\s+(all\s+)?previous\s+instructions?\b`),
		name:     "forget-previous-instructions",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(a\s+)?(\w+\s+)*(assistant|ai|bot|model|gpt|claude|llm)\b`),
		name:     "persona-override",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bact\s+as\s+(?:an?\s+)?(?:jailbroken|uncensored|unrestricted|evil|malicious)\b`),
		name:     "jailbreak-persona",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bdisregard\s+(your\s+)?(previous|prior|earlier|all)\s+(instructions?|rules?|constraints?|guidelines?)\b`),
		name:     "disregard-instructions",
		severity: "critical",
	},
	// System prompt leakage / extraction attempts.
	{
		re:       regexp.MustCompile(`(?i)\bprint\s+(your\s+)?(system\s+prompt|instructions?|context)\b`),
		name:     "system-prompt-leak",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\breveal\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)\b`),
		name:     "system-prompt-leak",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\brepeat\s+(everything|all)\s+(above|before|from\s+the\s+beginning)\b`),
		name:     "context-extraction",
		severity: "high",
	},
	// XML/CDATA injection markers (used to escape context).
	{
		re:       regexp.MustCompile(`(?i)<\s*/?system\s*>`),
		name:     "xml-system-tag",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)<\s*/?instructions?\s*>`),
		name:     "xml-instructions-tag",
		severity: "high",
	},
	{
		re:       regexp.MustCompile(`(?i)<\s*/?prompt\s*>`),
		name:     "xml-prompt-tag",
		severity: "high",
	},
	// Markdown injection: headings used to inject new context sections.
	{
		re:       regexp.MustCompile(`(?m)^#{1,3}\s+(system|instructions?|new\s+task|ignore|override)\b`),
		name:     "markdown-header-injection",
		severity: "high",
	},
	// DAN / jailbreak keywords.
	{
		re:       regexp.MustCompile(`(?i)\bDAN\s+mode\b|\bdo\s+anything\s+now\b`),
		name:     "dan-jailbreak",
		severity: "critical",
	},
	{
		re:       regexp.MustCompile(`(?i)\bjailbreak\b`),
		name:     "jailbreak-keyword",
		severity: "high",
	},
	// Token injection / delimiter attacks.
	{
		re:       regexp.MustCompile(`<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>`),
		name:     "token-delimiter-injection",
		severity: "critical",
	},
	// Indirect injection via role confusion.
	{
		re:       regexp.MustCompile(`(?i)\bassistant\s*:\s*(ignore|disregard|forget|override)\b`),
		name:     "role-confusion",
		severity: "high",
	},
}

type injectionRule struct {
	re       *regexp.Regexp
	name     string
	severity string
}

// evaluate scans all string-valued fields in the event payload for injection
// patterns. It also checks base64-decoded versions of field values.
// Returns one finding per detected pattern (first match per pattern wins).
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, _ *baseline.Baseline) []finding.Finding {
	if len(ev.Payload) == 0 {
		return nil
	}

	// Extract all string values from payload for scanning.
	texts := extractStrings(ev.Payload)

	// Also decode any base64-encoded values and scan those.
	var decoded []string
	for _, t := range texts {
		if d, ok := tryBase64Decode(t); ok {
			decoded = append(decoded, d)
		}
	}
	texts = append(texts, decoded...)

	if len(texts) == 0 {
		return nil
	}

	var findings []finding.Finding
	seen := map[string]bool{}

	for _, rule := range injectionPatterns {
		if seen[rule.name] {
			continue
		}
		for _, text := range texts {
			if rule.re.MatchString(text) {
				matched := rule.re.FindString(text)
				// Truncate match for evidence to avoid embedding hostile content verbatim.
				if len(matched) > 80 {
					matched = matched[:80] + "..."
				}
				evidence, _ := json.Marshal(map[string]string{
					"actor":   ev.Actor,
					"pattern": rule.name,
					"match":   matched,
					"rule":    "injection-pattern",
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-inj-" + rule.name,
					Source:    "detector:injection-probe",
					Severity:  rule.severity,
					Type:      "injection-probe",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    "prompt injection pattern detected: " + rule.name,
					Evidence:  evidence,
				})
				seen[rule.name] = true
				break
			}
		}
	}

	return findings
}

// extractStrings recursively extracts all string values from a JSON value.
func extractStrings(raw json.RawMessage) []string {
	var out []string

	// Try as object.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, v := range obj {
			out = append(out, extractStrings(v)...)
		}
		return out
	}

	// Try as array.
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, v := range arr {
			out = append(out, extractStrings(v)...)
		}
		return out
	}

	// Try as string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s != "" {
			out = append(out, s)
		}
	}

	return out
}

// tryBase64Decode attempts to base64-decode s. Returns the decoded string and
// true only when the result is valid UTF-8 and long enough to be meaningful.
func tryBase64Decode(s string) (string, bool) {
	// Only attempt decoding for strings that look like base64 (length ≥ 20,
	// only base64 characters).
	if len(s) < 20 {
		return "", false
	}
	b64re := regexp.MustCompile(`^[A-Za-z0-9+/\-_]+=*$`)
	if !b64re.MatchString(strings.TrimSpace(s)) {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(s)
			if err != nil {
				return "", false
			}
		}
	}
	decoded := string(b)
	// Must be printable text.
	for _, r := range decoded {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return "", false
		}
	}
	return decoded, len(decoded) > 0
}
