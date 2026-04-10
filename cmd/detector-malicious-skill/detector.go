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

// suspiciousURLPatterns match URLs used in known malicious skill patterns:
// data exfiltration via webhooks, ngrok tunnels, pastebins, etc.
var suspiciousURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)https?://[^/]*ngrok\.io`),
	regexp.MustCompile(`(?i)https?://[^/]*\.ngrok-free\.app`),
	regexp.MustCompile(`(?i)https?://[^/]*burpcollaborator\.net`),
	regexp.MustCompile(`(?i)https?://[^/]*interactsh\.com`),
	regexp.MustCompile(`(?i)https?://[^/]*pipedream\.net`),
	regexp.MustCompile(`(?i)https?://[^/]*webhook\.site`),
	regexp.MustCompile(`(?i)https?://[^/]*requestcatcher\.com`),
	regexp.MustCompile(`(?i)https?://[^/]*requestbin\.com`),
	regexp.MustCompile(`(?i)https?://pastebin\.com/raw/`),
	regexp.MustCompile(`(?i)https?://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/.*\.(sh|py|ps1|exe|bat|cmd)`),
	// IP address URLs (not domain-based) are suspicious for skills.
	regexp.MustCompile(`https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`),
}

// excessivePermissions are skill permission strings that indicate over-reach.
var excessivePermissions = []string{
	"*",
	"admin:*",
	"org:*",
	"write:*",
	"delete:*",
	"root",
	"superuser",
	"all",
}

// encodedPayloadMinLength is the minimum base64 string length to be considered
// a potential encoded payload.
const encodedPayloadMinLength = 64

// skillPayload is the expected structure for skill-related events.
type skillPayload struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	URL         string          `json:"url"`
	Source      string          `json:"source"`
	Permissions []string        `json:"permissions"`
	Config      json.RawMessage `json:"config"`
	Metadata    json.RawMessage `json:"metadata"`
}

// evaluate returns findings for skill events with malicious patterns.
// This is a pure function: no I/O, no globals mutated.
func evaluate(ev event.Event, _ *baseline.Baseline) []finding.Finding {
	// Only process skill-related events.
	if ev.Type != "skill_install" && ev.Type != "skill_update" &&
		ev.Type != "skill_register" && ev.Type != "skill_invoke" {
		return nil
	}

	if len(ev.Payload) == 0 {
		return nil
	}

	var sp skillPayload
	_ = json.Unmarshal(ev.Payload, &sp)

	var findings []finding.Finding

	// Rule 1: Suspicious URL in skill definition.
	urlsToCheck := []string{sp.URL, sp.Source}
	for _, u := range urlsToCheck {
		if u == "" {
			continue
		}
		for _, re := range suspiciousURLPatterns {
			if re.MatchString(u) {
				evidence, _ := json.Marshal(map[string]string{
					"actor":       ev.Actor,
					"skill_name":  sp.Name,
					"url":         u,
					"url_pattern": truncate(re.String(), 40),
					"rule":        "suspicious-url",
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-skill-url",
					Source:    "detector:malicious-skill",
					Severity:  "critical",
					Type:      "malicious-skill",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    "skill references suspicious exfiltration URL: " + u,
					Evidence:  evidence,
				})
				break
			}
		}
	}

	// Rule 2: Excessive permissions.
	for _, perm := range sp.Permissions {
		for _, excessive := range excessivePermissions {
			if strings.EqualFold(strings.TrimSpace(perm), excessive) {
				evidence, _ := json.Marshal(map[string]string{
					"actor":      ev.Actor,
					"skill_name": sp.Name,
					"permission": perm,
					"rule":       "excessive-permissions",
				})
				findings = append(findings, finding.Finding{
					ID:        "finding-" + ev.ID + "-skill-perm",
					Source:    "detector:malicious-skill",
					Severity:  "high",
					Type:      "malicious-skill",
					Actor:     ev.Actor,
					Timestamp: ev.Timestamp,
					Reason:    "skill requests excessive permission: " + perm,
					Evidence:  evidence,
				})
				break
			}
		}
	}

	// Rule 3: Encoded payload in config or metadata (possible obfuscated malware).
	for _, raw := range []json.RawMessage{ev.Payload, sp.Config, sp.Metadata} {
		if len(raw) == 0 {
			continue
		}
		if hasEncodedPayload(raw) {
			evidence, _ := json.Marshal(map[string]string{
				"actor":      ev.Actor,
				"skill_name": sp.Name,
				"rule":       "encoded-payload",
			})
			findings = append(findings, finding.Finding{
				ID:        "finding-" + ev.ID + "-skill-encoded",
				Source:    "detector:malicious-skill",
				Severity:  "high",
				Type:      "malicious-skill",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    "skill payload contains suspected encoded content",
				Evidence:  evidence,
			})
			break
		}
	}

	// Rule 4: Suspicious keywords in skill name or description.
	combined := strings.ToLower(sp.Name + " " + sp.Description)
	suspiciousKeywords := []string{
		"exfil", "backdoor", "reverse shell", "c2 ", "command and control",
		"keylogger", "rootkit", "payload loader", "dropper",
	}
	for _, kw := range suspiciousKeywords {
		if strings.Contains(combined, kw) {
			evidence, _ := json.Marshal(map[string]string{
				"actor":      ev.Actor,
				"skill_name": sp.Name,
				"keyword":    kw,
				"rule":       "suspicious-keyword",
			})
			findings = append(findings, finding.Finding{
				ID:        "finding-" + ev.ID + "-skill-kw",
				Source:    "detector:malicious-skill",
				Severity:  "critical",
				Type:      "malicious-skill",
				Actor:     ev.Actor,
				Timestamp: ev.Timestamp,
				Reason:    "skill name/description contains suspicious keyword: " + kw,
				Evidence:  evidence,
			})
			break
		}
	}

	return findings
}

// truncate returns s truncated to at most n characters.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// hasEncodedPayload checks whether a JSON value contains any string fields
// that look like base64-encoded binary payloads (high entropy, long strings).
func hasEncodedPayload(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, v := range obj {
			if hasEncodedPayload(v) {
				return true
			}
		}
		return false
	}

	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if len(s) >= encodedPayloadMinLength && looksLikeBase64Payload(s) {
			return true
		}
	}
	return false
}

var b64CharSet = regexp.MustCompile(`^[A-Za-z0-9+/=\-_]+$`)

// looksLikeBase64Payload returns true when s is long, passes base64 char check,
// and successfully decodes to binary-looking content.
func looksLikeBase64Payload(s string) bool {
	if !b64CharSet.MatchString(strings.TrimSpace(s)) {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return false
		}
	}
	// Consider it a payload if >20% of bytes are non-printable (binary).
	nonPrintable := 0
	for _, by := range b {
		if by < 0x20 && by != '\n' && by != '\r' && by != '\t' {
			nonPrintable++
		}
	}
	if len(b) > 0 && float64(nonPrintable)/float64(len(b)) > 0.20 {
		return true
	}
	return false
}
