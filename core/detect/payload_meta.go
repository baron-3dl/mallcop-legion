package detect

import "encoding/json"

// payloadMeta returns the discriminating metadata block a detector reads from an
// event payload, handling BOTH on-disk layouts the canonical schema defines:
//
//  1. CORPUS / eval-seeder shape (scenario_tools.go eventRecord): the payload is
//     {action, target, severity, metadata:{role, ip, collaborator, ...}} — the
//     discriminators live NESTED under payload.metadata.
//  2. PRODUCTION connector shape (normalizeEntry): the payload IS the raw audit
//     entry FLAT — {action, actor, collaborator, permission, role, ...} at the
//     top level.
//
// payloadMeta unmarshals the payload to a map and returns m["metadata"] when it is
// an object, else the top-level map itself. This mirrors core/tools'
// payloadDiscriminatingMeta metadata-first fallback so every detector stays
// aligned to BOTH contracts from ONE read pattern. A nil/empty/malformed payload
// yields an empty (never nil) map.
func payloadMeta(payload json.RawMessage) map[string]any {
	out := map[string]any{}
	if len(payload) == 0 {
		return out
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return out
	}
	if meta, ok := m["metadata"].(map[string]any); ok {
		return meta
	}
	return m
}

// metaStr reads key k from a meta map as a string, accepting the first present
// alias. Non-string scalars are not coerced (the corpus carries these fields as
// strings); a missing key yields "". Returns the value for the first alias found.
func metaStr(meta map[string]any, aliases ...string) string {
	for _, k := range aliases {
		if v, ok := meta[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// approvalSignalKeys are metadata keys whose PRESENCE marks a grant/change as
// pre-approved (a vetted vendor onboarding, a contractor with an HR ticket, a
// documented change ticket, a named approver). Shared by every detector that
// needs to tell a SANCTIONED change from an undocumented one on the same event
// shape: new_external_access.go's vendor/contractor onboarding gate (AC-04
// approved-vendor, AC-05 contractor-with-ticket) and config_drift.go's
// iam_policy_attach gate (the LAW/NIP-86 write-allowlist-grant fan-out,
// mallcoppro-192/mallcoppro-956) both key off it. Kept in ONE place so a
// connector's approval-signal vocabulary cannot silently diverge between
// detectors that both need to recognize it.
var approvalSignalKeys = []string{
	"vendor_approved", "vendor_id", "contract_ref", "ticket", "hr_ticket",
	"approved_by", "approval_id",
}

// hasApprovalSignal reports whether the event payload carries any
// approvalSignalKeys entry with a non-empty value, tolerating both the
// corpus-nested and production-flat payload shapes via payloadMeta.
func hasApprovalSignal(payload json.RawMessage) bool {
	meta := payloadMeta(payload)
	for _, k := range approvalSignalKeys {
		if metaStr(meta, k) != "" {
			return true
		}
	}
	return false
}

// metaBool reads key k from a meta map as a bool, accepting the first present
// alias. A JSON bool returns as-is; the string "true" also reads true (the
// corpus/eval shape carries some flags as strings). A missing/other value
// yields false, matching the zero value a direct json.Unmarshal would leave.
func metaBool(meta map[string]any, aliases ...string) bool {
	for _, k := range aliases {
		v, ok := meta[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return t == "true"
		}
	}
	return false
}

// metaStrSlice reads key k from a meta map as a []string, accepting the first
// present alias. A JSON array yields its string elements (non-string elements
// skipped); an already-[]string value returns as-is. A missing value yields nil
// — the same zero value a direct json.Unmarshal leaves for an absent array.
func metaStrSlice(meta map[string]any, aliases ...string) []string {
	for _, k := range aliases {
		v, ok := meta[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case []any:
			out := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return out
		case []string:
			return t
		}
	}
	return nil
}

// metaFloat reads key k from a meta map as a float64, accepting the first present
// alias. JSON numbers decode to float64; a string number is parsed. Returns
// (value, true) on the first numeric alias found, else (0, false).
func metaFloat(meta map[string]any, aliases ...string) (float64, bool) {
	for _, k := range aliases {
		v, ok := meta[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case float64:
			return t, true
		case int:
			return float64(t), true
		case json.Number:
			if f, err := t.Float64(); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}
