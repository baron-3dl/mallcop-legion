package proposer

import (
	"fmt"
	"strings"
	"unicode"
)

// Tool names the proposer advertises. The strict parser recognizes exactly these
// two add-only shapes; any other tool_use name is rejected.
const (
	toolMapping = "propose_mapping"
	toolTuning  = "propose_tuning"
)

// systemPrompt frames the run as DEFENSIVE security tooling and pins the
// add-only contract. It is constant (no interpolation) — the only variable data
// is the trusted structural gap, carried in the user turn / tool schema.
const systemPrompt = "You extend a DEFENSIVE security-monitoring product's coverage. " +
	"You may ONLY WIDEN coverage with add-only DATA: map an unclassified source action onto an " +
	"EXISTING known event type. You must call the provided tool exactly once with a valid choice. " +
	"You must NOT narrow, remove, suppress, force-escalate, or invent a new event type; those are refused. " +
	"If no listed event type fits the action, still call the tool with your single best-fit choice from the list."

// maxRawActionPromptLen bounds how many characters of RawAction are echoed into
// the free-text propose prompt (see sanitizeRawAction). Real connector action
// names are short (well under this); the cap exists to bound an adversarial or
// malformed value, not to truncate legitimate data.
const maxRawActionPromptLen = 200

// sanitizeRawAction neutralizes RawAction before it is interpolated into the
// FREE-TEXT prompt: it strips every Unicode control character (newlines,
// carriage returns, tabs, ESC, and other C0/C1 codes — the bytes an attacker
// would use to forge fake turn boundaries or hidden instructions into the
// prompt) and caps the result's length. This is anti prompt-injection-SHAPING:
// a connector's raw_action is untrusted external data (the engine never
// controls what a scanned source calls its own actions), and BuildPrompt is the
// one place it is interpolated as free text rather than carried as structured
// JSON.
//
// This is a DISPLAY-ONLY transform. The tool schema's raw_action const
// (mappingTool, below) and StrictParse's comparison (parse.go parseMapping)
// both still use the gap's ORIGINAL, unsanitized RawAction — sanitization never
// changes what counts as a conforming proposal. In the ordinary case (a short,
// control-char-free action name) sanitizeRawAction is a no-op and the round
// trip is unaffected; a RawAction that actually needed sanitizing echoes back
// changed text, so it fails the strict-parse comparison and is rejected
// (fail-closed) rather than silently smuggled through.
func sanitizeRawAction(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	clean := strings.Join(strings.Fields(b.String()), " ")
	runes := []rune(clean)
	if len(runes) > maxRawActionPromptLen {
		clean = string(runes[:maxRawActionPromptLen]) + "...(truncated)"
	}
	return clean
}

// BuildPrompt constructs the propose instruction from the gap's TRUSTED
// STRUCTURAL fields only — Source, RawAction, Count, and the closed
// SuggestedVocabulary. It NEVER interpolates raw sample payloads (the gap
// carries only event ids for provenance, not payloads), so a scanned artifact
// cannot inject an instruction. RawAction is additionally run through
// sanitizeRawAction before interpolation (display-only; see its doc) so a
// crafted value cannot shape the prompt with forged newlines/control bytes.
// Mirrors opencode.BuildTaskPrompt discipline.
func BuildPrompt(gap MappingGap) string {
	action := sanitizeRawAction(gap.RawAction)
	var b strings.Builder
	fmt.Fprintf(&b, `A connector could not classify a raw source action, so it fell through to the
"%s_other" default bucket %d time(s). Map it onto ONE existing known event type so
the typed detectors can see it. This WIDENS coverage; it never overrides a real
classification (the overlay is consulted only for the default bucket).

  source      : %s
  raw action  : %s
  seen count  : %d

Call %s exactly once with:
  source      = %q
  raw_action  = %q
  event_type  = one of the CLOSED list below (verbatim; do not invent a new type)

Allowed event types (the ONLY valid choices):
%s

Rules:
  - event_type MUST be an exact member of the list above. A type not on the list
    is refused (a mapping may only target a type some detector already gates on).
  - Do NOT propose a suppression, an escalation, a rule, or any removal/narrowing.
  - Choose the single best-fit type; if unsure, pick the closest structural match.`,
		gap.Source, gap.Count,
		gap.Source, action, gap.Count,
		toolMapping,
		gap.Source, action,
		bulletList(gap.SuggestedVocabulary),
	)
	return b.String()
}

// bulletList renders a vocabulary as a stable "  - <type>" block.
func bulletList(items []string) string {
	if len(items) == 0 {
		return "  (none — no known event types were supplied; you cannot propose a mapping)"
	}
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "  - %s\n", it)
	}
	return strings.TrimRight(b.String(), "\n")
}

// buildRequest assembles the one metered inference request: the trusted-only
// prompt plus a tool whose input_schema advertises the vocabulary as a CLOSED
// enum. The schema is a hint to the model; StrictParse is the actual gate.
func (p *Proposer) buildRequest(gap MappingGap) MessagesRequest {
	return MessagesRequest{
		Model:     p.lane(),
		MaxTokens: defaultMaxTokens,
		System:    systemPrompt,
		Messages: []Message{{
			Role:    "user",
			Content: []ContentBlock{{Type: "text", Text: BuildPrompt(gap)}},
		}},
		Tools: []Tool{mappingTool(gap)},
	}
}

// mappingTool advertises propose_mapping with event_type constrained to the
// gap's closed vocabulary via a JSON-schema enum. source and raw_action are
// pinned to const values so a compliant reply can only widen THIS gap.
func mappingTool(gap MappingGap) Tool {
	return Tool{
		Name:        toolMapping,
		Description: "Map the unclassified (source, raw_action) onto ONE existing known event_type. Add-only; widen-only.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"source":     map[string]any{"type": "string", "const": gap.Source},
				"raw_action": map[string]any{"type": "string", "const": gap.RawAction},
				"event_type": map[string]any{
					"type": "string",
					"enum": gap.SuggestedVocabulary,
				},
			},
			"required":             []string{"source", "raw_action", "event_type"},
			"additionalProperties": false,
		},
	}
}

// gapSystemPrompt frames a GapCandidate-driven tuning run — the DATA-lane
// consumer of operator override / committee dissent judgment (mallcoppro-b42,
// design §Gap B). It is constant (no interpolation); the only variable data is
// the trusted structural gap, carried in the user turn / tool schema. R9
// (consensus not rules): the ONLY lever offered is an additive extra_* list —
// there is no tool shape that can suppress, force-escalate, or otherwise
// change a verdict. This WIDENS what the committee sees; it never overrides
// the committee.
const gapSystemPrompt = "You extend a DEFENSIVE security-monitoring product's detection coverage in " +
	"response to a human operator's override or a consensus committee's dissent. " +
	"You may ONLY WIDEN coverage with add-only DATA: append new keyword(s) to a detector's EXISTING " +
	"additive extra_* tuning list, so the committee sees more of the signal that caused the " +
	"disagreement. You must call the provided tool exactly once with a valid choice. " +
	"You must NOT narrow, remove, suppress, force-escalate, or otherwise change how the committee " +
	"votes; those are refused and are not offered by any tool here."

// BuildGapPrompt constructs the tuning-widen instruction from a GapCandidate's
// TRUSTED STRUCTURAL fields only — Kind, DetectorFamily, Source, and the
// structured Evidence (HumanVerb/AgentAction for an override, the dissent
// marker for a dissent cluster). It NEVER interpolates raw operator free text
// or raw event payloads (GapCandidate/GapEvidence carry none — see mallcop
// core/collect.GapEvidence), so a scanned artifact or an operator's free-text
// report-miss description cannot inject an instruction. Mirrors BuildPrompt's
// discipline for the mapping lane.
func BuildGapPrompt(g GapCandidate) string {
	var b strings.Builder
	switch g.Kind {
	case "override_fp":
		fmt.Fprintf(&b, `An OPERATOR overrode detector %q's finding on source %q: the operator's verb
was %q while the agent's stored decision was %q. This disagreement is a
precision signal the committee should see MORE of, not a rule to patch the
verdict with — widen the detector's additive tuning list so future scans
surface this signal to the committee before it reaches a stored decision.

  detector    : %s
  source      : %s
  human verb  : %s
  agent verb  : %s
`, g.DetectorFamily, g.Source, g.Evidence.HumanVerb, g.Evidence.AgentAction,
			g.DetectorFamily, g.Source, g.Evidence.HumanVerb, g.Evidence.AgentAction)
	case "dissent":
		fmt.Fprintf(&b, `A consensus COMMITTEE DISSENTED on detector %q's finding on source %q (the
panel did not fully agree). Widen the detector's additive tuning list so the
committee sees more of the signal that caused disagreement — never resolve a
dissent by force-escalating or suppressing.

  detector    : %s
  source      : %s
`, g.DetectorFamily, g.Source, g.DetectorFamily, g.Source)
	default:
		fmt.Fprintf(&b, "Widen detector %q's additive tuning coverage for source %q.\n", g.DetectorFamily, g.Source)
	}
	fmt.Fprintf(&b, `
Call %s exactly once with:
  detector     = %q
  key          = one of the ADDITIVE keys below (verbatim; do not invent a new key)
  added_values = 1+ new keyword(s) this detector's family should additionally watch for

Allowed additive keys (the ONLY valid choices):
%s

Rules:
  - detector MUST equal %q (a proposal may only widen its own gap's detector).
  - key MUST be an exact member of the list above (a calibration knob — a
    threshold, a confidence penalty — is refused; only additive extra_* lists
    are expressible here).
  - Do NOT propose a suppression, a force-escalation, a narrowing rule, or any
    removal. This WIDENS what the committee sees; it never overrides the
    committee's verdict.`,
		toolTuning, g.DetectorFamily, bulletList(additiveTuningKeyList()), g.DetectorFamily)
	return b.String()
}

// buildGapRequest assembles the one metered inference request for a
// GapCandidate: the trusted-only tuning prompt plus a tool whose input_schema
// pins detector to the gap's own family and constrains key to the closed
// additive-key enum. The schema is a hint to the model; StrictParseGap is the
// actual gate.
func (p *Proposer) buildGapRequest(g GapCandidate) MessagesRequest {
	return MessagesRequest{
		Model:     p.lane(),
		MaxTokens: defaultMaxTokens,
		System:    gapSystemPrompt,
		Messages: []Message{{
			Role:    "user",
			Content: []ContentBlock{{Type: "text", Text: BuildGapPrompt(g)}},
		}},
		Tools: []Tool{gapTuningTool(g)},
	}
}

// gapTuningTool advertises propose_tuning with detector pinned to the gap's
// own family (const) and key constrained to the closed additive-key enum via
// JSON-schema. added_values requires at least one entry (add-only: an empty
// widen is a no-op, refused by parseTuning too).
func gapTuningTool(g GapCandidate) Tool {
	return Tool{
		Name:        toolTuning,
		Description: "Widen the detector's additive extra_* tuning list in response to an operator override or committee dissent. Add-only; widen-only.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"detector": map[string]any{"type": "string", "const": g.DetectorFamily},
				"key": map[string]any{
					"type": "string",
					"enum": additiveTuningKeyList(),
				},
				"added_values": map[string]any{
					"type":     "array",
					"items":    map[string]any{"type": "string"},
					"minItems": 1,
				},
			},
			"required":             []string{"detector", "key", "added_values"},
			"additionalProperties": false,
		},
	}
}
