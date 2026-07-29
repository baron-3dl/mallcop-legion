package proposer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// canonicalEventType mirrors mallcop detect.CanonicalEventType (vocab.go:106):
// lower + trim. A validated-but-non-canonical target ("PUSH", " login ") would
// pass a normalized membership check yet be EMITTED verbatim and silently never
// fire a case-sensitive typed gate (invariant 10), so the parser canonicalizes
// the target before it is ever stored.
func canonicalEventType(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// StrictParse is the ADD-ONLY gate on the inference reply. It accepts EXACTLY
// one conforming add-only shape — a single recognized tool_use, or (fallback) a
// single reply that is pure JSON of a recognized shape — and REJECTS everything
// else: prose-only, multiple blocks, an unknown tool, unknown fields, unknown
// vocab, or a narrowing shape. It NEVER retries (the caller poisons the
// fingerprint on any error). Mirrors overlay.ParseLearnedMappings fail-loud
// (overlay.go:86) and the widen-only tuning contract (tuning.yaml).
func StrictParse(resp MessagesResponse, gap MappingGap) (Proposal, error) {
	var recognized []ContentBlock
	var unrecognizedTool bool
	var textParts []string

	for _, blk := range resp.Content {
		switch blk.Type {
		case "tool_use":
			if blk.Name == toolMapping || blk.Name == toolTuning {
				recognized = append(recognized, blk)
			} else {
				unrecognizedTool = true
			}
		case "text":
			if strings.TrimSpace(blk.Text) != "" {
				textParts = append(textParts, blk.Text)
			}
		}
	}

	switch {
	case len(recognized) > 1:
		return Proposal{}, fmt.Errorf("strict-parse reject: %d proposal blocks (want exactly one add-only proposal)", len(recognized))
	case len(recognized) == 1:
		return parseBlock(recognized[0].Name, recognized[0].Input, gap)
	}

	// No recognized tool_use. An unrecognized tool_use is a shape we do not
	// understand — reject rather than guess.
	if unrecognizedTool {
		return Proposal{}, errors.New("strict-parse reject: reply used an unrecognized tool (only add-only propose_mapping / propose_tuning are accepted)")
	}

	// Text fallback: accept ONLY when the whole reply is one pure-JSON object of a
	// recognized shape. Any prose around the JSON makes json.Unmarshal fail →
	// rejection (prose-only replies are refused).
	joined := strings.TrimSpace(strings.Join(textParts, ""))
	if joined == "" {
		return Proposal{}, errors.New("strict-parse reject: empty reply (no add-only proposal)")
	}
	raw := json.RawMessage(joined)
	// Try mapping shape, then tuning shape; both strict (unknown fields fail).
	if prop, err := parseBlock(toolMapping, raw, gap); err == nil {
		return prop, nil
	}
	if prop, err := parseBlock(toolTuning, raw, gap); err == nil {
		return prop, nil
	}
	return Proposal{}, errors.New("strict-parse reject: reply is prose or an unrecognized JSON shape (no conforming add-only proposal)")
}

// parseBlock strict-decodes one tool input / JSON block into the named add-only
// shape and validates it (widen-only, closed-vocabulary, additive-key).
func parseBlock(name string, input any, gap MappingGap) (Proposal, error) {
	data, err := toJSON(input)
	if err != nil {
		return Proposal{}, err
	}
	switch name {
	case toolMapping:
		return parseMapping(data, gap)
	case toolTuning:
		return parseTuning(data)
	default:
		return Proposal{}, fmt.Errorf("strict-parse reject: unknown proposal shape %q", name)
	}
}

// parseMapping decodes and validates a MappingProposal. It fails loud on unknown
// fields, a source/raw_action that does not match the gap (an attempt to widen a
// DIFFERENT gap), an event_type outside the closed vocabulary (net-new type), or
// a mapping onto the default bucket (a no-op / narrowing).
func parseMapping(data []byte, gap MappingGap) (Proposal, error) {
	var m MappingProposal
	if err := strictUnmarshal(data, &m); err != nil {
		return Proposal{}, fmt.Errorf("strict-parse reject: mapping shape: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(m.Source), strings.TrimSpace(gap.Source)) {
		return Proposal{}, fmt.Errorf("strict-parse reject: mapping source %q != gap source %q (a proposal may only widen its own gap)", m.Source, gap.Source)
	}
	if strings.TrimSpace(m.RawAction) != strings.TrimSpace(gap.RawAction) {
		return Proposal{}, fmt.Errorf("strict-parse reject: mapping raw_action %q != gap raw_action %q", m.RawAction, gap.RawAction)
	}

	target := canonicalEventType(m.EventType)
	if target == "" {
		return Proposal{}, errors.New("strict-parse reject: empty event_type")
	}
	// Narrowing / no-op: mapping onto the connector's own default bucket widens
	// nothing (base-wins makes it dead) — refuse it.
	if target == canonicalEventType(gap.Source)+"_other" {
		return Proposal{}, fmt.Errorf("strict-parse reject: event_type %q is the default bucket (a no-op, not a widen)", m.EventType)
	}
	if !inVocabulary(target, gap.SuggestedVocabulary) {
		return Proposal{}, fmt.Errorf("strict-parse reject: event_type %q is not in the closed vocabulary (net-new types are refused)", m.EventType)
	}

	return Proposal{
		Kind: KindMapping,
		Mapping: &MappingProposal{
			Source:    gap.Source,
			RawAction: gap.RawAction,
			EventType: target, // canonical spelling (invariant 10)
		},
		Universal: true, // a factual source→action classification is universally true
	}, nil
}

// parseTuning decodes and validates a TuningDelta. It fails loud on unknown
// fields, a non-additive key (a committee-calibration knob is inexpressible in
// the widen-only tuning contract), an empty detector, or empty added values.
func parseTuning(data []byte) (Proposal, error) {
	var td TuningDelta
	if err := strictUnmarshal(data, &td); err != nil {
		return Proposal{}, fmt.Errorf("strict-parse reject: tuning shape: %w", err)
	}
	if strings.TrimSpace(td.Detector) == "" {
		return Proposal{}, errors.New("strict-parse reject: empty tuning detector")
	}
	if !IsAdditiveTuningKey(td.Key) {
		return Proposal{}, fmt.Errorf("strict-parse reject: tuning key %q is not an additive extra_* list (calibration knobs are refused)", td.Key)
	}
	var vals []string
	seen := map[string]bool{}
	for _, v := range td.AddedValues {
		cv := strings.ToLower(strings.TrimSpace(v)) // tuning values are lowercased
		if cv == "" || seen[cv] {
			continue
		}
		seen[cv] = true
		vals = append(vals, cv)
	}
	if len(vals) == 0 {
		return Proposal{}, errors.New("strict-parse reject: tuning added_values is empty")
	}
	return Proposal{
		Kind: KindTuning,
		Tuning: &TuningDelta{
			Detector:    strings.ToLower(strings.TrimSpace(td.Detector)),
			Key:         strings.ToLower(strings.TrimSpace(td.Key)),
			AddedValues: vals,
		},
		Universal: true,
	}, nil
}

// StrictParseGap is the ADD-ONLY gate on the inference reply for a
// GapCandidate-driven tuning run (StrictParse's sibling for the gap/tuning
// lane — mallcoppro-b42, design §Gap B). It accepts EXACTLY one conforming
// propose_tuning tool_use (or, as a fallback, one pure-JSON tuning object) and
// REJECTS everything else — including a propose_mapping call, which is not
// offered on this lane and is refused as an unrecognized tool. NEVER retries
// (the caller poisons the fingerprint on any error).
func StrictParseGap(resp MessagesResponse, gap GapCandidate) (Proposal, error) {
	var recognized []ContentBlock
	var unrecognizedTool bool
	var textParts []string

	for _, blk := range resp.Content {
		switch blk.Type {
		case "tool_use":
			if blk.Name == toolTuning {
				recognized = append(recognized, blk)
			} else {
				unrecognizedTool = true
			}
		case "text":
			if strings.TrimSpace(blk.Text) != "" {
				textParts = append(textParts, blk.Text)
			}
		}
	}

	switch {
	case len(recognized) > 1:
		return Proposal{}, fmt.Errorf("strict-parse reject: %d proposal blocks (want exactly one add-only proposal)", len(recognized))
	case len(recognized) == 1:
		data, err := toJSON(recognized[0].Input)
		if err != nil {
			return Proposal{}, err
		}
		return parseTuningForGap(data, gap)
	}

	if unrecognizedTool {
		return Proposal{}, errors.New("strict-parse reject: reply used an unrecognized tool (only add-only propose_tuning is accepted for a gap candidate)")
	}

	joined := strings.TrimSpace(strings.Join(textParts, ""))
	if joined == "" {
		return Proposal{}, errors.New("strict-parse reject: empty reply (no add-only proposal)")
	}
	return parseTuningForGap(json.RawMessage(joined), gap)
}

// parseTuningForGap decodes and validates a TuningDelta exactly as parseTuning
// does, plus an own-gap check mirroring parseMapping's: a proposal may only
// widen the detector family its OWN gap concerns, never a different one.
func parseTuningForGap(data []byte, gap GapCandidate) (Proposal, error) {
	prop, err := parseTuning(data)
	if err != nil {
		return Proposal{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(prop.Tuning.Detector), strings.TrimSpace(gap.DetectorFamily)) {
		return Proposal{}, fmt.Errorf("strict-parse reject: tuning detector %q != gap detector family %q (a proposal may only widen its own gap)", prop.Tuning.Detector, gap.DetectorFamily)
	}
	return prop, nil
}

// inVocabulary reports whether canonical target is a member of vocab (each vocab
// entry is canonicalized before comparison; mallcop's members are already
// canonical, so this only guards a non-canonical entry).
func inVocabulary(target string, vocab []string) bool {
	for _, v := range vocab {
		if canonicalEventType(v) == target {
			return true
		}
	}
	return false
}

// toJSON re-marshals a decoded tool input (an any) or passes a json.RawMessage
// through, so parseBlock can strict-decode it into a typed struct.
func toJSON(input any) ([]byte, error) {
	if rm, ok := input.(json.RawMessage); ok {
		return rm, nil
	}
	if b, ok := input.([]byte); ok {
		return b, nil
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("strict-parse reject: re-marshal tool input: %w", err)
	}
	return data, nil
}

// strictUnmarshal decodes data into v, failing loud on any unknown field —
// mirroring overlay.ParseLearnedMappings' KnownFields(true) fail-loud posture.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing content (a second object) — one block, one proposal.
	if dec.More() {
		return errors.New("trailing content after the proposal object")
	}
	return nil
}
