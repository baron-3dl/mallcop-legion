package proposer

import (
	"sort"
	"strings"
)

// ProposalKind is the shape of an accepted (or, for the router's defense-in-depth
// classification, a candidate) proposal.
type ProposalKind string

const (
	// KindMapping is a widen-only learned mapping: (source, raw_action) → a KNOWN
	// event_type. The proposer produces this from a MappingGap.
	KindMapping ProposalKind = "mapping"
	// KindTuning is a widen-only tuning delta: a detector's additive extra_*
	// keyword list. The proposer produces this from a tuning-shaped reply.
	KindTuning ProposalKind = "tuning"
	// KindOwnerSuppress is a TENANT-SCOPED owner suppression (the c8e addendum).
	// The proposer never generates one; the router honors it freely IN-OVERLAY
	// and NEVER auto-contributes it to OSS. A GLOBAL suppress is not this kind —
	// it is a consensus bypass.
	KindOwnerSuppress ProposalKind = "owner_suppress"
	// KindConsensusBypass is any consensus-bypass shape (a force-escalate /
	// family-match rule, a narrowing verb, a GLOBAL suppress). The proposer's
	// strict parser rejects these before they become proposals; the router
	// hard-rejects any it is nonetheless handed (defense in depth).
	KindConsensusBypass ProposalKind = "consensus_bypass"
)

// MappingProposal is the add-only learned-mapping delta. It mirrors the
// connect/overlay learned_mappings.yaml shape (source → {rawAction → event_type},
// overlay.go:67): the router appends source→raw_action→event_type to the tenant
// overlay, widen-only.
type MappingProposal struct {
	Source    string `json:"source"`
	RawAction string `json:"raw_action"`
	EventType string `json:"event_type"`
}

// TuningDelta is the add-only detector-tuning delta. It mirrors the
// detectors/tuning.yaml shape (detector → {extra_* → [values]}): the router
// appends AddedValues to the detector's additive extra_* list, widen-only. Key
// MUST be an additive extra_* key (see IsAdditiveTuningKey).
type TuningDelta struct {
	Detector    string   `json:"detector"`
	Key         string   `json:"key"`
	AddedValues []string `json:"added_values"`
}

// OwnerSuppression is a tenant-scoped owner suppression. Scope MUST be non-empty
// and tenant-scoped (never "global"); a global suppress is a consensus bypass.
type OwnerSuppression struct {
	FindingType string `json:"finding_type"`
	Scope       string `json:"scope"`
}

// Proposal is the union the proposer emits and the router routes. Exactly one of
// Mapping / Tuning / Owner is set for the corresponding Kind (none for
// KindConsensusBypass). The structural routing signals (Severity, Universal, ...)
// are TRUSTED derived fields carried from the originating gap — never free text.
type Proposal struct {
	Kind    ProposalKind      `json:"kind"`
	Mapping *MappingProposal  `json:"mapping,omitempty"`
	Tuning  *TuningDelta      `json:"tuning,omitempty"`
	Owner   *OwnerSuppression `json:"owner,omitempty"`
	// BypassReason describes the offending shape when Kind == KindConsensusBypass.
	BypassReason string `json:"bypass_reason,omitempty"`

	// Severity is the structural severity of the originating gap (critical →
	// human-gate). Empty for a mapping gap (which carries no severity).
	Severity string `json:"severity,omitempty"`
	// Universal reports whether this widen is universally applicable (a factual
	// classification, not tenant-specific) and therefore OSS-contribute-back
	// eligible. Owner suppressions are never universal.
	Universal bool `json:"universal"`

	// Fingerprint of the originating gap (provenance + reject set).
	Fingerprint string `json:"fingerprint,omitempty"`
	// SampleEventIDs are event ids for provenance.
	SampleEventIDs []string `json:"sample_event_ids,omitempty"`
	// Model is the lane/model the proposal was generated on (provenance).
	Model string `json:"model,omitempty"`
	// Endpoint is the inference base URL this proposal was billed to (the provider
	// URL on the metered rail, the user's URL on BYOI). Provenance only — NEVER
	// the key. Mirrors engine.Provenance.Endpoint (engine.go).
	Endpoint string `json:"endpoint,omitempty"`
}

// additiveTuningKeys is the allow-list of tuning.yaml keys that are ADDITIVE
// extra_* lists (widen-only by construction). It mirrors EXACTLY the keys the
// mallcop tuning loader accepts (core/detect/tuning.go's PrivEscalationTuning
// struct, detectors/tuning.yaml's priv_escalation section) — no more, no
// fewer. It previously advertised two phantom keys (extra_admin_actions,
// extra_sensitive_actions) that no loader field ever backed: the model could
// propose them, the router's IsAdditiveTuningKey check waved them through as
// "additive", and writeTuningOverlay wrote them straight into tuning.yaml —
// which core/detect/tuning.go's strict KnownFields decode then hard-rejected
// on the NEXT scan, aborting it (mallcoppro-2c2, subsumes mallcoppro-f7f).
// A key outside this set is either a committee-calibration knob (a threshold,
// a confidence penalty — inexpressible in the widen-only tuning contract) or a
// key the loader simply does not read; either way it is REJECTED by the
// strict parser / routed to a human by the router, never written.
var additiveTuningKeys = map[string]bool{
	"extra_elevated_keywords":        true,
	"extra_elevated_action_keywords": true,
	"extra_elevation_event_types":    true,
}

// IsAdditiveTuningKey reports whether key names an additive extra_* tuning list.
// A key is additive iff it is in the explicit allow-list AND carries the extra_
// prefix — both belt and suspenders, so a future non-additive "extra"-named knob
// cannot slip through, and an allow-listed key that loses its prefix is caught.
func IsAdditiveTuningKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	return strings.HasPrefix(k, "extra_") && additiveTuningKeys[k]
}

// additiveTuningKeyList returns the additive extra_* keys as a stable-ordered
// slice, for use as a closed enum in a tool schema (gapTuningTool, prompt.go).
func additiveTuningKeyList() []string {
	keys := make([]string, 0, len(additiveTuningKeys))
	for k := range additiveTuningKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
