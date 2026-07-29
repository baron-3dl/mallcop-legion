// Package router is the AUTONOMY ROUTER for mallcop's self-extension loop.
// Given a strict-parsed add-only proposal (from the proposer package) and
// the merged gate's verdict, it decides WHERE the proposal goes, enforcing the
// autonomy tiers (invariant 11) and the contribute-back consent rule (invariant
// 6):
//
//	FORBIDDEN         any consensus-bypass shape (force-escalate/family-match
//	                  rule, any narrowing, any GLOBAL suppress) — hard reject,
//	                  poison the fingerprint. Fail-safe, checked FIRST. NOT
//	                  gated by the autonomy dial — always rejected.
//	HUMAN-GATE        net-new event_type / net-new detector family / critical
//	                  severity / a committee-calibration knob / a non-GREEN
//	                  gate — a reviewable artifact, NEVER auto-applied. NOT
//	                  gated by the autonomy dial — always human, at every tier.
//	PENDING-APPROVAL  an otherwise-clean widen (would auto-route to
//	                  TENANT-OVERLAY) held for a human decision because the
//	                  AUTONOMY DIAL is "non" (propose-only).
//	                  Nothing is written — no overlay, no artifact.
//	TENANT-OVERLAY    data-only + additive + existing-vocab + GREEN gate with
//	                  coverage +1 and zero regression, AND the dial is "semi" or
//	                  "fully" — append-only into the CUSTOMER store overlay
//	                  (the DEFAULT auto-apply route for a clean widen at those
//	                  two tiers). Owner suppression is first-class here and
//	                  honored freely.
//	OSS-CONTRIB       ONLY with explicit per-build tenantConsent==true AND a
//	                  universally-applicable widen — emits an OSS-PR ARTIFACT
//	                  for human review; NEVER auto-pushes/merges, and the tenant
//	                  overlay is still written. Absent/unknown consent stays
//	                  overlay, FULL STOP (never confiscate or condition the fix
//	                  on consent). This tier is NOT gated by the autonomy dial —
//	                  contribute-back stays human/maintainer-reviewed
//	                  regardless of dial position (a hard line, not
//	                  operator-overridable).
//
// # Autonomy dial
//
// Router.Autonomy (autonomy.Dial) decides ONLY whether an
// otherwise-clean widen (FORBIDDEN/HUMAN-GATE-exempt, gate-GREEN) auto-applies
// to the tenant overlay: "non" holds it at PENDING-APPROVAL, "semi"/"fully"
// write it straight to TENANT-OVERLAY. It never affects FORBIDDEN, HUMAN-GATE,
// or OSS-CONTRIB — those are dial-independent by construction.
//
// # Anti-thrash
//
// A FORBIDDEN proposal poisons its fingerprint into the SHARED reject set
// (engine.RejectSet) the proposer consults first, so the same dead-end shape is
// never re-proposed. HUMAN-GATE, PENDING-APPROVAL, and the overlay/OSS routes
// do NOT poison — they are valid destinations, not rejections.
package router

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/proposer"
)

// Destination is where a routed proposal lands.
type Destination string

const (
	// DestTenantOverlay: append-only widen written into the customer store overlay.
	DestTenantOverlay Destination = "tenant_overlay"
	// DestHumanGate: a reviewable artifact awaiting a human decision (never auto).
	DestHumanGate Destination = "human_gate"
	// DestOSSContribBack: an OSS-PR artifact emitted for human review (never auto-merged),
	// with the tenant overlay also written.
	DestOSSContribBack Destination = "oss_contrib_back"
	// DestForbidden: a consensus-bypass shape, hard-rejected (fingerprint poisoned).
	DestForbidden Destination = "forbidden"
	// DestPendingApproval: an otherwise-clean widen held for a human decision
	// because the autonomy dial is "non" (propose-only) — nothing is written.
	DestPendingApproval Destination = "pending_approval"
)

// Decision is the router's verdict for one proposal.
type Decision struct {
	Destination  Destination
	Reason       string
	OverlayPath  string // set when the tenant overlay was written
	ArtifactPath string // set when an OSS-PR artifact was emitted
	Provenance   RoutedRecord
}

// Router routes strict-parsed proposals per the autonomy tiers. All fields are
// set once; Route is safe to call sequentially (overlay writes are append-only
// and serialized by the caller).
type Router struct {
	// KnownEventTypes is the CLOSED vocabulary (the collect envelope's
	// SuggestedVocabulary, crossing as DATA). A mapping targeting a type NOT in
	// this set is net-new → HUMAN-GATE. Empty → every mapping is treated as
	// net-new (fail-safe: nothing auto-routes without a known vocabulary).
	KnownEventTypes map[string]bool
	// KnownDetectorFamilies, when non-empty, gates tuning proposals: a delta on a
	// family NOT in the set is net-new → HUMAN-GATE. Empty → family-novelty is
	// not gated (the tuning additive-key check still applies).
	KnownDetectorFamilies map[string]bool

	// OverlayDir is the directory the CUSTOMER store overlay files live in
	// (learned_mappings.yaml / tuning.yaml / suppressions.yaml). Required for any
	// overlay/OSS route.
	OverlayDir string
	// ArtifactDir is where OSS-PR artifacts land. Required for the OSS route.
	ArtifactDir string
	// ProvenanceDir is where a RoutedRecord is written per route AND per
	// rejection. Empty → provenance is not persisted (still returned in Decision).
	ProvenanceDir string
	// Fingerprints is the SHARED anti-thrash reject set. A FORBIDDEN proposal is
	// poisoned into it. Required.
	Fingerprints *engine.RejectSet

	// Autonomy is the operator-owned dial deciding whether a
	// gate-GREEN clean widen auto-applies to the tenant overlay ("semi"/"fully")
	// or is held at PENDING-APPROVAL for a human ("non"). Zero value normalizes
	// to autonomy.NonAutonomy (fail-safe: an unconfigured Router never
	// auto-applies) via autonomy.Dial.Normalized — see autonomyDial. It never
	// affects FORBIDDEN, HUMAN-GATE, or OSS-CONTRIB, which are dial-independent.
	Autonomy autonomy.Dial

	// GitSHA is the customer store repo git sha recorded in provenance. Optional.
	GitSHA string
	// Logger receives non-secret routing events. Nil → discard.
	Logger *slog.Logger
	// Now is the clock, for tests. Nil → time.Now.
	Now func() time.Time
}

func (r *Router) logger() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return r.Logger
}

func (r *Router) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// autonomyDial normalizes r.Autonomy — a zero value (a Router literal that
// never set the field) is treated as autonomy.NonAutonomy, the fail-safe.
func (r *Router) autonomyDial() autonomy.Dial {
	return r.Autonomy.Normalized()
}

// Route classifies a proposal and (for overlay/OSS routes) performs the
// append-only overlay write and OSS-PR artifact emission. It returns the
// Decision; the error return is reserved for infrastructure failures (an
// unwritable overlay/artifact/provenance dir) — a FORBIDDEN/HUMAN-GATE verdict
// is a Decision with a nil error.
func (r *Router) Route(p proposer.Proposal, gate engine.GateResult, tenantConsent bool) (Decision, error) {
	if r.Fingerprints == nil {
		return Decision{}, errors.New("router: Fingerprints (shared reject set) is nil")
	}

	// (1) FORBIDDEN (fail-safe, first): any consensus-bypass shape. Poison the
	//     fingerprint so it is never re-proposed.
	if reason, forbidden := r.forbiddenReason(p); forbidden {
		if p.Fingerprint != "" {
			if err := r.Fingerprints.Add(p.Fingerprint); err != nil {
				r.logger().Error("router: persist forbidden fingerprint failed", "err", err)
			}
		}
		return r.finish(p, gate, DestForbidden, reason, "", "")
	}

	// (2) HUMAN-GATE: net-new type/family, critical severity, or a calibration
	//     knob — never auto-applied.
	if reason := r.humanGateReason(p); reason != "" {
		return r.finish(p, gate, DestHumanGate, reason, "", "")
	}

	// A clean AUTO route requires a GREEN gate with coverage +1 and zero
	// regression. Anything else escalates to a human (fail-safe: never
	// auto-apply a proposal the gate did not certify).
	if !gateCertifiesWiden(gate) {
		reason := "gate did not certify a clean widen (need Passed && coverage_plus>=1 && no new_firings && !novel_gap); escalating to human"
		if gate.NovelGap {
			reason = fmt.Sprintf("gate flagged NovelGap for %v — reference corpus has zero labeled must_fire coverage for this family, cannot independently grade it; escalating to human regardless of autonomy dial", gate.NovelGapFamilies)
		}
		return r.finish(p, gate, DestHumanGate, reason, "", "")
	}

	// (2.5) AUTONOMY DIAL: a clean widen only auto-applies at "semi"/"fully".
	// At "non" (propose-only, the fail-safe default) it is held for a human —
	// NOTHING is written (no overlay, no artifact). This is the ONLY place the
	// dial acts; it never touches the FORBIDDEN/HUMAN-GATE/OSS-CONTRIB checks
	// above and below.
	if !r.autonomyDial().AutoAppliesData() {
		return r.finish(p, gate, DestPendingApproval,
			"autonomy=non: clean widen held for human approval (propose-only) — no auto-write", "", "")
	}

	// (3) TENANT-OVERLAY: append-only widen into the customer store overlay. This
	//     is the default for a clean widen, INCLUDING owner suppression (honored
	//     freely in-overlay, never auto-contributed).
	overlayPath, err := WriteOverlay(r.OverlayDir, p, r.KnownEventTypes)
	if err != nil {
		return Decision{}, err
	}

	// Owner suppression stops at the tenant overlay — NEVER OSS (c8e addendum).
	if p.Kind == proposer.KindOwnerSuppress {
		return r.finish(p, gate, DestTenantOverlay, "owner suppression honored in tenant overlay (never auto-contributed)", overlayPath, "")
	}

	// (4) OSS-CONTRIB-BACK: ONLY with explicit consent AND a universal widen.
	//     Emits a reviewable OSS-PR artifact; NEVER auto-pushes/merges. The tenant
	//     overlay is written REGARDLESS of consent (the fix is never withheld).
	if tenantConsent && p.Universal {
		artifactPath, aerr := r.emitOSSArtifact(p, gate)
		if aerr != nil {
			return Decision{}, aerr
		}
		return r.finish(p, gate, DestOSSContribBack,
			"tenant consented; universal widen — OSS-PR artifact emitted for human review (no auto-merge)", overlayPath, artifactPath)
	}

	reason := "clean widen written to tenant overlay"
	if !tenantConsent {
		reason += " (no OSS contribute-back: tenant consent absent — overlay only, full stop)"
	} else if !p.Universal {
		reason += " (no OSS contribute-back: tenant-specific widen, not universally applicable)"
	}
	return r.finish(p, gate, DestTenantOverlay, reason, overlayPath, "")
}

// forbiddenReason reports whether a proposal is a consensus-bypass shape that
// must be hard-rejected, and why. Checked FIRST (fail-safe).
func (r *Router) forbiddenReason(p proposer.Proposal) (string, bool) {
	switch p.Kind {
	case proposer.KindConsensusBypass:
		reason := "consensus-bypass shape"
		if strings.TrimSpace(p.BypassReason) != "" {
			reason += ": " + p.BypassReason
		}
		return reason, true
	case proposer.KindOwnerSuppress:
		// A GLOBAL suppress is a consensus bypass; only a TENANT-scoped owner
		// suppression is first-class.
		if p.Owner == nil || isGlobalScope(p.Owner.Scope) {
			return "global suppression is a consensus bypass (only tenant-scoped owner suppression is honored)", true
		}
	}
	return "", false
}

// humanGateReason reports why a well-formed (non-forbidden) proposal must go to a
// human rather than auto-apply, or "" if it may auto-route.
func (r *Router) humanGateReason(p proposer.Proposal) string {
	if strings.EqualFold(strings.TrimSpace(p.Severity), "critical") {
		return "critical severity — human review required before auto-apply"
	}
	switch p.Kind {
	case proposer.KindMapping:
		if p.Mapping == nil {
			return "malformed mapping proposal (nil payload)"
		}
		target := strings.ToLower(strings.TrimSpace(p.Mapping.EventType))
		if !r.knownEventType(target) {
			return "net-new event_type " + p.Mapping.EventType + " (not in the closed vocabulary) — human review required"
		}
	case proposer.KindTuning:
		if p.Tuning == nil {
			return "malformed tuning proposal (nil payload)"
		}
		if !proposer.IsAdditiveTuningKey(p.Tuning.Key) {
			return "committee-calibration knob " + p.Tuning.Key + " (not an additive extra_* list) — human review required"
		}
		// SCHEMA GATE (mallcoppro-2c2): the additive-key check above only proves
		// the KEY is on the closed enum; it says nothing about whether the
		// proposal's own family has a loadable tuning.yaml SECTION at all, or
		// whether that key exists within THAT section's schema. Both are
		// distinct from "known detector family" below (a detector can be a
		// perfectly real, registered family — e.g. "unusual-login" — with zero
		// tuning section, because no PrivEscalationTuning-shaped sibling struct
		// exists for it yet). Writing either shape produces a tuning.yaml
		// core/detect/tuning.go's strict KnownFields decode hard-rejects on the
		// NEXT scan, so both must be caught HERE, before WriteOverlay ever runs,
		// and routed to a human instead.
		section := detect.TuningKey(p.Tuning.Detector)
		if !detect.KnownTuningSection(section) {
			return fmt.Sprintf("detector family %q has no loadable tuning.yaml section (writing one would hard-error the next scan's tuning load) — human review required", p.Tuning.Detector)
		}
		if !detect.KnownTuningKey(section, p.Tuning.Key) {
			return fmt.Sprintf("tuning key %q is not part of the %q section's loadable schema — human review required", p.Tuning.Key, section)
		}
		if len(r.KnownDetectorFamilies) > 0 && !r.KnownDetectorFamilies[strings.ToLower(strings.TrimSpace(p.Tuning.Detector))] {
			return "net-new detector family " + p.Tuning.Detector + " — human review required"
		}
	}
	return ""
}

// knownEventType reports whether target (canonical) is in the closed vocabulary.
// An empty vocabulary means "unknown" for everything (fail-safe).
func (r *Router) knownEventType(target string) bool {
	if len(r.KnownEventTypes) == 0 {
		return false
	}
	return r.KnownEventTypes[target]
}

// gateCertifiesWiden reports whether the gate GREEN-certified a clean widen: it
// passed, added at least one covered case, introduced zero regressions
// (validate.go:153/156), and carries no NovelGap (BOTH ruling,
// part B: a declared family the reference corpus has zero labeled must_fire
// rows for is a structural blind spot the gate cannot independently grade —
// NOT a property "clean" should ever certify, on either lane. This mirrors
// the router's own dial-independent OSS-CONTRIB hard line: a widen the gate
// itself flags as ungradable escalates to HUMAN-GATE regardless of the
// autonomy dial, exactly like a non-GREEN gate or a regression does below).
func gateCertifiesWiden(gate engine.GateResult) bool {
	return gate.Passed && gate.CoveragePlus >= 1 && len(gate.NewFirings) == 0 && !gate.NovelGap
}

// isGlobalScope reports whether an owner-suppression scope is global (empty or an
// explicit global marker) rather than tenant-scoped.
func isGlobalScope(scope string) bool {
	s := strings.ToLower(strings.TrimSpace(scope))
	return s == "" || s == "global" || s == "all" || s == "*"
}

// finish records provenance (per route AND per rejection) and returns the
// Decision.
func (r *Router) finish(p proposer.Proposal, gate engine.GateResult, dest Destination, reason, overlayPath, artifactPath string) (Decision, error) {
	rec := RoutedRecord{
		Fingerprint:    p.Fingerprint,
		SampleEventIDs: p.SampleEventIDs,
		ProposerModel:  p.Model,
		Endpoint:       p.Endpoint,
		BaseSHA:        gate.BaseSHA,
		HeadSHA:        gate.HeadSHA,
		GitSHA:         r.GitSHA,
		Destination:    string(dest),
		Decision:       reason,
		Timestamp:      r.now().UTC(),
	}
	if err := r.writeProvenance(rec); err != nil {
		return Decision{}, err
	}
	r.logger().Info("router: routed proposal",
		"destination", dest, "kind", p.Kind, "fingerprint", p.Fingerprint, "reason", reason)
	return Decision{
		Destination:  dest,
		Reason:       reason,
		OverlayPath:  overlayPath,
		ArtifactPath: artifactPath,
		Provenance:   rec,
	}, nil
}
