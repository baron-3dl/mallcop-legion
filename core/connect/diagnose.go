// diagnose.go defines the SELF-DIAGNOSIS kernel types: plain Go structs a
// connector uses to report a structured DiagnosisReport instead of forcing a
// caller to parse a raw error. This is hand-written product code, not a
// declarative spec interpreted by a generic engine (R2 hard invariant —
// docs/design-rulings.md; also docs/design/onboarding-self-service.md §3: "ONE
// code-first primitive per connector... no declarative DSL, no generic
// interpreter walking a data spec").
//
// GrantClaim is the one-per-connector-(or identity-family) primitive from
// design §3. core/connect carries its TYPE SHAPE only — no GrantClaim value is
// constructed here. The concrete Probe/Diagnose/Remediate/Confirm functions
// for a real identity family (Azure service principal first, design §11) are a
// separate, connector-family-specific item: a real Probe makes a live network
// call, and this package must stay pure stdlib + pkg/event (core/lint), the
// same reasoning that keeps ExecConnector itself outside core/.
package connect

import (
	"context"
	"time"
)

// IdentityKind names the cloud identity family a GrantClaim probes (e.g.
// AzureServicePrincipal, AWSRole, GCPServiceAccount). It is an opaque string so
// a new identity family is a new constant defined where that family's
// GrantClaim is authored, not a new type here.
type IdentityKind string

// ShellCommand is the least-privilege command an operator runs by hand to
// apply a RemediationOption. mallcop never executes it — the product only ever
// prints/narrates it; the operator decides whether to run it.
type ShellCommand string

// ProbeResult is the raw, connector-family-specific evidence a GrantClaim's
// Probe function gathers (e.g. a decoded JWT's claims for the Azure offline
// fast path, design §7). Its contents are owned by the connector family that
// produces it — core/connect only needs the envelope to exist so Diagnose has
// something to consume; it does not interpret Raw itself.
type ProbeResult struct {
	Raw map[string]any `json:"raw,omitempty"`
}

// Diagnosis is what a GrantClaim's Diagnose function turns a ProbeResult into:
// either a known, named deficiency, or Known:false — a GRANT-MISS the corpus
// hasn't mapped yet (design §3/§4).
type Diagnosis struct {
	// Known is false when the doctor saw a failure it cannot yet explain: a
	// GRANT-MISS row (design §4), not a crash.
	Known bool `json:"known"`
	// Summary is machine- and human-readable, e.g. "Log Analytics workspace in
	// resource-context access mode".
	Summary string `json:"summary"`
	// Confidence is in [0,1]; a low-confidence guess still surfaces but is
	// flagged uncertain to the operator/chat narrator.
	Confidence float64 `json:"confidence"`
}

// RemediationOption is one ranked, narrowest-first fix a GrantClaim's
// Remediate function offers for a Diagnosis. The product NEVER runs Command —
// only the operator does, by hand or after reviewing it in chat.
type RemediationOption struct {
	// Command is the least-privilege fix the operator runs.
	Command ShellCommand `json:"command"`
	// BlastRadius is plain English: what this grant lets the identity do, and
	// to what scope. Never omitted — an operator must be able to read what
	// they are about to grant before they run it.
	BlastRadius string `json:"blast_radius"`
	// KnownIssues are failure modes seen in the corpus for this exact
	// remediation (e.g. "propagation can take up to 5 minutes on Azure AD").
	KnownIssues []string `json:"known_issues,omitempty"`
	// DryRun is nil if the cloud has no dry-run mode for this command; else a
	// side-effect-free preview (e.g. `az ... --what-if`, `aws ... --dry-run`).
	DryRun *ShellCommand `json:"dry_run,omitempty"`
}

// ConfirmResult is what a GrantClaim's Confirm function returns after
// re-probing immediately following an operator-applied RemediationOption.
// Confirm is the loop-closer (design §3, NEW-A19): a RemediationOption that
// "succeeded" but left Resolved:false is itself a high-value GRANT-MISS — the
// exact failure mode that motivated requiring Confirm as kernel shape, never
// an optional per-connector nicety.
type ConfirmResult struct {
	// Resolved is true only when the re-probe shows the deficiency is gone.
	Resolved bool `json:"resolved"`
	// Diagnosis is the fresh diagnosis from the re-probe: Known:false on
	// success, or the persisting/new deficiency on failure.
	Diagnosis Diagnosis `json:"diagnosis"`
	// CheckedAt is when the re-probe ran.
	CheckedAt time.Time `json:"checked_at"`
}

// DiagnosisReport is the structured payload a Diagnosable connector returns
// from Diagnose — the OUTCOME this kernel exists for: a connector asked to
// self-diagnose returns a STRUCTURED report, never a raw error. It is what a
// --doctor-capable sibling binary prints as one JSON object on stdout, and
// what connect/exec's ExecConnector.Diagnose parses back into a Go value.
type DiagnosisReport struct {
	// ConnectorID identifies which configured connector this report is for
	// (Spec.ID in connect/exec), so a caller diagnosing many connectors can
	// tell the reports apart.
	ConnectorID string `json:"connector_id,omitempty"`
	// Diagnosis is the connector's current self-assessment.
	Diagnosis Diagnosis `json:"diagnosis"`
	// Remediation is the ranked, narrowest-first fix list for Diagnosis, when
	// one exists. Empty when Diagnosis.Known is false (nothing to rank yet) or
	// the deficiency needs no remediation.
	Remediation []RemediationOption `json:"remediation,omitempty"`
}

// GrantClaim is the ONE code-first primitive per connector (or per cloud
// identity family) the onboarding self-service kernel is built from (design
// §3). It is hand-written Go — there is no declarative DSL and no generic
// interpreter walking a data spec (R2 hard invariant): a new identity family
// means a new GrantClaim value with new Probe/Diagnose/Remediate/Confirm
// functions, reviewed and shipped as code, never as configuration a loader
// interprets.
type GrantClaim struct {
	// Identity names the cloud identity family this claim probes.
	Identity IdentityKind
	// Cadence is the expected pull frequency; it drives drift/liveness
	// detection (a cursor older than Cadence is itself a dated finding,
	// design §6).
	Cadence time.Duration
	// LastVerifiedLive is a provenance stamp set by mallcop's OWN CI eval job —
	// never by the customer — recording when this GrantClaim last proved
	// itself against a real live account.
	LastVerifiedLive time.Time

	// Probe is called at onboarding AND on every scheduled run.
	Probe func(ctx context.Context) (ProbeResult, error)
	// Diagnose turns a ProbeResult into a Diagnosis. Known:false emits a
	// GRANT-MISS row (design §4).
	Diagnose func(ProbeResult) (Diagnosis, error)
	// Remediate returns a RANKED list, narrowest-first. Never a single
	// "just in case" broad grant.
	Remediate func(Diagnosis) []RemediationOption
	// Confirm re-probes immediately after the operator applies a
	// RemediationOption. REQUIRED (NEW-A19) — not optional, not left to
	// individual connectors to remember: a Remediate that emits a command and
	// walks away never learns it didn't work.
	Confirm func(ctx context.Context, applied RemediationOption) (ConfirmResult, error)
}
