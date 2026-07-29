// Package proposer is the add-only coverage PROPOSER for mallcop's
// self-extension loop — the DATA-lane sibling of the opencode code-authoring
// engine (the engine package). Where the engine authors Go detector code
// and gates it, the proposer runs ONE metered inference call to turn a
// STORE-MINED coverage gap into an add-only DATA delta:
//
//	a MappingProposal   — (source, raw_action) → a KNOWN event_type, or
//	a TuningDelta        — a detector's additive extra_* keyword list.
//
// # Pipeline position
//
//	mallcop collect --json  → coverage gaps (this package's process boundary)
//	    → proposer.Propose   → ONE inference call → STRICT add-only parse
//	        → router.Route     → tenant overlay / human-gate / OSS / forbidden
//
// # Billing rail (session seam)
//
// Inference credentials and the billing lifecycle are supplied by a
// session.Session so the proposer runs identically on two rails:
//
//   - METERED: a commercial billing session consults the spend cap, mints a
//     capped, lane-scoped run key, measures the provider's usage delta, and
//     revokes on Close.
//   - BYOI: a session.BYOISession points at the OSS user's OWN endpoint+key —
//     NO cap, NO minted key, $0 recorded. It holds no billing handle, so a BYOI
//     run makes zero billing calls by construction.
//
// The seam is the ONLY difference between the rails. Every safety invariant
// below runs byte-identically on both.
//
// # Safety invariants (mirror engine.Run)
//
//   - A known-reject gap fingerprint is SKIPPED before the session is even
//     consulted — zero Authorize, zero mint, zero inference, on EITHER rail.
//   - On the metered rail the spend gate is consulted BEFORE a run key exists; a
//     refusal spends nothing (no inference is possible without a key).
//   - session.Close is deferred immediately after Authorize and fires regardless
//     of success, parse verdict, or a panic in the inference client — on the
//     metered rail this revokes the per-run run key (the load-bearing teardown).
//   - The prompt is built from TRUSTED STRUCTURAL gap fields only; raw sample
//     payloads are never interpolated (see prompt.go).
//   - The reply is STRICT-parsed against the closed vocabulary. Any non-add-only
//     shape, unknown vocab, or narrowing verb is REJECTED with NO retry, and the
//     gap fingerprint is poisoned into the SHARED anti-thrash reject set.
//   - A surfaced inference error is redacted with the run's key (minted run key
//     OR BYOI user key) before it is logged or returned.
//
// # Process boundary
//
// The proposer consumes coverage gaps as JSON over the `mallcop collect --json`
// process boundary rather than importing the collector: this package duplicates
// the small MappingGap / GapCandidate / GapEvidence structs with matching json
// tags (see collect.go) and decodes the versioned envelope.
package proposer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/redact"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// defaultLane is the inference lane a propose run uses when Proposer.Lane is
// empty. Proposing is a structured-analysis task (map a raw action onto a closed
// vocabulary), so it defaults to the investigate lane.
const defaultLane = "investigate"

// defaultMaxTokens bounds one propose reply. A mapping/tuning delta is tiny; a
// runaway generation is both a cost and a parse risk, so the ceiling is low.
const defaultMaxTokens = 1024

// InferenceClient is the ONE metered/billed call a propose run makes. The real
// impl (AnthropicClient, client.go) POSTs the Anthropic /v1/messages wire shape
// to the resolved endpoint with the run's key (a minted run key OR a BYOI user
// key); tests inject a FAKE returning canned JSON.
type InferenceClient interface {
	Messages(ctx context.Context, req MessagesRequest) (MessagesResponse, error)
}

// Proposer runs one add-only coverage proposal per Propose. All fields are set
// once; Propose is serialized by the caller (one proposal at a time, sharing the
// reject set with the engine).
type Proposer struct {
	// Session is the runtime seam that supplies inference credentials and, on the
	// metered rail, the spend-cap + run-key lifecycle. A commercial billing
	// session reproduces the metered billing preamble (authorize → mint →
	// usage-delta → revoke); a BYOISession points at the user's OWN endpoint +
	// key with NO cap and NO minted key. Required. It is the ONLY place billing
	// differs between the two rails — every safety rail below is identical.
	Session session.Session
	// Fingerprints is the SHARED anti-thrash reject set (engine.RejectSet). The
	// proposer consults it FIRST and poisons rejected gaps into it, so a known
	// dead end is never re-proposed — on either rail. Required.
	Fingerprints *engine.RejectSet
	// NewClient builds the inference client from the resolved base URL and the
	// run's key (minted run key OR BYOI user key). Nil → the real AnthropicClient.
	// Tests inject a FAKE.
	NewClient func(baseURL, key string) InferenceClient

	// Lane is the inference lane (the model string the endpoint receives). Empty
	// → "investigate".
	Lane string
	// BudgetUSD is the per-run spend ESTIMATE handed to Session.Authorize. On the
	// metered rail it is the spend-cap estimate and pool ceiling; BYOI ignores it.
	// Required (> 0).
	BudgetUSD float64

	// Logger receives non-secret lifecycle events. Nil → discard.
	Logger *slog.Logger
}

// Outcome is the terminal state of one Propose. Exactly one of Skipped /
// Refused / Proposed / Rejected / Failed is true. Skipped and Refused spend
// nothing. Mirrors engine.Outcome.
type Outcome struct {
	Skipped  bool // anti-thrash: known-reject fingerprint; spent nothing
	Refused  bool // spend gate denied; spent nothing
	Proposed bool // reply strict-parsed to a valid add-only delta
	Rejected bool // reply failed strict parse; fingerprint poisoned
	Failed   bool // operational/inference failure (transient; no fingerprint)

	Reason      string    // human-readable cause (denial reason, parse error, ...)
	Fingerprint string    // the gap fingerprint
	CostUSD     float64   // measured spend for this run
	Model       string    // the lane/model the proposal was generated on
	Proposal    *Proposal // set when Proposed: the accepted add-only delta
}

func (p *Proposer) lane() string {
	if p.Lane != "" {
		return p.Lane
	}
	return defaultLane
}

func (p *Proposer) logger() *slog.Logger {
	if p.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return p.Logger
}

func (p *Proposer) newClient(baseURL, key string) InferenceClient {
	if p.NewClient != nil {
		return p.NewClient(baseURL, key)
	}
	return &AnthropicClient{BaseURL: baseURL, Key: key}
}

// validate checks required fields before a run touches inference. The billing
// preconditions (spend gate, minter, account id, provider URL) now live inside
// the commercial billing session, so the Proposer only guards its rail-agnostic
// invariants.
func (p *Proposer) validate() error {
	switch {
	case p.Session == nil:
		return errors.New("proposer: Session is nil")
	case p.Fingerprints == nil:
		return errors.New("proposer: Fingerprints is nil")
	case p.BudgetUSD <= 0:
		return errors.New("proposer: BudgetUSD must be > 0")
	}
	return nil
}

// mappingFingerprint is the stable anti-thrash key for a mapping gap: sha256
// over the normalized (source, raw_action) pair, domain-prefixed so it never
// collides with a K7 TrustedGap fingerprint in the SHARED reject set.
func mappingFingerprint(g MappingGap) string {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	sum := sha256.Sum256([]byte("map\x00" + norm(g.Source) + "\x00" + norm(g.RawAction)))
	return hex.EncodeToString(sum[:])
}

// gapFingerprint is the stable anti-thrash key for a GapCandidate: sha256 over
// the normalized (kind, detector_family, source, first_finding_id) tuple,
// domain-prefixed "gap\x00" so it never collides with a mapping fingerprint
// ("map\x00") or a K7 TrustedGap fingerprint in the SHARED reject set.
func gapFingerprint(g GapCandidate) string {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	var fid string
	if len(g.FindingIDs) > 0 {
		fid = g.FindingIDs[0]
	}
	sum := sha256.Sum256([]byte("gap\x00" + norm(g.Kind) + "\x00" + norm(g.DetectorFamily) + "\x00" + norm(g.Source) + "\x00" + norm(fid)))
	return hex.EncodeToString(sum[:])
}

// ProposeGap runs ONE add-only tuning-widen proposal for a GapCandidate —
// the DATA-lane consumer of operator override (override_fp) / consensus
// dissent (dissent) judgment (mallcoppro-b42, design §Gap B). It shares the
// EXACT SAME anti-thrash/spend/parse/record lifecycle as Propose (runLoop);
// only the request/parse are tuning-shaped instead of mapping-shaped.
//
// R9 (consensus not rules): this only WIDENS what the committee sees (an
// additive extra_* keyword list) — it never emits a suppress/force-escalate
// rule; StrictParseGap refuses any shape but propose_tuning.
//
// Callers filter to override_fp/dissent kinds before calling this (detect_miss
// has no finding to tune against; reported_miss is the CODE-lane's separate
// seed — mallcoppro-0e9 — and is deliberately not routed here).
func (p *Proposer) ProposeGap(ctx context.Context, gap GapCandidate) (Outcome, error) {
	if verr := p.validate(); verr != nil {
		return Outcome{}, verr
	}
	fp := gapFingerprint(gap)
	log := p.logger().With("fingerprint", fp, "kind", gap.Kind, "detector", gap.DetectorFamily, "source", gap.Source)
	return p.runLoop(ctx, fp, log,
		func() MessagesRequest { return p.buildGapRequest(gap) },
		func(resp MessagesResponse) (Proposal, error) { return StrictParseGap(resp, gap) },
		func(prop *Proposal) {
			prop.SampleEventIDs = gap.SampleEventIDs
			prop.Severity = gap.Severity
		},
	)
}

// Propose runs ONE add-only coverage proposal for a mapping gap, copying the
// engine.Run ordering exactly and routing every billing step through the
// Session so the METERED and BYOI rails share ONE code path:
//
//	anti-thrash → session.Authorize → (defer) session.Close → session.Credentials
//	→ ONE inference call → strict parse → session.Record — ALWAYS.
//
// On the metered rail Authorize mints a capped run key and Close revokes it; on
// the BYOI rail both are no-ops and Credentials returns the user's own
// endpoint+key. Everything between anti-thrash and Record — the trusted-signal
// prompt, the strict add-only parse, the fingerprint poisoning, the redaction —
// is identical on both rails; only WHERE inference is billed differs.
//
// It returns an Outcome describing the terminal state; the error return is
// reserved for infrastructure failures (bad config, mint/resolver error) —
// expected terminal states are Outcomes with a nil error.
//
// Named returns let the deferred panic-guard convert a panic in the inference
// client into Outcome{Failed} while the deferred session Close still fires
// (revoking the minted run key).
func (p *Proposer) Propose(ctx context.Context, gap MappingGap) (Outcome, error) {
	if verr := p.validate(); verr != nil {
		return Outcome{}, verr
	}
	fp := mappingFingerprint(gap)
	log := p.logger().With("fingerprint", fp, "source", gap.Source, "raw_action", gap.RawAction)
	return p.runLoop(ctx, fp, log,
		func() MessagesRequest { return p.buildRequest(gap) },
		func(resp MessagesResponse) (Proposal, error) { return StrictParse(resp, gap) },
		func(prop *Proposal) { prop.SampleEventIDs = gap.SampleEventIDs },
	)
}

// runLoop is the SHARED add-only proposal lifecycle Propose (mapping/tuning)
// runs — the single place the METERED/BYOI session seam and every safety rail
// live. The ordering copies engine.Run exactly:
//
//	anti-thrash → session.Authorize → (defer) session.Close → session.Credentials
//	→ ONE inference call → strict parse → session.Record — ALWAYS.
//
// buildReq builds the ONE metered request from the lane's trusted prompt; parse
// STRICT-parses the reply into an add-only Proposal (rejecting prose, multiple
// blocks, unknown shapes, transport-code fields); provenance stamps the
// gap-specific provenance fields (e.g. SampleEventIDs) onto an accepted proposal.
// Fingerprint/Model/Endpoint are stamped here for both rails.
//
// Named returns let the deferred panic-guard convert a panic in the inference
// client into Outcome{Failed} while the deferred session Close still fires
// (revoking the minted run key).
func (p *Proposer) runLoop(
	ctx context.Context,
	fp string,
	log *slog.Logger,
	buildReq func() MessagesRequest,
	parse func(resp MessagesResponse) (Proposal, error),
	provenance func(prop *Proposal),
) (out Outcome, err error) {
	out.Fingerprint = fp
	out.Model = p.lane()

	// 1) Anti-thrash FIRST — before ANY session call. A known reject is skipped
	//    before anything is authorized, minted, or billed. This runs on BOTH
	//    rails, so a BYOI user spends ZERO inference on a known dead end too.
	if p.Fingerprints.Has(fp) {
		log.Info("proposer: skipping known-reject gap")
		return Outcome{Skipped: true, Reason: "known-reject fingerprint", Fingerprint: fp, Model: out.Model}, nil
	}

	// 2) Authorize. Metered: spend gate (BEFORE mint — a refusal spends nothing) +
	//    mint the capped, lane-scoped run key. BYOI: a no-op that always succeeds.
	//    A benign cap refusal is a *RefusalError (Refused, spent nothing); a
	//    mint/resolver failure surfaces as a hard error.
	if aerr := p.Session.Authorize(ctx, p.BudgetUSD); aerr != nil {
		if refusal, ok := session.AsRefusal(aerr); ok {
			log.Info("proposer: spend gate refused", "err", refusal)
			return Outcome{Refused: true, Reason: refusal.Error(), Fingerprint: fp, Model: out.Model}, nil
		}
		return Outcome{}, aerr
	}

	// 3) Teardown is unconditional (defer) — success, failure, or panic. Metered:
	//    revoke the run key + drain the pool. BYOI: a no-op.
	defer func() {
		if cerr := p.Session.Close(); cerr != nil {
			log.Error("proposer: session close failed (teardown)", "err", cerr)
		}
	}()

	// Panic guard registered LAST → runs FIRST during unwind, converting a panic
	// in the inference client into a Failed outcome; the Close defer (registered
	// earlier) then still runs, so the run-key revoke always fires.
	defer func() {
		if r := recover(); r != nil {
			err = nil
			out = Outcome{Failed: true, Reason: fmt.Sprintf("panic during inference/parse: %v", r), Fingerprint: fp, Model: p.lane()}
			log.Error("proposer: recovered panic during run", "panic", r)
		}
	}()

	// 4) Resolve inference credentials (minted run key OR BYOI user key) and make
	//    the ONE billed inference call. Credentials marks the usage-window start.
	baseURL, key, cerr := p.Session.Credentials(ctx)
	if cerr != nil {
		return Outcome{}, fmt.Errorf("proposer: resolve inference credentials: %w", cerr)
	}
	client := p.newClient(baseURL, key)
	resp, ierr := client.Messages(ctx, buildReq())
	if ierr != nil {
		cost := p.record(ctx, log, false)
		// Redact the run's key (minted run key OR the BYOI user key) from the
		// surfaced error. redact.Redact scrubs the exact key handed to it plus any
		// mallcop-sk-*/vendor-prefixed sibling, so a BYOI "sk-ant-..." key is
		// scrubbed even though it is not a mallcop key.
		redacted := redact.Redact(ierr.Error(), key)
		log.Error("proposer: inference call failed", "err", redacted, "cost_usd", cost)
		return Outcome{Failed: true, Reason: "inference: " + redacted, Fingerprint: fp, CostUSD: cost, Model: p.lane()}, nil
	}

	// 5) STRICT add-only parse. A non-conforming reply (prose, multiple blocks,
	//    unknown vocab, narrowing shape, off-schema/transport-code fields) is
	//    REJECTED with NO retry, and the gap fingerprint is poisoned into the
	//    shared reject set. IDENTICAL on both rails.
	prop, perr := parse(resp)
	if perr != nil {
		cost := p.record(ctx, log, false)
		if aerr := p.Fingerprints.Add(fp); aerr != nil {
			log.Error("proposer: persist rejected fingerprint failed", "err", aerr)
		}
		log.Info("proposer: reply rejected — fingerprint poisoned (no retry)", "reason", perr, "cost_usd", cost)
		return Outcome{Rejected: true, Reason: perr.Error(), Fingerprint: fp, CostUSD: cost, Model: p.lane()}, nil
	}

	// 6) Record spend (metered: provider usage delta + ledger; BYOI: $0).
	cost := p.record(ctx, log, true)
	prop.Fingerprint = fp
	prop.Model = p.lane()
	prop.Endpoint = baseURL
	if provenance != nil {
		provenance(&prop)
	}
	out.Proposed = true
	out.Proposal = &prop
	out.CostUSD = cost
	log.Info("proposer: add-only proposal accepted", "kind", prop.Kind, "cost_usd", cost)
	return out, nil
}

// record folds the run's measured spend into the Session ledger and returns the
// cost. On the metered rail the Session sums the provider usage delta since
// Credentials and calls Gate.Record; on the BYOI rail it returns 0 and records
// nothing. A record failure is non-fatal (logged, not returned).
func (p *Proposer) record(ctx context.Context, log *slog.Logger, success bool) float64 {
	cost, rerr := p.Session.Record(ctx, success, p.BudgetUSD)
	if rerr != nil {
		log.Error("proposer: session record failed", "err", rerr)
	}
	return cost
}
