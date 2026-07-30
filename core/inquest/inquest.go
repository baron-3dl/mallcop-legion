// inquest.go — the RunAll orchestrator: per-escalated-finding idempotency
// check, budget gate, per-finding panic guard, and the record write.
package inquest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// defaultMaxPerScan is Config.MaxPerScan's fallback when unset/non-positive —
// mirrors core/config.Investigate's default (10).
const defaultMaxPerScan = 10

// DefaultMaxDeepPerScan is Config.MaxDeepPerScan's fallback when unset/non-positive
// — the low-confidence deeper-investigation retrigger's SEPARATE metered-call
// budget (mallcoppro-09a). Deliberately smaller than defaultMaxPerScan: the deep
// pass only fires on the subset of escalations whose first pass came back low
// confidence, and each one also drives a full committee re-vote (several more
// cascade calls), so its blast radius must be tightly bounded. Exported so the
// core/pipeline orchestration that owns the retrigger (RunAll itself never reads
// MaxDeepPerScan) can apply the same fallback the field's doc promises.
const DefaultMaxDeepPerScan = 5

// defaultModelCallTimeout bounds EACH narrate call — the scan's core output
// can never be delayed past this per finding (failureSemantics §design). The
// actual bound is Config.CallTimeout when set; this is its fallback.
const defaultModelCallTimeout = 60 * time.Second

// Config is core/inquest's OWN copy of the investigate: config block.
// core/config cannot be imported here (see imports_test.go's closed
// allowlist — inquest reaches the model ONLY through the injected
// agent.Client, never a concrete config/transport dependency); the caller
// (core/pipeline, fed by cli/scan.go) maps core/config.Investigate onto this
// struct once per run.
type Config struct {
	// Enabled gates the WHOLE package: false means RunAll writes NO records at
	// all, not even evidence-only (see the off-switch semantics note on
	// StatusAbsentDisabled).
	Enabled bool
	// Model is the model id sent on the narrate request. "" lets the injected
	// agent.Client fall back to its own default (core/inference.DirectClient's
	// documented per-request-wins contract) — the "inherit the scan's resolved
	// model" semantic.
	Model string
	// MaxPerScan bounds the number of METERED narrate calls THIS scan may make
	// (new + degraded-refresh combined). <= 0 uses defaultMaxPerScan.
	MaxPerScan int
	// Retries is carried for schema completeness only. RunAll makes exactly
	// ONE call per finding regardless of this value — retry-until-pass is
	// structurally absent (the hard one-call contract); a failed/invalid reply
	// degrades the record instead of retrying within this scan.
	Retries int
	// NeighborWindow bounds section 2 (NEIGHBORS). <= 0 uses 1h.
	NeighborWindow time.Duration
	// MaxNeighbors caps the neighbor list. <= 0 uses 50.
	MaxNeighbors int
	// CorrelationWindow bounds section 5 (SCAN-SCHEDULE CORRELATION)'s
	// "correlated" gate. <= 0 uses 10m.
	CorrelationWindow time.Duration
	// MaxTokens bounds the narrate call's MaxTokens. <= 0 uses 1024.
	MaxTokens int
	// CallTimeout bounds EACH narrate call's context deadline. <= 0 uses
	// defaultModelCallTimeout (60s — the production default; see
	// failureSemantics §design). Exposed as a config knob (rather than a bare
	// constant) purely so a test can drive a hung-client scenario without a
	// real 60s wait — cli/scan.go leaves this unset in production.
	CallTimeout time.Duration
	// OwnedEntities is the operator's configured owned accounts/roles/relays
	// (mallcoppro-995, mirrors core/config.Org.Owned — cli/scan.go maps that
	// onto this field once per run), fed to section 6 (ORG CONTEXT) so a
	// recurring, baseline-known, owned-account actor resolves with its
	// relationship named instead of narrating as an unknown external actor.
	// nil is the safe absent default — no evidence is ever marked owned.
	OwnedEntities []OwnedEntity

	// --- Low-confidence re-vote (mallcoppro-09a) -----------------------------
	// These three fields are CARRIED THROUGH this struct (it is the resolved
	// investigate: settings bundle cli/scan.go maps onto core/pipeline.Config)
	// but are NOT read by RunAll itself — RunAll only makes the ONE narrate call
	// per finding it always has. They are consumed by core/pipeline's step-6
	// orchestration: an escalated finding whose investigation came back "ok" but
	// with investigator Confidence < LowConfidenceThreshold is re-investigated
	// with a deeper pass (RunAll again, Force=true, budgeted at MaxDeepPerScan)
	// and put to a committee RE-VOTE (core/agent.RunRevoteGate, any-escalate-wins).
	// inquest itself never runs the cascade — that would violate the consensus
	// invariant (imports_test bans core/agent's ResolveFindingWith); the re-vote
	// lives in core/pipeline + core/agent, and these are just the tuning knobs it
	// reads off the resolved config.

	// LowConfidenceThreshold is the investigator-confidence floor below which an
	// "ok" escalated investigation is treated as too shaky to ship as-is and is
	// sent to the deeper-pass + re-vote path. <= 0 DISABLES the whole
	// low-confidence retrigger (no deep pass, no re-vote) — the pre-09a behavior.
	LowConfidenceThreshold float64
	// MaxDeepPerScan bounds the number of METERED deeper-investigation narrate
	// calls the low-confidence retrigger may make THIS scan — a SEPARATE budget
	// from MaxPerScan so a noisy scan's re-pass cannot starve (or be starved by)
	// the first-pass budget. <= 0 uses DefaultMaxDeepPerScan (the pipeline
	// resolves this fallback — RunAll never reads this field).
	MaxDeepPerScan int
	// DeepModel is the model id the deeper investigation pass pins (typically a
	// stronger lane than the first pass — the whole point of "go deeper"). ""
	// inherits the first pass's Model.
	DeepModel string
}

// OwnedEntity is core/inquest's OWN copy of core/config.OwnedEntity (same
// closed-allowlist reason as Config's doc comment above — core/config cannot
// be imported here). Match is substring-matched against a finding's
// caller/target/actor identity fields; Name/Relationship are the
// plain-language labels the narrate prompt is instructed to use.
type OwnedEntity struct {
	Match        string
	Name         string
	Relationship string
}

// EscalatedFinding pairs one finding with the cascade resolution that
// escalated it — the ONLY findings RunAll is ever given. A resolved-benign
// finding is never investigated.
type EscalatedFinding struct {
	Finding    finding.Finding
	Resolution ResolutionRef
	// CaseID is the case cluster (mallcoppro-554's core/cases.Key —
	// type+actor+entity) this finding belongs to, resolved by the caller via
	// the EXPORTED core/cases.CaseID hash — core/inquest itself cannot
	// import core/cases (see imports_test.go's closed allowlist), so this is
	// a plain string, never a core/cases.Key. core/pipeline sets this for
	// every production finding (mallcoppro-42e); "" is the safe fallback for
	// any caller (mostly this package's own tests) that hasn't resolved one
	// — see RecordKey.
	CaseID string
}

// RecordKey resolves the on-disk investigation-record identity for ef: its
// CaseID when set (mallcoppro-42e — multiple findings recurring under the
// SAME case share ONE record, refreshed on each refire, never duplicated),
// falling back to the finding's own ID for any caller that hasn't resolved a
// case (this package's own unit tests, and any pre-migration embedder) —
// exactly the pre-42e per-finding keying for that fallback. Exported so
// core/pipeline's low-confidence re-vote step (attach.go's ReadRecord/
// AttachRevote) resolves the SAME key inquest.RunAll itself used, rather than
// re-deriving the fallback logic a second time.
func (ef EscalatedFinding) RecordKey() string {
	if ef.CaseID != "" {
		return ef.CaseID
	}
	return ef.Finding.ID
}

// Input is RunAll's whole input.
type Input struct {
	// Store is the ALREADY-OPEN store this scan wrote findings/resolutions to.
	// Required.
	Store *store.Store
	// Client is the SAME inference seam the cascade used this scan. nil is
	// valid (the scan ran with no inference client configured) and produces
	// StatusAbsentNoClient evidence-only records — never a panic.
	Client agent.Client
	// Findings is this scan's escalated findings, order-independent (RunAll
	// sorts by finding ID for deterministic budget consumption).
	Findings []EscalatedFinding
	// AllEvents is the full known event history this scan gated detection on:
	// priorEvents ++ this scan's deduped batch. The caller (core/pipeline)
	// already holds both — zero extra I/O.
	AllEvents []event.Event
	// Baseline is the SAME baseline the scan gated detection on. nil is
	// treated as an empty baseline.
	Baseline *baseline.Baseline
	// MallcopVersion is a best-effort provenance stamp for the record. Empty
	// when unknown — never fabricated.
	MallcopVersion string
	// Config is the resolved investigate: settings for this run.
	Config Config
	// AttentionWeights maps finding.ID to the attention weight accumulated
	// from any matching focus/watch-closer directive (Gap C, mallcoppro-4da;
	// core/pipeline.DirectiveDispatcher.AttentionWeights). nil/absent is the
	// safe default: every finding weighs 0, and RunAll's budget-consumption
	// order falls back to the pre-Gap-C pure finding-ID sort. A finding
	// present in Findings but absent from this map ALSO weighs 0 — it is
	// never an error to omit an entry. This ONLY reorders which findings a
	// budget-limited scan spends its metered calls on FIRST; it never grants
	// extra calls, never bypasses the idempotency skip, and never touches a
	// committee verdict (R9: naming/weighting/annotation only).
	AttentionWeights map[string]float64
	// Force, when true, bypasses the idempotency skip (processOne's
	// found+ok+current-schema short-circuit) UNCONDITIONALLY for every finding
	// in this call — the caller has already decided this specific subset needs a
	// FRESH pass (the low-confidence deeper-investigation retrigger,
	// mallcoppro-09a). It changes NOTHING on the normal (Force==false) path: the
	// skip logic, budget gate, CreatedAt preservation, and failure semantics are
	// all identical. The caller is responsible for passing ONLY the subset that
	// warrants a re-pass — Force does not widen the budget, so a Force call over
	// the full escalated set would still burn MaxPerScan re-investigating
	// already-confident findings; the pipeline scopes it to the low-confidence
	// subset (mallcoppro-09a risk 6). Force also NEVER downgrades a prior "ok"
	// record: if the fresh pass itself lands anything other than "ok" (deep
	// budget exhausted, model error/timeout, invalid output), processOne keeps
	// the existing ok record rather than overwriting it with a degraded one
	// (mallcoppro-09a review fix — a Force re-pass that fails must not destroy
	// a good verdict the customer-facing surface already reads).
	Force bool
}

// Outcome is RunAll's result. RunAll NEVER returns an error the caller
// propagates — see the package doc.
type Outcome struct {
	// Investigated counts findings this run wrote (or refreshed) a record for
	// with NarrativeStatus "ok".
	Investigated int
	// Degraded counts findings this run wrote (or refreshed) a record for with
	// any NarrativeStatus OTHER than "ok" — the deterministic evidence still
	// shipped. ALSO counts a finding skipped after a transient error reading
	// its existing record (readExistingRecord's error path in processOne), OR
	// a Force re-pass that failed to reach "ok" over a finding whose prior
	// record WAS "ok" (the overwrite guard below) — both of those cases write
	// NO record at all (protecting budget, CreatedAt, and — for the Force
	// case — the prior good verdict); they are still tallied here so the
	// operator sees the failed attempt rather than silence.
	Degraded int
	// Skipped counts findings whose existing record was already current + ok:
	// zero calls, zero writes. Not surfaced on pipeline.Summary; exists so a
	// caller/test can assert idempotency directly.
	Skipped int
	// FreshOKIDs lists the finding IDs that received a FRESH "ok" verdict this
	// run — a model call landed a trusted verdict AND it was durably written.
	// len(FreshOKIDs) == Investigated, and the order matches RunAll's
	// deterministic finding-ID sort. It is the per-finding companion to the
	// Investigated tally, added for the low-confidence re-vote (core/pipeline,
	// mallcoppro-09a): a Force deeper pass that FAILS for a finding keeps that
	// finding's prior (first-pass) "ok" record on disk (the overwrite guard in
	// processOne), so the two are byte-indistinguishable to a re-reader. The
	// caller MUST re-vote only findings IN this set — a finding NOT here kept
	// its first-pass evidence, and re-voting it would feed the committee that
	// first-pass evidence relabeled as a "deeper investigation" that never
	// landed, misrepresenting provenance (mallcoppro-09a review finding).
	FreshOKIDs []string
	// Errors carries one human-readable line per degraded/failed record, for
	// the caller to print as a non-fatal warning. Never fails the scan.
	Errors []string
}

// RunAll investigates every finding in in.Findings, at most ONE metered model
// call per finding, budgeted at in.Config.MaxPerScan calls total THIS run,
// and commits a Record to investigations/<case-id>.json — the SAME record for
// every finding sharing a case (EscalatedFinding.CaseID, mallcoppro-42e),
// refreshed rather than duplicated on a refire; falls back to
// investigations/<finding-id>.json for any caller that hasn't resolved a case
// (see recordPath, EscalatedFinding.RecordKey). It NEVER returns an error the
// caller must handle, AND IT NEVER PANICS OUT — every failure mode (nil store, model failure, panic, marshal
// error) degrades an INDIVIDUAL record via processOne's own per-finding
// guard; a panic anywhere else in RunAll's OWN body (the deterministic-order
// setup below, or any future code added to this function) is caught by the
// top-level defer/recover immediately below and converted into the Outcome
// accumulated so far plus a warning line, never propagated into the caller
// (core/pipeline.Run — see pipeline.go's RunAll call site doc). This makes
// failureSemantics' "the whole inquest step is panic-guarded" claim literally
// true: there is no code path in this package that can crash the scan.
//
// Idempotency: a finding whose case (or, absent a case, itself) already has a
// record at the current SchemaVersion, NarrativeStatus "ok", AND that THIS
// finding has itself already contributed a trusted pass to (either it is the
// record's most recent contributor, FindingID, OR its ID is a member of
// Record.InvestigatedFindingIDs — the per-finding membership set a
// multi-finding-per-case record accumulates, mallcoppro-42e review fix) is
// skipped entirely — zero calls, zero store reads beyond the one existence
// check, zero writes (a genuine re-run of that same finding, even when OTHER
// findings share its case). A finding whose record is absent, schema-stale,
// degraded, or that has NOT itself yet contributed (a refire — a NEW finding
// recurring under the same case, or a co-occurring finding new to this scan)
// is (re-)investigated, preserving the original CreatedAt on a refresh and
// flagging any change in trusted verdict: Record.VerdictFlip for a change
// across scans (a genuine refire), or Record.CoOccurringVerdict for two
// findings sharing a case that simply disagreed within ONE scan (never a
// flip — nothing changed over time) — never averaging or suppressing either.
func RunAll(ctx context.Context, in Input) (out Outcome) {
	defer func() {
		if r := recover(); r != nil {
			out.Errors = append(out.Errors, fmt.Sprintf(
				"inquest: panic in RunAll outside any single finding's guard: %v — returning the %d investigated/%d degraded/%d skipped accumulated before the panic",
				r, out.Investigated, out.Degraded, out.Skipped))
		}
	}()

	if !in.Config.Enabled {
		// Off-switch: no records at all, not even evidence-only.
		return out
	}
	if in.Store == nil {
		out.Errors = append(out.Errors, "inquest: nil store — skipped every finding")
		return out
	}
	if len(in.Findings) == 0 {
		return out
	}

	maxPerScan := in.Config.MaxPerScan
	if maxPerScan <= 0 {
		maxPerScan = defaultMaxPerScan
	}

	if runAllPanicHookForTest != nil {
		runAllPanicHookForTest()
	}

	// Deterministic order: a re-run of the same scan budgets identically
	// regardless of upstream map/slice iteration order. Gap C (mallcoppro-4da):
	// a finding with a HIGHER attention weight (focus/watch-closer directives,
	// via in.AttentionWeights) is budgeted FIRST, so a budget-limited scan
	// spends its metered calls on what the operator asked to watch closer
	// before it spends them on everything else; ties (including the common
	// case of two 0-weight findings, or nil AttentionWeights) fall back to the
	// pre-Gap-C finding-ID order, so this is a strict superset of the old
	// behavior, not a replacement for it.
	findings := append([]EscalatedFinding(nil), in.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		wi, wj := in.AttentionWeights[findings[i].Finding.ID], in.AttentionWeights[findings[j].Finding.ID]
		if wi != wj {
			return wi > wj
		}
		return findings[i].Finding.ID < findings[j].Finding.ID
	})

	// Gap E2: an operator prioritize/criticality directive re-sorts (never
	// filters) this finding-ID order — a source the operator called out
	// spends the metered narrate budget first when MaxPerScan can't cover
	// every escalated finding this scan. A directive load failure degrades
	// to the pre-existing finding-ID order (sortByAttention treats nil
	// directives as "everyone weighs 0") rather than failing the scan — this
	// package never returns an error the caller must handle (see RunAll's
	// doc above).
	if dirs, derr := in.Store.LoadDirectives(); derr == nil {
		sortByAttention(findings, dirs)
	} else {
		out.Errors = append(out.Errors, fmt.Sprintf(
			"inquest: load directives for attention weighting: %v — falling back to finding-ID order", derr))
	}

	// touchedThisRun tracks, per record key, whether an EARLIER finding in
	// THIS SAME RunAll call has already written to that key — the
	// scan-awareness seam mallcoppro-42e's review fix needs: two findings
	// sharing a case that BOTH land in this one call's Findings slice can
	// disagree (co-occurring, never a temporal flip), while a finding
	// sharing a case with a record from an EARLIER RunAll call (a genuine
	// refire, possibly scans apart) is comparing across time, where a
	// differing verdict IS a flip. See processOne's use of this map.
	touchedThisRun := make(map[string]bool, len(findings))

	callsUsed := 0
	for _, ef := range findings {
		investigated, degraded, skipped, errMsg := processOne(ctx, in, ef, maxPerScan, &callsUsed, touchedThisRun)
		out.Investigated += investigated
		out.Degraded += degraded
		out.Skipped += skipped
		if investigated == 1 {
			// A fresh "ok" verdict landed AND persisted for this finding (see
			// processOne's write-failure guard, which downgrades a failed write
			// out of the investigated tally). Record the ID so the caller can
			// tell a genuine deeper verdict from a preserved first-pass one.
			out.FreshOKIDs = append(out.FreshOKIDs, ef.Finding.ID)
		}
		if errMsg != "" {
			out.Errors = append(out.Errors, errMsg)
		}
	}
	return out
}

// runAllPanicHookForTest, when non-nil, is invoked exactly once per RunAll
// call, immediately after setup (maxPerScan resolution) and BEFORE the
// sort/slice-copy step — the only seam a test can use to force a panic in
// RunAll's OWN body (as opposed to inside one finding's processOne, which
// panickingClient already covers) and prove the top-level defer/recover above
// actually catches it. Always nil in production.
var runAllPanicHookForTest func()

// processOne handles exactly one finding under a panic guard: any panic
// during evidence assembly, prompt building, or record write converts to a
// degraded record rather than propagating (crashing the scan). modelCallAttempted
// tracks whether the panic happened during/after the actual model call (an
// honest StatusAbsentModelError) or strictly BEFORE it — evidence assembly,
// prompt building — which is inquest's OWN bug and must never be mislabeled
// as a model failure (StatusAbsentInternalError instead; review finding 3a).
// priorCreatedAt/havePriorCreatedAt are captured from the pre-panic
// existing-record read (below) so the panic-guard fallback record preserves a
// known CreatedAt rather than resetting it to now() (review finding 3b).
func processOne(ctx context.Context, in Input, ef EscalatedFinding, maxPerScan int, callsUsed *int, touchedThisRun map[string]bool) (investigated, degraded, skipped int, errMsg string) {
	var modelCallAttempted bool
	var priorCreatedAt string
	var havePriorCreatedAt bool
	var priorFindingIDs []string

	key := ef.RecordKey()
	// sameScanPriorWrite is true when an EARLIER finding in THIS SAME RunAll
	// call already wrote to key — see touchedThisRun's doc comment (RunAll)
	// and the verdict-comparison use below (mallcoppro-42e review fix: an
	// intra-scan disagreement between co-occurring findings is never a
	// "flip", since nothing changed over time). Computed BEFORE marking
	// touched below, so it reflects state as of the START of this finding's
	// processing, not this finding's own write.
	sameScanPriorWrite := touchedThisRun[key]
	touchedThisRun[key] = true

	defer func() {
		if r := recover(); r != nil {
			errMsg = appendErr(errMsg, fmt.Sprintf("inquest: panic investigating %s: %v", ef.Finding.ID, r))
			status := StatusAbsentInternalError
			if modelCallAttempted {
				status = StatusAbsentModelError
			}
			// Best-effort: still write a minimal degraded record so the
			// operator sees SOMETHING rather than silence. A second panic here
			// (this only marshals/writes a small struct) is swallowed — it
			// must never escape and abort the scan.
			func() {
				defer func() { _ = recover() }()
				rec := minimalDegradedRecord(ef, in.MallcopVersion, status)
				if havePriorCreatedAt {
					rec.CreatedAt = priorCreatedAt
					rec.InvestigatedFindingIDs = priorFindingIDs
				}
				_, _ = writeRecord(in.Store, key, rec)
			}()
			degraded = 1
		}
	}()

	existing, found, rerr := readExistingRecord(in.Store, key)
	if rerr != nil {
		// Transient read error (e.g. a git-pull/read hiccup) — existing may
		// hold a perfectly good record we simply can't verify right now.
		// SKIP this finding for THIS scan entirely: no assembly, no metered
		// call, no write. Burning a call and resetting CreatedAt on a finding
		// that may already have a good record would be worse than doing
		// nothing; the next scan retries the read. Never invent a success.
		return 0, 1, 0, appendErr(errMsg, fmt.Sprintf("inquest: read existing record for %s: %v — skipped this scan (no call, no write) to protect budget and CreatedAt", ef.Finding.ID, rerr))
	}
	if found {
		priorCreatedAt = existing.CreatedAt
		havePriorCreatedAt = true
		priorFindingIDs = existing.InvestigatedFindingIDs
	}
	// The ok-skip must be scoped to THIS finding, PER FINDING — not just to
	// "the last write to this case record" (mallcoppro-42e review fix: BUG
	// 1). Under case-keying, several DISTINCT findings can share one case
	// and each independently, genuinely need investigating the first time
	// they're seen; a true RE-RUN of any ONE of them (the scan retried, or
	// the same finding handed to RunAll twice) must still cost zero calls,
	// even though it is no longer the LAST finding to have written this
	// shared record. existing.FindingID == ef.Finding.ID (true whenever
	// THIS finding was the most recent contributor) is kept as the exact
	// pre-42e check for backward compatibility with a record written before
	// InvestigatedFindingIDs existed; existing.InvestigatedFindingIDs
	// containing this finding's ID is the per-finding membership check that
	// covers every other case-keyed re-run. For the CaseID=="" fallback,
	// InvestigatedFindingIDs (once populated) holds exactly the one ID this
	// keying ever sees, so the two checks agree and nothing changes there.
	alreadyInvestigated := existing.FindingID == ef.Finding.ID || containsString(existing.InvestigatedFindingIDs, ef.Finding.ID)
	if !in.Force && found && existing.SchemaVersion == SchemaVersion && existing.NarrativeStatus == StatusOK && alreadyInvestigated {
		return 0, 0, 1, errMsg
	}

	if processOnePanicHookForTest != nil {
		processOnePanicHookForTest(ef.Finding.ID)
	}
	ev := assemble(in.Store, in.AllEvents, in.Baseline, ef, in.Config)
	// Case-keyed recurrence continuity (mallcoppro-42e): assembleRecurrence's
	// own per-(actor,type) prior-finding scan reads recordPath(priorFindingID)
	// for EACH historically co-occurring finding — a lookup that only ever
	// resolved anything back when every record lived at its own finding's
	// path. Under case-keying, a case's own history now lives at ONE shared
	// path (this case's), so that scan silently finds nothing for any prior
	// finding sharing this case (the file that WAS at its finding-ID path is
	// gone — superseded by the shared record). The one piece of continuity
	// that actually matters — "what did this SAME case's last investigation
	// conclude" — is exactly what `existing` (read above, before this pass
	// overwrites it) already holds, so it is appended here as the most
	// RECENT prior investigation, restoring the "reference-and-refresh,
	// never contradict" guarantee the narrate prompt depends on
	// (assemble.go's PriorInvestigation doc) without a second clustering
	// pass or a broader assemble.go signature change.
	if found && existing.NarrativeStatus == StatusOK {
		ev.Recurrence.PriorInvestigations = append(ev.Recurrence.PriorInvestigations, PriorInvestigation{
			FindingID:  existing.FindingID,
			Verdict:    string(existing.Verdict),
			Confidence: existing.Confidence,
			UpdatedAt:  existing.UpdatedAt,
		})
	}

	rec := Record{
		SchemaVersion:  SchemaVersion,
		FindingID:      ef.Finding.ID,
		CaseID:         ef.CaseID,
		EventID:        underlyingEventID(ef.Finding.ID),
		MallcopVersion: in.MallcopVersion,
		CreatedAt:      nowRFC3339(),
		UpdatedAt:      nowRFC3339(),
		Role:           "evidence",
		Resolution:     ef.Resolution,
		Verdict:        VerdictUnassessed,
		Evidence:       ev,
	}
	if found {
		rec.CreatedAt = existing.CreatedAt           // preserve on refresh
		rec.InvestigatedFindingIDs = priorFindingIDs // carry forward membership; appended to below only on a fresh ok landing
	}

	switch {
	case in.Client == nil:
		rec.NarrativeStatus = StatusAbsentNoClient
		degraded = 1
	case *callsUsed >= maxPerScan:
		rec.NarrativeStatus = StatusAbsentBudget
		degraded = 1
	default:
		userDoc, buildErr := buildUserMessage(ef.Finding, ef.Resolution, ev)
		if buildErr != nil {
			rec.NarrativeStatus = StatusAbsentInvalidOutput
			degraded = 1
			errMsg = appendErr(errMsg, fmt.Sprintf("inquest: build prompt for %s: %v", ef.Finding.ID, buildErr))
			break
		}
		*callsUsed++
		timeout := in.Config.CallTimeout
		if timeout <= 0 {
			timeout = defaultModelCallTimeout
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		modelCallAttempted = true // from here on, a panic is an honest model-error, not inquest's own bug
		res := narrate(callCtx, in.Client, in.Config.Model, in.Config.MaxTokens, userDoc, ev)
		cancel()

		rec.NarrativeStatus = res.Status
		rec.Model = res.Model
		rec.Usage = res.Usage
		if res.Status == StatusOK {
			rec.Verdict = res.Verdict
			rec.Confidence = res.Confidence
			rec.Narrative = res.Narrative
			rec.ContractNotes = res.ContractNotes
			investigated = 1
			// Per-finding membership (mallcoppro-42e review fix, BUG 1): this
			// finding just landed a trusted pass, so it joins the set the
			// idempotency skip checks against — see the skip's doc comment
			// above.
			rec.InvestigatedFindingIDs = appendUniqueFindingID(rec.InvestigatedFindingIDs, ef.Finding.ID, maxTrackedFindingIDs)

			// Verdict-change detection (mallcoppro-42e): the ONLY prior
			// verdict worth comparing against is one this package itself
			// already trusted (found, current-ish record, StatusOK, a REAL
			// verdict — never VerdictUnassessed, which never represents a
			// trusted assessment). A DIFFERENT trusted verdict must never
			// average or silently supersede the prior one: it WRITES the
			// fresh verdict (already done, above) and FLAGS the change
			// in-band in the narrative — but WHICH flag depends on WHEN the
			// prior verdict was written (review fix, BUG 2):
			//
			//   - sameScanPriorWrite (the existing record was written
			//     EARLIER IN THIS SAME RunAll call, by a co-occurring
			//     finding sharing this case): nothing changed over TIME —
			//     two findings that happened to land in the same scan simply
			//     disagreed. This is CoOccurringVerdict, never VerdictFlip.
			//   - otherwise: existing predates this RunAll call (a genuine
			//     refire, possibly scans apart, or none at all if !found).
			//     A differing trusted verdict here IS a flip.
			if found && existing.NarrativeStatus == StatusOK && existing.Verdict != VerdictUnassessed && existing.Verdict != rec.Verdict {
				if sameScanPriorWrite {
					rec.CoOccurringVerdict = &VerdictFlip{From: existing.Verdict, To: rec.Verdict}
					rec.Narrative = fmt.Sprintf("[CO-OCCURRING VERDICTS THIS SCAN: %s -> %s] %s", existing.Verdict, rec.Verdict, rec.Narrative)
				} else {
					rec.VerdictFlip = &VerdictFlip{From: existing.Verdict, To: rec.Verdict}
					rec.Narrative = fmt.Sprintf("[VERDICT FLIP: %s -> %s] %s", existing.Verdict, rec.Verdict, rec.Narrative)
				}
			}
		} else {
			degraded = 1
			if res.Err != nil {
				errMsg = appendErr(errMsg, fmt.Sprintf("inquest: narrate %s: %v", ef.Finding.ID, res.Err))
			}
		}
	}

	if in.Force && found && existing.NarrativeStatus == StatusOK && rec.NarrativeStatus != StatusOK {
		// A Force re-pass (the low-confidence deeper-investigation retrigger,
		// mallcoppro-09a) that itself failed to land a fresh "ok" verdict —
		// deep budget exhausted, model error/timeout, invalid output — must
		// NEVER overwrite the prior good record. The customer-facing surface
		// reads Verdict/Confidence/Narrative straight from the persisted
		// record; downgrading a benign/confident "ok" to absent-budget/
		// unassessed would ship WORSE copy than leaving the record alone.
		// Keep the existing ok record untouched: no write, budget/CreatedAt
		// unaffected. Tallied as Degraded (not Skipped) so the operator sees
		// the failed re-pass rather than silence — same precedent as the
		// transient-read-error path above.
		return 0, 1, 0, appendErr(errMsg, fmt.Sprintf("inquest: force re-pass for %s did not reach ok (status=%s) — kept prior ok record, no overwrite", ef.Finding.ID, rec.NarrativeStatus))
	}

	if _, werr := writeRecord(in.Store, key, rec); werr != nil {
		errMsg = appendErr(errMsg, fmt.Sprintf("inquest: write record for %s: %v", ef.Finding.ID, werr))
		if investigated == 1 {
			// The fresh "ok" verdict never persisted — the on-disk record is
			// UNCHANGED (still the prior/first-pass record, or absent). A failed
			// write must never be reported as a landed fresh investigation:
			// RunAll keys FreshOKIDs off investigated==1, and the low-confidence
			// re-vote (mallcoppro-09a) uses that set to conclude a genuine deeper
			// verdict exists. Re-voting on the stale on-disk record would
			// misrepresent first-pass evidence as a deeper pass. Downgrade to
			// Degraded so the operator sees the failed attempt, not silence.
			investigated, degraded = 0, 1
		}
	}
	return investigated, degraded, 0, errMsg
}

// processOnePanicHookForTest, when non-nil, is invoked once per finding
// immediately BEFORE evidence assembly (strictly before any model call could
// ever be attempted) — the seam a test uses to force an assembly-time panic
// and prove it gets the honest StatusAbsentInternalError label (never
// StatusAbsentModelError) and preserves a known prior CreatedAt. Always nil
// in production.
var processOnePanicHookForTest func(findingID string)

// recordPath is the store path an investigation record lives at, keyed by
// key — a CaseID (mallcoppro-42e's case-keyed recurrence design) or, for any
// caller that hasn't resolved one, a bare finding ID (the pre-42e per-finding
// keying, preserved exactly as the fallback — see EscalatedFinding.RecordKey).
func recordPath(key string) string {
	return "investigations/" + key + ".json"
}

// readExistingRecord reads back the current record at key's path, if any.
func readExistingRecord(st *store.Store, key string) (Record, bool, error) {
	data, err := st.ReadSnapshot(recordPath(key))
	if err != nil {
		return Record{}, false, err
	}
	if len(data) == 0 {
		return Record{}, false, nil
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

// writeRecord applies the record size cap and commits rec at key's path via
// WriteSnapshot (a full-document replace, CAS-retried, byte-identical no-op —
// a refresh that changes nothing costs no commit). key is the caller's
// resolved record identity (EscalatedFinding.RecordKey() — a CaseID when the
// caller has one, else the finding's own ID; mallcoppro-42e) — NOT
// necessarily rec.FindingID, which (on a case-keyed record) is just the MOST
// RECENT contributing finding, not the record's path.
func writeRecord(st *store.Store, key string, rec Record) (string, error) {
	rec, _, err := enforceRecordSizeCap(rec)
	if err != nil {
		return "", err
	}
	return st.WriteSnapshot(recordPath(key), rec)
}

// minimalDegradedRecord builds the smallest valid Record for the panic-guard
// fallback write: no evidence (assembly itself may be what panicked), an
// honest degraded status (StatusAbsentInternalError for a panic before the
// model call was attempted, StatusAbsentModelError for one during/after —
// see processOne's modelCallAttempted). CreatedAt defaults to now() here
// (the "brand new record" case); the caller overwrites it with a known prior
// CreatedAt when processOne captured one before the panic, so a refresh never
// silently resets it.
func minimalDegradedRecord(ef EscalatedFinding, mallcopVersion string, status NarrativeStatus) Record {
	now := nowRFC3339()
	return Record{
		SchemaVersion:   SchemaVersion,
		FindingID:       ef.Finding.ID,
		CaseID:          ef.CaseID,
		EventID:         underlyingEventID(ef.Finding.ID),
		MallcopVersion:  mallcopVersion,
		CreatedAt:       now,
		UpdatedAt:       now,
		Role:            "evidence",
		Resolution:      ef.Resolution,
		Verdict:         VerdictUnassessed,
		NarrativeStatus: status,
	}
}

// underlyingEventID is a BEST-EFFORT provenance stamp only — identity
// assembly resolves the real underlying event via tools.GetRawEvent (which
// applies the full "finding-" leniency itself); this is not used for any
// lookup. Finding ids are "finding-"+event.ID, optionally with a
// "-"+createdEntity suffix (core/detect/new_actor.go) — stripping only the
// "finding-" prefix is exact for the common case and a documented
// approximation for the suffixed one.
func underlyingEventID(findingID string) string {
	return strings.TrimPrefix(findingID, "finding-")
}

// containsString reports whether s is present in ss.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// appendUniqueFindingID appends id to ids unless it is already present,
// capping the result at maxLen via FIFO (oldest dropped first) — see
// Record.InvestigatedFindingIDs's doc comment. A no-op re-add (id already a
// member) returns ids unchanged rather than growing/reordering it, so a
// finding that lands "ok" more than once (e.g. a Force deeper pass over a
// finding whose first pass already added it) never duplicates its own entry.
func appendUniqueFindingID(ids []string, id string, maxLen int) []string {
	for _, v := range ids {
		if v == id {
			return ids
		}
	}
	out := append(append([]string(nil), ids...), id)
	if len(out) > maxLen {
		out = out[len(out)-maxLen:]
	}
	return out
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// appendErr chains a new message onto an existing one (used when BOTH the
// existing-record read AND the processing step produce a warning for the same
// finding), separated by "; ".
func appendErr(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}
