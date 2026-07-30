// Package pipeline is the ORCHESTRATOR that assembles the four core seams into
// one agentic scan cycle:
//
//	core/connect  →  core/detect  →  core/agent (cascade)  →  core/store
//	  (Pull)          (Detect)        (ResolveFinding)         (Append)
//
// Run is the single entry point. It pulls events through a Connector, runs the
// deterministic detector floor, then resolves EACH finding through the tiered
// triage→investigate→escalate cascade (core/agent.ResolveFindingWith), and
// durably appends both the findings and their resolutions to the git-backed
// store. It returns a Summary of what happened.
//
// CONCURRENCY: findings are resolved through a bounded worker pool (Config.Workers,
// default modest). This is safe because the two shared collaborators are
// concurrency-safe by construction:
//
//   - the inference client (core/agent.Client, in practice inference.DirectClient)
//     is a stateless net/http POSTer — every Messages call builds its own request;
//     there is no shared mutable state, so N goroutines may call it at once.
//   - the store serializes every Append behind its per-repo Serializer lock and a
//     git compare-and-swap, so concurrent appends linearize with no lost write.
//
// The pipeline adds NOTHING to that floor: it never bypasses the cascade (the
// untrusted-data handling, the hard-constraint floor, the structural gate, and
// the fail-safe all live INSIDE ResolveFindingWith — the pipeline calls it and
// honors whatever it returns). A finding the floor force-escalates never reaches
// the model; a finding the cascade escalates is recorded as escalated; the
// pipeline cannot and does not re-decide.
//
// IMPORT DISCIPLINE: this package imports core/connect, core/detect, core/agent,
// core/store, and pkg/* — and NOTHING that talks to a model directly. It reaches
// inference ONLY through the core/agent.Client interface threaded in by the
// caller (the cmd layer hands it an inference.DirectClient). The core import-lint
// (core/lint) and this package's imports_test.go forbid any framework / transport
// / vendor-SDK import here.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/cases"
	"github.com/mallcop-app/mallcop/core/connect"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/inquest"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// defaultWorkers is the bounded resolve-pool size when Config.Workers <= 0. Modest
// on purpose: per-finding cost is dominated by model latency (real backend) or is
// near-instant (canned backend), so a small pool keeps memory + connection
// pressure low while still overlapping the per-finding model round-trips.
const defaultWorkers = 4

// defaultMaxFindingsForActors is the volume circuit-breaker ceiling applied when
// Config.Budget.MaxFindingsForActors <= 0. A run whose detector floor produces
// strictly MORE findings than this trips the breaker (agent.CheckCircuitBreaker),
// which appends a synthetic critical meta-finding that force-escalates to a human.
// It mirrors src/mallcop/budget.py BudgetConfig.max_findings_for_actors (= 25) —
// the legacy default, kept in exactly one place so the flag/env only OVERRIDE it.
const defaultMaxFindingsForActors = 25

// Config is the immutable input to one Run. The {Client, ...} the pipeline needs
// are injected — the pipeline constructs none of them, so the import-lint floor
// holds (no inference, no transport built here).
type Config struct {
	// Connector is the event source (FILE/STDIN by default; a cloud connector in a
	// later wave). Required.
	Connector connect.Connector

	// Client is the inference seam the cascade reaches the model through. A nil
	// Client makes EVERY finding fail safe to escalate (the cascade's documented
	// nil-client behavior) — a scan still runs and records escalations, it just
	// never resolves anything benign. Typically an *inference.DirectClient.
	Client agent.Client

	// Store is the git-backed sink for findings + resolutions. Required: a scan
	// with nowhere to durably write its output is a misconfiguration, not a
	// silent no-op.
	Store *store.Store

	// Baseline supplies historical context to the baseline-dependent detectors
	// (new-actor, priv-escalation, unusual-login, …). Nil is treated as an empty
	// baseline (content-only detectors still fire).
	Baseline *baseline.Baseline

	// Cascade carries the model tiers + (optional) live tools for ResolveFindingWith.
	// The zero value uses the cascade's documented defaults and no live tools.
	Cascade agent.CascadeOptions

	// Workers bounds the concurrent resolve pool. <= 0 uses defaultWorkers. The
	// pool never exceeds the number of findings.
	Workers int

	// Budget carries the volume circuit-breaker ceiling (MaxFindingsForActors).
	// A run whose (post-suppression) detector floor produces strictly MORE
	// findings than the ceiling trips the breaker: a synthetic critical
	// meta-finding (family "mallcop-budget") is appended to the finding set and
	// force-escalated to a human via the seeded E-006 route (see Run). The zero
	// value applies defaultMaxFindingsForActors — the caller only sets this to
	// OVERRIDE the default (scan.go threads a --max-findings flag through here).
	Budget agent.BudgetConfig

	// Investigate is the resolved investigate: config for detection-time
	// investigation (mallcoppro-e3c, core/inquest). The zero value has
	// Enabled==false — a caller that wants the config-driven default (ON) must
	// resolve core/config.Investigate onto this struct itself (cli/scan.go
	// does this via config.LoadEffective, which always returns a
	// Defaults()-floored Config regardless of whether a mallcop.yaml is
	// present). Existing callers that construct Config{} directly (tests,
	// other embedders) get investigate OFF by default, unaffected by this
	// addition.
	Investigate inquest.Config

	// MallcopVersion is a best-effort provenance stamp threaded onto both the
	// KindScans register and investigation records. Empty when unknown —
	// never fabricated.
	MallcopVersion string
}

// Summary is the result of one completed scan cycle. The four counts answer the
// operator's questions: how much did we look at, how much did we flag, how much
// did the agent close on its own, and how much needs a human.
//
// Invariant: Resolved + Escalated == FindingsDetected (every finding terminates
// in exactly one of the two dispositions — the cascade has no third outcome).
type Summary struct {
	// EventsScanned is the number of events the detector floor actually
	// evaluated this scan — i.e. the connector's pull count MINUS any events
	// dropped by the ID-based dedupe (see DuplicatesSkipped) because they were
	// already committed by an earlier scan, or repeated within this same pull.
	// A connector without a durable pull cursor (azure, github) can re-pull an
	// overlapping window every scan; EventsScanned reflects only the NEW events
	// this scan processed, not the raw pull size.
	EventsScanned int `json:"events_scanned"`
	// FindingsDetected is the number of findings the detector floor produced.
	FindingsDetected int `json:"findings_detected"`
	// Resolved is the number of findings the cascade closed as benign
	// (ActionProceed) — agent-handled, no human needed.
	Resolved int `json:"resolved"`
	// Escalated is the number of findings the cascade routed to a human
	// (ActionEscalated), whether by the pre-LLM floor or a tier verdict.
	Escalated int `json:"escalated"`
	// DuplicatesSkipped is the number of pulled events dropped by the dedupe:
	// events whose ID already exists in the store's committed KindEvents
	// stream, plus any repeat IDs within this scan's own pulled batch. Omitted
	// from the JSON encoding when zero (the common case: a connector with a
	// durable cursor never re-pulls).
	DuplicatesSkipped int `json:"duplicates_skipped,omitempty"`
	// Investigated is the number of ESCALATED findings this scan produced a
	// successful (narrative_status "ok") detection-time investigation record
	// for (mallcoppro-e3c, core/inquest). Omitted when zero.
	Investigated int `json:"investigated,omitempty"`
	// InvestigationsDegraded is the number of escalated findings whose
	// investigation record this scan wrote (or refreshed) with a non-"ok"
	// narrative_status — the deterministic evidence chain still shipped, only
	// the model narrative degraded. Omitted when zero.
	InvestigationsDegraded int `json:"investigations_degraded,omitempty"`
	// LowConfidenceRevotes is the number of escalated findings whose "ok" but
	// low-confidence detection-time investigation this scan put to a committee
	// re-vote after a deeper investigation pass (mallcoppro-09a). Omitted when
	// zero.
	LowConfidenceRevotes int `json:"low_confidence_revotes,omitempty"`
	// RevoteDeescalations is how many of those re-votes came back a UNANIMOUS
	// resolve — the committee, re-weighing the deeper evidence, agreed the
	// finding is benign. The escalate disposition STILL stands in the audit
	// trail (the re-vote is a second opinion for the presentation layer, never a
	// re-resolution); this counts how many escalations a customer-facing surface
	// may frame as investigated-benign rather than action-required. Omitted when
	// zero.
	RevoteDeescalations int `json:"revote_deescalations,omitempty"`
	// InvestigationWarnings carries one human-readable line per degraded/failed
	// investigation record this scan produced (inquest.Outcome.Errors),
	// entirely for the CLI's own non-fatal stderr reporting — excluded from the
	// JSON summary (it is operational noise, not part of the machine-readable
	// contract; the same pattern as the gated Discord-emit warning in
	// cli/scan.go).
	InvestigationWarnings []string `json:"-"`
	// Duration is the wall-clock time the whole Run took, for latency reporting.
	Duration time.Duration `json:"duration_ms"`
}

// resolved is one finding paired with its cascade resolution, carried out of a
// worker goroutine so the store writes and counting happen on the main goroutine
// in a deterministic order (sorted by finding ID) — the store linearizes anyway,
// but ordering the writes keeps the on-disk log reproducible for a fixed input.
type resolved struct {
	finding    finding.Finding
	resolution agent.Resolution
}

// Run executes one scan cycle and returns its Summary. The order is load-bearing
// and mirrors the architecture topology exactly:
//
//  1. CONNECT: cfg.Connector.Pull(ctx) — pull the normalized event batch. A pull
//     error aborts the scan (we will not detect over a partial/corrupt source).
//  2. DETECT: detect.Detect(events, baseline) — the deterministic floor. No
//     inference key, no network. Findings are appended to the store FIRST so the
//     durable record of "what we flagged" exists even if a later resolve panics
//     or the process is killed mid-scan.
//  3. RESOLVE: for each finding, agent.ResolveFindingWith(ctx, client, f, opts)
//     through a bounded worker pool. The cascade owns the hard-constraint floor,
//     the untrusted-data boxing, the structural gate, and the fail-safe — the
//     pipeline does not reach around any of it.
//  4. STORE: each resolution is appended to the store as a pkg/resolution.Resolution
//     so the notification binaries and the git audit trail see a uniform record.
//
// Run is safe to call once per Config. A non-nil error means the scan could not
// complete (connector, detector-input, or a store write failed); a nil error with
// a Summary means the scan completed and the counts are authoritative. Either
// way (mallcoppro-24e), Run appends exactly one store.ScanRecord before
// returning — Success=true on the nil-error path, Success=false with
// FailedStage/Error populated on every error path, including a connector Pull
// failure. The store never goes dark on a failed scan.
//
// Run uses NAMED returns (summary, err) so the deferred recordScan call below
// can see whatever value the function is actually returning at each of its
// many early-return sites, without every one of them needing to be rewritten
// to also append a ScanRecord (mallcoppro-24e). See the defer immediately
// after the Connector/Store nil guards for the mechanism.
func Run(ctx context.Context, cfg Config) (summary Summary, err error) {
	start := time.Now()

	if cfg.Connector == nil {
		return Summary{}, fmt.Errorf("pipeline: nil Connector")
	}
	if cfg.Store == nil {
		return Summary{}, fmt.Errorf("pipeline: nil Store")
	}

	// stage names the pipeline phase in flight. It advances ONLY after a
	// phase's fallible step succeeds, so at any early return its value is
	// exactly the phase that was running when the error fired — recordScan
	// (deferred below) uses it to fill ScanRecord.FailedStage. It is
	// meaningless on the success path (recordScan clears FailedStage whenever
	// err is nil), so no discipline is needed advancing it past the last
	// fallible step.
	stage := "connect"

	// mallcoppro-24e (design §5, the reinforcing bug): a connector Pull
	// failure used to return at this point BEFORE recordScan ever fired, so
	// a 403-on-connect left NO ScanRecord at all — the store went dark
	// exactly when the liveness watchdog needed the signal. Deferring the
	// append here means EVERY return from Run — success or any of the many
	// error returns below — commits exactly one ScanRecord. cfg.Store is
	// already validated non-nil above, so the handle is safe to use no
	// matter which stage fails.
	defer func() {
		if rerr := recordScan(cfg, summary, start, stage, err); rerr != nil {
			// recordScan's own doc comment treats a write failure here as a
			// hard error like any other store append in Run. If Run was
			// otherwise succeeding, that failure becomes Run's error; if Run
			// was already failing, the original failure is more actionable,
			// so the record failure is folded in for legibility rather than
			// replacing it.
			if err == nil {
				err = rerr
				summary = Summary{}
			} else {
				err = fmt.Errorf("%w (additionally failed to record scan: %v)", err, rerr)
			}
		}
	}()

	// (1) CONNECT.
	events, connErr := cfg.Connector.Pull(ctx)
	if connErr != nil {
		// mallcoppro-d3f (Design §Gap D wiring): a Pull failure used to dead-end
		// here as a raw, uninterpreted error — nothing durable recorded WHY, and
		// no path for the operator to act on an unclassified failure short of
		// reading logs. If the connector can self-diagnose, record what it found
		// onto the SAME spine the rest of the store already steers from,
		// instead — never replacing or masking connErr, which remains Run's
		// error either way (a diagnosis, known or not, never turns a genuine
		// connect failure into a successful scan).
		err = fmt.Errorf("pipeline: connect: %w", connErr)
		if derr := recordConnectorDiagnosis(ctx, cfg.Store, cfg.Connector); derr != nil {
			err = fmt.Errorf("%w (additionally failed to record connector diagnosis: %v)", err, derr)
		}
		return Summary{}, err
	}

	// mallcoppro-d3f (veracity rework, Route 2): a SUCCESSFUL Pull is the
	// scan's own signal that whatever the connector was diagnosed as missing
	// last time might now be fixed — this is the REAL production caller of
	// RecordConfirmOutcome (route 2's write half) and the REAL reader of the
	// grants stream (route 2's read half, pendingGrantMiss), so the loop this
	// item exists to close is provably driven from cli/scan.go's actual
	// path, not only exercised by a test calling RecordConfirmOutcome
	// directly. confirmResolvedGrants costs nothing beyond one cheap store
	// read per Diagnosable connector unless that connector genuinely has an
	// outstanding, unresolved miss to re-probe.
	stage = "confirm_grants"
	if err := confirmResolvedGrants(ctx, cfg.Store, cfg.Connector); err != nil {
		return Summary{}, fmt.Errorf("pipeline: confirm grant resolution: %w", err)
	}
	stage = "baseline"

	// (1a) DERIVE THE BASELINE FROM PRIOR HISTORY — the idempotency keystone.
	// Read the store's ALREADY-committed events (everything earlier scans saw)
	// BEFORE appending THIS scan's batch below, then derive the baseline the
	// baseline-dependent detectors gate on. The ordering is load-bearing: an actor
	// or pattern first seen in THIS scan must NOT already be in the baseline (it is
	// investigated exactly once — now), so the prior-events read MUST precede the
	// KindEvents append. An explicit Config.Baseline (the eval/academy pre-built
	// corpus, or a --baseline file) ALWAYS wins — the derived baseline is used only
	// when none was supplied, so the explicit-override path is unchanged. On the
	// first scan the store holds no prior events → an empty baseline → every actor
	// fires (correct). This is the fix for the steady-state re-investigation cost
	// bug: without it cfg.Baseline was nil, detect saw an EMPTY baseline, and
	// new-actor re-flagged (and the cascade re-charged inference for) every actor on
	// every scan.
	//
	// This SAME prior-events read also feeds the DEDUPE below (a second, load-
	// bearing reason the ordering must not move): a connector without a durable
	// pull cursor (azure, github) can re-pull events its OWN earlier scan already
	// committed, and without a dedupe the events stream only grows — regrowing
	// exactly the O(N * filesize) commit-churn problem AppendBatch fixes on the
	// write side. On the derived-baseline path (bl == nil) priorEvents is already
	// being loaded for baseline.Build, so the dedupe ID set reuses that EXACT
	// slice — zero extra I/O. On the explicit-Config.Baseline path priorEvents is
	// NOT otherwise loaded (the explicit baseline needs no history), so we load it
	// here purely to build the dedupe ID set; it is never fed to baseline.Build in
	// that branch.
	bl := cfg.Baseline
	derived := false
	var priorEvents []event.Event
	if bl == nil {
		var perr error
		priorEvents, perr = loadPriorEvents(cfg.Store)
		if perr != nil {
			return Summary{}, fmt.Errorf("pipeline: load prior events for baseline: %w", perr)
		}
		fresh := baseline.Build(priorEvents)

		// STORE-ROTATION SURVIVAL (mallcoppro-9e2): merge in the LAST persisted
		// KindBaseline snapshot before gating. An operational store rotation
		// (mallcoppro-ee3: the events stream is archived and truncated to bound git
		// blob churn) empties priorEvents WITHOUT touching the separately persisted
		// KindBaseline stream — so `fresh` alone would forget every actor/hour/role
		// this system already investigated and re-fire on all of them. Baseline.Merge
		// unions the two (MAX on counts, so a normal non-rotated scan — where fresh is
		// already a superset — is unaffected; see Merge's doc comment). A store that
		// was never scanned in derive mode has no persisted snapshot, so
		// lastPersisted is nil and the merge is a no-op.
		lastPersisted, perr := loadPersistedBaseline(cfg.Store)
		if perr != nil {
			return Summary{}, fmt.Errorf("pipeline: load persisted baseline: %w", perr)
		}
		bl = lastPersisted.Merge(fresh)
		derived = true
	} else {
		var perr error
		priorEvents, perr = loadPriorEvents(cfg.Store)
		if perr != nil {
			return Summary{}, fmt.Errorf("pipeline: load prior events for dedupe: %w", perr)
		}
	}

	// DEDUPE-ON-APPEND (mallcoppro-ee3): drop every pulled event whose ID already
	// exists in the store's committed KindEvents stream (priorEvents, read above
	// — BEFORE this scan's batch is appended), and collapse duplicate IDs WITHIN
	// the pulled batch itself (keep the first). An event with an EMPTY ID is
	// NEVER dropped — an empty-string ID is not an identity, and a connector or
	// test fixture that never assigns one must not have its events silently
	// discarded. detect MUST see this DEDUPED slice (not the raw pull), so a
	// re-pulled duplicate is neither re-detected nor re-appended.
	var duplicatesSkipped int
	events, duplicatesSkipped = dedupeEvents(events, priorEvents)

	stage = "store_events"
	// Append every (deduped) pulled event to the durable store, in ONE commit
	// instead of one commit per event, so the scan's input corpus is itself
	// reconstructable from the git log (the store is the one brain) without
	// paying a per-event commit's whole-file re-hash cost (see
	// store.AppendBatch's doc comment). This runs AFTER the prior-events read
	// above so this scan's events never baseline (or dedupe) themselves.
	if len(events) > 0 {
		batch := make([]any, len(events))
		for i := range events {
			batch[i] = events[i]
		}
		if _, err := cfg.Store.AppendBatch(store.KindEvents, batch); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store events batch: %w", err)
		}
	}

	// (2) DETECT — deterministic, offline. Gated on the baseline derived from prior
	// history (or the explicit override), so a KNOWN actor/pattern is not re-detected
	// on a steady-state re-scan, while a genuinely new actor/pattern still fires once.
	findings := detect.Detect(events, bl)

	// BACKSTOP (mallcoppro-323): see backstopEventIDs's doc comment.
	findings = backstopEventIDs(findings)

	// Persist the DERIVED baseline as a KindBaseline snapshot: it is otherwise
	// ephemeral (built in-memory each scan), so recording it makes it observable in
	// the git log, portable (a fresh clone reconstructs it), and loadable by the
	// investigate path so check-baseline can see the same baseline the scan gated on.
	// Only the derived baseline is persisted — an explicit Config.Baseline is already
	// a durable file, and re-appending it would only add noise to the eval/academy
	// path. Append (not overwrite): KindBaseline is the append-only history stream.
	stage = "store_baseline_snapshot"
	if derived {
		if _, err := cfg.Store.Append(store.KindBaseline, bl); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store baseline snapshot: %w", err)
		}
	}

	// OPERATOR FEEDBACK: replay the directives stream and DROP any finding an
	// operator has suppressed (via `mallcop feedback <id> dismiss`). This is the
	// keystone that makes persisted feedback honored by the NEXT scan: without
	// it the directives stream is inert. The drop happens BEFORE the
	// findings-append below, so a suppressed finding is neither recorded nor
	// resolved — the operator's decision persists and the next scan obeys it.
	stage = "load_directives"
	directives, err := cfg.Store.LoadDirectives()
	if err != nil {
		return Summary{}, fmt.Errorf("pipeline: load directives: %w", err)
	}
	findings = applyDirectives(findings, directives)

	// CASE-SCOPED SUPPRESSION (mallcoppro-419): applyDirectives above matches
	// on the coarser "<source>/<type>/<actor>" finding key (Entity dropped),
	// so a 'suppress' directive silences every sibling case sharing
	// type/actor regardless of entity. A 'suppress-case' directive names a
	// CaseID instead — exactly as narrow as the case the operator was shown
	// (core/pipeline/consumer_suppress_case.go) — and is applied here as a
	// SEPARATE filter, never folded into applyDirectives/matchPattern's
	// segment-glob contract. Order relative to applyDirectives does not
	// matter: each filter only removes findings, so applying both
	// (regardless of order) yields the same surviving set.
	findings = ApplySuppressCase(findings, directives)

	// VOLUME CIRCUIT BREAKER (L4 resource floor, ports src/mallcop/budget.py
	// check_circuit_breaker). A flood of findings — e.g. an attacker generating
	// noise to drown a single real boundary violation — must NOT be quietly
	// auto-handled. When the (post-suppression) finding count exceeds the budget
	// ceiling, CheckCircuitBreaker returns a synthetic CRITICAL meta-finding
	// (family "mallcop-budget"). We APPEND it to the finding set HERE, before the
	// count and the store-append below, so that:
	//   - it is counted in FindingsDetected (the Resolved+Escalated invariant holds),
	//   - it is durably stored like any other finding, and
	//   - it flows through the SAME resolve loop, where checkHardConstraints matches
	//     the seeded E-006 escalate_route and force-escalates it to a HUMAN with no
	//     model call. We do NOT merely log the trip: it becomes a first-class,
	//     escalated finding an operator sees. At or under the ceiling, nothing is
	//     appended (CheckCircuitBreaker returns nil).
	budget := cfg.Budget
	if budget.MaxFindingsForActors <= 0 {
		budget.MaxFindingsForActors = defaultMaxFindingsForActors
	}
	if mf := agent.CheckCircuitBreaker(findings, budget); mf != nil {
		findings = append(findings, *mf)
	}

	summary = Summary{
		EventsScanned:     len(events),
		FindingsDetected:  len(findings),
		DuplicatesSkipped: duplicatesSkipped,
	}

	// Gap C (mallcoppro-4da) / R9 FIX (mallcoppro-e38): apply any "severity"
	// directive's label override to a SEPARATE display copy — never to `findings`
	// itself. `findings` (original detector severity) is what gets threaded into
	// resolveAll below, so an operator's severity relabel can NEVER change which
	// tier/gate a finding routes through (core/agent/triagerisk.go's
	// triageResolveMustEscalate reads finding.Severity directly — feeding it the
	// override would silently flip the committee's escalate/quiet verdict, the
	// exact R9 violation mallcoppro-e38 fixed: the operator's annotation must
	// never feed back into the vote). displayFindings is used ONLY for what an
	// operator/the web chat SEES (the persisted findings batch + findings.json
	// snapshot below) — it never reaches resolveAll.
	displayFindings := defaultDirectiveDispatcher.ApplySeverityOverrides(findings, directives)

	// Persist the findings BEFORE resolving them, in ONE commit. The findings
	// stream is the durable record of "what the floor flagged"; it must survive
	// a crash during resolution. AppendBatch is the only path; the store
	// linearizes. Persists displayFindings (severity-overridden) so an operator's
	// relabel is visible in the durable record — this is a display artifact, not
	// resolve input (see the R9 note above `displayFindings`'s assignment).
	stage = "store_findings"
	if len(displayFindings) > 0 {
		batch := make([]any, len(displayFindings))
		for i := range displayFindings {
			batch[i] = displayFindings[i]
		}
		if _, err := cfg.Store.AppendBatch(store.KindFindings, batch); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store findings batch: %w", err)
		}
	}

	// Publish the browser-readable snapshot: the current, deduped, non-suppressed
	// findings as a single JSON document. The web chat reads this instead of the
	// append-only findings.jsonl, which accumulates history + suppressed records
	// across scans. Written on every scan (including the empty set, so a cleared
	// scan overwrites a stale snapshot). Uses displayFindings for the same reason
	// as the store batch above — the severity label an operator sees, never the
	// resolve input.
	stage = "write_findings_snapshot"
	if _, err := cfg.Store.WriteSnapshot("findings.json", displayFindings); err != nil {
		return Summary{}, fmt.Errorf("pipeline: write findings snapshot: %w", err)
	}

	if len(findings) == 0 {
		// The tail recordScan call this used to be lives in the deferred call
		// registered above now — every return from Run appends exactly one
		// ScanRecord, this early return included.
		summary.Duration = time.Since(start)
		return summary, nil
	}

	// (3) RESOLVE through a bounded worker pool. The cascade is the security floor;
	// the pool only parallelizes the per-finding model round-trips.
	stage = "resolve"
	results, err := resolveAll(ctx, cfg, findings)
	if err != nil {
		return Summary{}, err
	}
	stage = "store_resolutions"

	// (4) STORE resolutions + count. Build every resolution record and tally
	// Escalated/Resolved in the SAME deterministic finding-order loop as before,
	// then persist the whole set as ONE commit (instead of one commit per
	// resolution) — deterministic on-disk ordering for a fixed input is
	// unchanged; only the number of commits it costs to get there drops.
	resRecords := make([]any, len(results))
	for i, r := range results {
		resRecords[i] = toResolutionRecord(r.finding, r.resolution)
		if r.resolution.Action == agent.ActionEscalated {
			summary.Escalated++
		} else {
			summary.Resolved++
		}
	}
	if len(resRecords) > 0 {
		if _, err := cfg.Store.AppendBatch(store.KindResolutions, resRecords); err != nil {
			return Summary{}, fmt.Errorf("pipeline: store resolutions batch: %w", err)
		}
	}

	// (5) INVESTIGATE at detection time (mallcoppro-e3c), STRICTLY AFTER the
	// resolutions batch above has committed. This ordering is load-bearing for
	// the consensus invariant: by the time inquest.RunAll runs, every
	// disposition is already durably persisted, so an investigation
	// PHYSICALLY cannot change one — inquest has no write path to
	// findings/resolutions/directives/findings.json, only to
	// investigations/<case-id>.json (core/inquest's package doc; case-keyed
	// since mallcoppro-42e — see CaseID below). RunAll NEVER returns an error
	// this function propagates: a bug or model failure degrades one record,
	// it never aborts or delays the scan's core output.
	var escalated []inquest.EscalatedFinding
	for _, r := range results {
		if r.resolution.Action == agent.ActionEscalated {
			escalated = append(escalated, inquest.EscalatedFinding{
				Finding:    r.finding,
				Resolution: inquest.ResolutionRef{Action: "escalate", Reason: r.resolution.Reason},
				// CaseID (mallcoppro-42e): resolved via the EXPORTED
				// core/cases.CaseID — the SAME clustering hash
				// cli/cases.go's collapseCases (mallcoppro-554) feeds into
				// cases.Collapse for THIS EXACT (type, actor, entity) triple
				// (Actor is r.finding.Actor, not a resolution-carried field —
				// mirrors toResolutionRecord's own Actor source below). Never
				// re-derived independently: a second clustering path
				// computing its own notion of "the same case" is exactly the
				// drift bug this field exists to prevent.
				CaseID: cases.CaseID(cases.Key{
					Type:   r.finding.Type,
					Actor:  r.finding.Actor,
					Entity: cases.ExtractEntity(r.finding.Evidence),
				}),
			})
		}
	}
	if len(escalated) > 0 {
		allEvents := make([]event.Event, 0, len(priorEvents)+len(events))
		allEvents = append(allEvents, priorEvents...)
		allEvents = append(allEvents, events...)
		// Gap C (mallcoppro-4da): focus/watch-closer directives raise a
		// finding's attention weight, which RunAll consumes to spend its
		// (budget-limited) investigation calls on higher-attention findings
		// FIRST — the "watch-closer" half of the attention consumer. Built
		// from the SAME directive stream applyDirectives/ApplySeverityOverrides
		// already loaded above; a finding with no matching directive gets
		// weight 0 and keeps the pre-existing ID-only tiebreak order.
		escalatedFindings := make([]finding.Finding, len(escalated))
		for i, ef := range escalated {
			escalatedFindings[i] = ef.Finding
		}
		attentionWeights := defaultDirectiveDispatcher.AttentionWeights(escalatedFindings, directives)

		outcome := inquest.RunAll(ctx, inquest.Input{
			Store:            cfg.Store,
			Client:           cfg.Client,
			Findings:         escalated,
			AllEvents:        allEvents,
			Baseline:         bl,
			MallcopVersion:   cfg.MallcopVersion,
			Config:           cfg.Investigate,
			AttentionWeights: attentionWeights,
		})
		summary.Investigated = outcome.Investigated
		summary.InvestigationsDegraded = outcome.Degraded
		summary.InvestigationWarnings = outcome.Errors

		// (6) LOW-CONFIDENCE RE-VOTE (mallcoppro-09a), STRICTLY AFTER the first
		// investigation pass. An escalated finding whose investigation came back
		// "ok" but with LOW investigator confidence is not trustworthy enough to
		// ship customer-facing action-required copy as-is. For that subset we run a
		// DEEPER investigation pass (stronger evidence) and put it to a committee
		// RE-VOTE (any-escalate-wins). The re-vote OUTCOME is attached to the
		// EVIDENCE record only — never to the resolutions stream — so the
		// disposition audit trail is untouched (consensus invariant: the escalation
		// stands; the re-vote is a second opinion for the presentation layer, the
		// SAME N-voter cascade fed better evidence, never a rule).
		revotes, deescalations, warns := runLowConfidenceRevotes(ctx, cfg, escalated, allEvents, bl)
		summary.LowConfidenceRevotes = revotes
		summary.RevoteDeescalations = deescalations
		summary.InvestigationWarnings = append(summary.InvestigationWarnings, warns...)
	}

	// The tail recordScan call this used to be lives in the deferred call
	// registered near the top of Run now (mallcoppro-24e) — every return from
	// Run appends exactly one ScanRecord, this success path included.
	summary.Duration = time.Since(start)
	return summary, nil
}

// runLowConfidenceRevotes implements pipeline step 6 (mallcoppro-09a). For every
// finding in escalated whose just-written investigation record is "ok" but
// carries an investigator Confidence BELOW cfg.Investigate.LowConfidenceThreshold,
// it (a) re-investigates it with a DEEPER pass (inquest.RunAll Force=true, a
// SEPARATE MaxDeepPerScan budget, optionally a stronger DeepModel), then (b) puts
// the deeper evidence to a committee RE-VOTE (agent.RunRevoteGate, N =
// DefaultConsensusRuns, any-escalate-wins), and (c) attaches the re-vote OUTCOME
// to the investigation record (inquest.AttachRevote) — never to the resolutions
// stream. It returns the number of findings re-voted, how many of those re-votes
// were a UNANIMOUS resolve, and any non-fatal warning lines. It NEVER fails the
// scan: a read/deep-pass/attach error is collected as a warning and the finding
// is skipped, exactly like the first investigation pass's failure semantics.
//
// PROVENANCE HONESTY: step (b) runs ONLY for a finding whose deeper pass
// actually landed a FRESH trusted verdict — the set inquest.RunAll reports as
// FreshOKIDs. A finding whose deeper pass FAILED (deep budget exhausted mid-pass,
// model error/timeout, invalid output) keeps its FIRST-pass "ok" record on disk
// (processOne's overwrite guard), which is byte-indistinguishable from a genuine
// deeper verdict to a re-reader. For those, NO re-vote runs — re-voting would
// feed the committee the first-pass evidence relabeled as a "deeper
// investigation" that never happened, poisoning the record customer-facing copy
// is generated from (mallcoppro-09a review finding). Instead the finding's record
// is marked deep_pass_failed (RevoteOutcome{Triggered:false, DeepPassFailed:true})
// so the console can say the deeper pass didn't land; the finding keeps its
// first-pass verdict + low confidence and STAYS escalated (any-escalate-wins
// preserved exactly). Such findings are NOT counted in the returned revote tally.
//
// BUDGET: the re-vote loop is bounded to AT MOST MaxDeepPerScan findings — the
// low-confidence subset is sorted by finding ID (the same deterministic order
// inquest.RunAll sorts by internally) and truncated to the deep budget BEFORE
// either the deep pass or the re-vote runs. This keeps the committee re-vote —
// the expensive part of this step — capped at the SAME budget the deep pass
// itself is capped at; a finding that falls past the deep budget is left as a
// normal low-confidence escalation, untouched, never re-voted on stale
// first-pass evidence mislabeled as a "deeper investigation" that never ran
// for it (mallcoppro-09a review finding).
//
// The whole step is a no-op (returns 0,0,nil) when the retrigger is disabled
// (LowConfidenceThreshold <= 0), the client is nil (nothing to re-vote with — the
// nil-client scan already escalated everything and wrote absent-no-client
// evidence-only records, none of which are "ok"), or nothing is below threshold.
func runLowConfidenceRevotes(ctx context.Context, cfg Config, escalated []inquest.EscalatedFinding, allEvents []event.Event, bl *baseline.Baseline) (revotes, deescalations int, warnings []string) {
	if cfg.Investigate.LowConfidenceThreshold <= 0 || cfg.Client == nil {
		return 0, 0, nil
	}

	// Which escalated findings came back "ok" but low-confidence? Read each
	// just-written record and select the subset. A missing/malformed record is a
	// warning, not a failure — the finding is simply not re-voted.
	var lowConf []inquest.EscalatedFinding
	for _, ef := range escalated {
		rec, found, err := inquest.ReadRecord(cfg.Store, ef.RecordKey())
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("revote: read record for %s: %v — skipped", ef.Finding.ID, err))
			continue
		}
		if !found || rec.NarrativeStatus != inquest.StatusOK {
			continue // no trusted verdict to second-guess (degraded/absent records already render honestly)
		}
		if rec.Confidence < cfg.Investigate.LowConfidenceThreshold {
			lowConf = append(lowConf, ef)
		}
	}
	if len(lowConf) == 0 {
		return 0, 0, nil
	}

	// Bound the low-confidence subset ITSELF to the deep budget, BEFORE either
	// the deep pass or the re-vote loop runs (mallcoppro-09a review finding: an
	// unbounded re-vote loop over ALL low-confidence findings — while
	// inquest.RunAll's own MaxDeepPerScan budget only lets the FIRST deepBudget
	// of them actually receive a fresh deep pass — fed the committee
	// first-pass evidence relabeled as a "deeper investigation" for the rest,
	// and blew the metered-cost bound MaxDeepPerScan exists to enforce). Sort
	// by finding ID first — the SAME deterministic order inquest.RunAll sorts
	// by internally before spending its budget — so the truncated subset is
	// exactly the subset RunAll will actually spend a call on, not an
	// arbitrary prefix of escalation order.
	deepBudget := cfg.Investigate.MaxDeepPerScan
	if deepBudget <= 0 {
		deepBudget = inquest.DefaultMaxDeepPerScan
	}
	sort.Slice(lowConf, func(i, j int) bool { return lowConf[i].Finding.ID < lowConf[j].Finding.ID })
	if len(lowConf) > deepBudget {
		lowConf = lowConf[:deepBudget]
	}

	// (a) DEEPER investigation pass over ONLY the (now budget-bounded)
	// low-confidence subset, Force=true so the idempotency skip does not
	// short-circuit the fresh pass, budgeted at the SEPARATE MaxDeepPerScan and
	// pinned to the (optionally stronger) DeepModel. RunAll never errors out;
	// it degrades individual records.
	deepCfg := cfg.Investigate
	deepCfg.MaxPerScan = deepBudget // its own budget, not shared with the first pass
	if cfg.Investigate.DeepModel != "" {
		deepCfg.Model = cfg.Investigate.DeepModel
	}
	deepOut := inquest.RunAll(ctx, inquest.Input{
		Store:          cfg.Store,
		Client:         cfg.Client,
		Findings:       lowConf,
		AllEvents:      allEvents, // same full known-event history the first pass assembled evidence from
		Baseline:       bl,        // the SAME derived/merged baseline the first pass (and detection) gated on
		MallcopVersion: cfg.MallcopVersion,
		Config:         deepCfg,
		Force:          true,
	})
	warnings = append(warnings, deepOut.Errors...)

	// Which of the budget-bounded low-confidence findings did the deeper pass
	// actually land a FRESH trusted verdict for? RunAll reports exactly those
	// IDs (FreshOKIDs) — a Force re-pass that FAILED (deep budget exhausted mid-
	// pass, model error/timeout, invalid output) keeps the finding's prior
	// FIRST-pass "ok" record on disk via processOne's overwrite guard, so the
	// re-read below cannot distinguish a genuine deeper verdict from the
	// preserved first-pass one. Only a finding in this set has genuinely deeper
	// evidence to re-vote on (mallcoppro-09a review finding).
	freshOK := make(map[string]bool, len(deepOut.FreshOKIDs))
	for _, id := range deepOut.FreshOKIDs {
		freshOK[id] = true
	}

	// (b)+(c) Re-vote each low-confidence finding with the deeper evidence and
	// attach the outcome. The re-vote runs the SAME cascade the resolutions came
	// from (cfg.Cascade), so its committee is the production committee.
	for _, ef := range lowConf {
		if !freshOK[ef.Finding.ID] {
			// The forced deeper pass did NOT land a fresh trusted verdict for
			// this finding — the on-disk record is STILL the first-pass
			// evidence. Re-voting now would hand the committee that first-pass
			// evidence relabeled as a "deeper investigation" that never
			// happened, misrepresenting provenance and poisoning the record the
			// customer-facing copy is generated from (mallcoppro-09a review
			// finding). Do NOT re-vote. Record deep_pass_failed so the console
			// can honestly say the deeper pass didn't land; the finding keeps
			// its first-pass verdict + low confidence and STAYS escalated
			// (any-escalate-wins preserved exactly — a finding we could not
			// de-escalate is never quietly cleared).
			if err := inquest.AttachRevote(cfg.Store, ef.RecordKey(), inquest.RevoteOutcome{
				Triggered:      false,
				DeepPassFailed: true,
				Reason:         "Deeper investigation pass did not produce a fresh trusted verdict (deep budget exhausted, model error, or invalid output); NO committee re-vote ran — re-deciding on the first-pass evidence relabeled as a deeper investigation would misrepresent provenance. The escalation stands at its first-pass confidence.",
			}); err != nil {
				warnings = append(warnings, fmt.Sprintf("revote: attach deep_pass_failed for %s: %v", ef.Finding.ID, err))
			}
			continue
		}
		rec, found, err := inquest.ReadRecord(cfg.Store, ef.RecordKey())
		if err != nil || !found {
			warnings = append(warnings, fmt.Sprintf("revote: re-read deep record for %s: found=%v err=%v — skipped", ef.Finding.ID, found, err))
			continue
		}
		deepEvidence := formatDeepEvidence(rec)
		result := agent.RunRevoteGate(ctx, cfg.Client, ef.Finding, cfg.Cascade, deepEvidence, agent.DefaultConsensusRuns)
		if err := inquest.AttachRevote(cfg.Store, ef.RecordKey(), inquest.RevoteOutcome{
			Triggered:        true,
			ResolveVotes:     result.ResolveVotes,
			TotalVotes:       result.TotalVotes,
			UnanimousResolve: result.UnanimousResolve,
			Reason:           result.Reason,
		}); err != nil {
			warnings = append(warnings, fmt.Sprintf("revote: attach outcome for %s: %v", ef.Finding.ID, err))
			continue
		}
		revotes++
		if result.UnanimousResolve {
			deescalations++
		}
	}
	return revotes, deescalations, warnings
}

// formatDeepEvidence renders the deeper investigation record into the compact,
// human-readable evidence string the re-vote committee re-weighs (as boxed,
// untrusted context — see agent.enrichFindingWithInvestigation). It carries the
// verdict, the numeric confidence, and the narrative; a degraded deep record
// (no trusted verdict) contributes only its narrative_status so the committee
// knows the deeper pass did not produce a stronger verdict.
func formatDeepEvidence(rec inquest.Record) string {
	if rec.NarrativeStatus != inquest.StatusOK {
		return fmt.Sprintf("deeper investigation did not produce a trusted verdict (status %q); re-decide on the original evidence.", rec.NarrativeStatus)
	}
	return fmt.Sprintf("verdict=%s confidence=%.2f; %s", rec.Verdict, rec.Confidence, rec.Narrative)
}

// backstopEventIDs is the mallcoppro-323 defense-in-depth line: every
// detector in core/detect is REQUIRED to populate Finding.EventIDs directly
// (enforced by core/detect's TestDetectorFindingsCarryEventLinkage lint —
// the primary fix), but a finding can still reach this point with an empty
// EventIDs for reasons the lint cannot catch: a third-party/sidecar detector
// this repo does not own, or a finding replayed from an OLDER stored record
// that predates the field. For any such finding, recover linkage from the
// Evidence blob's conventional event_id/event_ids keys
// (finding.ExtractEvidenceEventIDs — the SAME extraction
// cmd/mallcop-finding-context uses, reused rather than duplicated) so
// downstream identity resolution (core/inquest's assembleIdentity) degrades
// only when the detector genuinely recorded no event linkage anywhere, not
// merely because it used the older Evidence-only convention. A finding that
// already carries EventIDs is returned unchanged.
func backstopEventIDs(findings []finding.Finding) []finding.Finding {
	for i := range findings {
		if len(findings[i].EventIDs) == 0 {
			findings[i].EventIDs = finding.ExtractEvidenceEventIDs(findings[i].Evidence)
		}
	}
	return findings
}

// recordScan appends one store.ScanRecord to the store's KindScans register —
// the durable, rotation-surviving source detection-time investigation's
// scan-schedule correlation reads (core/inquest's assemble.go). Called via a
// defer registered near the top of Run (mallcoppro-24e), so it fires on EVERY
// return from Run — success, a mid-pipeline failure, or the empty-findings
// early exit — instead of only the tail success path. That is the fix for
// the reinforcing bug (design §5): a connector 403-on-connect used to return
// before recordScan ever fired, leaving the register dark exactly when the
// liveness watchdog needed the signal. A write failure here is still a hard
// error, exactly like every other store append in Run — the defer at Run's
// top folds it into Run's returned error (see that comment for the exact
// precedence rule when Run was already failing).
//
// runErr is Run's own error at the time it returned (nil on success). When
// non-nil, the record carries Success=false, FailedStage=stage (the pipeline
// phase in flight when runErr fired), and Error=runErr.Error(). When nil, the
// record carries Success=true and both string fields empty.
func recordScan(cfg Config, summary Summary, startedAt time.Time, stage string, runErr error) error {
	rec := store.ScanRecord{
		StartedAt:        startedAt,
		FinishedAt:       time.Now(),
		EventsScanned:    summary.EventsScanned,
		FindingsDetected: summary.FindingsDetected,
		Escalated:        summary.Escalated,
		MallcopVersion:   cfg.MallcopVersion,
		Success:          runErr == nil,
	}
	if runErr != nil {
		rec.FailedStage = stage
		rec.Error = runErr.Error()
	}
	if _, err := cfg.Store.Append(store.KindScans, rec); err != nil {
		return fmt.Errorf("pipeline: store scan record: %w", err)
	}
	return nil
}

// resolveAll runs ResolveFindingWith over every finding through a bounded pool of
// at most cfg.Workers goroutines (never more than len(findings)). Results are
// collected into a slice indexed by input position, so the caller sees them in
// the SAME order as the (name-sorted, deterministic) detector output regardless
// of which worker finished first.
//
// The inference client and the store are concurrency-safe (see package doc), so
// the only shared state the pool touches is the pre-allocated results slice —
// and each goroutine writes a DISTINCT index, so there is no data race (proven by
// -race in the package tests).
func resolveAll(ctx context.Context, cfg Config, findings []finding.Finding) ([]resolved, error) {
	workers := cfg.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	if workers > len(findings) {
		workers = len(findings)
	}

	results := make([]resolved, len(findings))
	jobs := make(chan int)

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				f := findings[idx]
				// ResolveFindingWith carries the ENTIRE security floor: the
				// hard-constraint pre-LLM router, untrusted-data boxing, the
				// structural gate, and the fail-safe. The pipeline does not reach
				// around any of it — it records exactly what the cascade returns.
				res := agent.ResolveFindingWith(ctx, cfg.Client, f, cfg.Cascade)
				results[idx] = resolved{finding: f, resolution: res}
			}
		}()
	}

	for idx := range findings {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

// loadPriorEvents replays the store's committed KindEvents stream (everything
// earlier scans durably recorded at HEAD) and unmarshals it to []event.Event —
// the corpus baseline.Build derives the derived baseline from. A stream with no
// records (a first scan, or a fresh store) is not an error: it yields nil, which
// Build turns into an empty baseline (every actor fires — correct for scan one).
// A malformed record is a hard error: a corrupt event history must not silently
// degrade the baseline into re-investigating everything.
func loadPriorEvents(st *store.Store) ([]event.Event, error) {
	raws, err := st.Load(store.KindEvents)
	if err != nil {
		return nil, err
	}
	if len(raws) == 0 {
		return nil, nil
	}
	out := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("decode prior event %d: %w", i, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

// loadPersistedBaseline returns the MOST RECENT baseline the pipeline persisted
// to the store's KindBaseline stream on an earlier derived scan, or nil when the
// stream is empty (a fresh store, or one whose every scan supplied an explicit
// Config.Baseline — never persisted, see the derived-only Append below). KindBaseline
// is append-only history, so the LAST record is the most current snapshot. Used by
// the (1a) derivation step to survive a store rotation (mallcoppro-9e2): mirrors
// cli/investigate.go's loadPersistedBaseline (duplicated, not imported — cli
// depends on core/pipeline's sibling packages, not the reverse, and this package's
// import-lint forbids reaching into cli). A nil result is not an error; Merge
// treats a nil receiver as an empty baseline.
func loadPersistedBaseline(st *store.Store) (*baseline.Baseline, error) {
	raws, err := st.Load(store.KindBaseline)
	if err != nil {
		return nil, err
	}
	if len(raws) == 0 {
		return nil, nil
	}
	var b baseline.Baseline
	if err := json.Unmarshal(raws[len(raws)-1], &b); err != nil {
		return nil, fmt.Errorf("decode persisted baseline: %w", err)
	}
	return &b, nil
}

// dedupeEvents drops every event in pulled whose ID already appears in prior
// (the store's already-committed KindEvents stream, read BEFORE this scan's
// batch is appended — see the (1a) ordering invariant in Run) and collapses
// duplicate IDs WITHIN pulled itself, keeping the first occurrence. An event
// with an EMPTY ID is NEVER dropped, by either rule: an empty string is not an
// identity, so it can never be a "duplicate" of anything, and treating it as
// one would silently discard events from a connector (or test fixture) that
// assigns no ID. Order is preserved. Returns the deduped slice and the count
// of events dropped (for Summary.DuplicatesSkipped).
func dedupeEvents(pulled, prior []event.Event) ([]event.Event, int) {
	priorIDs := make(map[string]bool, len(prior))
	for _, ev := range prior {
		if ev.ID != "" {
			priorIDs[ev.ID] = true
		}
	}

	seen := make(map[string]bool, len(pulled))
	out := make([]event.Event, 0, len(pulled))
	skipped := 0
	for _, ev := range pulled {
		if ev.ID == "" {
			out = append(out, ev)
			continue
		}
		if priorIDs[ev.ID] || seen[ev.ID] {
			skipped++
			continue
		}
		seen[ev.ID] = true
		out = append(out, ev)
	}
	return out, skipped
}

// toResolutionRecord maps the cascade's internal agent.Resolution onto the
// shared pkg/resolution.Resolution wire record the store streams and the
// notification binaries consume. The mapping is mechanical:
//
//   - ActionEscalated → "escalate"; anything else (ActionProceed) → "resolve".
//   - Reason, Actor, Severity, Source carry through from the cascade resolution
//     and the originating finding so the record is self-describing on the wire.
//
// The cascade never reports a numeric confidence on its terminal Resolution, so
// Confidence is left zero — the disposition (escalate vs resolve) is the
// authoritative signal, not a self-reported score.
func toResolutionRecord(f finding.Finding, r agent.Resolution) resolution.Resolution {
	action := "resolve"
	if r.Action == agent.ActionEscalated {
		action = "escalate"
	}
	return resolution.Resolution{
		FindingID: f.ID,
		Action:    action,
		Reason:    r.Reason,
		Actor:     f.Actor,
		Severity:  f.Severity,
		Source:    f.Source,
		Timestamp: time.Now().UTC(),
	}
}
