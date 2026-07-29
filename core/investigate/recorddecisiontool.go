// recorddecisiontool.go — the "record_decision" chat tool (Gap A, rd
// mallcoppro-999): the investigating model can act on the operator's steering
// decision in the same breath it surfaced a finding — suppress/mute/focus/
// severity/close-case — reachable conversationally instead of only at a shell.
//
// # It is the SAME seam as `mallcop feedback`, never a parallel one
//
// Every write is a store.Directive appended to store.KindDirectives through
// opts.Store.Append — the identical record shape and append call
// cli/feedback.go's runFeedback uses for approve/dismiss/report-miss. This
// file builds no directive-store mutation of its own kind; it only assembles
// the same store.Directive{Op, Pattern, Reason, Actor, Meta} value the CLI
// verb assembles and hands it to the same store seam. Dual-audience (R4) is
// therefore true by construction: a decision recorded in chat is
// byte-for-byte what the operator would get typing `mallcop feedback …` (or,
// once mallcoppro-ce6 lands the CLI verbs, `mallcop feedback … mute/watch/
// severity` and `mallcop case close`).
//
// # Execution & credential (grounded in the runtime, no new credential path)
//
// The model runs `mallcop investigate --serve` INSIDE the customer's GHA
// runner with a live opts.Store handle and GitMailbox.Push, authenticated by
// the runner's own contents:write GITHUB_TOKEN. This tool writes into that
// SAME checkout's store; the serve loop's existing commit path lands it —
// mallcop-pro never holds a write credential for this.
//
// # The autonomy dial gate
//
// learning.autonomy is read from the checked-out mallcop.yaml (the same file
// set_config.go reads/writes):
//
//   - propose-only (config.AutonomyNon, the default): the tool commits
//     NOTHING. It returns a `proposed` payload describing exactly the
//     directive it would have appended; the model surfaces this as an
//     Apply/Discard row (the browser already renders this affordance for
//     chat_config_action) and the operator's Apply re-issues the SAME call
//     with confirm=true, which commits.
//   - an auto dial (config.AutonomySemi / config.AutonomyFully): the tool
//     commits immediately — a steering directive is within blast radius at
//     those dials (unlike set_config's R3 hard line, which always gates a
//     dial-raise/contribute-back-enable regardless of the current dial;
//     record_decision carries no such hard line of its own).
package investigate

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/core/tools"
)

// recordDecisionOps is the documented directive vocabulary this tool may
// issue (mirrors store/records.go's DirectiveMeta doc comment and the item's
// DONE condition: suppress/mute/focus/severity/close-case). unsuppress and
// report-miss are deliberately NOT exposed here — unsuppress reverses an
// existing suppress (a distinct, narrower CLI verb) and report-miss has its
// own tool-shaped seam already (mallcoppro-ce6 territory); widening this
// tool's op enum is a separate decision, not silently folded in here.
var recordDecisionOps = map[string]bool{
	"suppress":   true,
	"mute":       true,
	"focus":      true,
	"severity":   true,
	"close-case": true,
}

// RecordDecisionInput is the "record_decision" tool_use input.
type RecordDecisionInput struct {
	// Op selects the directive verb: one of suppress, mute, focus, severity,
	// close-case. Required.
	Op string `json:"op"`

	// FindingID resolves the target finding via the store's findings stream
	// (accepts a truncated/prefix id, same as search_findings) and derives the
	// stable "<source>/<type>/<actor>" Pattern from it — the SAME derivation
	// cli/feedback.go uses so a directive suppresses the CLASS of finding, not
	// one transient per-run id. Exactly one of FindingID or Pattern is
	// required.
	FindingID string `json:"finding_id,omitempty"`

	// Pattern is an explicit directive pattern (finding-key
	// "source/type/actor", or a gap-key/source when paired with
	// meta.target_kind — see store.DirectiveMeta) for a decision that isn't
	// anchored to one on-screen finding. Exactly one of FindingID or Pattern
	// is required.
	Pattern string `json:"pattern,omitempty"`

	// Reason is the operator-facing rationale, recorded verbatim on the
	// directive for the audit trail.
	Reason string `json:"reason"`

	// Severity is the override value when Op=="severity" (finding.Severity's
	// vocabulary; not validated here — the severity consumer is authoritative,
	// mirroring how config.SetAutonomy is authoritative for set_config).
	Severity string `json:"severity,omitempty"`

	// Weight is the attention weight when Op=="focus" (fed to finding ranking
	// / inquest depth budget by the focus consumer once registered).
	Weight float64 `json:"weight,omitempty"`

	// TTL is a duration string (e.g. "720h" for 30d) applied when Op=="mute":
	// stored as Meta.ExpiresAt = now+TTL so the mute auto-expires on replay.
	TTL string `json:"ttl,omitempty"`

	// Confirm re-issues a prior propose-only call with the operator's
	// explicit Apply. It has no effect at an auto dial (already committing).
	Confirm bool `json:"confirm,omitempty"`
}

// RecordDecisionOutput is record_decision's tool_result payload.
type RecordDecisionOutput struct {
	// Applied is true only when a real Directive was appended to the store.
	Applied bool `json:"applied"`

	// Proposed carries the directive that WOULD be appended, when the
	// autonomy dial is propose-only and Confirm was not set. Nil once
	// Applied is true.
	Proposed *ProposedDirective `json:"proposed,omitempty"`

	Op      string `json:"op"`
	Pattern string `json:"pattern,omitempty"`
	Summary string `json:"summary"`
}

// ProposedDirective is the propose-only preview of the directive record_decision
// would append — everything the surface needs to render an Apply/Discard row
// and everything an Apply re-issue needs to reproduce the SAME write.
type ProposedDirective struct {
	Op       string  `json:"op"`
	Pattern  string  `json:"pattern"`
	Reason   string  `json:"reason"`
	Severity string  `json:"severity,omitempty"`
	Weight   float64 `json:"weight,omitempty"`
	TTL      string  `json:"ttl,omitempty"`
}

// recordDecisionTool implements the "record_decision" chat tool: it resolves
// the target Pattern, reads the effective autonomy dial, and either appends a
// real store.Directive (auto dials, or a confirmed propose-only re-issue) or
// returns a proposal (propose-only, unconfirmed).
func recordDecisionTool(opts Options, in RecordDecisionInput) (any, error) {
	op := strings.TrimSpace(in.Op)
	if !recordDecisionOps[op] {
		return nil, fmt.Errorf("record_decision: unknown op %q (want one of suppress, mute, focus, severity, close-case)", in.Op)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, fmt.Errorf("record_decision: reason is required")
	}
	if (in.FindingID == "") == (in.Pattern == "") {
		return nil, fmt.Errorf("record_decision: exactly one of finding_id or pattern is required")
	}

	pattern := in.Pattern
	if in.FindingID != "" {
		if opts.Store == nil {
			return nil, fmt.Errorf("record_decision: no store available to resolve finding_id")
		}
		findings, err := tools.SearchFindings(opts.Store, tools.SearchFindingsInput{IDs: []string{in.FindingID}})
		if err != nil {
			return nil, fmt.Errorf("record_decision: resolve finding_id: %w", err)
		}
		if len(findings) == 0 {
			return nil, fmt.Errorf("record_decision: finding_id %q not found in store", in.FindingID)
		}
		f := findings[0]
		// SAME derivation as cli/feedback.go's runFeedback: the stable
		// "<source>/<type>/<actor>" key, so the directive steers the CLASS of
		// finding, not one transient per-run id.
		pattern = f.Source + "/" + f.Type + "/" + f.Actor
	}

	// Resolve the effective mallcop.yaml the SAME way set_config.go does:
	// pinned RepoRoot when set (the serve loop's checkout root), else the
	// walk-up discovery LoadEffective("") performs from cwd.
	override := ""
	if rr := strings.TrimSpace(opts.RepoRoot); rr != "" {
		override = filepath.Join(rr, config.ConfigFileName)
	}
	cfg, _, err := config.LoadEffective(override)
	if err != nil {
		return nil, fmt.Errorf("record_decision: %w", err)
	}

	proposed := &ProposedDirective{
		Op:       op,
		Pattern:  pattern,
		Reason:   in.Reason,
		Severity: in.Severity,
		Weight:   in.Weight,
		TTL:      in.TTL,
	}

	// Dial gate: propose-only (config.AutonomyNon) commits nothing unless the
	// operator's Apply re-issues with confirm=true; semi/fully commit
	// immediately — a steering directive carries no R3 hard line of its own.
	if cfg.Learning.Autonomy == config.AutonomyNon && !in.Confirm {
		return RecordDecisionOutput{
			Applied:  false,
			Proposed: proposed,
			Op:       op,
			Pattern:  pattern,
			Summary: fmt.Sprintf("mallcop is at the propose-only autonomy dial — nothing was written. This %s directive for %q is proposed; re-issue with confirm=true only after the operator approves it in this conversation.", op, pattern),
		}, nil
	}

	if opts.Store == nil {
		return nil, fmt.Errorf("record_decision: no store available to append the directive")
	}

	meta := store.DirectiveMeta{
		Severity:   in.Severity,
		Weight:     in.Weight,
		TargetKind: "finding-key",
	}
	if in.TTL != "" {
		d, err := time.ParseDuration(in.TTL)
		if err != nil {
			return nil, fmt.Errorf("record_decision: invalid ttl %q: %w", in.TTL, err)
		}
		meta.ExpiresAt = time.Now().UTC().Add(d)
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("record_decision: encode meta: %w", err)
	}

	actor := "mallcop-investigate"
	directive := store.Directive{
		Op:      op,
		Pattern: pattern,
		Reason:  in.Reason,
		Actor:   actor,
		Meta:    json.RawMessage(metaJSON),
	}
	if _, err := opts.Store.Append(store.KindDirectives, directive); err != nil {
		return nil, fmt.Errorf("record_decision: append directive: %w", err)
	}

	return RecordDecisionOutput{
		Applied: true,
		Op:      op,
		Pattern: pattern,
		Summary: fmt.Sprintf("recorded %s directive for %q — takes effect on the next scan. Landed as a git-backed store write the operator can revert (mallcop feedback / a future unsuppress).", op, pattern),
	}, nil
}
