// selfexttool.go — the "dispatch_selfext" chat tool (Gap A, mallcoppro-0d95):
// the investigating model can dispatch a self-extension authoring run
// (`mallcop selfext --run`/`--propose`) in the same breath it diagnosed a
// detection gap, instead of only at a shell.
//
// # Outcome-level parity, not an HTTP call
//
// mallcop-pro's browser UI dispatches self-extension through its own
// server-side endpoint. core/investigate CANNOT reach that endpoint — this
// package is net/http-banned (see imports_test.go), on purpose: the loop
// that reasons over untrusted security data must never also be the thing
// that makes outbound network calls. Parity with the UI path is therefore
// OUTCOME-level: this tool commits a durable dispatch record onto the SAME
// git-backed store every other write-tool in this family uses
// (store.KindSelfextDispatches — see core/store/records.go), through the
// identical opts.Store.Append seam configtool.go's setConfigTool commits
// config changes through. The serve loop's surrounding checkout already has
// a contents:write GITHUB_TOKEN and pushes the store branch as part of its
// normal run (the same path every other store write rides) — this tool opens
// NO new mallcop-pro credential path. The privileged mallcop-pro side reads
// this stream and is what actually kicks off the authoring run; the chat
// loop's job stops at recording the authorized request.
//
// # The autonomy dial gates COMMIT, not the tool's existence
//
// SelfextDispatchInput never carries an autonomy field — the model cannot
// raise its own blast radius by simply asserting a dial position. Instead
// this tool reads the REAL learning.autonomy off the checked-out
// mallcop.yaml (the same LoadEffective resolution setConfigTool uses):
//
//   - "non" (propose-only, the default): commits NOTHING. The tool returns a
//     Proposed=true result describing what WOULD be dispatched; the surface
//     renders this as an Apply/Discard row the operator can act on (the
//     browser already renders exactly this affordance for chat_config_action
//     -- reused here, not forked).
//   - "semi" or "fully" (an "auto" dial): commits immediately, within the
//     operator's already-declared blast radius. Neither is treated as an R3
//     hard line here -- unlike RAISING the dial or ENABLING contribute-back
//     (set_config's job), dispatching a proposed authoring run at a dial the
//     operator already set is exactly what that dial means.
package investigate

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/store"
)

// SelfextDispatchInput is the "dispatch_selfext" tool_use input. Fields mirror
// `mallcop selfext --run`'s own gap-description flags (cli/selfext.go's
// runArgs) so a consumer of the resulting store.SelfextDispatchRecord can
// build the equivalent CLI invocation directly. There is deliberately NO
// autonomy field: the dial is read from the checked-out mallcop.yaml, never
// accepted from the model.
type SelfextDispatchInput struct {
	// Lane is the authoring lane requested, e.g. "heal" or "investigate".
	// Required.
	Lane string `json:"lane"`
	// DetectorID is the proposed authored detector id. Required.
	DetectorID string `json:"detector_id"`
	// EventType is the connector event type the detector keys on. Required.
	EventType string `json:"event_type"`
	// TargetFamily is an optional finding-metadata family tag (default: the
	// detector id -- mirrors `mallcop selfext --run --target-family`).
	TargetFamily string `json:"target_family,omitempty"`
	// Severity is the structural severity of the gap exemplar (default
	// "medium" if empty, matching the CLI's own default).
	Severity string `json:"severity,omitempty"`
	// Actor is the structural actor field of the gap exemplar.
	Actor string `json:"actor,omitempty"`
	// Source is the structural source field of the gap exemplar.
	Source string `json:"source,omitempty"`
	// Reason is the model's rationale for the dispatch, preserved for audit
	// on the committed record.
	Reason string `json:"reason,omitempty"`
}

// SelfextDispatchOutput is dispatch_selfext's tool_result payload. Committed
// reports whether a store.SelfextDispatchRecord was actually appended; when
// Proposed is true (always the "non"/propose-only case, and ONLY that case)
// nothing was written and the surface should offer the operator an
// Apply/Discard affordance whose Apply re-issues the equivalent request at a
// raised dial (via set_config) or through the CLI directly.
type SelfextDispatchOutput struct {
	Committed bool   `json:"committed"`
	Proposed  bool   `json:"proposed,omitempty"`
	Autonomy  string `json:"autonomy"`
	Summary   string `json:"summary"`
}

// dispatchSelfextTool implements the "dispatch_selfext" chat tool. It loads
// the effective mallcop.yaml for the session (the SAME resolution
// setConfigTool uses: opts.RepoRoot when pinned, else LoadEffective's own
// walk-up), reads the REAL learning.autonomy off it, and either returns a
// no-commit proposal ("non") or appends a store.SelfextDispatchRecord through
// opts.Store.Append -- the SAME store-append seam every other durable write
// in this family (set_config's config writes, and any future record_decision
// directive write) rides, never a parallel one.
func dispatchSelfextTool(opts Options, in SelfextDispatchInput) (any, error) {
	lane := strings.TrimSpace(in.Lane)
	if lane == "" {
		return nil, fmt.Errorf("dispatch_selfext: lane is required")
	}
	detectorID := strings.TrimSpace(in.DetectorID)
	if detectorID == "" {
		return nil, fmt.Errorf("dispatch_selfext: detector_id is required")
	}
	eventType := strings.TrimSpace(in.EventType)
	if eventType == "" {
		return nil, fmt.Errorf("dispatch_selfext: event_type is required")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("dispatch_selfext: no store configured for this session")
	}

	severity := strings.TrimSpace(in.Severity)
	if severity == "" {
		severity = "medium"
	}

	// Resolve mallcop.yaml the SAME way setConfigTool does: pin to
	// opts.RepoRoot when set (the serve loop's checkout root), else let
	// LoadEffective walk up from cwd -- inside the customer's GHA runner that
	// IS the checked-out repo root.
	override := ""
	if rr := strings.TrimSpace(opts.RepoRoot); rr != "" {
		override = filepath.Join(rr, config.ConfigFileName)
	}
	cfg, resolvedPath, err := config.LoadEffective(override)
	if err != nil {
		return nil, fmt.Errorf("dispatch_selfext: %w", err)
	}
	if resolvedPath == "" {
		return nil, fmt.Errorf("dispatch_selfext: no %s found (run `mallcop init` first)", config.ConfigFileName)
	}

	autonomyDial := cfg.Learning.Autonomy

	if autonomyDial == config.AutonomyNon {
		// Propose-only (the default): commit NOTHING. The model surfaces this
		// as an Apply/Discard row; nothing lands on the selfext_dispatches
		// stream until the operator raises the dial or applies directly.
		return SelfextDispatchOutput{
			Committed: false,
			Proposed:  true,
			Autonomy:  autonomyDial,
			Summary: fmt.Sprintf(
				"learning.autonomy=%q is propose-only -- NOTHING was dispatched. Proposed: lane=%q detector_id=%q event_type=%q. "+
					"The operator can Apply (raise the dial via set_config with confirm=true, then re-issue) or run `mallcop selfext --run` directly.",
				autonomyDial, lane, detectorID, eventType),
		}, nil
	}

	// "semi" or "fully" -- an auto dial. Commit within the operator's
	// already-declared blast radius, through the SAME store-append seam every
	// other write-tool in this family uses.
	rec := store.SelfextDispatchRecord{
		RequestedAt:  time.Now().UTC(),
		Lane:         lane,
		DetectorID:   detectorID,
		EventType:    eventType,
		TargetFamily: strings.TrimSpace(in.TargetFamily),
		Severity:     severity,
		Actor:        strings.TrimSpace(in.Actor),
		Source:       strings.TrimSpace(in.Source),
		Reason:       strings.TrimSpace(in.Reason),
		Autonomy:     autonomyDial,
	}
	if _, err := opts.Store.Append(store.KindSelfextDispatches, rec); err != nil {
		return nil, fmt.Errorf("dispatch_selfext: %w", err)
	}

	return SelfextDispatchOutput{
		Committed: true,
		Autonomy:  autonomyDial,
		Summary: fmt.Sprintf(
			"Dispatched: lane=%q detector_id=%q event_type=%q (learning.autonomy=%q). "+
				"Committed to the selfext_dispatches stream for the runner to pick up.",
			lane, detectorID, eventType, autonomyDial),
	}, nil
}
