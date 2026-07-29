// configtool.go — the "set_config" chat tool (Gap A, rd mallcoppro-7a6): the
// investigating model can reconfigure mallcop.yaml in the same breath it
// answered you — autonomy dial, connectors, and the contribute-back opt-in —
// reachable conversationally instead of only at a shell.
//
// # It is the SAME seam as `mallcop config set`, never a parallel one
//
// Every write goes through the SHARED mutation primitive
// (core/config.SetAutonomy / AddConnector / SetContributeBack) followed by
// core/config.WriteConfigAtomic — the identical call sequence cli/configset.go
// runs. This package builds NO config mutation of its own and NEVER marshals or
// os.WriteFile's mallcop.yaml directly (R5: the loop itself never writes the
// config file; the sanctioned operator-authorized primitive does). Dual-audience
// (R4) is therefore true by construction: a change made in chat is byte-for-byte
// what the operator would get typing `mallcop config set …`.
//
// # The R3 hard line — always operator-confirmed, never auto at any dial
//
// Two changes are ALWAYS gated on an explicit operator confirmation, regardless
// of the deployment's autonomy dial:
//
//   - RAISING the autonomy dial (non→semi, non→fully, semi→fully); and
//   - ENABLING contribute-back (contribute_back → true).
//
// Both widen the operator's own blast radius (a raise lets the loop act more
// autonomously; contribute-back offers this deployment's improvements up to the
// SHARED OSS corpus, which affects other tenants). So the model may only carry
// out either change when the operator has explicitly approved it — surfaced to
// this tool as `confirm: true`. Absent that, the tool writes NOTHING and returns
// a `requires_confirm` proposal the surface renders as an Apply/Discard row; the
// operator's Apply is the confirmed re-issue. This is enforced here in core, so
// the guarantee holds at every issuance surface (chat, CLI, a future TUI), never
// only in one renderer.
//
// LOWERING the dial (a de-escalation) and DISABLING contribute-back are the safe
// direction and need no confirm. Adding a connector expands data sources, not the
// loop's authority, and is likewise not part of the R3 hard line.
package investigate

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mallcop-app/mallcop/core/config"
)

// SetConfigInput is the "set_config" tool_use input. Exactly one of the three
// settings is addressed per call, selected by `setting`; the value field for
// the OTHER two settings is ignored. `confirm` carries the operator's explicit
// approval for an R3 hard-line change (dial raise / contribute-back enable) and
// is meaningless for the safe-direction changes.
type SetConfigInput struct {
	// Setting selects which config surface to mutate: "autonomy",
	// "connector", or "contribute_back".
	Setting string `json:"setting"`

	// Autonomy is the requested dial position when Setting=="autonomy":
	// "non", "semi", or "fully" (validated by config.SetAutonomy, never here).
	Autonomy string `json:"autonomy,omitempty"`

	// ContributeBack is the requested opt-in state when
	// Setting=="contribute_back".
	ContributeBack bool `json:"contribute_back,omitempty"`

	// Connector is the connector to append when Setting=="connector". Its
	// fields map 1:1 to `mallcop config set connector`'s flags; all semantic
	// validation (kind enum, unique id, env-are-NAMES) is config.AddConnector's
	// own, duplicated nowhere here.
	Connector *SetConfigConnector `json:"connector,omitempty"`

	// Confirm is the operator's explicit approval for an R3 hard-line change.
	// Ignored for safe-direction changes; REQUIRED (true) for a dial raise or a
	// contribute-back enable, else the change is refused and returned as a
	// proposal.
	Confirm bool `json:"confirm,omitempty"`
}

// SetConfigConnector mirrors config.Connector's operator-settable fields for
// the tool input. It is decoded into a config.Connector and handed straight to
// config.AddConnector — this struct adds no validation of its own.
type SetConfigConnector struct {
	Kind   string   `json:"kind"`
	ID     string   `json:"id"`
	Path   string   `json:"path,omitempty"`
	Org    string   `json:"org,omitempty"`
	Source string   `json:"source,omitempty"`
	Binary string   `json:"binary,omitempty"`
	Since  string   `json:"since,omitempty"`
	Args   []string `json:"args,omitempty"`
	Env    []string `json:"env,omitempty"`
}

// SetConfigOutput is set_config's tool_result payload. Applied reports whether
// the file was written; when RequiresConfirm is true the change was an R3
// hard-line raise/enable issued WITHOUT confirm, so nothing was written and the
// surface should offer the operator an Apply/Discard affordance whose Apply
// re-issues the SAME call with confirm=true.
type SetConfigOutput struct {
	Applied         bool   `json:"applied"`
	RequiresConfirm bool   `json:"requires_confirm,omitempty"`
	Setting         string `json:"setting"`
	Path            string `json:"path,omitempty"`
	Summary         string `json:"summary"`
}

// autonomyRank orders the three dial positions so a "raise" (more autonomy) is
// distinguishable from a "lower" (de-escalation). It mirrors the documented
// dial ordering non < semi < fully. An unrecognized value ranks -1 so it is
// never mistaken for a de-escalation of a real position — but config.SetAutonomy
// is the authoritative validator; this ordering is only used to decide whether
// the R3 confirm gate applies.
func autonomyRank(a string) int {
	switch a {
	case config.AutonomyNon:
		return 0
	case config.AutonomySemi:
		return 1
	case config.AutonomyFully:
		return 2
	default:
		return -1
	}
}

// setConfigTool implements the "set_config" chat tool. It loads the effective
// mallcop.yaml for the session (pinned to opts.RepoRoot when set, else the same
// walk-up discovery the CLI uses), applies exactly one setting change through
// the shared config primitive, enforces the R3 confirm gate on the two
// hard-line changes, and writes the result atomically.
func setConfigTool(opts Options, in SetConfigInput) (any, error) {
	setting := strings.TrimSpace(in.Setting)

	// Resolve the config file the same way cli/configset.go does. When
	// RepoRoot is pinned (an operator passed --repo-root, or the serve loop set
	// it) we address mallcop.yaml under that root explicitly rather than
	// trusting a second walk; otherwise LoadEffective("") discovers it from cwd,
	// which — inside the customer's GHA runner — IS the checked-out repo root.
	override := ""
	if rr := strings.TrimSpace(opts.RepoRoot); rr != "" {
		override = filepath.Join(rr, config.ConfigFileName)
	}
	cfg, resolvedPath, err := config.LoadEffective(override)
	if err != nil {
		return nil, fmt.Errorf("set_config: %w", err)
	}
	if resolvedPath == "" {
		return nil, fmt.Errorf("set_config: no %s found (run `mallcop init` first)", config.ConfigFileName)
	}

	switch setting {
	case "autonomy":
		value := strings.TrimSpace(in.Autonomy)
		// R3 hard line: a RAISE is always operator-confirmed. Compute the raise
		// BEFORE mutating so an unconfirmed raise writes nothing. A same-level or
		// lower request is the safe direction and needs no confirm. Rank of -1
		// (an invalid value) is never treated as a de-escalation — but the
		// authoritative rejection of a bad value is config.SetAutonomy's, below.
		if autonomyRank(value) > autonomyRank(cfg.Learning.Autonomy) && !in.Confirm {
			return SetConfigOutput{
				Applied:         false,
				RequiresConfirm: true,
				Setting:         setting,
				Summary: fmt.Sprintf("Raising the autonomy dial from %q to %q widens what the loop may do on its own — an R3 hard-line change that is ALWAYS operator-confirmed, never auto at any dial. Nothing was written. Re-issue with confirm=true only after the operator explicitly approves the raise.",
					cfg.Learning.Autonomy, value),
			}, nil
		}
		next, err := config.SetAutonomy(cfg, value)
		if err != nil {
			return nil, fmt.Errorf("set_config: %w", err)
		}
		if err := config.WriteConfigAtomic(resolvedPath, next); err != nil {
			return nil, fmt.Errorf("set_config: %w", err)
		}
		return SetConfigOutput{
			Applied: true,
			Setting: setting,
			Path:    resolvedPath,
			Summary: fmt.Sprintf("learning.autonomy=%s in %s — takes effect on the next `mallcop scan`. Landed as a config change the operator can revert.", value, resolvedPath),
		}, nil

	case "contribute_back":
		// R3 hard line: ENABLING contribute-back is always operator-confirmed —
		// it offers this deployment's improvements up to the SHARED OSS corpus,
		// which affects other tenants. Disabling is the safe direction.
		if in.ContributeBack && !in.Confirm {
			return SetConfigOutput{
				Applied:         false,
				RequiresConfirm: true,
				Setting:         setting,
				Summary: "Enabling contribute-back offers this deployment's improvements up to the SHARED OSS corpus (it affects other tenants) — an R3 hard-line change that is ALWAYS operator-confirmed, never auto at any dial. Nothing was written. Re-issue with confirm=true only after the operator explicitly approves opting in.",
			}, nil
		}
		next, err := config.SetContributeBack(cfg, in.ContributeBack)
		if err != nil {
			return nil, fmt.Errorf("set_config: %w", err)
		}
		if err := config.WriteConfigAtomic(resolvedPath, next); err != nil {
			return nil, fmt.Errorf("set_config: %w", err)
		}
		return SetConfigOutput{
			Applied: true,
			Setting: setting,
			Path:    resolvedPath,
			Summary: fmt.Sprintf("learning.contribute_back=%t in %s. Landed as a config change the operator can revert. Note: this only makes contribute-back ELIGIBLE — every contributed PR stays maintainer-reviewed (R3).", in.ContributeBack, resolvedPath),
		}, nil

	case "connector":
		if in.Connector == nil {
			return nil, errors.New("set_config: setting=connector requires a connector object")
		}
		conn := config.Connector{
			Kind:   in.Connector.Kind,
			ID:     in.Connector.ID,
			Path:   in.Connector.Path,
			Org:    in.Connector.Org,
			Source: in.Connector.Source,
			Binary: in.Connector.Binary,
			Since:  in.Connector.Since,
			Args:   in.Connector.Args,
			Env:    in.Connector.Env,
		}
		next, err := config.AddConnector(cfg, conn)
		if err != nil {
			return nil, fmt.Errorf("set_config: %w", err)
		}
		if err := config.WriteConfigAtomic(resolvedPath, next); err != nil {
			return nil, fmt.Errorf("set_config: %w", err)
		}
		return SetConfigOutput{
			Applied: true,
			Setting: setting,
			Path:    resolvedPath,
			Summary: fmt.Sprintf("added connector %q (kind=%s) to %s — takes effect on the next `mallcop scan`.", conn.ID, conn.Kind, resolvedPath),
		}, nil

	default:
		return nil, fmt.Errorf("set_config: unknown setting %q (want \"autonomy\", \"connector\", or \"contribute_back\")", in.Setting)
	}
}
