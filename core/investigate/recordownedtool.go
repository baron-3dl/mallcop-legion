// recordownedtool.go — the "record_owned" chat tool (Gap A, rd mallcoppro-e07):
// the investigating model can name one of the operator's OWN accounts/roles/
// relays into mallcop.yaml's org.owned block in the same breath it answered you,
// so a recurring, baseline-known actor resolves as an OWNED entity by name and
// relationship at the next investigation — instead of being narrated as an
// unknown external actor (mallcoppro-995 shipped that READ side; this is the
// WRITE last mile).
//
// # It is the SAME seam as `mallcop config set org.owned`, never a parallel one
//
// The write goes through the SHARED mutation primitive (core/config.AddOwned)
// followed by core/config.WriteConfigAtomic — the identical call sequence
// cli/configset.go's `config set org.owned` runs. This package builds NO config
// mutation of its own and NEVER marshals or os.WriteFile's mallcop.yaml directly
// (R5: the loop itself never writes the config file; the sanctioned operator-
// authorized primitive does). Dual-audience (R4) is therefore true by
// construction: a change made in chat is byte-for-byte what the operator would
// get typing `mallcop config set org.owned …`.
//
// # The dial gate — a TENANT-LOCAL write inside the operator's OWN blast radius
//
// Naming an owned entity is a config write on the operator's OWN repo (inside
// their blast radius), NOT a contribution to the SHARED OSS corpus — so it is
// NOT the R3 reviewed hard line (that hard line is raising the autonomy dial and
// enabling contribute-back, both handled by set_config). Instead it is gated on
// the deployment's autonomy dial, the ordinary DATA-change rule:
//
//   - propose-only (autonomy=non, the fail-safe default): the tool writes
//     NOTHING and returns a `requires_confirm` proposal the surface renders as an
//     Apply/Discard row. The operator's Apply re-issues the SAME call with
//     confirm=true, which commits.
//   - auto dials (autonomy=semi or fully): a data/config widen auto-applies —
//     the tool commits immediately, within blast radius.
//
// Enforced here in core so the guarantee holds at every issuance surface (chat,
// CLI, a future TUI), never only in one renderer.
//
// # Naming-only, never a verdict override
//
// An appended org.owned entry augments the narrative and attention budget only;
// it never overrides the committee's verdict (core/inquest/narrate.go's
// systemPrompt clause). This tool changes WHO an actor is named as, never
// WHETHER a finding escalates.
package investigate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mallcop-app/mallcop/core/config"
)

// RecordOwnedInput is the "record_owned" tool_use input — one owned entity to
// append to mallcop.yaml's org.owned block. Match/Name/Relationship map 1:1 to
// `mallcop config set org.owned`'s flags; all semantic validation (non-empty
// match, minimum match length) is config.AddOwned's own, duplicated nowhere
// here.
type RecordOwnedInput struct {
	// Match identifies the entity: an account id, ARN, or role-name segment,
	// substring-matched against a finding's caller/target/actor identity fields.
	// Required; config.AddOwned rejects an empty or too-short value.
	Match string `json:"match"`

	// Name is a short label the narrate prompt uses instead of "unknown external
	// actor", e.g. "forge-proxy".
	Name string `json:"name,omitempty"`

	// Relationship is the plain-language phrase narrate must use, e.g.
	// "operator's own hourly inference relay".
	Relationship string `json:"relationship,omitempty"`

	// Confirm carries the operator's explicit approval when the deployment is at
	// the propose-only dial (autonomy=non): without it the tool writes nothing
	// and returns a proposal. It is ignored (a no-op) at an auto dial, where the
	// change auto-applies within blast radius.
	Confirm bool `json:"confirm,omitempty"`
}

// RecordOwnedOutput is record_owned's tool_result payload. Applied reports
// whether the file was written; when RequiresConfirm is true the deployment was
// at the propose-only dial and no confirm was given, so nothing was written and
// the surface should offer an Apply/Discard affordance whose Apply re-issues the
// SAME call with confirm=true.
type RecordOwnedOutput struct {
	Applied         bool   `json:"applied"`
	RequiresConfirm bool   `json:"requires_confirm,omitempty"`
	Path            string `json:"path,omitempty"`
	Summary         string `json:"summary"`
}

// recordOwnedTool implements the "record_owned" chat tool. It loads the
// effective mallcop.yaml for the session (pinned to opts.RepoRoot when set, else
// the same walk-up discovery the CLI uses), applies the org.owned append through
// the shared config primitive, enforces the autonomy dial gate (propose-only
// needs an explicit confirm; auto dials commit immediately), and writes the
// result atomically.
func recordOwnedTool(opts Options, in RecordOwnedInput) (any, error) {
	// Resolve the config file the same way cli/configset.go and setConfigTool do.
	// When RepoRoot is pinned we address mallcop.yaml under that root explicitly;
	// otherwise LoadEffective("") discovers it from cwd, which — inside the
	// customer's GHA runner — IS the checked-out repo root.
	override := ""
	if rr := strings.TrimSpace(opts.RepoRoot); rr != "" {
		override = filepath.Join(rr, config.ConfigFileName)
	}
	cfg, resolvedPath, err := config.LoadEffective(override)
	if err != nil {
		return nil, fmt.Errorf("record_owned: %w", err)
	}
	if resolvedPath == "" {
		return nil, fmt.Errorf("record_owned: no %s found (run `mallcop init` first)", config.ConfigFileName)
	}

	owned := config.OwnedEntity{
		Match:        strings.TrimSpace(in.Match),
		Name:         in.Name,
		Relationship: in.Relationship,
	}

	// Dial gate: at the propose-only dial an unconfirmed append writes NOTHING
	// and comes back as a proposal. Validate the entry FIRST so a proposal is
	// only ever offered for a well-formed entity — a bad match is a hard error
	// the model must fix, not a proposal the operator would approve into a
	// broken config.
	if _, verr := config.AddOwned(cfg, owned); verr != nil {
		return nil, fmt.Errorf("record_owned: %w", verr)
	}
	if cfg.Learning.Autonomy == config.AutonomyNon && !in.Confirm {
		return RecordOwnedOutput{
			Applied:         false,
			RequiresConfirm: true,
			Summary: fmt.Sprintf("This deployment is at the propose-only autonomy dial (%q), so naming %q (%s) as owned waits for the operator's explicit approval. Nothing was written. Re-issue with confirm=true after the operator approves — or the operator can raise the autonomy dial to auto-apply org.owned changes within their blast radius.",
				config.AutonomyNon, owned.Name, owned.Match),
		}, nil
	}

	next, err := config.AddOwned(cfg, owned)
	if err != nil {
		return nil, fmt.Errorf("record_owned: %w", err)
	}
	if err := config.WriteConfigAtomic(resolvedPath, next); err != nil {
		return nil, fmt.Errorf("record_owned: %w", err)
	}
	return RecordOwnedOutput{
		Applied: true,
		Path:    resolvedPath,
		Summary: fmt.Sprintf("Recorded owned entity match=%q name=%q in %s — the next `mallcop scan`'s investigation resolves this actor as owned by name/relationship instead of an unknown external actor. Landed as a config change the operator can revert. (Naming only — never a verdict override.)", owned.Match, owned.Name, resolvedPath),
	}, nil
}
