// In-place deploy-repo upgrade (mallcoppro-973): `mallcop migrate` re-rigs an
// EXISTING customer deployment repo to the current schema + pinned release, so
// a live customer can bump versions without a hand re-scaffold.
//
// The v0.10.0 config loader (core/config) is a STRICT decoder: an old-shape
// mallcop.yaml (v0.9.3 and earlier — `secrets:`/`routing:`/`actor_chain:`/
// `pro:` blocks, `connectors:` as a kind->cfg MAP) is a loud load error, so
// every pre-v0.10 deploy repo's workflows fail the moment they read the config
// ("field secrets not found", "connectors: cannot unmarshal map into
// []Connector", "field routing not found"). This command performs the exact
// re-rig reproduced against the customer0 fixture:
//
//   1. mallcop.yaml  — legacy shape -> the new strict schema (config.Config),
//      carrying over what maps (github org, findings budget, the donut rail)
//      and LOUDLY reporting every dropped key rather than silently eating it.
//   2. .github/workflows/  — refresh scan.yml AND add the (v0.10) new
//      mallcop-investigate.yml, both pinned to the target release. A file
//      that's byte-identical to what mallcop generated for its OWN pinned
//      version (i.e. genuinely stale, never hand-touched — see
//      planWorkflowRefresh/refreshDeployWorkflows in deployrepo.go) advances
//      cleanly; a file that has DIVERGED from the generated template (an
//      operator hand-edit) is left completely untouched and reported instead
//      of clobbered (mallcoppro-f19 CRITICAL SAFETY). A run with any diverged
//      file returns a non-nil error so a partial update is never reported as
//      success, even though the rest of the repo still advances.
//   3. go.mod  — bump the github.com/mallcop-app/mallcop require to the target
//      release so CI sidecar builds match the workflow's downloaded binary.
//
// It is offline and in-place: it rewrites files under --dir (a checked-out
// deploy repo). Committing + pushing the result is the operator's step (the
// printed next-steps), the same division of labor as `mallcop init` vs
// `mallcop init --create-repo`. Setting the MALLCOP_API_KEY repo secret is
// likewise printed as the exact `gh secret set` command (mallcoppro-7b1's live
// GitHub-secret-API path is deferred — see the item).
package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/mallcop-app/mallcop/core/config"
	"gopkg.in/yaml.v3"
)

// runMigrate implements `mallcop migrate`.
func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	dir := fs.String("dir", ".", "Deploy-repo directory to upgrade in place")
	mallcopVersion := fs.String("mallcop-version", "", "mallcop release tag to pin (default: query the latest GitHub release)")
	configOnly := fs.Bool("config-only", false, "Only migrate mallcop.yaml; do not touch workflows or go.mod")
	dryRun := fs.Bool("dry-run", false, "Print what would change without writing any files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		return fmt.Errorf("resolving dir: %w", err)
	}

	configPath := filepath.Join(absDir, config.ConfigFileName)
	if _, err := os.Stat(configPath); err != nil {
		return fmt.Errorf("no %s in %s — migrate operates on an existing deploy repo (run `mallcop init --create-repo` to create one)", config.ConfigFileName, absDir)
	}

	// Resolve the target release once (workflows + go.mod share it). Skipped
	// entirely with --config-only so a purely-offline config migration needs
	// no network.
	version := *mallcopVersion
	if version == "" && !*configOnly {
		version, err = latestMallcopRelease(context.Background(), nil)
		if err != nil {
			return fmt.Errorf("resolving --mallcop-version: %w (pass --mallcop-version to skip the network lookup)", err)
		}
	}

	// --- 1. mallcop.yaml ---------------------------------------------------
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", configPath, err)
	}
	if _, loadErr := config.Load(configPath); loadErr == nil {
		fmt.Printf("mallcop migrate: %s already parses under the current schema — leaving it unchanged\n", config.ConfigFileName)
	} else {
		cfg, warnings, mErr := migrateLegacyConfig(data)
		if mErr != nil {
			return fmt.Errorf("migrating %s: %w (original strict-load error: %v)", config.ConfigFileName, mErr, loadErr)
		}
		// The migrated struct must itself pass the strict loader — otherwise we
		// would write a config the very next `mallcop scan` rejects.
		if vErr := roundTripValidate(cfg); vErr != nil {
			return fmt.Errorf("migrated config failed re-validation (this is a bug, please report): %w", vErr)
		}
		if *dryRun {
			fmt.Printf("mallcop migrate: [dry-run] would rewrite %s to the current schema\n", config.ConfigFileName)
		} else if err := config.WriteConfig(configPath, cfg); err != nil {
			return fmt.Errorf("writing migrated %s: %w", config.ConfigFileName, err)
		} else {
			fmt.Printf("mallcop migrate: rewrote %s to the current schema\n", config.ConfigFileName)
		}
		for _, w := range warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	// --- 2 + 3. workflows + go.mod ----------------------------------------
	divergedCount := 0
	if !*configOnly {
		if *dryRun {
			plan, err := planWorkflowRefresh(absDir, version)
			if err != nil {
				return err
			}
			for _, st := range plan {
				rel := filepath.Join(".github", "workflows", st.Name)
				switch {
				case !st.Existed:
					fmt.Printf("mallcop migrate: [dry-run] would CREATE %s (pinned %s)\n", rel, version)
				case st.Diverged:
					divergedCount++
					fmt.Printf("mallcop migrate: [dry-run] %s has diverged from what mallcop generated (hand-edited since %s) — would be LEFT UNTOUCHED\n", rel, describeFromVersion(st.FromVersion))
				case st.FromVersion == version:
					fmt.Printf("mallcop migrate: [dry-run] %s already pinned to %s — no change\n", rel, version)
				default:
					fmt.Printf("mallcop migrate: [dry-run] would refresh %s: %s -> %s\n", rel, st.FromVersion, version)
				}
			}
			fmt.Printf("mallcop migrate: [dry-run] would refresh go.mod pin to %s (if a github.com/mallcop-app/mallcop require line exists)\n", version)
		} else {
			plan, err := refreshDeployWorkflows(absDir, version)
			if err != nil {
				return err
			}
			for _, st := range plan {
				rel := filepath.Join(".github", "workflows", st.Name)
				switch {
				case st.Diverged:
					divergedCount++
					fmt.Printf("mallcop migrate: SKIPPED %s — diverged from what mallcop generated (hand-edited since %s); left untouched, review it manually\n", rel, describeFromVersion(st.FromVersion))
				case st.Changed:
					fmt.Printf("mallcop migrate: refreshed %s (pinned %s)\n", rel, version)
				default:
					fmt.Printf("mallcop migrate: %s already current — no change\n", rel)
				}
			}

			hadPin, err := refreshGoMod(absDir, version)
			if err != nil {
				return err
			}
			if hadPin {
				fmt.Printf("mallcop migrate: go.mod require github.com/mallcop-app/mallcop pinned to %s\n", version)
			} else {
				fmt.Printf("mallcop migrate: no github.com/mallcop-app/mallcop require line in go.mod — skipped go.mod pin bump\n")
			}
		}
	}

	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  1. Review the changes:   git -C %s diff\n", *dir)
	fmt.Printf("  2. Commit + push:        git -C %s add -A && git -C %s commit -m 'mallcop migrate' && git -C %s push\n", *dir, *dir, *dir)
	fmt.Printf("  3. Ensure the inference key secret is set on the repo:\n")
	fmt.Printf("       gh secret set MALLCOP_API_KEY --repo <owner/name> --body \"$MALLCOP_API_KEY\"\n")

	if divergedCount > 0 {
		return fmt.Errorf("mallcop migrate: PARTIAL — %d managed workflow file(s) were hand-edited since generation and left unchanged (see above); resolve them manually, then re-run", divergedCount)
	}
	return nil
}

// describeFromVersion renders a FromVersion for a log line, covering the
// case where no pin marker could be found at all (predates the marker, or
// isn't a mallcop-generated file).
func describeFromVersion(fromVersion string) string {
	if fromVersion == "" {
		return "an unrecognized version (no MALLCOP_VERSION marker found)"
	}
	return fromVersion
}

// legacyConfig is the pre-v0.10 mallcop.yaml shape (v0.9.3 and earlier). Every
// field is optional and non-strict: this struct exists ONLY to read whatever an
// old deploy repo has so migrateLegacyConfig can carry it forward. Pointers
// distinguish "block absent" from "block present but empty".
type legacyConfig struct {
	Secrets    map[string]any             `yaml:"secrets"`
	Connectors map[string]legacyConnector `yaml:"connectors"`
	Routing    map[string]any             `yaml:"routing"`
	ActorChain map[string]any             `yaml:"actor_chain"`
	Budget     *legacyBudget              `yaml:"budget"`
	Pro        *legacyPro                 `yaml:"pro"`
}

type legacyConnector struct {
	Org            string `yaml:"org"`
	InstallationID int64  `yaml:"installation_id"`
	Path           string `yaml:"path"`
	Source         string `yaml:"source"`
}

type legacyBudget struct {
	MaxFindingsForActors int `yaml:"max_findings_for_actors"`
	MaxTokensPerRun      int `yaml:"max_tokens_per_run"`
	MaxTokensPerFinding  int `yaml:"max_tokens_per_finding"`
}

type legacyPro struct {
	AccountURL   string `yaml:"account_url"`
	InferenceURL string `yaml:"inference_url"`
}

// migrateLegacyConfig maps an old-shape mallcop.yaml onto the current schema,
// starting from config.Defaults() so every unset section keeps its safe
// default. It returns the new Config plus a human-readable list of keys that
// had no equivalent and were DROPPED — surfaced loudly to the operator, never
// silently eaten (rule: no silent spec deviations).
func migrateLegacyConfig(data []byte) (config.Config, []string, error) {
	var legacy legacyConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Non-strict: we are reading an OLD schema by definition.
	if err := dec.Decode(&legacy); err != nil && !errors.Is(err, io.EOF) {
		return config.Config{}, nil, fmt.Errorf("parse legacy config: %w", err)
	}

	cfg := config.Defaults()
	var warnings []string

	// inference: an old `pro:` block with an inference_url means the repo was
	// on the managed donut rail -> map it forward. No pro block -> keep the
	// offline fail-safe default.
	if legacy.Pro != nil && legacy.Pro.InferenceURL != "" {
		cfg.Inference = config.Inference{
			Mode:     "donut",
			Endpoint: legacy.Pro.InferenceURL,
			KeyEnv:   "MALLCOP_API_KEY",
			Model:    cfg.Inference.Model,
		}
	}
	if legacy.Pro != nil && legacy.Pro.AccountURL != "" {
		warnings = append(warnings, "dropped pro.account_url (unused: the donut rail authenticates per-scan via the MALLCOP_API_KEY secret)")
	}

	// connectors: kind->cfg MAP -> []Connector list.
	if len(legacy.Connectors) > 0 {
		kinds := make([]string, 0, len(legacy.Connectors))
		for k := range legacy.Connectors {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds) // deterministic output order
		conns := make([]config.Connector, 0, len(kinds))
		for _, kind := range kinds {
			lc := legacy.Connectors[kind]
			switch kind {
			case "github":
				conns = append(conns, config.Connector{Kind: "github", ID: "github", Org: lc.Org})
				if lc.InstallationID != 0 {
					warnings = append(warnings, "dropped connectors.github.installation_id (GitHub App creds now come from the runner environment, not mallcop.yaml)")
				}
			case "file":
				path := lc.Path
				if path == "" {
					path = "./events.jsonl"
				}
				conns = append(conns, config.Connector{Kind: "file", ID: "file", Path: path})
			default:
				source := lc.Source
				if source == "" {
					source = kind
				}
				conns = append(conns, config.Connector{Kind: "cloud", ID: kind, Source: source})
				warnings = append(warnings, fmt.Sprintf("connector %q migrated as kind:cloud source:%s — review connectors[] in the new mallcop.yaml", kind, source))
			}
		}
		cfg.Connectors = conns
	}

	// budget -> budgets: only max_findings has a home; the token budgets are
	// enforced by the donut rail now.
	if legacy.Budget != nil {
		if legacy.Budget.MaxFindingsForActors > 0 {
			cfg.Budgets.MaxFindings = legacy.Budget.MaxFindingsForActors
		}
		if legacy.Budget.MaxTokensPerRun > 0 || legacy.Budget.MaxTokensPerFinding > 0 {
			warnings = append(warnings, "dropped budget.max_tokens_per_run / max_tokens_per_finding (token budgets are enforced by the donut rail, not mallcop.yaml)")
		}
	}

	// Blocks with no equivalent in the new schema.
	if len(legacy.Secrets) > 0 {
		warnings = append(warnings, "dropped secrets block (credentials are env-var NAMES in the new schema: inference.key_env / connectors[].env)")
	}
	if len(legacy.Routing) > 0 {
		warnings = append(warnings, "dropped routing block (model routing is handled by the donut rail)")
	}
	if len(legacy.ActorChain) > 0 {
		warnings = append(warnings, "dropped actor_chain block (no longer part of mallcop.yaml)")
	}

	return cfg, warnings, nil
}

// roundTripValidate confirms the migrated Config marshals to YAML that the
// STRICT loader accepts — the exact check that matters: the file we are about
// to write must be one the next `mallcop scan`/`config.Load` reads without
// error.
func roundTripValidate(cfg config.Config) error {
	data, err := config.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp, err := os.CreateTemp("", "mallcop-migrate-*.yaml")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	tmp.Close()
	if _, err := config.Load(tmp.Name()); err != nil {
		return err
	}
	return nil
}
