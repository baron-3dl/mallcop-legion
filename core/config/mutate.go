package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file is the SHARED MUTATION PRIMITIVE (rd mallcoppro-2df): the one place
// that knows how to change mallcop.yaml. `mallcop config set connector` /
// `mallcop config set autonomy` (cli/configset.go) call these functions
// directly — they contain NO mutation logic of their own, only flag parsing.
// Any other driver of a config change (a chat surface, a future TUI) MUST
// route through the same functions rather than re-implementing the mutation,
// so the strict-decode contract (KnownFields, secret-shaped value rejection,
// autonomy enum) is enforced identically everywhere a change enters the file.

// AddConnector returns a copy of cfg with conn appended, after validating conn
// in isolation (Kind is one of file/github/cloud; ID is non-empty and unique
// among cfg's existing connectors; Env entries are env-var NAMES, never
// inline secrets — same discipline as validate()) and validating the
// resulting whole config (so a bad connector can never silently corrupt an
// otherwise-valid file). cfg itself is never mutated in place.
func AddConnector(cfg Config, conn Connector) (Config, error) {
	if conn.ID == "" {
		return cfg, fmt.Errorf("config: connector.id is required")
	}
	switch conn.Kind {
	case "file", "github", "cloud":
	default:
		return cfg, fmt.Errorf("config: connector.kind must be one of \"file\", \"github\", \"cloud\" — got %q", conn.Kind)
	}
	for _, existing := range cfg.Connectors {
		if existing.ID == conn.ID {
			return cfg, fmt.Errorf("config: connector id %q already exists — ids must be unique", conn.ID)
		}
	}
	for _, e := range conn.Env {
		if looksLikeSecret(e) {
			return cfg, fmt.Errorf("config: connector %q env must list env-var NAMES, not inline secret values — got %q", conn.ID, e)
		}
	}

	next := cfg
	next.Connectors = append(append([]Connector{}, cfg.Connectors...), conn)

	if err := Validate(next); err != nil {
		return cfg, err
	}
	return next, nil
}

// AddOwned returns a copy of cfg with owned appended to Org.Owned, after
// validating owned in isolation (Match is non-empty and at least minOrgMatchLen
// characters — the SAME floor validate() enforces on load, so a chat- or
// CLI-proposed short/blank match can never silently substring-match every
// identity field and mark unrelated findings owned) and re-validating the
// resulting whole config. cfg itself is never mutated in place.
//
// This is the WRITE last-mile for org-ownership (rd mallcoppro-e07): mallcoppro-995
// shipped the READ side (org.owned static config -> inquest evidence.org_context);
// this is the sanctioned operator-authorized seam that appends an entry, routed
// through WriteConfigAtomic by the caller (cli/configset.go's `config set
// org.owned` and core/investigate's record_owned tool). The loop itself never
// hand-writes mallcop.yaml (R5). org-context stays NAMING-ONLY — an appended
// entry augments narrative + attention, never overrides a committee verdict.
func AddOwned(cfg Config, owned OwnedEntity) (Config, error) {
	if strings.TrimSpace(owned.Match) == "" {
		return cfg, fmt.Errorf("config: org.owned.match must be non-empty — an empty match string substring-matches EVERY identity field, silently marking every finding as owned")
	}
	if len(owned.Match) < minOrgMatchLen {
		return cfg, fmt.Errorf("config: org.owned.match %q is only %d characters — must be at least %d (a full account id or ARN/role-name segment) to avoid false-positive substring matches across unrelated findings", owned.Match, len(owned.Match), minOrgMatchLen)
	}

	next := cfg
	next.Org.Owned = append(append([]OwnedEntity{}, cfg.Org.Owned...), owned)

	if err := Validate(next); err != nil {
		return cfg, err
	}
	return next, nil
}

// SetAutonomy returns a copy of cfg with Learning.Autonomy set to autonomy,
// after validating it is one of the three strict dial positions
// (AutonomyNon / AutonomySemi / AutonomyFully — see IsValidAutonomy). Any
// other value is a loud error, identical to what Load would report for the
// same value in the file — a chat-proposed typo can never silently become a
// new, unvalidated dial position. cfg itself is never mutated in place.
func SetAutonomy(cfg Config, autonomy string) (Config, error) {
	if !IsValidAutonomy(autonomy) {
		return cfg, fmt.Errorf("config: learning.autonomy must be one of %q, %q, %q — got %q", AutonomyNon, AutonomySemi, AutonomyFully, autonomy)
	}
	next := cfg
	next.Learning.Autonomy = autonomy
	if err := Validate(next); err != nil {
		return cfg, err
	}
	return next, nil
}

// SetContributeBack returns a copy of cfg with Learning.ContributeBack set to
// enabled, after re-validating the resulting whole config (mirroring
// SetAutonomy's discipline, even though a bool has no enum to reject —
// Validate is still run so any future cross-field rule on this setting is
// enforced identically to a file-load path). This sets ONLY the STANDING
// opt-in gate documented on Learning.ContributeBack — it does not merge
// anything and does not touch autonomy; the per-improvement confirm is a
// separate, later gate at promote time. cfg itself is never mutated in
// place.
func SetContributeBack(cfg Config, enabled bool) (Config, error) {
	next := cfg
	next.Learning.ContributeBack = enabled
	if err := Validate(next); err != nil {
		return cfg, err
	}
	return next, nil
}

// Validate exports the package's strict cross-field validation (the same
// check Load runs after a successful decode) so callers that build a
// candidate Config in memory — AddConnector/SetAutonomy above, and any future
// mutation — can apply the identical rule set a file load would enforce,
// without duplicating it.
func Validate(cfg Config) error {
	return validate(cfg)
}

// WriteConfigAtomic marshals cfg and atomically replaces the file at path: it
// writes to a temp file in the SAME directory (so the final rename is on one
// filesystem) and renames over path, so a reader (or a concurrent `mallcop
// scan`) never observes a partially-written file — unlike WriteConfig's plain
// os.WriteFile, which a crash mid-write can leave truncated. Mutation entry
// points (cli/configset.go) use this; `mallcop init`'s one-shot create-if-
// absent path keeps using WriteConfig, which is unaffected.
func WriteConfigAtomic(path string, cfg Config) error {
	data, err := Marshal(cfg)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".mallcop-config-*.tmp")
	if err != nil {
		return fmt.Errorf("config: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup: if we return before the rename succeeds, remove the
	// temp file rather than leaving it behind.
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temp file %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("config: chmod temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("config: rename %s -> %s: %w", tmpPath, path, err)
	}
	succeeded = true
	return nil
}
