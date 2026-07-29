package investigate

import (
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
)

// writeConfigAt writes a valid mallcop.yaml with the given autonomy dial and
// contribute-back state into dir, returning the file path. It goes through the
// real config marshal/write path so the on-disk file is exactly what mallcop
// itself would produce and re-load.
func writeConfigAt(t *testing.T, dir, autonomy string, contributeBack bool) string {
	t.Helper()
	cfg := config.Defaults()
	cfg.Learning.Autonomy = autonomy
	cfg.Learning.ContributeBack = contributeBack
	path := filepath.Join(dir, config.ConfigFileName)
	if err := config.WriteConfig(path, cfg); err != nil {
		t.Fatalf("seed mallcop.yaml: %v", err)
	}
	return path
}

// loadAutonomy reads the on-disk mallcop.yaml back and returns its dial — the
// GROUND TRUTH the tool either did or did not change. Reading the real file
// (not the tool's own return value) is what proves "nothing was written" vs
// "committed to a real config on disk".
func loadAutonomy(t *testing.T, path string) config.Config {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload mallcop.yaml: %v", err)
	}
	return cfg
}

// TestToolDefs_IncludesSetConfig proves set_config is actually advertised to
// the model — a tool the loop can execute but never announces is unreachable.
func TestToolDefs_IncludesSetConfig(t *testing.T) {
	names := toolNames(ToolDefs())
	found := false
	for _, n := range names {
		if n == "set_config" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ToolDefs() missing set_config; got %v", names)
	}
}

// TestSetConfig_UnconfirmedDialRaise_Rejected is R3 enforcement (a): raising the
// autonomy dial WITHOUT confirm writes NOTHING and returns a requires-confirm
// proposal. Proven end-to-end through ExecuteTool (the real dispatch + JSON
// decode path the model hits), and verified against the on-disk file, not just
// the return value.
func TestSetConfig_UnconfirmedDialRaise_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":  "autonomy",
		"autonomy": config.AutonomyFully,
		// no "confirm" — this is the unconfirmed raise the R3 hard line must refuse.
	})
	if err != nil {
		t.Fatalf("ExecuteTool returned an error, want a refusal result: %v", err)
	}
	out, ok := res.(SetConfigOutput)
	if !ok {
		t.Fatalf("result type = %T, want SetConfigOutput", res)
	}
	if out.Applied {
		t.Fatalf("unconfirmed dial raise reported Applied=true — R3 hard line breached")
	}
	if !out.RequiresConfirm {
		t.Fatalf("unconfirmed dial raise did not set RequiresConfirm; got %+v", out)
	}
	// Ground truth: the file on disk is untouched.
	if got := loadAutonomy(t, path).Learning.Autonomy; got != config.AutonomyNon {
		t.Fatalf("on-disk autonomy = %q after an unconfirmed raise, want it UNCHANGED at %q", got, config.AutonomyNon)
	}
}

// TestSetConfig_ConfirmedDialRaise_Commits is R3 enforcement (b): an approved
// (confirm=true) raise IS applied and lands in the real config on disk.
func TestSetConfig_ConfirmedDialRaise_Commits(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":  "autonomy",
		"autonomy": config.AutonomyFully,
		"confirm":  true,
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out, ok := res.(SetConfigOutput)
	if !ok {
		t.Fatalf("result type = %T, want SetConfigOutput", res)
	}
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("confirmed raise not applied; got %+v", out)
	}
	// Ground truth: the file on disk now carries the raised dial.
	if got := loadAutonomy(t, path).Learning.Autonomy; got != config.AutonomyFully {
		t.Fatalf("on-disk autonomy = %q after a confirmed raise, want %q", got, config.AutonomyFully)
	}
}

// TestSetConfig_DialLower_NoConfirmNeeded proves the SAFE direction is not
// gated: lowering the dial (a de-escalation) applies without confirm, so the R3
// gate is specific to a RAISE, not a blanket freeze on the setting.
func TestSetConfig_DialLower_NoConfirmNeeded(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyFully, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":  "autonomy",
		"autonomy": config.AutonomyNon,
		// no confirm — lowering is the safe direction.
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out := res.(SetConfigOutput)
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("dial lower should apply without confirm; got %+v", out)
	}
	if got := loadAutonomy(t, path).Learning.Autonomy; got != config.AutonomyNon {
		t.Fatalf("on-disk autonomy = %q after a lower, want %q", got, config.AutonomyNon)
	}
}

// TestSetConfig_UnconfirmedContributeBackEnable_Rejected is R3 enforcement for
// the second hard-line change: enabling contribute-back without confirm writes
// nothing.
func TestSetConfig_UnconfirmedContributeBackEnable_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":         "contribute_back",
		"contribute_back": true,
		// no confirm.
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out := res.(SetConfigOutput)
	if out.Applied || !out.RequiresConfirm {
		t.Fatalf("unconfirmed contribute-back enable must be refused; got %+v", out)
	}
	if got := loadAutonomy(t, path).Learning.ContributeBack; got != false {
		t.Fatalf("contribute_back = %v after an unconfirmed enable, want it UNCHANGED (false)", got)
	}
}

// TestSetConfig_ConfirmedContributeBackEnable_Commits proves the confirmed
// enable is applied to the real file.
func TestSetConfig_ConfirmedContributeBackEnable_Commits(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":         "contribute_back",
		"contribute_back": true,
		"confirm":         true,
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out := res.(SetConfigOutput)
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("confirmed contribute-back enable not applied; got %+v", out)
	}
	if got := loadAutonomy(t, path).Learning.ContributeBack; got != true {
		t.Fatalf("contribute_back = %v after a confirmed enable, want true", got)
	}
}

// TestSetConfig_ContributeBackDisable_NoConfirmNeeded proves DISABLING is the
// safe direction: it applies without confirm.
func TestSetConfig_ContributeBackDisable_NoConfirmNeeded(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, true)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":         "contribute_back",
		"contribute_back": false,
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out := res.(SetConfigOutput)
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("contribute-back disable should apply without confirm; got %+v", out)
	}
	if got := loadAutonomy(t, path).Learning.ContributeBack; got != false {
		t.Fatalf("contribute_back = %v after a disable, want false", got)
	}
}

// TestSetConfig_AddConnector_Applies proves the connector path routes through
// config.AddConnector + WriteConfigAtomic (not a parallel mutation) and lands on
// disk. Adding a connector is not an R3 hard-line change, so no CONFIRM is
// required — but (mallcoppro-bc1e) it IS still gated by the standard
// propose-only autonomy dial, same as record_decision/record_owned/
// dispatch_selfext. This test proves the "auto dial commits" half; the
// propose-only half is TestSetConfig_AddConnector_ProposeOnly_RequiresConfirm
// below.
func TestSetConfig_AddConnector_Applies(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomySemi, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting": "connector",
		"connector": map[string]any{
			"kind": "github",
			"id":   "payments-audit",
			"org":  "acme-payments",
		},
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out := res.(SetConfigOutput)
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("connector add should apply at an auto dial; got %+v", out)
	}
	cfg := loadAutonomy(t, path)
	found := false
	for _, c := range cfg.Connectors {
		if c.ID == "payments-audit" && c.Kind == "github" && c.Org == "acme-payments" {
			found = true
		}
	}
	if !found {
		t.Fatalf("connector payments-audit not present on disk after add; connectors=%+v", cfg.Connectors)
	}
}

// TestSetConfig_AddConnector_ProposeOnly_RequiresConfirm is the antipattern-sweep
// enforcement test for mallcoppro-bc1e: at the propose-only autonomy dial
// (config.AutonomyNon, the default) set_config's "connector" case must NOT
// commit AddConnector unconditionally — it must follow the SAME dial gate as
// the other non-hard-line settings (record_decision et al): commit NOTHING and
// return a requires_confirm proposal.
func TestSetConfig_AddConnector_ProposeOnly_RequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting": "connector",
		"connector": map[string]any{
			"kind": "github",
			"id":   "payments-audit",
			"org":  "acme-payments",
		},
		// no confirm — propose-only must refuse to write.
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out, ok := res.(SetConfigOutput)
	if !ok {
		t.Fatalf("result type = %T, want SetConfigOutput", res)
	}
	if out.Applied {
		t.Fatalf("connector add at propose-only reported Applied=true — dial gate breached")
	}
	if !out.RequiresConfirm {
		t.Fatalf("connector add at propose-only did not set RequiresConfirm; got %+v", out)
	}
	// Ground truth: the file on disk is untouched — the proposed connector was
	// NOT written (defaults may already carry an unrelated connector, so check
	// for absence of this specific one rather than an empty list).
	cfg := loadAutonomy(t, path)
	for _, c := range cfg.Connectors {
		if c.ID == "payments-audit" {
			t.Fatalf("connector payments-audit present on disk after an unconfirmed propose-only add, want it UNWRITTEN; connectors=%+v", cfg.Connectors)
		}
	}
}

// TestSetConfig_AddConnector_ProposeOnly_ConfirmCommits proves the operator's
// confirmed re-issue at propose-only DOES commit — mirroring record_decision's
// confirm-overrides-propose-only behavior for a non-hard-line setting.
func TestSetConfig_AddConnector_ProposeOnly_ConfirmCommits(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting": "connector",
		"connector": map[string]any{
			"kind": "github",
			"id":   "payments-audit",
			"org":  "acme-payments",
		},
		"confirm": true,
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	out := res.(SetConfigOutput)
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("confirmed connector add at propose-only should apply; got %+v", out)
	}
	cfg := loadAutonomy(t, path)
	found := false
	for _, c := range cfg.Connectors {
		if c.ID == "payments-audit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("connector payments-audit not present on disk after confirmed add; connectors=%+v", cfg.Connectors)
	}
}

// TestSetConfig_InvalidAutonomyValue_Errored proves the shared primitive's
// validation is honored (not bypassed): an out-of-enum dial value is a loud tool
// error, and — because it also is not a "raise" over a real position — never
// silently written. confirm=true does not launder an invalid value.
func TestSetConfig_InvalidAutonomyValue_Errored(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	_, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{
		"setting":  "autonomy",
		"autonomy": "turbo",
		"confirm":  true,
	})
	if err == nil {
		t.Fatalf("expected an error for an invalid autonomy value")
	}
	if got := loadAutonomy(t, path).Learning.Autonomy; got != config.AutonomyNon {
		t.Fatalf("on-disk autonomy = %q after an invalid set, want it UNCHANGED at %q", got, config.AutonomyNon)
	}
}

// TestSetConfig_UnknownSetting_Errored guards the switch's default arm.
func TestSetConfig_UnknownSetting_Errored(t *testing.T) {
	dir := t.TempDir()
	writeConfigAt(t, dir, config.AutonomyNon, false)
	if _, err := ExecuteTool(Options{RepoRoot: dir}, "set_config", map[string]any{"setting": "bogus"}); err == nil {
		t.Fatalf("expected an error for an unknown setting")
	}
}
