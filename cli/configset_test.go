package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
)

// seedConfig writes config.Defaults() to <dir>/mallcop.yaml and returns the path.
func seedConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, config.ConfigFileName)
	if err := config.WriteConfig(path, config.Defaults()); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return path
}

// ---- `mallcop config set connector` ----

func TestConfigSetConnector_AddsSourceAndPersistsToFile(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	err := runConfigSetConnector([]string{
		"--config", path,
		"--kind", "github",
		"--id", "acme-gh",
		"--org", "acme",
	})
	if err != nil {
		t.Fatalf("config set connector: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	found := false
	for _, c := range cfg.Connectors {
		if c.ID == "acme-gh" && c.Kind == "github" && c.Org == "acme" {
			found = true
		}
	}
	if !found {
		t.Fatalf("connector not present on disk after config set: %+v", cfg.Connectors)
	}
}

func TestConfigSetConnector_MissingIDFailsAndFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}

	err = runConfigSetConnector([]string{"--config", path, "--kind", "file", "--path", "./x.jsonl"})
	if err == nil {
		t.Fatal("expected error for missing --id")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after failed set: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("config file changed despite a rejected connector:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestConfigSetConnector_InvalidKindFailsAndFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	before, _ := os.ReadFile(path)

	err := runConfigSetConnector([]string{"--config", path, "--kind", "ftp", "--id", "x"})
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config file changed despite a rejected connector kind")
	}
}

func TestConfigSetConnector_DuplicateIDFailsAndFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	cfg, _ := config.Load(path)
	dupID := cfg.Connectors[0].ID
	before, _ := os.ReadFile(path)

	err := runConfigSetConnector([]string{"--config", path, "--kind", "file", "--id", dupID, "--path", "./y.jsonl"})
	if err == nil {
		t.Fatal("expected error for duplicate connector id")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config file changed despite a rejected duplicate id")
	}
}

// ---- `mallcop config set autonomy` ----

func TestConfigSetAutonomy_ValidValuePersists(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	for _, v := range []string{config.AutonomySemi, config.AutonomyFully, config.AutonomyNon} {
		if err := runConfigSetAutonomy([]string{"--config", path, v}); err != nil {
			t.Fatalf("config set autonomy %s: %v", v, err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("reload after setting %s: %v", v, err)
		}
		if cfg.Learning.Autonomy != v {
			t.Fatalf("autonomy = %q, want %q", cfg.Learning.Autonomy, v)
		}
	}
}

func TestConfigSetAutonomy_InvalidValueFailsAndFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	before, _ := os.ReadFile(path)

	err := runConfigSetAutonomy([]string{"--config", path, "yolo"})
	if err == nil {
		t.Fatal("expected error for invalid autonomy value")
	}
	if !strings.Contains(err.Error(), "yolo") {
		t.Fatalf("error should name the bad value, got: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config file changed despite a rejected autonomy value")
	}
}

func TestConfigSetAutonomy_NoValueErrors(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	if err := runConfigSetAutonomy([]string{"--config", path}); err == nil {
		t.Fatal("expected error when no autonomy value is given")
	}
}

// ---- `mallcop config set contribute_back` ----

func TestConfigSetContributeBack_OnAndOffPersist(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	if cfg.Learning.ContributeBack {
		t.Fatal("seed config should default learning.contribute_back to false")
	}

	if err := runConfigSetContributeBack([]string{"--config", path, "on"}); err != nil {
		t.Fatalf("config set contribute_back on: %v", err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatalf("reload after on: %v", err)
	}
	if !cfg.Learning.ContributeBack {
		t.Fatal("learning.contribute_back not persisted as true after \"on\"")
	}

	if err := runConfigSetContributeBack([]string{"--config", path, "off"}); err != nil {
		t.Fatalf("config set contribute_back off: %v", err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatalf("reload after off: %v", err)
	}
	if cfg.Learning.ContributeBack {
		t.Fatal("learning.contribute_back not persisted as false after \"off\"")
	}
}

func TestConfigSetContributeBack_InvalidValueFailsAndFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	before, _ := os.ReadFile(path)

	err := runConfigSetContributeBack([]string{"--config", path, "true"})
	if err == nil {
		t.Fatal("expected error for value other than on/off")
	}
	if !strings.Contains(err.Error(), "on") || !strings.Contains(err.Error(), "off") {
		t.Fatalf("error should name the accepted values, got: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config file changed despite a rejected contribute_back value")
	}
}

func TestConfigSetContributeBack_NoValueErrors(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)
	if err := runConfigSetContributeBack([]string{"--config", path}); err == nil {
		t.Fatal("expected error when no contribute_back value is given")
	}
}

func TestRunConfigSet_DispatchesContributeBack(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	if err := runConfigSet([]string{"contribute_back", "--config", path, "on"}); err != nil {
		t.Fatalf("config set contribute_back via dispatch: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !cfg.Learning.ContributeBack {
		t.Fatal("learning.contribute_back not persisted via runConfigSet dispatch")
	}
}

// ---- `mallcop config set org.owned` ----

func TestConfigSetOrgOwned_AddsEntryAndPersistsToFile(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	err := runConfigSetOrgOwned([]string{
		"--config", path,
		"--match", "225635015146",
		"--name", "forge-proxy",
		"--relationship", "operator's own hourly inference relay",
	})
	if err != nil {
		t.Fatalf("config set org.owned: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Org.Owned) != 1 {
		t.Fatalf("Org.Owned len = %d on disk, want 1: %+v", len(cfg.Org.Owned), cfg.Org.Owned)
	}
	want := config.OwnedEntity{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"}
	if cfg.Org.Owned[0] != want {
		t.Fatalf("Org.Owned[0] = %+v, want %+v", cfg.Org.Owned[0], want)
	}
}

func TestConfigSetOrgOwned_TooShortMatchFailsAndFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	err := runConfigSetOrgOwned([]string{"--config", path, "--match", "aws", "--name", "too-short"})
	if err == nil {
		t.Fatal("expected error for a too-short --match, got nil")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Org.Owned) != 0 {
		t.Fatalf("Org.Owned = %+v on disk, want empty after a rejected match", cfg.Org.Owned)
	}
}

func TestRunConfigSet_DispatchesOrgOwned(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	if err := runConfigSet([]string{"org.owned", "--config", path, "--match", "225635015146", "--name", "forge-proxy"}); err != nil {
		t.Fatalf("config set org.owned via dispatch: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Org.Owned) != 1 || cfg.Org.Owned[0].Match != "225635015146" {
		t.Fatalf("org.owned not persisted via runConfigSet dispatch: %+v", cfg.Org.Owned)
	}
}

// ---- dispatch (`mallcop config` vs `mallcop config set ...`) ----

func TestRunConfigSet_UnknownTargetErrors(t *testing.T) {
	if err := runConfigSet([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown config-set target")
	}
}

func TestRunConfigSet_NoTargetErrors(t *testing.T) {
	if err := runConfigSet(nil); err == nil {
		t.Fatal("expected error when config set has no target")
	}
}

// ---- CLI-parity: config set drives mallcop scan to pick up the new source ----

// TestConfigSetConnector_TakesEffectOnNextScan is the DONE condition of
// mallcoppro-2df stated in mallcop terms: adding a source via `mallcop config
// set connector` (the linux-mode primitive) causes a subsequent zero-flag
// `mallcop scan` to read from it. We prove the config-level contract here
// (LoadEffective sees the new connector, in connector-declaration order) —
// the full scan-picks-it-up proof (including the offline $0 scan run) is
// exercised end-to-end in mallcop-pro's e2e (same shared primitive, driven
// from a chat-shaped request instead of flags).
func TestConfigSetConnector_TakesEffectOnNextScan(t *testing.T) {
	dir := t.TempDir()
	path := seedConfig(t, dir)

	eventsPath := filepath.Join(dir, "extra-events.jsonl")
	if err := os.WriteFile(eventsPath, []byte(`{"id":"e1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write events fixture: %v", err)
	}

	if err := runConfigSetConnector([]string{
		"--config", path,
		"--kind", "file",
		"--id", "added-by-config-set",
		"--path", eventsPath,
	}); err != nil {
		t.Fatalf("config set connector: %v", err)
	}

	// This is exactly what runScan's zero-flag config path does: LoadEffective
	// then iterate cfg.Connectors building the multi-connector fan-in.
	cfg, resolvedPath, err := config.LoadEffective(path)
	if err != nil {
		t.Fatalf("LoadEffective: %v", err)
	}
	if resolvedPath != path {
		t.Fatalf("resolvedPath = %q, want %q", resolvedPath, path)
	}
	var got *config.Connector
	for i := range cfg.Connectors {
		if cfg.Connectors[i].ID == "added-by-config-set" {
			got = &cfg.Connectors[i]
		}
	}
	if got == nil {
		t.Fatalf("added connector missing from LoadEffective result (scan would not see it): %+v", cfg.Connectors)
	}
	if got.Path != eventsPath {
		t.Fatalf("connector path = %q, want %q", got.Path, eventsPath)
	}
}
