package investigate

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/config"
	"github.com/mallcop-app/mallcop/core/inquest"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// TestToolDefs_IncludesRecordOwned proves record_owned is actually advertised to
// the model — a tool the loop can execute but never announces is unreachable.
func TestToolDefs_IncludesRecordOwned(t *testing.T) {
	names := toolNames(ToolDefs())
	found := false
	for _, n := range names {
		if n == "record_owned" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ToolDefs() missing record_owned; got %v", names)
	}
}

// TestRecordOwned_AutoDialCommits is the WRITE last-mile proof (mallcoppro-e07):
// at an auto dial (semi) record_owned commits a real org.owned entry via
// WriteConfigAtomic to a real config on disk with NO confirm required. Proven
// end-to-end through ExecuteTool (the real dispatch + JSON decode path the model
// hits) and verified against the on-disk file, not just the return value.
func TestRecordOwned_AutoDialCommits(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomySemi, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "record_owned", map[string]any{
		"match":        "225635015146",
		"name":         "forge-proxy",
		"relationship": "operator's own hourly inference relay",
		// no confirm — an auto dial auto-applies within blast radius.
	})
	if err != nil {
		t.Fatalf("ExecuteTool(record_owned): %v", err)
	}
	out, ok := res.(RecordOwnedOutput)
	if !ok {
		t.Fatalf("result type = %T, want RecordOwnedOutput", res)
	}
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("out = %+v, want Applied=true RequiresConfirm=false at an auto dial", out)
	}

	// Ground truth: re-read the real file. The entry must be present verbatim.
	cfg := loadAutonomy(t, path)
	if len(cfg.Org.Owned) != 1 {
		t.Fatalf("Org.Owned len = %d, want 1 on disk: %+v", len(cfg.Org.Owned), cfg.Org.Owned)
	}
	want := config.OwnedEntity{Match: "225635015146", Name: "forge-proxy", Relationship: "operator's own hourly inference relay"}
	if cfg.Org.Owned[0] != want {
		t.Fatalf("on-disk owned entity = %+v, want %+v", cfg.Org.Owned[0], want)
	}
}

// TestRecordOwned_ProposeOnlyUnconfirmed_Rejected proves the dial gate: at the
// propose-only dial (autonomy=non) an append WITHOUT confirm writes NOTHING and
// returns a requires-confirm proposal. Verified against the on-disk file.
func TestRecordOwned_ProposeOnlyUnconfirmed_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "record_owned", map[string]any{
		"match": "225635015146",
		"name":  "forge-proxy",
		// no confirm — propose-only must refuse.
	})
	if err != nil {
		t.Fatalf("ExecuteTool returned an error, want a refusal result: %v", err)
	}
	out, ok := res.(RecordOwnedOutput)
	if !ok {
		t.Fatalf("result type = %T, want RecordOwnedOutput", res)
	}
	if out.Applied || !out.RequiresConfirm {
		t.Fatalf("out = %+v, want Applied=false RequiresConfirm=true", out)
	}

	// Ground truth: nothing was written.
	cfg := loadAutonomy(t, path)
	if len(cfg.Org.Owned) != 0 {
		t.Fatalf("Org.Owned = %+v on disk, want empty (nothing written on an unconfirmed propose-only append)", cfg.Org.Owned)
	}
}

// TestRecordOwned_ProposeOnlyConfirmed_Commits proves the operator's Apply path:
// the SAME propose-only append re-issued with confirm=true commits to disk. This
// is the second half of the Apply/Discard affordance.
func TestRecordOwned_ProposeOnlyConfirmed_Commits(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	res, err := ExecuteTool(Options{RepoRoot: dir}, "record_owned", map[string]any{
		"match":   "225635015146",
		"name":    "forge-proxy",
		"confirm": true,
	})
	if err != nil {
		t.Fatalf("ExecuteTool(record_owned confirmed): %v", err)
	}
	out := res.(RecordOwnedOutput)
	if !out.Applied || out.RequiresConfirm {
		t.Fatalf("out = %+v, want Applied=true after confirm", out)
	}
	cfg := loadAutonomy(t, path)
	if len(cfg.Org.Owned) != 1 || cfg.Org.Owned[0].Match != "225635015146" {
		t.Fatalf("Org.Owned = %+v on disk, want the confirmed entry", cfg.Org.Owned)
	}
}

// TestRecordOwned_InvalidMatchIsHardError proves a malformed match (too short —
// below config's minOrgMatchLen floor) is a HARD ERROR the model must fix, never
// a proposal the operator would approve into a broken config, and writes
// nothing. Checked at the propose-only dial so the validation short-circuits the
// proposal path itself.
func TestRecordOwned_InvalidMatchIsHardError(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigAt(t, dir, config.AutonomyNon, false)

	_, err := ExecuteTool(Options{RepoRoot: dir}, "record_owned", map[string]any{
		"match": "aws", // 3 chars — under the 8-char floor
		"name":  "too-short",
	})
	if err == nil {
		t.Fatal("expected a hard error for a too-short match, got nil")
	}
	cfg := loadAutonomy(t, path)
	if len(cfg.Org.Owned) != 0 {
		t.Fatalf("Org.Owned = %+v on disk, want empty after a rejected match", cfg.Org.Owned)
	}
}

// TestRecordOwned_WriteThenInquestAssemblesOrgContext is the FULL enforcement
// loop (mallcoppro-e07): record_owned at an auto dial commits a real org.owned
// entry via WriteConfigAtomic to a real config on disk, and the NEXT scan's
// inquest — fed that config's Org.Owned exactly as cli/scan.go maps it —
// assembles a populated evidence.org_context naming the actor owned. Uses a nil
// inference client so the evidence-only record is written deterministically
// ($0, no model), which still runs the full org-context assembly.
func TestRecordOwned_WriteThenInquestAssemblesOrgContext(t *testing.T) {
	dir := initRepo(t)
	writeConfigAt(t, dir, config.AutonomySemi, false)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	// 1. The model records an owned entity through the tool.
	if _, err := ExecuteTool(Options{RepoRoot: dir, Store: st}, "record_owned", map[string]any{
		"match":        "forge-proxy-relay",
		"name":         "forge-proxy",
		"relationship": "operator's own hourly inference relay",
	}); err != nil {
		t.Fatalf("ExecuteTool(record_owned): %v", err)
	}

	// 2. The NEXT scan reads the config off disk and maps it to inquest's owned
	//    entities EXACTLY as cli/scan.go does.
	cfg, err := config.Load(filepath.Join(dir, config.ConfigFileName))
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if len(cfg.Org.Owned) != 1 {
		t.Fatalf("Org.Owned len = %d after record_owned, want 1", len(cfg.Org.Owned))
	}
	owned := make([]inquest.OwnedEntity, len(cfg.Org.Owned))
	for i, o := range cfg.Org.Owned {
		owned[i] = inquest.OwnedEntity{Match: o.Match, Name: o.Name, Relationship: o.Relationship}
	}

	// 3. Run the scan's investigation over a finding whose actor is the owned
	//    relay. A nil client → an evidence-only record, but org-context is still
	//    assembled from the mapped owned entities.
	in := inquest.Input{
		Store:  st,
		Client: nil,
		Findings: []inquest.EscalatedFinding{{
			Finding:    finding.Finding{ID: "finding-1", Actor: "forge-proxy-relay", Type: "assume_role", Timestamp: time.Now()},
			Resolution: inquest.ResolutionRef{Action: "escalate", Reason: "test"},
		}},
		Config: inquest.Config{Enabled: true, MaxPerScan: 10, MaxTokens: 1024, OwnedEntities: owned},
	}
	out := inquest.RunAll(context.Background(), in)
	if out.Degraded != 1 {
		t.Fatalf("RunAll outcome = %+v, want Degraded=1 (nil client evidence record)", out)
	}

	// 4. The committed evidence record's org_context names the actor owned.
	rec, found, err := inquest.ReadRecord(st, "finding-1")
	if err != nil || !found {
		t.Fatalf("ReadRecord(finding-1): found=%v err=%v", found, err)
	}
	got := rec.Evidence.OrgContext.ActorOwned
	if got == nil {
		t.Fatalf("evidence.org_context.actor_owned = nil, want a match naming the owned relay: %+v", rec.Evidence.OrgContext)
	}
	if got.Name != "forge-proxy" || got.Relationship != "operator's own hourly inference relay" || got.Match != "forge-proxy-relay" {
		t.Fatalf("actor_owned = %+v, want the recorded entity's own match/name/relationship", *got)
	}
}
