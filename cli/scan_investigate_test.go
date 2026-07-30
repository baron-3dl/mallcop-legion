package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mallcop-app/mallcop/core/cases"
)

// investigationRecordPath is the on-disk path (inside the store's real work
// tree — syncWorkTree reconciles it after every commit, see core/store's doc)
// of the git-oops force-push finding's investigation record. Case-keyed
// (mallcoppro-42e): core/pipeline resolves EscalatedFinding.CaseID via the
// SAME exported core/cases.CaseID hash over (Type, Actor, Entity), so this
// helper computes the identical case ID rather than a second clustering
// path. Deterministic for gitOopsEvent: core/detect/git_oops.go's force-push
// finding is always Type "git-oops", Actor "dev" (the fixture's ev.Actor),
// and Entity "" (its Evidence carries no grantee/target/member key).
func investigationRecordPath(storePath string) string {
	caseID := cases.CaseID(cases.Key{Type: "git-oops", Actor: "dev", Entity: ""})
	return filepath.Join(storePath, "investigations", caseID+".json")
}

// TestScanInvestigate_OnByDefault_OfflineDegradesHonestly proves detection-time
// investigation (mallcoppro-e3c) runs with ZERO config/flags — the "ships in
// the binary" requirement — and that an offline (nil-client) scan produces an
// honest, evidence-only degraded record rather than silently skipping it.
func TestScanInvestigate_OnByDefault_OfflineDegradesHonestly(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)
	storePath := filepath.Join(dir, "store")

	err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("want findings sentinel, got %v", err)
	}

	if _, statErr := os.Stat(investigationRecordPath(storePath)); statErr != nil {
		t.Fatalf("expected an investigation record at %s (investigate defaults ON with zero flags/config), stat error: %v",
			investigationRecordPath(storePath), statErr)
	}
}

// TestScanInvestigate_NoInvestigateFlag_WritesNoRecord proves --no-investigate
// suppresses detection-time investigation entirely for the run.
func TestScanInvestigate_NoInvestigateFlag_WritesNoRecord(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)
	storePath := filepath.Join(dir, "store")

	err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath, "--no-investigate"})
	if !isFindingsError(err) {
		t.Fatalf("want findings sentinel, got %v", err)
	}

	if _, statErr := os.Stat(investigationRecordPath(storePath)); !os.IsNotExist(statErr) {
		t.Fatalf("expected NO investigation record with --no-investigate, stat error: %v", statErr)
	}
}

// TestScanInvestigate_EnvOffWritesNoRecord proves $MALLCOP_INVESTIGATE=off
// suppresses detection-time investigation, mirroring --no-investigate.
func TestScanInvestigate_EnvOffWritesNoRecord(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)
	storePath := filepath.Join(dir, "store")

	t.Setenv(envInvestigate, "off")
	err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath})
	if !isFindingsError(err) {
		t.Fatalf("want findings sentinel, got %v", err)
	}

	if _, statErr := os.Stat(investigationRecordPath(storePath)); !os.IsNotExist(statErr) {
		t.Fatalf("expected NO investigation record with $%s=off, stat error: %v", envInvestigate, statErr)
	}
}

// TestScanInvestigate_FlagWinsOverEnvOn proves the flag takes the HIGHEST
// precedence: --no-investigate suppresses investigation even when
// $MALLCOP_INVESTIGATE=on is also set.
func TestScanInvestigate_FlagWinsOverEnvOn(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	writeFile(t, eventsPath, gitOopsEvent)
	storePath := filepath.Join(dir, "store")

	t.Setenv(envInvestigate, "on")
	err := runScan([]string{"--store", storePath, "--connector", "file", "--events", eventsPath, "--no-investigate"})
	if !isFindingsError(err) {
		t.Fatalf("want findings sentinel, got %v", err)
	}

	if _, statErr := os.Stat(investigationRecordPath(storePath)); !os.IsNotExist(statErr) {
		t.Fatalf("expected --no-investigate to win over $%s=on, stat error: %v", envInvestigate, statErr)
	}
}
