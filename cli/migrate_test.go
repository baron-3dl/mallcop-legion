package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/config"
)

// customer0LegacyConfig is the EXACT pre-v0.10 (v0.9.3) mallcop.yaml shape the
// customer0 deploy fixture (~/projects/mallcop-deploy) carries — the config the
// strict v0.10 loader rejects with "field secrets not found" /
// "connectors: cannot unmarshal map into []Connector" / "field routing not
// found". This is the ground-truth input `mallcop migrate` must fix.
const customer0LegacyConfig = `secrets:
  backend: env
connectors:
  github:
    org: 3dl-dev
    installation_id: 116376961
routing: {}
actor_chain: {}
budget:
  max_findings_for_actors: 25
  max_tokens_per_run: 50000
  max_tokens_per_finding: 5000
pro:
  account_url: https://api.mallcop.app/api/account
  inference_url: https://api.mallcop.app
`

// TestLegacyConfigIsRejectedByStrictLoader documents the actual breakage this
// item exists to fix: the old shape does NOT load under the current schema.
// If this ever stops failing, the migration is moot and this test should be
// revisited.
func TestLegacyConfigIsRejectedByStrictLoader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.ConfigFileName)
	if err := os.WriteFile(path, []byte(customer0LegacyConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected the legacy config to be REJECTED by the strict loader, but Load succeeded")
	}
}

// TestMigrateLegacyConfigProducesValidSchema is the core proof: the customer0
// legacy config migrates to a Config the strict loader accepts, carrying the
// github org, the donut rail, and the findings budget forward.
func TestMigrateLegacyConfigProducesValidSchema(t *testing.T) {
	cfg, warnings, err := migrateLegacyConfig([]byte(customer0LegacyConfig))
	if err != nil {
		t.Fatalf("migrateLegacyConfig: %v", err)
	}

	// The migrated struct must round-trip through the STRICT loader.
	if err := roundTripValidate(cfg); err != nil {
		t.Fatalf("migrated config failed strict round-trip: %v", err)
	}

	// Donut rail carried over from the old pro block.
	if cfg.Inference.Mode != "donut" {
		t.Errorf("inference.mode = %q, want donut", cfg.Inference.Mode)
	}
	if cfg.Inference.Endpoint != "https://api.mallcop.app" {
		t.Errorf("inference.endpoint = %q, want https://api.mallcop.app", cfg.Inference.Endpoint)
	}
	if cfg.Inference.KeyEnv != "MALLCOP_API_KEY" {
		t.Errorf("inference.key_env = %q, want MALLCOP_API_KEY", cfg.Inference.KeyEnv)
	}

	// github connector: map -> single list entry, installation_id dropped.
	if len(cfg.Connectors) != 1 {
		t.Fatalf("connectors = %+v, want exactly 1", cfg.Connectors)
	}
	c := cfg.Connectors[0]
	if c.Kind != "github" || c.ID != "github" || c.Org != "3dl-dev" {
		t.Errorf("connector = %+v, want kind=github id=github org=3dl-dev", c)
	}

	// findings budget carried over.
	if cfg.Budgets.MaxFindings != 25 {
		t.Errorf("budgets.max_findings = %d, want 25", cfg.Budgets.MaxFindings)
	}

	// every block that actually DROPPED data must be reported loudly. The
	// customer0 fixture's routing:{}/actor_chain:{} are empty, so they carry
	// nothing and correctly produce no warning.
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"secrets", "installation_id", "account_url", "max_tokens"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a warning mentioning %q, got:\n%s", want, joined)
		}
	}
}

// TestMigrateNoProBlockKeepsOffline proves a legacy config with no pro block
// migrates to the offline fail-safe rail (not accidentally donut).
func TestMigrateNoProBlockKeepsOffline(t *testing.T) {
	legacy := `secrets:
  backend: env
connectors:
  github:
    org: acme
budget:
  max_findings_for_actors: 10
`
	cfg, _, err := migrateLegacyConfig([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inference.Mode != "offline" {
		t.Errorf("inference.mode = %q, want offline (no pro block)", cfg.Inference.Mode)
	}
	if err := roundTripValidate(cfg); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
}

// TestRunMigrateInPlace exercises the whole command against a fixture deploy
// repo laid out exactly like customer0: legacy mallcop.yaml, a stale-but-real
// (unmodified since it was generated) scan.yml pinned to an old release, NO
// mallcop-investigate.yml, and a go.mod pinned to the old release. After
// migrate the config loads, both workflows exist pinned to the new release,
// and the go.mod pin is bumped. scan.yml is seeded via renderScanWorkflow
// itself (not a hand-typed stub) so it is byte-identical to what mallcop
// generated at v0.9.3 — i.e. genuinely stale, never hand-edited, exactly the
// mallcoppro-f19 scenario (3dl-dev/mallcop-deploy pinned v0.19.0 with a
// scan.yml predating the doctor-publish step) — which must advance, in
// contrast to a hand-edited file (see TestRunMigrateReportsDivergedWorkflow).
func TestRunMigrateInPlace(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mallcop.yaml"), customer0LegacyConfig)
	mustWrite(t, filepath.Join(dir, "go.mod"), "module github.com/3dl-dev/mallcop-deploy\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop v0.9.3\n")
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "scan.yml"), renderScanWorkflow("v0.9.3"))

	if err := runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.10.1"}); err != nil {
		t.Fatalf("runMigrate: %v", err)
	}

	// config now loads under the strict schema.
	if _, err := config.Load(filepath.Join(dir, "mallcop.yaml")); err != nil {
		t.Fatalf("migrated mallcop.yaml still fails to Load: %v", err)
	}

	// both workflows exist, pinned to the new version.
	scan := mustRead(t, filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if strings.Contains(scan, `MALLCOP_VERSION: "v0.9.3"`) {
		t.Error("scan.yml was not refreshed (still pinned to the old v0.9.3 version)")
	}
	if !strings.Contains(scan, "v0.10.1") {
		t.Error("scan.yml is not pinned to v0.10.1")
	}
	inv := mustRead(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"))
	if !strings.Contains(inv, "v0.10.1") {
		t.Error("mallcop-investigate.yml missing or not pinned to v0.10.1")
	}

	// go.mod pin bumped.
	gomod := mustRead(t, filepath.Join(dir, "go.mod"))
	if !strings.Contains(gomod, "require github.com/mallcop-app/mallcop v0.10.1") {
		t.Errorf("go.mod pin not bumped:\n%s", gomod)
	}
	if !strings.Contains(gomod, "module github.com/3dl-dev/mallcop-deploy") {
		t.Error("go.mod module line was clobbered")
	}
}

// TestRunMigrateIsIdempotent proves a second migrate on an already-migrated
// repo is a no-op that does not corrupt the config.
func TestRunMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "mallcop.yaml"), customer0LegacyConfig)
	mustWrite(t, filepath.Join(dir, "go.mod"), "module x\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop v0.9.3\n")

	if err := runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.10.1"}); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	first := mustRead(t, filepath.Join(dir, "mallcop.yaml"))
	if err := runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.10.1"}); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	second := mustRead(t, filepath.Join(dir, "mallcop.yaml"))
	if first != second {
		t.Errorf("migrate is not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// mustGit runs a git subcommand with a deterministic committer identity, for
// use by the REAL-git-repo integration tests below (mallcoppro-f19
// acceptance: "prove against a REAL git repo").
func mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// initDeployGitRepo creates a real, locally-hosted git deploy repo (working
// tree + a local BARE remote, per the item's "a local bare remote is
// sufficient — do not push to a customer repo as a test side effect")
// seeded with a valid current-schema mallcop.yaml, go.mod pinned to
// oldVersion, and both managed workflows rendered at oldVersion (a
// genuinely stale-but-untouched deploy repo — the mallcoppro-f19 scenario).
// The seed is committed and pushed to the bare remote so the test starts
// from a real, clean git history exactly like a customer's checked-out repo.
func initDeployGitRepo(t *testing.T, oldVersion string) (workDir, remoteDir string) {
	t.Helper()
	remoteDir = t.TempDir()
	if out, err := exec.Command("git", "init", "--quiet", "--bare", "-b", "main", remoteDir).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}

	workDir = t.TempDir()
	mustGit(t, workDir, "init", "-q", "-b", "main")
	mustGit(t, workDir, "config", "user.name", "test")
	mustGit(t, workDir, "config", "user.email", "test@example.com")
	mustGit(t, workDir, "config", "commit.gpgsign", "false")
	mustGit(t, workDir, "remote", "add", "origin", remoteDir)

	if err := config.WriteConfig(filepath.Join(workDir, config.ConfigFileName), config.Defaults()); err != nil {
		t.Fatalf("seeding mallcop.yaml: %v", err)
	}
	mustWrite(t, filepath.Join(workDir, "go.mod"),
		"module github.com/acme/mallcop-deploy\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop "+oldVersion+"\n")
	mustWrite(t, filepath.Join(workDir, ".github", "workflows", "scan.yml"), renderScanWorkflow(oldVersion))
	mustWrite(t, filepath.Join(workDir, ".github", "workflows", "mallcop-investigate.yml"), renderInvestigateWorkflow(oldVersion))

	mustGit(t, workDir, "add", "-A")
	mustGit(t, workDir, "commit", "-q", "-m", "seed: deploy repo at "+oldVersion)
	mustGit(t, workDir, "push", "-q", "origin", "main")
	return workDir, remoteDir
}

// gitPorcelainStatus returns `git status --porcelain` output for dir,
// trimmed. Empty means a clean working tree — nothing a commit would pick up.
func gitPorcelainStatus(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git status --porcelain: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestRunMigrateAdvancesRealRepoAndIsIdempotentThroughGit is the
// mallcoppro-f19 ACCEPTANCE proof, run through the REAL pipeline end to end
// against a real git repo (with a local bare remote, never pushed to a
// customer repo):
//
//  1. A deploy repo genuinely stale at oldVersion (committed, pushed) gets
//     `mallcop migrate` run against it -- both workflows and go.mod advance
//     to newVersion, and `git status --porcelain` shows real, non-empty
//     diffs (proving migrate actually changed tracked content, not just
//     rewrote identical bytes).
//  2. Those changes are committed and pushed (the exact commands migrate's
//     own "Next steps" output tells the operator to run) -- proving the
//     command's output is actually git-committable, non-broken content.
//  3. Running `mallcop migrate` AGAIN at the same newVersion against the
//     now-current repo is a no-op: `git status --porcelain` is EMPTY, i.e.
//     a second commit would have nothing to commit (idempotent, no empty
//     commit) -- the acceptance's central idempotency claim, proven at the
//     git layer, not just by comparing in-memory strings.
func TestRunMigrateAdvancesRealRepoAndIsIdempotentThroughGit(t *testing.T) {
	workDir, remoteDir := initDeployGitRepo(t, "v0.19.0")

	if err := runMigrate([]string{"--dir", workDir, "--mallcop-version", "v0.20.0"}); err != nil {
		t.Fatalf("first runMigrate: %v", err)
	}

	diff := gitPorcelainStatus(t, workDir)
	if diff == "" {
		t.Fatal("first migrate produced no git diff at all -- expected scan.yml/mallcop-investigate.yml/go.mod to advance")
	}
	for _, want := range []string{"scan.yml", "mallcop-investigate.yml", "go.mod"} {
		if !strings.Contains(diff, want) {
			t.Errorf("git status --porcelain does not show %s as changed:\n%s", want, diff)
		}
	}

	scan := mustRead(t, filepath.Join(workDir, ".github", "workflows", "scan.yml"))
	if !strings.Contains(scan, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Errorf("scan.yml not pinned to v0.20.0:\n%s", scan)
	}
	gomod := mustRead(t, filepath.Join(workDir, "go.mod"))
	if !strings.Contains(gomod, "require github.com/mallcop-app/mallcop v0.20.0") {
		t.Errorf("go.mod pin not bumped:\n%s", gomod)
	}

	// Commit + push exactly as migrate's own printed "Next steps" instruct.
	mustGit(t, workDir, "add", "-A")
	mustGit(t, workDir, "commit", "-q", "-m", "mallcop migrate")
	mustGit(t, workDir, "push", "-q", "origin", "main")

	// A real second clone from the bare remote proves the push actually
	// landed the migrated content (not just left it in the working tree).
	cloneDir := t.TempDir()
	if out, err := exec.Command("git", "clone", "--quiet", remoteDir, cloneDir).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	cloneScan := mustRead(t, filepath.Join(cloneDir, ".github", "workflows", "scan.yml"))
	if !strings.Contains(cloneScan, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Errorf("pushed clone's scan.yml is not pinned to v0.20.0:\n%s", cloneScan)
	}

	// Second migrate at the SAME version: idempotent no-op.
	if err := runMigrate([]string{"--dir", workDir, "--mallcop-version", "v0.20.0"}); err != nil {
		t.Fatalf("second runMigrate: %v", err)
	}
	if diff := gitPorcelainStatus(t, workDir); diff != "" {
		t.Fatalf("second migrate at the same version left a git diff (would produce an empty-but-nonempty commit):\n%s", diff)
	}
}

// TestRunMigrateReportsHandEditedWorkflowInsteadOfSteamrolling is the
// mallcoppro-f19 CRITICAL SAFETY proof through the real pipeline: an
// operator hand-edit to scan.yml, committed to a real git repo, survives a
// `mallcop migrate` version bump untouched (git shows NO diff for that
// file), while the untouched sibling mallcop-investigate.yml and go.mod
// still advance -- and the command reports the run as PARTIAL (non-nil
// error), never as a silent success.
func TestRunMigrateReportsHandEditedWorkflowInsteadOfSteamrolling(t *testing.T) {
	workDir, _ := initDeployGitRepo(t, "v0.19.0")

	scanPath := filepath.Join(workDir, ".github", "workflows", "scan.yml")
	handEdited := mustRead(t, scanPath) + "\n# operator: added a Slack notify step here, do not remove\n"
	mustWrite(t, scanPath, handEdited)
	mustGit(t, workDir, "add", "-A")
	mustGit(t, workDir, "commit", "-q", "-m", "operator: customize scan.yml")

	stdout := captureStdout(t, func() {
		err := runMigrate([]string{"--dir", workDir, "--mallcop-version", "v0.20.0"})
		if err == nil {
			t.Fatal("runMigrate must return a non-nil error when a managed workflow was left unchanged due to divergence (partial != success)")
		}
		if !strings.Contains(err.Error(), "PARTIAL") {
			t.Errorf("runMigrate error does not communicate a partial outcome: %v", err)
		}
	})
	if !strings.Contains(stdout, "scan.yml") || !strings.Contains(stdout, "SKIPPED") {
		t.Errorf("runMigrate did not report the hand-edited file as skipped:\n%s", stdout)
	}

	// The hand-edited file must be byte-for-byte untouched -- git shows no
	// diff for it at all.
	diff := gitPorcelainStatus(t, workDir)
	if strings.Contains(diff, "scan.yml") {
		t.Errorf("scan.yml was modified despite being hand-edited (should have been left untouched):\n%s", diff)
	}
	if mustRead(t, scanPath) != handEdited {
		t.Error("scan.yml content changed even though git status shows it clean -- unexpected")
	}

	// The untouched sibling AND go.mod still advanced (partial, not total,
	// failure).
	if !strings.Contains(diff, "mallcop-investigate.yml") {
		t.Errorf("mallcop-investigate.yml (never hand-edited) should still have advanced:\n%s", diff)
	}
	if !strings.Contains(diff, "go.mod") {
		t.Errorf("go.mod should still have advanced despite the workflow divergence:\n%s", diff)
	}
	inv := mustRead(t, filepath.Join(workDir, ".github", "workflows", "mallcop-investigate.yml"))
	if !strings.Contains(inv, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Errorf("mallcop-investigate.yml was not advanced to v0.20.0:\n%s", inv)
	}
}

// seedMigrateDir creates a t.TempDir() deploy-repo fixture with a
// current-schema mallcop.yaml, so runMigrate's config-migration branch is a
// no-op and only the workflow-refresh path under test is exercised. No git
// repo here (unlike initDeployGitRepo) -- these tests target runMigrate's
// --dry-run REPORTING and error-return branches directly, which need only
// real file I/O and the real config loader, not a git history.
func seedMigrateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := config.WriteConfig(filepath.Join(dir, config.ConfigFileName), config.Defaults()); err != nil {
		t.Fatalf("seeding mallcop.yaml: %v", err)
	}
	return dir
}

// stripStampMarker removes the MALLCOP_STAMP marker line and its following
// explanation comment lines from a rendered workflow, WITHOUT touching
// anything else -- simulating a file generated before mallcoppro-f19's
// content-hash provenance tracking existed. Used only to drive runMigrate's
// --dry-run CLI reporting through the Unstamped branch; the SUBSTANTIVE
// claim that a real pre-stamp file is handled correctly is proven separately
// against an actual historical git tag (see
// TestRefreshDeployWorkflowsHandlesGenuinelyOldUnstampedFile in
// deployrepo_test.go) -- this helper only needs to trigger the same code
// path to test the CLI's message formatting and error return.
func stripStampMarker(rendered string) string {
	lines := strings.Split(rendered, "\n")
	out := make([]string, 0, len(lines))
	skipping := false
	for _, line := range lines {
		if strings.HasPrefix(line, `# MALLCOP_STAMP:`) {
			skipping = true
			continue
		}
		if skipping {
			if strings.HasPrefix(line, "#") {
				continue
			}
			skipping = false
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// TestRunMigrateDryRunReportsCreateForMissingWorkflows covers the --dry-run
// CREATE branch (previously entirely untested): a deploy repo with no
// workflow files at all must report "would CREATE" for both managed files,
// write nothing, and return no error.
func TestRunMigrateDryRunReportsCreateForMissingWorkflows(t *testing.T) {
	dir := seedMigrateDir(t)

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.20.0", "--dry-run"})
	})
	if runErr != nil {
		t.Fatalf("dry-run with missing workflows must not error: %v", runErr)
	}
	for _, want := range []string{"would CREATE", "scan.yml", "mallcop-investigate.yml"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".github", "workflows", "scan.yml")); !os.IsNotExist(err) {
		t.Errorf("--dry-run must not actually create scan.yml, stat err=%v", err)
	}
}

// TestRunMigrateDryRunReportsAlreadyPinned covers the --dry-run "already
// pinned, no change" branch (previously entirely untested).
func TestRunMigrateDryRunReportsAlreadyPinned(t *testing.T) {
	dir := seedMigrateDir(t)
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "scan.yml"), renderScanWorkflow("v0.20.0"))
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"), renderInvestigateWorkflow("v0.20.0"))

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.20.0", "--dry-run"})
	})
	if runErr != nil {
		t.Fatalf("dry-run on an already-current repo must not error: %v", runErr)
	}
	if !strings.Contains(stdout, "already pinned to v0.20.0 — no change") {
		t.Errorf("dry-run output missing the already-pinned no-change line:\n%s", stdout)
	}
}

// TestRunMigrateDryRunReportsRefresh covers the --dry-run "would refresh"
// branch (previously entirely untested): a genuinely stale (stamped,
// untouched) workflow at an old version reports "would refresh oldVersion ->
// newVersion", writes nothing, and returns no error.
func TestRunMigrateDryRunReportsRefresh(t *testing.T) {
	dir := seedMigrateDir(t)
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "scan.yml"), renderScanWorkflow("v0.19.0"))
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"), renderInvestigateWorkflow("v0.19.0"))

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.20.0", "--dry-run"})
	})
	if runErr != nil {
		t.Fatalf("dry-run over a genuinely stale repo must not error: %v", runErr)
	}
	if !strings.Contains(stdout, "would refresh") || !strings.Contains(stdout, "v0.19.0 -> v0.20.0") {
		t.Errorf("dry-run output missing the refresh line:\n%s", stdout)
	}
	if got := mustRead(t, filepath.Join(dir, ".github", "workflows", "scan.yml")); !strings.Contains(got, `MALLCOP_VERSION: "v0.19.0"`) {
		t.Error("--dry-run must not actually write the refreshed file")
	}
}

// TestRunMigrateDryRunReportsDivergedAndReturnsPartialError is the
// mallcoppro-f19 REWORK requirement's DIVERGED-branch + dry-run-PARTIAL-error
// coverage (previously entirely untested, on the operator-facing safety
// surface that decides whether someone runs the real command at all): a
// hand-edited scan.yml must be reported "has diverged ... would be LEFT
// UNTOUCHED", and --dry-run itself must return the non-nil PARTIAL error --
// a dry preview of a run that WOULD be partial must not itself report clean
// success.
func TestRunMigrateDryRunReportsDivergedAndReturnsPartialError(t *testing.T) {
	dir := seedMigrateDir(t)
	handEdited := renderScanWorkflow("v0.19.0") + "\n# operator: custom step, do not remove\n"
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "scan.yml"), handEdited)
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"), renderInvestigateWorkflow("v0.19.0"))

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.20.0", "--dry-run"})
	})
	if runErr == nil {
		t.Fatal("--dry-run over a diverged workflow must return a non-nil PARTIAL error, not silent success")
	}
	if !strings.Contains(runErr.Error(), "PARTIAL") {
		t.Errorf("dry-run error does not communicate a partial outcome: %v", runErr)
	}
	if !strings.Contains(stdout, "has diverged from what mallcop generated") || !strings.Contains(stdout, "would be LEFT UNTOUCHED") {
		t.Errorf("dry-run output missing the diverged/left-untouched line:\n%s", stdout)
	}
	if got := mustRead(t, filepath.Join(dir, ".github", "workflows", "scan.yml")); got != handEdited {
		t.Error("--dry-run must never write, even when reporting divergence")
	}
}

// TestRunMigrateDryRunReportsUnstampedAndAdoptFlagAdvances covers the
// --dry-run Unstamped branch (mallcoppro-f19 REWORK requirement, previously
// entirely untested) and the --adopt-unstamped opt-in end to end through the
// CLI: a legacy workflow with a version marker but no content-hash stamp is,
// by default, reported as unverifiable and left untouched with a non-nil
// PARTIAL error; passing --adopt-unstamped instead reports it as an adopted
// refresh and returns no error.
func TestRunMigrateDryRunReportsUnstampedAndAdoptFlagAdvances(t *testing.T) {
	dir := seedMigrateDir(t)
	unstamped := stripStampMarker(renderScanWorkflow("v0.19.0"))
	if strings.Contains(unstamped, "MALLCOP_STAMP") {
		t.Fatalf("test setup bug: stripStampMarker did not remove the stamp:\n%s", unstamped)
	}
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "scan.yml"), unstamped)
	mustWrite(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"), renderInvestigateWorkflow("v0.19.0"))

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.20.0", "--dry-run"})
	})
	if runErr == nil {
		t.Fatal("--dry-run over an unstamped legacy workflow must return a non-nil PARTIAL error by default")
	}
	if !strings.Contains(runErr.Error(), "PARTIAL") {
		t.Errorf("dry-run error does not communicate a partial outcome: %v", runErr)
	}
	if !strings.Contains(stdout, "no provenance stamp") || !strings.Contains(stdout, "would be LEFT UNTOUCHED") {
		t.Errorf("dry-run output missing the unstamped/left-untouched line:\n%s", stdout)
	}

	stdout2 := captureStdout(t, func() {
		runErr = runMigrate([]string{"--dir", dir, "--mallcop-version", "v0.20.0", "--dry-run", "--adopt-unstamped"})
	})
	if runErr != nil {
		t.Fatalf("--dry-run --adopt-unstamped over an unstamped-but-untouched file must not error: %v", runErr)
	}
	if !strings.Contains(stdout2, "would refresh") || !strings.Contains(stdout2, "adopted via --adopt-unstamped") {
		t.Errorf("dry-run --adopt-unstamped output missing the adopted-refresh line:\n%s", stdout2)
	}
}
