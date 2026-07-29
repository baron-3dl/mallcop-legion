// selfext_reportedmiss_codelane_test.go proves mallcoppro-0e9 (design §Gap B):
// a reported_miss GapCandidate — sourced from the REAL collector
// (core/collect.DetectorGaps), never a hand-rolled stub — seeds the CODE
// lane's opencode.TrustedGap authoring run through gapCandidateToTrustedGap
// and is gated by the EXACT SAME engine path (buildCodeLaneEngine) the
// hand-typed `selfext --run --detector-id ...` flags drive.
//
// VERACITY FIX (mallcoppro-0e9, closing the same standard b42/mallcoppro-b42
// met via cli/selfext_realgate_test.go): an earlier version of this file
// graded every run with rmWriteGreenValidateStub — a shell script that
// unconditionally printed `passed:true, coverage_plus:1` regardless of what
// was authored. That proved the ENGINE'S autonomy-dial routing (the plumbing
// around the gate), but NOT the item's headline claim that a reported_miss
// seed can earn a genuine GREEN, coverage-producing verdict from the REAL
// `mallcop validate-proposal` gate — the stub made GREEN and "no novel gap"
// tautologically true, masking both the RED arm and the novel-gap arm.
//
// Every test below builds and runs the REAL `mallcop` binary (mirroring
// cli/selfext_realgate_test.go / selfext/engine/realgate_test.go's own
// convention) as --validate-bin, with NO --gate-json / stub gate anywhere on
// the path:
//
//   - TestReportedMissCodeLane_RealGate_CoveredWiden_GatedIdenticallyToHandTypedRun_AutoApplies
//     reopens the REAL, already-merged authored-deploy-flood detector's gap
//     (core/detect/authored/deployflood/deployflood.go + its registry.go
//     blank import removed from a fresh clone's BASE commit — the file's own
//     labeled exam pair, exams/scenarios/authored/deployflood-*.yaml, is left
//     untouched and already pinned in the corpus) and proves BOTH the
//     hand-typed `--run` path and the reported_miss `--propose` route restore
//     the EXACT SAME file, earn CoveragePlus>=1 from the REAL gate, and
//     merge-automate to the identical branch at autonomy=fully. Reusing the
//     real, already-production-proven detector+scenario pair (rather than a
//     hand-invented one) means the fixture carries zero risk of an
//     undeclared new firing elsewhere in the corpus — this exact file
//     already runs clean against the WHOLE real corpus on every mallcop CI
//     run today.
//   - TestReportedMissCodeLane_RealGate_NonAutonomyNeverAutoMerges proves the
//     SAME real-gate-GREEN fixture stays Proposed-only (never merge-
//     automated) at the default (non) autonomy dial — R9's dial-gated
//     invariant, now proven against a REAL gate instead of a stub that could
//     not have told the difference between GREEN and RED.
//   - TestReportedMissCodeLane_RealGate_NovelGap_WithholdsMergeAutomationAtFully
//     is the NOVEL-GAP arm the stub could never reach (NovelGap is
//     CUSTOMER-TREE MODE ONLY — Options.ExamRepo — see
//     core/selfgate/validate.go's GateResult.NovelGap doc): a reported_miss
//     GapCandidate seeds a customer-shaped THIN-EMBED target repo (no
//     cmd/mallcop) with a REAL wasip1-sidecar detector (built and graded
//     through the real detecthost/wazero host, per
//     core/selfgate/customerexam.go) targeting a family the reference corpus
//     has ZERO must_fire coverage for. The REAL gate returns Passed=true
//     (the detector is well-behaved: it fires on its own proof pair, stays
//     silent on the reference corpus) AND NovelGap=true — and this test
//     proves engine.Engine's autonomy routing (engine.go: `AutoAppliesCode()
//     && gate.NovelGap` withholds merge automation) actually withholds the
//     merge even at autonomy=fully, reading the real GateResult back out of
//     the emitted artifact's gate.json to confirm NovelGap was really the
//     reason a GREEN proposal never became a branch.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/opencode"
	"github.com/mallcop-app/mallcop/selfext/proposer"
)

// ---- fixture: a real reported_miss GapCandidate, sourced from the REAL
// collector (mirrors selfext_realgate_test.go's realgateOverrideFPGapEnvelope
// for override_fp; this is the report-miss/reported_miss sibling) ----------

func rmInitStoreRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.name", "test")
	run("config", "user.email", "test@example.com")
	run("config", "commit.gpgsign", "false")
	run("commit", "-q", "--allow-empty", "-m", "root")
	return dir
}

// rmRealReportedMissGapCandidate runs `mallcop feedback report-miss`'s
// production write path (an append of a real store.Directive{Op:"report-miss"})
// then the REAL core/collect.DetectorGaps reader over it — proving the
// GapCandidate this test feeds into gapCandidateToTrustedGap is exactly what
// the collector emits in production, not a hand-built stub.
func rmRealReportedMissGapCandidate(t *testing.T, source, eventType, actor string) collect.GapCandidate {
	t.Helper()
	st, err := store.Open(rmInitStoreRepo(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	meta, err := json.Marshal(map[string]any{"source": source, "event_type": eventType, "actor": actor})
	if err != nil {
		t.Fatalf("marshal directive meta: %v", err)
	}
	if _, err := st.Append(store.KindDirectives, store.Directive{
		Op: "report-miss", Actor: "operator", Reason: "operator-witnessed miss (free text, dropped by the collector)",
		Meta: meta,
	}); err != nil {
		t.Fatalf("append report-miss directive: %v", err)
	}

	gaps, err := collect.DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}
	if len(gaps) != 1 || gaps[0].Kind != collect.GapReportedMiss {
		t.Fatalf("harness precondition: want exactly 1 reported_miss gap, got %+v", gaps)
	}
	return gaps[0]
}

// rmCollectGapToProposerGapEnvelope crosses the process boundary exactly like
// production: marshal the real collect.GapCandidate through the SAME
// collectReport wire type `mallcop collect --json` emits, then decode it back
// with proposer.DecodeCollectEnvelope — the identical path runSelfextPropose
// itself uses, so the proposer.GapCandidate under test is never hand-built.
func rmCollectGapToProposerGapEnvelope(t *testing.T, gap collect.GapCandidate) string {
	t.Helper()
	rep := collectReport{SchemaVersion: CollectSchemaVersion, MappingGaps: []collect.MappingGap{}, GapCandidates: []collect.GapCandidate{gap}}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal collect envelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gaps.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write gaps.json: %v", err)
	}
	return path
}

// rmDecodeSingleGapCandidate round-trips a collect envelope through the REAL
// production decode path (proposer.DecodeCollectEnvelope) and returns its one
// proposer.GapCandidate — the same conversion runSelfextPropose itself
// performs, so a test deriving a detector id / package name from it is
// deriving the SAME value production would.
func rmDecodeSingleGapCandidate(t *testing.T, envelopePath string) proposer.GapCandidate {
	t.Helper()
	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	env, err := proposer.DecodeCollectEnvelope(raw)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(env.GapCandidates) != 1 {
		t.Fatalf("want 1 gap candidate in the envelope, got %d", len(env.GapCandidates))
	}
	return env.GapCandidates[0]
}

// ---- unit proof: the mapping + the lane split -------------------------------

// TestGapCandidateToTrustedGap_RealReportedMiss proves gapCandidateToTrustedGap
// maps a REAL collector-sourced reported_miss GapCandidate's structured fields
// onto the TrustedGap fields runSelfextRun's hand-typed flags populate, and
// that filterReportedMissGapCandidates/filterTuningGapCandidates are disjoint
// (design §Gap B's "never double-consume the same operator signal on two
// lanes" invariant).
func TestGapCandidateToTrustedGap_RealReportedMiss(t *testing.T) {
	gap := rmRealReportedMissGapCandidate(t, "payments-provider-x", "payments.transfer_failed", "ci-bot")
	if gap.DetectorFamily != "payments-provider-x" {
		t.Fatalf("harness precondition: want the real collector's family, got %q", gap.DetectorFamily)
	}

	envelopePath := rmCollectGapToProposerGapEnvelope(t, gap)
	pgap := rmDecodeSingleGapCandidate(t, envelopePath)

	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	env, err := proposer.DecodeCollectEnvelope(raw)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	reportedMiss := filterReportedMissGapCandidates(env.GapCandidates)
	tuning := filterTuningGapCandidates(env.GapCandidates)
	if len(reportedMiss) != 1 {
		t.Fatalf("filterReportedMissGapCandidates: want 1, got %d", len(reportedMiss))
	}
	if len(tuning) != 0 {
		t.Fatalf("filterTuningGapCandidates must NOT select a reported_miss gap (double-consumption): got %d", len(tuning))
	}

	got := gapCandidateToTrustedGap(pgap)
	want := opencode.TrustedGap{
		DetectorID:   "authored-payments-provider-x",
		EventType:    "payments.transfer_failed",
		TargetFamily: "payments-provider-x",
		Severity:     "medium", // reported_miss carries no finding -> no finding severity -> the same default --severity uses
		Actor:        "ci-bot",
		Source:       "payments-provider-x",
	}
	if got != want {
		t.Fatalf("gapCandidateToTrustedGap = %+v, want %+v", got, want)
	}
}

// ---- shared real-gate plumbing ----------------------------------------------

var (
	rmBinOnce sync.Once
	rmBinPath string
	rmBinErr  error
)

// rmBuildBinOnce builds the REAL `mallcop` binary (the trusted gate) once per
// test-binary run and caches it. Every test in this file uses the SAME
// --validate-bin (the in-tree lane and the --exam-repo customer-tree lane
// both dispatch through one `mallcop validate-proposal` subprocess contract)
// — building it fresh per test (3x in this file) would triple this file's
// already-slow real-integration wall time for zero additional proof value.
func rmBuildBinOnce(t *testing.T) string {
	t.Helper()
	rmBinOnce.Do(func() {
		root := realgateRepoRoot(t)
		dir, err := os.MkdirTemp("", "mallcop-rm-bin-")
		if err != nil {
			rmBinErr = err
			return
		}
		bin := filepath.Join(dir, "mallcop")
		cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			rmBinErr = fmt.Errorf("go build ./cmd/mallcop: %v\n%s", err, out)
			return
		}
		rmBinPath = bin
	})
	if rmBinErr != nil {
		t.Fatalf("rmBuildBinOnce: %v", rmBinErr)
	}
	return rmBinPath
}

// rmWriteScript writes an executable script into its own fresh temp dir.
func rmWriteScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// rmWriteFileAuthoringStub fakes the headless opencode CLI: it copies srcBytes
// — an exact, byte-for-byte payload, never re-typed into a shell heredoc —
// into $dir/<relPath> inside the worktree opencode.Adapter passes via `--dir`,
// then emits the two JSONL protocol lines the adapter parses (a text turn + a
// "write" tool call), mirroring selfext/engine/engine_test.go's
// writeOpencodeStub convention (duplicated across the package boundary, as
// that file's own header documents).
func rmWriteFileAuthoringStub(t *testing.T, relPath string, srcBytes []byte) string {
	t.Helper()
	payloadDir := t.TempDir()
	payload := filepath.Join(payloadDir, "payload")
	if err := os.WriteFile(payload, srcBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
set -e
d=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--dir" ]; then d="$a"; fi
  prev="$a"
done
mkdir -p "$d/%s"
cp %q "$d/%s"
printf '{"type":"text","text":"authored %s"}\n'
printf '{"type":"tool","tool":"write","state":{"input":{"filePath":%q}}}\n'
exit 0
`, filepath.Dir(relPath), payload, relPath, relPath, relPath)
	return rmWriteScript(t, "opencode-stub.sh", script)
}

// rmWriteMultiFileAuthoringStub is rmWriteFileAuthoringStub for MULTIPLE
// authored files in one opencode invocation (a sidecar detector needs
// main.go PLUS its own scenarios/{must-fire,benign-twin}.yaml). Content is
// authored by THIS test file (not copied from an existing repo file, unlike
// rmWriteFileAuthoringStub) so it is embedded directly rather than staged as
// a side-payload — safe here because every byte is under this test's own
// control.
func rmWriteMultiFileAuthoringStub(t *testing.T, files map[string]string) string {
	t.Helper()
	names := make([]string, 0, len(files))
	for rel := range files {
		names = append(names, rel)
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -e\nd=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"--dir\" ]; then d=\"$a\"; fi\n  prev=\"$a\"\ndone\n")
	for _, rel := range names {
		fmt.Fprintf(&b, "mkdir -p %q\n", "$d/"+filepath.Dir(rel))
	}
	for _, rel := range names {
		fmt.Fprintf(&b, "cat > %q <<'RMFILEEOF'\n%s\nRMFILEEOF\n", "$d/"+rel, files[rel])
	}
	b.WriteString("printf '{\"type\":\"text\",\"text\":\"authored fixture files\"}\\n'\n")
	for _, rel := range names {
		fmt.Fprintf(&b, "printf '{\"type\":\"tool\",\"tool\":\"write\",\"state\":{\"input\":{\"filePath\":%q}}}\\n'\n", rel)
	}
	b.WriteString("exit 0\n")
	return rmWriteScript(t, "opencode-stub.sh", b.String())
}

func rmBranchExists(t *testing.T, repo, branch string) bool {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "rev-parse", "--verify", "refs/heads/"+branch)
	return cmd.Run() == nil
}

// ---- fixture A: reopen the REAL, already-merged authored-deploy-flood gap --

// rmCloneAndReopenDeployfloodGap clones the repo under test
// (realgateCloneRepo) and REOPENS the authored-deploy-flood gap by removing
// the REAL, currently-merged core/detect/authored/deployflood/deployflood.go
// file and its registry.go blank import, committing that as BASE. The
// detector's own labeled exam pair
// (exams/scenarios/authored/deployflood-{must-fire,benign-twin}.yaml) is left
// completely untouched — it is not a fixture this test invents, it is the
// real, already-merged proof pair for this real detector, already pinned in
// the corpus at both base and head. Removing the detector's own-package .go
// file (and only that) makes authored-deploy-flood-must-fire.yaml go RED at
// BASE (no registered detector claims "authored-deploy-flood"); restoring the
// EXACT SAME file at HEAD makes it pass again — a genuine CoveragePlus>=1
// gap-close the real gate grades using code + corpus already proven safe in
// production (zero risk of an accidental new firing elsewhere: this exact
// file already runs clean against the WHOLE real corpus on every mallcop CI
// run today, so there is nothing "invented" here for the widen-monotonicity
// check to catch).
func rmCloneAndReopenDeployfloodGap(t *testing.T) (dir, baseSHA string, deployfloodSrc []byte) {
	t.Helper()
	root := realgateRepoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "core", "detect", "authored", "deployflood", "deployflood.go"))
	if err != nil {
		t.Fatalf("read the real, currently-merged deployflood.go (fixture precondition): %v", err)
	}

	clone := realgateCloneRepo(t)
	if err := os.RemoveAll(filepath.Join(clone, "core", "detect", "authored", "deployflood")); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(clone, "core", "detect", "authored", "registry.go")
	reg, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	const deployfloodImportLine = "\t_ \"github.com/mallcop-app/mallcop/core/detect/authored/deployflood\"\n"
	if !strings.Contains(string(reg), deployfloodImportLine) {
		t.Fatalf("fixture precondition: registry.go does not contain the expected deployflood import line verbatim:\n%s", reg)
	}
	newReg := strings.Replace(string(reg), deployfloodImportLine, "", 1)
	if err := os.WriteFile(registryPath, []byte(newReg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Reformat corpus.pin to the SAME bare "count N\nsha256 X\n" shape
	// engine.go's regenerateCorpusPin (a TRUSTED step Run() calls
	// unconditionally after any authored change, per its own doc) writes —
	// stripping the header comment the real committed file carries. Neither
	// this fixture nor the authoring stub touches any exams/scenarios/*.yaml
	// file, so the recomputed count/sha are IDENTICAL to what is already
	// pinned; only the byte FORMAT differs (header vs. no header). Without
	// this, HEAD's trusted regenerateCorpusPin call would rewrite corpus.pin
	// to the bare shape as a side effect of authoring the UNRELATED
	// deployflood.go file, and the guard's corpus-pin-pairing rule correctly
	// (if here spuriously, for this fixture's purposes) rejects a corpus.pin
	// byte-diff with no accompanying scenario file change. Pre-matching the
	// format at BASE makes HEAD's trusted rewrite a byte-for-byte no-op, so
	// git diff shows no corpus.pin change at all — never a "generic engine"
	// content mutation, just this fixture's BASE construction step.
	count, sha := realgateRecomputeCorpusPin(t, clone)
	pinPath := filepath.Join(clone, "exams", "scenarios", "corpus.pin")
	if err := os.WriteFile(pinPath, []byte(fmt.Sprintf("count %d\nsha256 %s\n", count, sha)), 0o644); err != nil {
		t.Fatal(err)
	}

	realgateGit(t, clone, "add", "-A")
	realgateGit(t, clone, "commit", "-q", "--no-verify", "-m", "fixture base: reopen the authored-deploy-flood gap (remove the real detector + its registry import)")
	return clone, realgateGit(t, clone, "rev-parse", "HEAD"), src
}

// rmReadDeployfloodFromBranch reads the authored file back off the
// merge-automation branch — proof the branch really carries the restored
// detector, not just an empty/placeholder commit.
func rmReadDeployfloodFromBranch(t *testing.T, repo, branch string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "show", branch+":core/detect/authored/deployflood/deployflood.go").CombinedOutput()
	if err != nil {
		t.Fatalf("read authored file off %s: %v: %s", branch, err, out)
	}
	return string(out)
}

// rmReadGateJSON reads back the GateResult the engine wrote into a GREEN
// proposal's artifact directory (engine.go's writeProposalArtifact writes
// gate.json) — the REAL wire struct the `mallcop validate-proposal` subprocess
// produced, round-tripped through engine.GateResult exactly as production
// decodes it. artifactDir is the ArtifactDir passed to the run; this expects
// exactly one proposal-* subdirectory under it.
func rmReadGateJSON(t *testing.T, artifactDir string) engine.GateResult {
	t.Helper()
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		t.Fatalf("read artifact dir %s: %v", artifactDir, err)
	}
	var proposalDir string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "proposal-") {
			proposalDir = filepath.Join(artifactDir, e.Name())
		}
	}
	if proposalDir == "" {
		t.Fatalf("no proposal-* artifact directory found under %s (entries: %v) — the run did not reach a GREEN proposal", artifactDir, entries)
	}
	raw, err := os.ReadFile(filepath.Join(proposalDir, "gate.json"))
	if err != nil {
		t.Fatalf("read gate.json: %v", err)
	}
	var gate engine.GateResult
	if err := json.Unmarshal(raw, &gate); err != nil {
		t.Fatalf("unmarshal gate.json: %v", err)
	}
	return gate
}

// TestReportedMissCodeLane_RealGate_CoveredWiden_GatedIdenticallyToHandTypedRun_AutoApplies
// is the proof the item requires: a reported_miss GapCandidate sourced from
// the REAL collector seeds a TrustedGap-driven CODE-lane authoring run
// through runSelfextPropose, and that run earns a genuine GREEN,
// CoveragePlus>=1 verdict from the REAL `mallcop validate-proposal` gate and
// reaches the SAME dial-gated outcome (autonomy=fully + GREEN gate + no novel
// gap [the in-tree lane never sets NovelGap — see GateResult.NovelGap's doc]
// => Applied, a local merge-automation branch carrying the restored
// deployflood.go) as `selfext --run`'s hand-typed --detector-id/--event-type
// flags reach for the structurally identical gap — because both call the ONE
// engine construction path, buildCodeLaneEngine, never a bespoke
// re-implementation, and both are graded by the SAME real gate binary.
func TestReportedMissCodeLane_RealGate_CoveredWiden_GatedIdenticallyToHandTypedRun_AutoApplies(t *testing.T) {
	bin := rmBuildBinOnce(t)
	// Hermetic reject-set/spend-freeze state: LoadRejectSet("")/the spend-cap
	// gate default to persisting under the REAL developer machine's
	// ~/.cache/mallcop. Every test in this file must isolate its own
	// fingerprint/freeze bookkeeping into a fresh dir per test — both so
	// tests never leak state into each other (a RED run in one test poisoning
	// another test's identical fingerprint) and so running this suite never
	// pollutes a real developer's actual selfext state.
	t.Setenv("MALLCOP_SPEND_DIR", t.TempDir())
	wantBranch := "selfext/applied/authored-deploy-flood"

	// ---- Path A: the hand-typed --run flags (the pre-existing CODE lane) ----
	repoA, baseA, srcA := rmCloneAndReopenDeployfloodGap(t)
	t.Setenv("MALLCOP_RM_TEST_KEY_A", "sk-test-fake")
	runA := runArgs{
		inferenceURL:    "https://inference.example.invalid",
		inferenceKeyEnv: "MALLCOP_RM_TEST_KEY_A",
		targetRepo:      repoA,
		baseRef:         baseA,
		lane:            "heal",
		artifactDir:     t.TempDir(),
		opencodeBin:     rmWriteFileAuthoringStub(t, "core/detect/authored/deployflood/deployflood.go", srcA),
		validateBin:     bin,
		budgetUSD:       2.00,
		autonomy:        autonomy.FullyAutonomy,
		// noJail: the Landlock jail re-execs the binary under an OS sandbox —
		// real, valuable, and already proven separately by
		// selfext/opencode/jail_policy_test.go. This test's fake opencode
		// binary is a plain shell script; running IT through the real jail
		// (as engine_test.go's own fixtures never do — see realAdapter)
		// exercises the sandbox launcher, not the autonomy/gate wiring under
		// test here, and can behave unpredictably in a nested container.
		noJail:       true,
		detectorID:   "authored-deploy-flood",
		eventType:    "github.deployment",
		targetFamily: "deploy-flood",
		severity:     "high",
		actor:        "burst-actor",
		source:       "github",
	}
	if err := runSelfextRun(runA); err != nil {
		t.Fatalf("runSelfextRun (hand-typed): %v", err)
	}
	if !rmBranchExists(t, repoA, wantBranch) {
		t.Fatalf("hand-typed --run path: expected merge-automation branch %q in %s, not found", wantBranch, repoA)
	}
	gotA := rmReadDeployfloodFromBranch(t, repoA, wantBranch)
	if gotA != string(srcA) {
		t.Fatalf("hand-typed --run path: merge-automation branch's authored file does not match the real deployflood.go byte-for-byte")
	}
	gateA := rmReadGateJSON(t, runA.artifactDir)
	if !gateA.Passed {
		t.Fatalf("hand-typed --run path: real gate did not certify GREEN: %+v", gateA)
	}
	if gateA.CoveragePlus < 1 {
		t.Fatalf("hand-typed --run path: real gate CoveragePlus = %d, want >=1 (the reopened authored-deploy-flood-must-fire.yaml gap must close)", gateA.CoveragePlus)
	}
	if gateA.NovelGap {
		t.Fatalf("hand-typed --run path: in-tree lane must never set NovelGap, got true: %+v", gateA)
	}

	// ---- Path B: the reported_miss GapCandidate CODE-lane seed (mallcoppro-0e9) ----
	repoB, baseB, srcB := rmCloneAndReopenDeployfloodGap(t)
	gap := rmRealReportedMissGapCandidate(t, "deploy-flood", "github.deployment", "burst-actor")
	collectJSON := rmCollectGapToProposerGapEnvelope(t, gap)

	t.Setenv("MALLCOP_RM_TEST_KEY_B", "sk-test-fake")
	proposeArtifactDir := t.TempDir()
	err := runSelfextPropose(proposeArgs{
		inferenceURL:    "https://inference.example.invalid",
		inferenceKeyEnv: "MALLCOP_RM_TEST_KEY_B",
		collectJSON:     collectJSON,
		storeRepo:       t.TempDir(), // unused by the CODE lane; DATA lane writes here (no tuning/mapping gaps present)
		targetRepo:      repoB,
		baseRef:         baseB,
		lane:            "heal",
		artifactDir:     proposeArtifactDir,
		opencodeBin:     rmWriteFileAuthoringStub(t, "core/detect/authored/deployflood/deployflood.go", srcB),
		validateBin:     bin,
		budgetUSD:       2.00,
		autonomy:        autonomy.FullyAutonomy,
		noJail:          true, // see Path A's noJail comment above
	})
	if err != nil {
		t.Fatalf("runSelfextPropose (reported_miss CODE-lane route): %v", err)
	}
	if !rmBranchExists(t, repoB, wantBranch) {
		t.Fatalf("reported_miss CODE-lane route: expected the SAME merge-automation branch %q in %s as the hand-typed path, not found — gating diverged", wantBranch, repoB)
	}
	gotB := rmReadDeployfloodFromBranch(t, repoB, wantBranch)
	if gotB != string(srcB) {
		t.Fatalf("reported_miss CODE-lane route: merge-automation branch's authored file does not match the real deployflood.go byte-for-byte")
	}
	if gotB != gotA {
		t.Fatalf("hand-typed and reported_miss routes produced DIFFERENT authored content — gating/authoring diverged between the two entry points")
	}
	gateB := rmReadGateJSON(t, proposeArtifactDir)
	if !gateB.Passed {
		t.Fatalf("reported_miss CODE-lane route: real gate did not certify GREEN: %+v", gateB)
	}
	if gateB.CoveragePlus < 1 {
		t.Fatalf("reported_miss CODE-lane route: real gate CoveragePlus = %d, want >=1", gateB.CoveragePlus)
	}
	if gateB.NovelGap {
		t.Fatalf("reported_miss CODE-lane route: in-tree lane must never set NovelGap, got true: %+v", gateB)
	}
}

// TestReportedMissCodeLane_RealGate_NonAutonomyNeverAutoMerges proves the
// DIAL-GATED invariant the item calls out explicitly: at the default (non)
// autonomy dial a reported_miss-seeded CODE-lane run reaches a REAL, GREEN,
// CoveragePlus>=1 gate verdict but NEVER merge-automates — the same rule
// engine.Engine already enforces for the hand-typed path, now proven against
// the REAL gate (not a stub that could not distinguish GREEN from RED) for
// the GapCandidate-seeded origin.
func TestReportedMissCodeLane_RealGate_NonAutonomyNeverAutoMerges(t *testing.T) {
	bin := rmBuildBinOnce(t)
	t.Setenv("MALLCOP_SPEND_DIR", t.TempDir()) // see the parity test's comment on this
	repo, base, src := rmCloneAndReopenDeployfloodGap(t)

	gap := rmRealReportedMissGapCandidate(t, "deploy-flood", "github.deployment", "burst-actor")
	collectJSON := rmCollectGapToProposerGapEnvelope(t, gap)

	t.Setenv("MALLCOP_RM_TEST_KEY2", "sk-test-fake")
	artifactDir := t.TempDir()
	err := runSelfextPropose(proposeArgs{
		inferenceURL:    "https://inference.example.invalid",
		inferenceKeyEnv: "MALLCOP_RM_TEST_KEY2",
		collectJSON:     collectJSON,
		storeRepo:       t.TempDir(),
		targetRepo:      repo,
		baseRef:         base,
		lane:            "heal",
		artifactDir:     artifactDir,
		opencodeBin:     rmWriteFileAuthoringStub(t, "core/detect/authored/deployflood/deployflood.go", src),
		validateBin:     bin,
		budgetUSD:       2.00,
		autonomy:        autonomy.NonAutonomy, // default dial: propose-only
		noJail:          true,                 // see the parity test's noJail comment
	})
	if err != nil {
		t.Fatalf("runSelfextPropose: %v", err)
	}
	wantBranch := "selfext/applied/authored-deploy-flood"
	if rmBranchExists(t, repo, wantBranch) {
		t.Fatalf("autonomy=non: reported_miss CODE-lane route merge-automated a branch (%q) — must stay propose-only until autonomy=fully", wantBranch)
	}
	gate := rmReadGateJSON(t, artifactDir)
	if !gate.Passed {
		t.Fatalf("autonomy=non: real gate did not certify GREEN (the proposal must still be genuinely GREEN, just not merged): %+v", gate)
	}
	if gate.CoveragePlus < 1 {
		t.Fatalf("autonomy=non: real gate CoveragePlus = %d, want >=1", gate.CoveragePlus)
	}
}

// ---- fixture B: a customer-shaped sidecar detector for a genuinely NOVEL
// family (zero reference-corpus must_fire coverage) ---------------------------

const (
	rmNovelGapSource    = "rm-novelgap-quarantine"
	rmNovelGapEventType = "widget-quarantine-event"
	rmNovelGapActor     = "cust-actor"
)

// rmSidecarMainSrc is a REAL, NARROW, well-behaved customer-tree wasip1
// sidecar detector (package main, detectorhost.Run) — the exact shape
// core/selfgate/novelgap_test.go's novelNarrowDetectorSrc / customergate_test.go's
// customerFixtureDetectorMainSrc establish as gate-passing (duplicated across
// the package/module boundary, that file's own header convention). It fires
// ONLY on event_type rmNovelGapEventType with a payload action=="breach",
// staying silent on the SAME event_type with action=="routine" — a measured
// minimal mutation. rmNovelGapEventType never occurs anywhere in the real
// reference corpus, so this detector emits nothing when graded against it
// (the held-out-corpus control has nothing to reject); its own scenarios
// below are what prove it, and the reference corpus's total silence on the
// family is exactly what makes NovelGap true.
func rmSidecarMainSrc(detectorID string) string {
	return `package main

import (
	"encoding/json"
	"os"

	"github.com/mallcop-app/mallcop/pkg/baseline"
	"github.com/mallcop-app/mallcop/pkg/detectorhost"
	"github.com/mallcop-app/mallcop/pkg/event"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

type rmNovelGapDetector struct{}

func (rmNovelGapDetector) Name() string { return "` + detectorID + `" }

func (rmNovelGapDetector) Detect(events []event.Event, _ *baseline.Baseline) []finding.Finding {
	var out []finding.Finding
	for _, ev := range events {
		if ev.Type != "` + rmNovelGapEventType + `" {
			continue
		}
		var payload struct {
			Action string ` + "`json:\"action\"`" + `
		}
		_ = json.Unmarshal(ev.Payload, &payload)
		if payload.Action != "breach" {
			continue
		}
		out = append(out, finding.Finding{
			ID:     "finding-" + ev.ID + "-rmnovelgap",
			Source: "detector:` + detectorID + `",
			Type:   "` + detectorID + `",
			Actor:  ev.Actor,
		})
	}
	return out
}

func main() { os.Exit(detectorhost.Run(rmNovelGapDetector{})) }
`
}

func rmSidecarMustFireYAML(detectorID string) string {
	return `id: RM-NOVELGAP-01-must-fire
finding:
  id: fnd_rmnovelgap_01
  detector: ` + detectorID + `
  title: 'rm novel-gap: quarantine breach'
  severity: high
events:
- id: evt_rmnovelgap_01
  timestamp: '2026-07-01T00:30:00Z'
  source: customer-app
  event_type: ` + rmNovelGapEventType + `
  actor: ` + rmNovelGapActor + `
  action: breach
expected_detection:
  must_fire:
  - ` + detectorID + `
`
}

func rmSidecarBenignTwinYAML(detectorID string) string {
	return `id: RM-NOVELGAP-02-benign-twin
finding:
  id: fnd_rmnovelgap_02
  detector: ` + detectorID + `
  title: 'rm novel-gap: quarantine routine (measured minimal mutation: same event_type/actor/source, action differs)'
  severity: warn
events:
- id: evt_rmnovelgap_02
  timestamp: '2026-07-01T00:35:00Z'
  source: customer-app
  event_type: ` + rmNovelGapEventType + `
  actor: ` + rmNovelGapActor + `
  action: routine
expected_detection:
  must_not_fire:
  - ` + detectorID + `
`
}

// rmInitThinCustomerRepo creates a git repo shaped like a REAL `mallcop init
// --create-repo` THIN-EMBED customer deployment (mirrors
// core/selfgate/customergate_test.go's buildCustomerShapedRepo and
// selfext/engine/engine_test.go's initThinCustomerRepo — duplicated across
// the package/module boundary, the same convention those two files document
// for one another): go.mod requires+replaces github.com/mallcop-app/mallcop
// back to the repo under test (offline-safe, no proxy needed), with NO
// cmd/mallcop and NO core/detect/authored/ tree at all — the customerShaped
// signal buildCodeLaneEngine's real gate reads via hasCmdMallcop. go.sum is
// precomputed via a scratch detector importing the SAME framework surface a
// real sidecar needs (pkg/baseline/detectorhost/event/finding), then removed
// BEFORE the base commit, so base and head share a byte-identical
// go.mod/go.sum pair — the guard's protected-module-files rule never fires
// for either commit this fixture builds.
func rmInitThinCustomerRepo(t *testing.T) (dir, baseSHA string) {
	t.Helper()
	mallcopRoot := realgateRepoRoot(t)
	dir = t.TempDir()
	realgateGit(t, dir, "init", "-q", "-b", "main")

	goMod := fmt.Sprintf(`module example.com/rm-novelgap-fixture

go 1.25.0

require github.com/mallcop-app/mallcop v0.0.0-00010101000000-000000000000

replace github.com/mallcop-app/mallcop => %s
`, mallcopRoot)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("customer deployment repo (THIN-EMBED fixture, mallcoppro-0e9)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scratchDir := filepath.Join(dir, "detectors", "tidyscratch")
	if err := os.MkdirAll(scratchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratchDir, "main.go"), []byte(rmSidecarMainSrc("scratch-tidy-only")), 0o644); err != nil {
		t.Fatal(err)
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy (precompute go.sum offline via replace): %v\n%s", err, out)
	}
	if err := os.RemoveAll(scratchDir); err != nil {
		t.Fatal(err)
	}

	realgateGit(t, dir, "add", "-A")
	realgateGit(t, dir, "commit", "-q", "--no-verify", "-m", "fixture base: THIN-EMBED scaffold, no cmd/mallcop, no core/detect/authored")
	return dir, realgateGit(t, dir, "rev-parse", "HEAD")
}

// TestReportedMissCodeLane_RealGate_NovelGap_WithholdsMergeAutomationAtFully
// is the NOVEL-GAP arm the earlier stub-gated version of this file could
// never reach (NovelGap is CUSTOMER-TREE MODE ONLY — see
// core/selfgate/validate.go's GateResult.NovelGap doc — and a stub `mallcop
// validate-proposal` replacement has no way to compute it against a real
// reference corpus). A reported_miss GapCandidate seeds a customer-shaped
// THIN-EMBED target repo with a real wasip1-sidecar detector (built and
// graded through the real detecthost/wazero host) targeting a family the
// reference corpus (an unmodified real clone of the repo under test) has
// ZERO must_fire coverage for. The real gate must certify Passed=true (the
// detector proves itself against its own must-fire/benign-twin pair and
// never fires on the reference corpus) AND NovelGap=true — and
// engine.Engine's autonomy routing must withhold merge automation EVEN AT
// autonomy=fully (engine.go: `AutoAppliesCode() && gate.NovelGap` forces
// human review regardless of the dial), proving
// "AutoAppliesCode() && NovelGap => not merged" against the real gate, not a
// stub that could not have produced NovelGap in the first place.
func TestReportedMissCodeLane_RealGate_NovelGap_WithholdsMergeAutomationAtFully(t *testing.T) {
	bin := rmBuildBinOnce(t)
	t.Setenv("MALLCOP_SPEND_DIR", t.TempDir()) // see the parity test's comment on this
	// The reference tree: an UNMODIFIED real clone of the repo under test —
	// its own pinned corpus has no opinion at all about rmNovelGapEventType /
	// the family this fixture declares, which is exactly what makes the
	// resulting gate verdict NovelGap=true.
	examRepo := realgateCloneRepo(t)

	gap := rmRealReportedMissGapCandidate(t, rmNovelGapSource, rmNovelGapEventType, rmNovelGapActor)
	collectJSON := rmCollectGapToProposerGapEnvelope(t, gap)
	pgap := rmDecodeSingleGapCandidate(t, collectJSON)
	trustedGap := gapCandidateToTrustedGap(pgap)
	if trustedGap.DetectorID == "" || trustedGap.PackageName() == "" {
		t.Fatalf("harness precondition: derived TrustedGap/package name empty: %+v", trustedGap)
	}
	detectorID := trustedGap.DetectorID
	pkg := trustedGap.PackageName()

	customerRepo, baseSHA := rmInitThinCustomerRepo(t)
	opencodeBin := rmWriteMultiFileAuthoringStub(t, map[string]string{
		"detectors/" + pkg + "/main.go":                   rmSidecarMainSrc(detectorID),
		"detectors/" + pkg + "/scenarios/must-fire.yaml":   rmSidecarMustFireYAML(detectorID),
		"detectors/" + pkg + "/scenarios/benign-twin.yaml": rmSidecarBenignTwinYAML(detectorID),
	})

	t.Setenv("MALLCOP_RM_NOVELGAP_KEY", "sk-test-fake")
	artifactDir := t.TempDir()
	err := runSelfextPropose(proposeArgs{
		inferenceURL:    "https://inference.example.invalid",
		inferenceKeyEnv: "MALLCOP_RM_NOVELGAP_KEY",
		collectJSON:     collectJSON,
		storeRepo:       t.TempDir(),
		targetRepo:      customerRepo,
		baseRef:         baseSHA,
		lane:            "heal",
		artifactDir:     artifactDir,
		opencodeBin:     opencodeBin,
		validateBin:     bin,
		examRepo:        examRepo,
		budgetUSD:       2.00,
		autonomy:        autonomy.FullyAutonomy, // the most permissive dial — the strongest proof NovelGap still withholds merge
		noJail:          true,
	})
	if err != nil {
		t.Fatalf("runSelfextPropose (reported_miss CODE-lane, customer-shaped/NovelGap route): %v", err)
	}

	wantBranch := "selfext/applied/" + detectorID
	if rmBranchExists(t, customerRepo, wantBranch) {
		t.Fatalf("autonomy=fully NovelGap=true: merge automation must be withheld, but branch %q exists in %s", wantBranch, customerRepo)
	}

	gate := rmReadGateJSON(t, artifactDir)
	if !gate.Passed {
		t.Fatalf("expected the real gate to certify GREEN for a well-behaved narrow detector, got Passed=false: %+v", gate)
	}
	if !gate.NovelGap {
		t.Fatalf("expected the real gate to flag NovelGap=true (zero reference-corpus must_fire coverage for %q), got false: %+v", detectorID, gate)
	}
	found := false
	for _, fam := range gate.NovelGapFamilies {
		if fam == detectorID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected NovelGapFamilies to name %q, got %v", detectorID, gate.NovelGapFamilies)
	}
}
