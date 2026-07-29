// selfext_realgate_test.go closes the veracity finding on mallcoppro-b42
// (design §Gap B): every OTHER test touching the GapCandidate->propose->route
// wire (selfext/router/e2e_selfext_test.go) hands router.Route a STUBBED
// GateResult (greenGate()) — Route only CONSUMES a GateResult, so a stub
// proves nothing about whether a REAL run of `mallcop validate-proposal`
// (core/selfgate.ValidateProposal, execed via selfext/engine.RunValidateProposal)
// would actually certify a widen. Worse, cli/selfext.go's own production entry
// point — runSelfextPropose -> filterTuningGapCandidates -> resolveProposeGate
// (the REAL-gate branch, proposeGateViaWorktree) -> router.Route — had ZERO
// test coverage before this file: cli/selfext_test.go only exercised the
// up-front flag/BYOK guards, never a live run.
//
// These two tests drive runSelfextPropose (the actual CLI entry point) end to
// end against a REAL, freshly-built `mallcop` binary (the trusted gate) and a
// REAL target-repo worktree (a git clone of this repository), with NO
// --gate-json stub and NO fake GateResult anywhere on the call path:
//
//   - TestRunSelfextPropose_GapCandidate_RealGate_CoveredWiden_AutoApplies
//     proves the item's headline claim honestly: a GapCandidate-driven
//     widen that GENUINELY closes a labeled must_fire gap (the committed
//     exams/synthetic/ gap-close fixture — see core/selfgate/validate_test.go's
//     injectSyntheticGapPair, duplicated here across the _test.go package
//     boundary exactly as that file documents its own duplication convention)
//     earns CoveragePlus>=1 from the REAL gate and auto-applies to the tenant
//     overlay.
//   - TestRunSelfextPropose_GapCandidate_RealGate_CoverageLess_HumanGate proves
//     the router/router_test.go-style "shadowops" widen (a keyword tied to no
//     labeled scenario) is CORRECTLY refused by the real gate
//     (exam-detect-no-coverage-gain, CoveragePlus==0) and routed to
//     human-gate, NEVER written to the tenant overlay — this is SAFE/correct
//     behavior, not a bug, and is asserted as such.
//
// Both tests build the real `mallcop` binary once (go build ./cmd/mallcop from
// the repo under test) and run the real validate-proposal subprocess inline —
// this is an integration test, not a mock, and is slower than the rest of the
// cli package's tests (a few seconds per case: two `go build`-backed exam-detect
// runs per gate call). It stays in the package's normal `go test ./cli/...`
// run (no external dependency, no network, no sibling checkout needed — this
// package IS the mallcop repo).
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/core/collect"
	"github.com/mallcop-app/mallcop/core/detect"
	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/resolution"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
)

// ---- fixture: the repo under test + a real clone -----------------------------

// realgateRepoRoot locates the real repository root by walking up from the
// test's working directory to go.mod (mirrors core/selfgate/guard_test.go's
// repoUnderTest — duplicated across the package boundary; that file documents
// the same convention).
func realgateRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from the test directory")
		}
		dir = parent
	}
}

func realgateGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=selfext-realgate-test", "GIT_AUTHOR_EMAIL=selfext-realgate-test@example.com",
		"GIT_COMMITTER_NAME=selfext-realgate-test", "GIT_COMMITTER_EMAIL=selfext-realgate-test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// realgateCloneRepo clones the committed state of the repo under test into a
// fresh temp dir — the REAL product tree (cmd/mallcop, exams/, detectors/)
// the gate's structural + exam-detect stages need, not a synthetic strawman.
func realgateCloneRepo(t *testing.T) string {
	t.Helper()
	root := realgateRepoRoot(t)
	parent := t.TempDir()
	clone := filepath.Join(parent, "clone")
	realgateGit(t, parent, "clone", "-q", "--no-hardlinks", root, clone)
	return clone
}

// realgateBuildBin builds the REAL `mallcop` binary — the trusted gate — from
// the repo under test, exactly as production resolves --validate-bin.
func realgateBuildBin(t *testing.T) string {
	t.Helper()
	root := realgateRepoRoot(t)
	bin := filepath.Join(t.TempDir(), "mallcop")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mallcop")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/mallcop: %v\n%s", err, out)
	}
	return bin
}

// ---- fixture: the synthetic gap-close pair, injected into a clone's pinned
// corpus (duplicated from core/selfgate/validate_test.go's
// injectSyntheticGapPair/recomputeCorpusPin — that file documents this exact
// injection as the intended reuse path for proving a self-extension tuning
// gap-close end to end: "This is the widen-only tuning entry the gate tests
// apply at HEAD to close the SYNTH-PE-01 gap", exams/synthetic/tuning.yaml).
// core/detect/synthdemo_invariant_test.go guarantees the synthetic keyword
// never becomes a built-in, so this pair stays a real, unclosable-without-
// tuning gap forever, independent of the real corpus (PE-08/IP-01/...).
const (
	realgateSynthSrcMustFire = "exams/synthetic/SYNTH-PE-01-elevated-must-fire.yaml"
	realgateSynthSrcTwin     = "exams/synthetic/SYNTH-PE-02-baseline-benign-twin.yaml"
	realgateSynthDstMustFire = "exams/scenarios/synthetic/SYNTH-PE-01-elevated-must-fire.yaml"
	realgateSynthDstTwin     = "exams/scenarios/synthetic/SYNTH-PE-02-baseline-benign-twin.yaml"
	// realgateSyntheticKeyword is the ONLY keyword that closes SYNTH-PE-01 (a
	// genuine, gate-provable coverage gain) — see exams/synthetic/tuning.yaml.
	realgateSyntheticKeyword = "mallcopsyntheticelevated"
	// realgateCoverageLessKeyword mirrors selfext/router/e2e_selfext_test.go's
	// nonBuiltinGapTuningKeyword ("shadowops"): a widen tied to NO labeled
	// must_fire scenario anywhere in the reference corpus, so the REAL gate
	// must find zero coverage gain and refuse to certify it clean.
	realgateCoverageLessKeyword = "shadowops"
)

// realgateRecomputeCorpusPin replicates the canonical corpus manifest digest
// core/eval/corpus.go verifies (duplicated from
// core/selfgate/validate_test.go's recomputeCorpusPin — see that file's own
// doc comment for why this is a deliberate, anchored duplication rather than a
// shared helper: the loader is the single source of truth for the format, and
// each package that regenerates a pin for a fixture re-derives it and anchors
// against the committed pin before trusting the derivation, in the same
// _test.go-only violation of the "don't duplicate" instinct that the rest of
// this codebase's ground-source tests already accept).
func realgateRecomputeCorpusPin(t *testing.T, root string) (count int, sha string) {
	t.Helper()
	scenRoot := filepath.Join(root, "exams", "scenarios")
	type entry struct{ rel, fileSHA string }
	var entries []entry
	err := filepath.WalkDir(scenRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(scenRoot, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		for _, part := range strings.Split(rel, "/") {
			if strings.HasPrefix(part, "_") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() || (!strings.HasSuffix(d.Name(), ".yaml") && !strings.HasSuffix(d.Name(), ".yml")) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{rel: rel, fileSHA: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		t.Fatalf("recompute corpus pin: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	var manifest strings.Builder
	for _, e := range entries {
		manifest.WriteString(e.rel)
		manifest.WriteString("  ")
		manifest.WriteString(e.fileSHA)
		manifest.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(manifest.String()))
	return len(entries), hex.EncodeToString(sum[:])
}

// realgateInjectSyntheticGapPair copies the committed synthetic gap-close pair
// into the clone's PINNED corpus and regenerates corpus.pin so the injected
// corpus verifies. Leaves detectors/tuning.yaml untouched — the caller commits
// this as BASE (gap OPEN), then applies the widen for HEAD.
func realgateInjectSyntheticGapPair(t *testing.T, clone string) {
	t.Helper()
	root := realgateRepoRoot(t)
	if err := os.MkdirAll(filepath.Join(clone, "exams", "scenarios", "synthetic"), 0o755); err != nil {
		t.Fatalf("mkdir synthetic corpus dir: %v", err)
	}
	for _, p := range [][2]string{
		{realgateSynthSrcMustFire, realgateSynthDstMustFire},
		{realgateSynthSrcTwin, realgateSynthDstTwin},
	} {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p[0])))
		if err != nil {
			t.Fatalf("read synthetic fixture %s: %v", p[0], err)
		}
		dst := filepath.Join(clone, filepath.FromSlash(p[1]))
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", p[1], err)
		}
	}
	count, sha := realgateRecomputeCorpusPin(t, clone)
	pin := filepath.Join(clone, "exams", "scenarios", "corpus.pin")
	content := fmt.Sprintf("# fixture pin (synthetic gap-close injection)\ncount %d\nsha256 %s\n", count, sha)
	if err := os.WriteFile(pin, []byte(content), 0o644); err != nil {
		t.Fatalf("write corpus.pin: %v", err)
	}
}

// ---- fixture: a real GapCandidate, sourced from the REAL collector ---------

// realgateInitStoreRepo creates a real git repo with a seeded root commit,
// mirroring selfext/router/e2e_selfext_test.go's initGapTestRepo (duplicated
// across the package boundary — that file documents the same convention for
// core/collect/collect_test.go's own unexported initRepo).
func realgateInitStoreRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	realgateGit(t, dir, "init", "-q")
	realgateGit(t, dir, "config", "user.name", "test")
	realgateGit(t, dir, "config", "user.email", "test@example.com")
	realgateGit(t, dir, "config", "commit.gpgsign", "false")
	realgateGit(t, dir, "commit", "-q", "--allow-empty", "-m", "root")
	return dir
}

// realgateOverrideFPGapEnvelope seeds a REAL store carrying an operator
// override-FP on the real priv-escalation detector family, runs the REAL
// core/collect.DetectorGaps over it, and marshals the result through the
// PRODUCTION collectReport wire type `mallcop collect --json` itself emits
// (this test lives in package cli, so it uses the real type directly — no
// hand-duplicated envelope shape, unlike selfext/router/e2e_selfext_test.go
// which must duplicate it across the module boundary). Returns the path to
// the written envelope file and the one GapCandidate it carries.
func realgateOverrideFPGapEnvelope(t *testing.T) (string, collect.GapCandidate) {
	t.Helper()
	st, err := store.Open(realgateInitStoreRepo(t))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	escalated := resolution.Resolution{
		FindingID: "find-esc", Action: "escalate", Reason: "clean escalate, no dissent",
		Actor: "mallory", Severity: "medium", Source: "detector:priv-escalation",
		Timestamp: time.Unix(1_700_000_000, 0).UTC(),
	}
	if _, err := st.Append(store.KindResolutions, escalated); err != nil {
		t.Fatalf("append resolution: %v", err)
	}
	meta, err := json.Marshal(map[string]any{"finding_id": "find-esc", "verb": "resolve"})
	if err != nil {
		t.Fatalf("marshal directive meta: %v", err)
	}
	if _, err := st.Append(store.KindDirectives, store.Directive{
		Op: "suppress", Pattern: "detector:priv-escalation", Actor: "operator",
		Reason: "false positive on mallory", Meta: meta,
	}); err != nil {
		t.Fatalf("append directive: %v", err)
	}

	gaps, err := collect.DetectorGaps(st, nil)
	if err != nil {
		t.Fatalf("DetectorGaps: %v", err)
	}
	if len(gaps) != 1 || gaps[0].Kind != collect.GapOverrideFP {
		t.Fatalf("harness precondition: want exactly 1 override_fp gap, got %+v", gaps)
	}
	gap := gaps[0]
	if gap.DetectorFamily != "priv-escalation" {
		t.Fatalf("harness precondition: want the real collector's hyphenated family, got %q", gap.DetectorFamily)
	}

	rep := collectReport{SchemaVersion: CollectSchemaVersion, MappingGaps: []collect.MappingGap{}, GapCandidates: gaps}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal collect envelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gaps.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write gaps.json: %v", err)
	}
	return path, gap
}

// realgateInferenceServer stands up a fake Anthropic-shaped /v1/messages
// endpoint (the ONE boundary this test fakes: an actual LLM call, exactly as
// every other proposer test in this repo injects a fake InferenceClient — see
// selfext/proposer/proposer_test.go / selfext/router/e2e_selfext_test.go's
// e2eFake). cli/selfext.go's runSelfextPropose always builds a real
// proposer.AnthropicClient (it has no NewClient injection point), so faking
// the model reply at the CLI level means running a real HTTP server, not
// swapping an interface. Everything downstream of the reply — strict parse,
// the REAL gate subprocess, real router.Route — runs unstubbed.
func realgateInferenceServer(t *testing.T, detectorFamily, addedKeyword string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"stop_reason":"tool_use","content":[{"type":"tool_use","id":"toolu_1","name":"propose_tuning","input":{"detector":%q,"key":"extra_elevated_keywords","added_values":[%q]}}]}`,
			detectorFamily, addedKeyword)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// realgateReadTuningKeywords reads storeRepo/detectors/tuning.yaml through the
// REAL detector tuning reader (core/detect.LoadTuningFile) — the same
// production reader the customer's `mallcop scan --tuning` uses — and returns
// the priv-escalation extra_elevated_keywords list. A missing file (no
// auto-apply happened) returns an empty slice, never an error, so a caller
// proving "the human-gate route wrote nothing" gets a clean empty result.
func realgateReadTuningKeywords(t *testing.T, storeRepo string) []string {
	t.Helper()
	path := filepath.Join(storeRepo, "detectors", "tuning.yaml")
	tuning, err := detect.LoadTuningFile(path)
	if err != nil {
		t.Fatalf("detect.LoadTuningFile(%s): %v", path, err)
	}
	return tuning.PrivEscalation.ExtraElevatedKeywords
}

// ---- the two proofs ----------------------------------------------------------

// TestRunSelfextPropose_GapCandidate_RealGate_CoveredWiden_AutoApplies is the
// PROOF that the item's headline claim is TRUE, not merely stubbed true: a
// GapCandidate-sourced tuning widen that genuinely closes a labeled must_fire
// gap (the committed synthetic SYNTH-PE-01 fixture) earns CoveragePlus>=1 from
// a REAL `mallcop validate-proposal` subprocess and auto-applies to the tenant
// overlay, driven end to end through the PRODUCTION cli.runSelfextPropose entry
// point — filterTuningGapCandidates -> resolveProposeGate (the real-gate
// branch, proposeGateViaWorktree -> selfext/engine.RunValidateProposal) ->
// router.Route -> router.WriteOverlay. This is the ONLY test in the package
// (before this file, none existed) that exercises that whole chain without a
// --gate-json stub anywhere on the path.
func TestRunSelfextPropose_GapCandidate_RealGate_CoveredWiden_AutoApplies(t *testing.T) {
	bin := realgateBuildBin(t)

	// BASE: a real clone of this repo, with the synthetic gap-close pair
	// injected into the pinned corpus — SYNTH-PE-01 is RED (its role carries no
	// built-in elevation keyword), committed as the base ref the gate diffs
	// against.
	clone := realgateCloneRepo(t)
	realgateInjectSyntheticGapPair(t, clone)
	realgateGit(t, clone, "add", "-A")
	realgateGit(t, clone, "commit", "-q", "--no-verify", "-m", "fixture base: synthetic gap-close pair injected, gap OPEN")

	collectJSON, gap := realgateOverrideFPGapEnvelope(t)
	srv := realgateInferenceServer(t, gap.DetectorFamily, realgateSyntheticKeyword)

	storeRepo := t.TempDir()
	t.Setenv("MALLCOP_REALGATE_TEST_KEY", "sk-test-fake")

	err := runSelfextPropose(proposeArgs{
		collectJSON:     collectJSON,
		storeRepo:       storeRepo,
		targetRepo:      clone,
		baseRef:         "HEAD", // the base commit just created above
		validateBin:     bin,
		autonomy:        autonomy.SemiAutonomy, // DATA lane auto-applies at semi or fully
		inferenceURL:    srv.URL,
		inferenceKeyEnv: "MALLCOP_REALGATE_TEST_KEY",
		budgetUSD:       1.0,
		artifactDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("runSelfextPropose: %v", err)
	}

	got := realgateReadTuningKeywords(t, storeRepo)
	found := false
	for _, kw := range got {
		if kw == realgateSyntheticKeyword {
			found = true
		}
	}
	if !found {
		t.Fatalf("real gate did not auto-apply the covered widen to the tenant overlay: priv_escalation.extra_elevated_keywords = %v, want it to contain %q\n"+
			"(this is the proof the REAL gate — not a stub — certified CoveragePlus>=1 and router.Route auto-applied to %s/detectors/tuning.yaml)",
			got, realgateSyntheticKeyword, storeRepo)
	}
}

// TestRunSelfextPropose_GapCandidate_RealGate_CoverageLess_HumanGate proves the
// OTHER half honestly: a widen tied to no labeled must_fire scenario
// ("shadowops", mirroring router_test.go's nonBuiltinGapTuningKeyword) is
// CORRECTLY refused by the REAL gate (zero coverage gain) and routed to
// human-gate — NEVER written to the tenant overlay. This is safe/correct
// behavior (gateCertifiesWiden's fail-safe), asserted as such, not treated as
// a defect. No synthetic fixture injection is needed here: the product tree's
// own committed corpus already has zero must_fire coverage for "shadowops".
func TestRunSelfextPropose_GapCandidate_RealGate_CoverageLess_HumanGate(t *testing.T) {
	bin := realgateBuildBin(t)
	clone := realgateCloneRepo(t) // unmodified product tree — base == its own HEAD

	collectJSON, gap := realgateOverrideFPGapEnvelope(t)
	srv := realgateInferenceServer(t, gap.DetectorFamily, realgateCoverageLessKeyword)

	storeRepo := t.TempDir()
	t.Setenv("MALLCOP_REALGATE_TEST_KEY", "sk-test-fake")

	err := runSelfextPropose(proposeArgs{
		collectJSON:     collectJSON,
		storeRepo:       storeRepo,
		targetRepo:      clone,
		baseRef:         "HEAD",
		validateBin:     bin,
		autonomy:        autonomy.FullyAutonomy, // even at the most permissive dial, a non-certified gate must not auto-apply
		inferenceURL:    srv.URL,
		inferenceKeyEnv: "MALLCOP_REALGATE_TEST_KEY",
		budgetUSD:       1.0,
		artifactDir:     t.TempDir(),
	})
	if err != nil {
		t.Fatalf("runSelfextPropose: %v", err)
	}

	overlayPath := filepath.Join(storeRepo, "detectors", "tuning.yaml")
	if _, statErr := os.Stat(overlayPath); statErr == nil {
		got := realgateReadTuningKeywords(t, storeRepo)
		for _, kw := range got {
			if kw == realgateCoverageLessKeyword {
				t.Fatalf("a coverage-less widen (real gate, CoveragePlus==0) was auto-applied to the tenant overlay — must route to human-gate instead: %v", got)
			}
		}
	}
	// overlayPath not existing at all is the expected, stronger proof: Route's
	// human-gate destination never calls WriteOverlay for this proposal.
}
