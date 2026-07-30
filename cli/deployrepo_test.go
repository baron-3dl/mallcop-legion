package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestScaffoldDeployAssetsWritesAllExpectedFiles proves scaffoldDeployAssets
// is offline/pure: it writes go.mod (D1 pin), .gitignore, detectors/README.md,
// connectors/README.md, and .github/workflows/scan.yml, with no network and
// no git — fully covered by t.TempDir().
func TestScaffoldDeployAssetsWritesAllExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.7.0"); err != nil {
		t.Fatalf("scaffoldDeployAssets: %v", err)
	}

	goMod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("go.mod not written: %v", err)
	}
	if !strings.Contains(string(goMod), "module github.com/acme/mallcop-deploy") {
		t.Fatalf("go.mod missing module line: %s", goMod)
	}
	if !strings.Contains(string(goMod), "require github.com/mallcop-app/mallcop v0.7.0") {
		t.Fatalf("go.mod missing D1 pin: %s", goMod)
	}

	gitignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf(".gitignore not written: %v", err)
	}
	if !strings.Contains(string(gitignore), "/store/") {
		t.Fatalf(".gitignore does not exclude store/ (D3 same-repo-but-separate-branch): %s", gitignore)
	}

	for _, p := range []string{
		filepath.Join("detectors", "README.md"),
		filepath.Join("connectors", "README.md"),
		filepath.Join(".github", "workflows", "scan.yml"),
		filepath.Join(".github", "workflows", "mallcop-investigate.yml"),
	} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}

	workflow, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if err != nil {
		t.Fatalf("reading scan.yml: %v", err)
	}
	w := string(workflow)

	// mallcoppro-c32 boundary fix (3): MALLCOP_API_KEY must never be a
	// job-level env var (every step, including any third-party `uses:`
	// action, would inherit it) -- it must be scoped to only the specific
	// run step that actually needs it ("Run mallcop scan").
	assertAPIKeyScopedToRunStep(t, w, "mallcop scan")

	// D2+2fd: the pinned release binary is installed, never rebuilt from
	// customer code; only detectors/<name> compiles, and only to wasip1/wasm.
	if !strings.Contains(w, `MALLCOP_VERSION: "v0.7.0"`) {
		t.Fatalf("scan.yml does not pin MALLCOP_VERSION to v0.7.0:\n%s", w)
	}
	if !strings.Contains(w, "releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz") {
		t.Fatalf("scan.yml does not install the pinned release binary from GitHub Releases:\n%s", w)
	}
	// The asset name must be resolved from the runner's actual OS/arch, never
	// hardcoded to a single platform -- the release publishes linux-amd64,
	// linux-arm64, AND darwin-arm64 (see the release-assets test below).
	if !strings.Contains(w, "RUNNER_OS") || !strings.Contains(w, "RUNNER_ARCH") {
		t.Fatalf("scan.yml does not resolve the release asset from RUNNER_OS/RUNNER_ARCH:\n%s", w)
	}
	for _, want := range []string{"linux-amd64", "linux-arm64", "darwin-arm64"} {
		if !strings.Contains(w, want) {
			t.Fatalf("scan.yml platform-detection step is missing the %q asset mapping:\n%s", want, w)
		}
	}
	if !strings.Contains(w, "GOOS=wasip1 GOARCH=wasm go build") {
		t.Fatalf("scan.yml does not build sidecars to wasip1/wasm:\n%s", w)
	}
	if !strings.Contains(w, "GOFLAGS: -mod=mod") {
		t.Fatalf("scan.yml sidecar build step does not set GOFLAGS=-mod=mod (see cli/sidecars.go buildAndRegisterSourceSidecar for why a customer's detectors/ build needs it):\n%s", w)
	}
	if strings.Contains(w, "go build -o mallcop") || strings.Contains(w, "go build ./cmd/mallcop") {
		t.Fatalf("scan.yml must never rebuild the whole mallcop binary from customer code:\n%s", w)
	}
	if !strings.Contains(w, "mallcop scan") {
		t.Fatalf("scan.yml does not run 'mallcop scan':\n%s", w)
	}
	// The workflow must be BOTH schedulable (real "scheduled scan") AND
	// manually triggerable (workflow_dispatch -- how this item's live proof
	// runs it deterministically instead of waiting on a cron tick).
	if !strings.Contains(w, "schedule:") || !strings.Contains(w, "cron:") {
		t.Fatalf("scan.yml is missing a cron schedule trigger:\n%s", w)
	}
	if !strings.Contains(w, "workflow_dispatch:") {
		t.Fatalf("scan.yml is missing a workflow_dispatch trigger:\n%s", w)
	}
	if !strings.Contains(w, "mallcop-findings") {
		t.Fatalf("scan.yml does not reference the findings-persistence branch:\n%s", w)
	}
	if !strings.Contains(w, "git -C store push") {
		t.Fatalf("scan.yml does not push the findings store:\n%s", w)
	}
	// Live proof (mallcoppro-f3b) found 'mallcop scan' can leave store/'s
	// working tree in a deletion-staged-but-uncommitted state after it
	// returns; a manual 'git add -A && git commit' in this workflow would
	// capture that as a real (destructive) commit. The workflow must only
	// ever push whatever store/ already committed internally.
	if strings.Contains(w, "add -A") || strings.Contains(w, `commit -q -m "scan:`) {
		t.Fatalf("scan.yml must not run its own git add/commit inside store/ (see mallcoppro-f3b finding):\n%s", w)
	}
}

// TestScanWorkflowPublishesGapsAndGatesOnMiss proves the self-heal S5 additions to
// the scheduled-scan workflow: it publishes coverage gaps as store/gaps.json (for
// 'mallcop status') and FAILS the run on a recall red via 'mallcop collect --gate'
// (Baron FAIL-ON-MISS). The gaps commit must stage ONLY gaps.json (never 'add -A')
// so it does not restage the working tree the mallcoppro-f3b finding warned about.
func TestScanWorkflowPublishesGapsAndGatesOnMiss(t *testing.T) {
	w := renderScanWorkflow("v0.7.0")

	if !strings.Contains(w, "mallcop collect --json --store ./store > store/gaps.json") {
		t.Fatalf("scan.yml does not publish coverage gaps to store/gaps.json:\n%s", w)
	}
	if !strings.Contains(w, "git -C store add gaps.json") {
		t.Fatalf("scan.yml gaps publish must stage ONLY gaps.json (never add -A):\n%s", w)
	}
	if !strings.Contains(w, "mallcop collect --gate --store ./store") {
		t.Fatalf("scan.yml does not gate the scan on a recall red (fail-on-miss):\n%s", w)
	}
	// Still no forbidden restage-everything / scan-message commit.
	if strings.Contains(w, "add -A") || strings.Contains(w, `commit -q -m "scan:`) {
		t.Fatalf("gaps publish must not restage the whole tree or reuse the scan commit form:\n%s", w)
	}
	// The gate step runs AFTER the store push, so gaps.json is durably published
	// even on a failing run. Assert order: push findings, then the gate.
	pushIdx := strings.Index(w, "git -C store push")
	gateIdx := strings.Index(w, "mallcop collect --gate")
	if pushIdx < 0 || gateIdx < 0 || gateIdx < pushIdx {
		t.Fatalf("the fail-on-miss gate must run AFTER the findings push (push@%d, gate@%d):\n%s", pushIdx, gateIdx, w)
	}
	// Migrate force-refreshes generated workflows, so the same publish+gate must be
	// present in the refresh path too (existing repos upgrade on 'mallcop migrate').
	dir := t.TempDir()
	if _, err := refreshDeployWorkflows(dir, "v0.9.0", false); err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if err != nil {
		t.Fatalf("read refreshed scan.yml: %v", err)
	}
	if !strings.Contains(string(raw), "mallcop collect --gate --store ./store") {
		t.Fatalf("refreshed scan.yml (migrate path) is missing the fail-on-miss gate:\n%s", raw)
	}
}

// TestScanWorkflowPublishesDoctorReports is the mallcoppro-62c DONE CONDITION
// check: the rendered scan.yml runs 'mallcop doctor --all --json' and
// publishes the result as store/doctor.json on the findings branch -- the
// MISSING LINK between the doctor CLI (mallcoppro-529) and the console
// reader (mallcoppro-99b0). It must stage ONLY doctor.json (never 'add -A',
// matching the sibling gaps.json publish step's own discipline), must run
// BEFORE the findings-store push (so doctor.json is durably published, same
// ordering discipline as the gaps.json step), and must never fail the job
// (the doctor invocation's own exit code is neutralized before the
// git add/commit).
func TestScanWorkflowPublishesDoctorReports(t *testing.T) {
	w := renderScanWorkflow("v0.7.0")

	if !strings.Contains(w, "mallcop doctor --all --json --store ./store") {
		t.Fatalf("scan.yml does not run 'mallcop doctor --all --json' to build the doctor.json aggregate:\n%s", w)
	}
	if !strings.Contains(w, "store/doctor.json") {
		t.Fatalf("scan.yml does not write store/doctor.json:\n%s", w)
	}
	if !strings.Contains(w, "git -C store add doctor.json") {
		t.Fatalf("scan.yml doctor publish must stage ONLY doctor.json (never add -A):\n%s", w)
	}
	if strings.Contains(w, "add -A") || strings.Contains(w, `commit -q -m "scan:`) {
		t.Fatalf("doctor publish must not restage the whole tree or reuse the scan commit form:\n%s", w)
	}

	// The doctor invocation's own exit code must be neutralized (a deficient
	// or errored connector must not fail the scheduled job) BEFORE the
	// git add/commit runs.
	if !strings.Contains(w, "set +e") || !strings.Contains(w, "set -e") {
		t.Fatalf("scan.yml doctor publish does not neutralize 'mallcop doctor --all's own exit code:\n%s", w)
	}

	// Publish BEFORE the push, same ordering discipline as gaps.json, so the
	// artifact is durably published even on a failing run.
	pushIdx := strings.Index(w, "git -C store push")
	doctorIdx := strings.Index(w, "mallcop doctor --all --json")
	if pushIdx < 0 || doctorIdx < 0 || doctorIdx > pushIdx {
		t.Fatalf("doctor publish must run BEFORE the findings push (doctor@%d, push@%d):\n%s", doctorIdx, pushIdx, w)
	}

	// The step must parse as a well-formed YAML step within the scan job
	// (not just a substring match).
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(w), &doc); err != nil {
		t.Fatalf("scan.yml does not parse as YAML: %v\n%s", err, w)
	}
	jobs, _ := doc["jobs"].(map[string]any)
	scanJob, _ := jobs["scan"].(map[string]any)
	steps, _ := scanJob["steps"].([]any)
	found := false
	for _, s := range steps {
		stepMap, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if run, _ := stepMap["run"].(string); strings.Contains(run, "mallcop doctor --all") {
			found = true
		}
	}
	if !found {
		t.Fatalf("scan.yml has no parsed step running 'mallcop doctor --all':\n%s", w)
	}

	// Migrate force-refreshes generated workflows, so the doctor publish must
	// be present in the refresh path too (existing repos upgrade on 'mallcop
	// migrate'), matching the sibling gaps.json/watchdog coverage above.
	dir := t.TempDir()
	if _, err := refreshDeployWorkflows(dir, "v0.9.0", false); err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if err != nil {
		t.Fatalf("read refreshed scan.yml: %v", err)
	}
	if !strings.Contains(string(raw), "mallcop doctor --all --json --store ./store") {
		t.Fatalf("refreshed scan.yml (migrate path) is missing the doctor publish step:\n%s", raw)
	}
}

// TestScanWorkflowHasLivenessWatchdog is the mallcoppro-1e0 DONE CONDITION
// check: the rendered scan.yml carries an `if: always()` step invoking
// `mallcop status --gate --max-age 48h` (design §5 primitive 1 — the
// whole-pipeline liveness watchdog, the customer's own cron as dead-man's
// switch). always() is load-bearing: without it, GitHub Actions skips this
// step the moment an earlier step (e.g. 'Run mallcop scan') has already
// failed — exactly the case this watchdog exists to still catch. Also
// proves the step parses as a well-formed YAML step (not just a substring
// match) and that it needs no MALLCOP_API_KEY (it only reads the local
// store checkout — no new standing credential).
func TestScanWorkflowHasLivenessWatchdog(t *testing.T) {
	w := renderScanWorkflow("v0.7.0")

	if !strings.Contains(w, "mallcop status --gate --store ./store --max-age 48h") {
		t.Fatalf("scan.yml does not run the whole-pipeline liveness watchdog ('mallcop status --gate --max-age 48h'):\n%s", w)
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(w), &doc); err != nil {
		t.Fatalf("scan.yml does not parse as YAML: %v\n%s", err, w)
	}
	jobs, _ := doc["jobs"].(map[string]any)
	scanJob, _ := jobs["scan"].(map[string]any)
	steps, _ := scanJob["steps"].([]any)
	if len(steps) == 0 {
		t.Fatalf("scan.yml's scan job has no steps:\n%s", w)
	}
	var watchdog map[string]any
	for _, s := range steps {
		stepMap, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if run, _ := stepMap["run"].(string); strings.Contains(run, "mallcop status --gate") {
			watchdog = stepMap
		}
	}
	if watchdog == nil {
		t.Fatalf("scan.yml has no parsed step running 'mallcop status --gate':\n%s", w)
	}
	// YAML's "always()" reads back as the literal string "always()" under
	// yaml.v3's default any-decoding (it is a GitHub Actions expression, not
	// a YAML boolean literal).
	ifCond, _ := watchdog["if"].(string)
	if ifCond != "always()" {
		t.Fatalf("the liveness watchdog step must be if: always() (so it still runs after an earlier step already failed the job), got %q:\n%s", ifCond, w)
	}
	if _, has := watchdog["env"]; has {
		t.Fatalf("the liveness watchdog step needs no env / credential (it only reads the local store checkout), got: %+v", watchdog["env"])
	}

	// Migrate force-refreshes generated workflows, so the watchdog must be
	// present in the refresh path too (existing repos upgrade on 'mallcop
	// migrate'), matching the sibling recall-red gate's own coverage above.
	dir := t.TempDir()
	if _, err := refreshDeployWorkflows(dir, "v0.9.0", false); err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "scan.yml"))
	if err != nil {
		t.Fatalf("read refreshed scan.yml: %v", err)
	}
	if !strings.Contains(string(raw), "mallcop status --gate --store ./store --max-age 48h") {
		t.Fatalf("refreshed scan.yml (migrate path) is missing the liveness watchdog:\n%s", raw)
	}
}

// TestScaffoldDeployAssetsWritesWellFormedInvestigateWorkflow is the
// mallcoppro-067 DONE CONDITION check for the GHA scaffold half of the item:
// mallcop-investigate.yml must PARSE as YAML (not just contain the right
// substrings) and its parsed structure must carry a required
// workflow_dispatch input named session_id, a pinned-binary install step, a
// mallcop-findings checkout step, and a 'mallcop investigate --serve'
// invocation.
func TestScaffoldDeployAssetsWritesWellFormedInvestigateWorkflow(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.7.0"); err != nil {
		t.Fatalf("scaffoldDeployAssets: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"))
	if err != nil {
		t.Fatalf("reading mallcop-investigate.yml: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("mallcop-investigate.yml does not parse as YAML: %v\n%s", err, raw)
	}

	// workflow_dispatch input session_id, required. YAML's bare "on:" key
	// must survive as the literal string "on" (yaml.v3 does NOT apply
	// YAML-1.1 on/off boolean resolution) -- assert the map key directly
	// rather than trusting a substring match.
	onNode, ok := doc["on"].(map[string]any)
	if !ok {
		t.Fatalf("mallcop-investigate.yml has no parsed \"on:\" trigger map (keys present: %v)\n%s", mapKeys(doc), raw)
	}
	dispatch, ok := onNode["workflow_dispatch"].(map[string]any)
	if !ok {
		t.Fatalf("mallcop-investigate.yml's \"on:\" has no workflow_dispatch trigger:\n%s", raw)
	}
	inputs, ok := dispatch["inputs"].(map[string]any)
	if !ok {
		t.Fatalf("workflow_dispatch has no inputs map:\n%s", raw)
	}
	sessionInput, ok := inputs["session_id"].(map[string]any)
	if !ok {
		t.Fatalf("workflow_dispatch.inputs has no session_id input:\n%s", raw)
	}
	if required, _ := sessionInput["required"].(bool); !required {
		t.Fatalf("workflow_dispatch.inputs.session_id is not required: %#v", sessionInput)
	}

	jobs, ok := doc["jobs"].(map[string]any)
	if !ok || len(jobs) == 0 {
		t.Fatalf("mallcop-investigate.yml has no jobs:\n%s", raw)
	}
	var allSteps []map[string]any
	for _, job := range jobs {
		jobMap, ok := job.(map[string]any)
		if !ok {
			continue
		}
		steps, ok := jobMap["steps"].([]any)
		if !ok {
			continue
		}
		for _, s := range steps {
			if stepMap, ok := s.(map[string]any); ok {
				allSteps = append(allSteps, stepMap)
			}
		}
	}
	if len(allSteps) == 0 {
		t.Fatalf("mallcop-investigate.yml's job has no steps:\n%s", raw)
	}

	stepRun := func(pred func(step map[string]any) bool) (map[string]any, bool) {
		for _, s := range allSteps {
			if pred(s) {
				return s, true
			}
		}
		return nil, false
	}
	hasRunSubstring := func(sub string) bool {
		_, ok := stepRun(func(s map[string]any) bool {
			run, _ := s["run"].(string)
			return strings.Contains(run, sub)
		})
		return ok
	}
	hasUses := func(sub string) bool {
		_, ok := stepRun(func(s map[string]any) bool {
			uses, _ := s["uses"].(string)
			return strings.Contains(uses, sub)
		})
		return ok
	}

	if !hasUses("actions/checkout@") {
		t.Fatalf("mallcop-investigate.yml has no actions/checkout step:\n%s", raw)
	}
	if !hasRunSubstring("releases/download/${MALLCOP_VERSION}/mallcop-${MALLCOP_ASSET}.tar.gz") {
		t.Fatalf("mallcop-investigate.yml does not install the pinned release binary from GitHub Releases:\n%s", raw)
	}
	if !hasRunSubstring("--branch \"mallcop-findings\"") && !hasRunSubstring("--branch \"{{FINDINGS_BRANCH}}\"") {
		if !strings.Contains(string(raw), "mallcop-findings") {
			t.Fatalf("mallcop-investigate.yml does not check out the mallcop-findings store branch:\n%s", raw)
		}
	}
	if !hasRunSubstring("mallcop investigate --serve") {
		t.Fatalf("mallcop-investigate.yml does not run 'mallcop investigate --serve':\n%s", raw)
	}
	if !hasRunSubstring("--session") || !hasRunSubstring("SESSION_ID") {
		t.Fatalf("mallcop-investigate.yml's serve invocation does not pass through the session id:\n%s", raw)
	}

	// mallcoppro-ebef: exactly one runner per session (the git mailbox's
	// single-writer-per-file invariant — two runners interleaving seq
	// counters on one outbox corrupt the browser's dedup cursor), queued
	// rather than cancelled so a live runner is never killed mid-answer.
	conc, ok := doc["concurrency"].(map[string]any)
	if !ok {
		t.Fatalf("mallcop-investigate.yml has no concurrency group:\n%s", raw)
	}
	if group, _ := conc["group"].(string); !strings.Contains(group, "${{ inputs.session_id }}") {
		t.Fatalf("concurrency.group is not keyed on the session id: %#v", conc)
	}
	if cancel, _ := conc["cancel-in-progress"].(bool); cancel {
		t.Fatalf("concurrency.cancel-in-progress must be false (a duplicate dispatch must queue, not kill a live runner mid-answer): %#v", conc)
	}

	// mallcoppro-ebef: a conversation-scale idle timeout — at the 90s
	// library default the runner exits inside an ordinary human pause and
	// the next question lands in a dead mailbox.
	if !hasRunSubstring("--idle-timeout 10m") {
		t.Fatalf("mallcop-investigate.yml's serve invocation does not set the conversation-scale --idle-timeout:\n%s", raw)
	}
	if !hasRunSubstring("--chat-branch \"mallcop-chat\"") {
		t.Fatalf("mallcop-investigate.yml's serve invocation does not pin --chat-branch to mallcop-chat (must differ from the findings branch):\n%s", raw)
	}

	// mallcoppro-c32 boundary fix (3): MALLCOP_API_KEY must never be a
	// job-level env var (every step, including any third-party `uses:`
	// action, would inherit it) -- it must be scoped to only the
	// "Run mallcop investigate --serve" step's own env.
	assertAPIKeyScopedToRunStep(t, string(raw), "mallcop investigate --serve")

	perms, ok := doc["permissions"].(map[string]any)
	if !ok || perms["contents"] != "write" {
		t.Fatalf("mallcop-investigate.yml does not grant contents: write:\n%s", raw)
	}
}

// assertAPIKeyScopedToRunStep is the mallcoppro-c32 regression check shared by
// both scan.yml and mallcop-investigate.yml: MALLCOP_API_KEY must appear ONLY
// in the env: map of the specific run step whose `run:` text contains
// runStepSubstring (e.g. "mallcop scan" or "mallcop investigate --serve"),
// never as a job-level or top-level workflow env key -- a job-level env is
// visible to every step in the job, including any third-party `uses:` action,
// which is exactly the exposure this item closes.
func assertAPIKeyScopedToRunStep(t *testing.T, raw string, runStepSubstring string) {
	t.Helper()

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("workflow does not parse as YAML: %v\n%s", err, raw)
	}

	if topEnv, ok := doc["env"].(map[string]any); ok {
		if _, has := topEnv["MALLCOP_API_KEY"]; has {
			t.Fatalf("workflow exposes MALLCOP_API_KEY as a job-level/top-level env var (every step, incl. third-party actions, would inherit it):\n%s", raw)
		}
	}

	jobs, ok := doc["jobs"].(map[string]any)
	if !ok || len(jobs) == 0 {
		t.Fatalf("workflow has no jobs:\n%s", raw)
	}
	for _, job := range jobs {
		jobMap, ok := job.(map[string]any)
		if !ok {
			continue
		}
		if jobEnv, ok := jobMap["env"].(map[string]any); ok {
			if _, has := jobEnv["MALLCOP_API_KEY"]; has {
				t.Fatalf("workflow exposes MALLCOP_API_KEY as a job-level env var (every step, incl. third-party actions, would inherit it):\n%s", raw)
			}
		}
	}

	var runStep map[string]any
	for _, job := range jobs {
		jobMap, ok := job.(map[string]any)
		if !ok {
			continue
		}
		steps, ok := jobMap["steps"].([]any)
		if !ok {
			continue
		}
		for _, s := range steps {
			stepMap, ok := s.(map[string]any)
			if !ok {
				continue
			}
			run, _ := stepMap["run"].(string)
			if strings.Contains(run, runStepSubstring) {
				runStep = stepMap
			}
		}
	}
	if runStep == nil {
		t.Fatalf("workflow has no run step containing %q to check env scoping:\n%s", runStepSubstring, raw)
	}
	stepEnv, ok := runStep["env"].(map[string]any)
	if !ok {
		t.Fatalf("the %q run step has no env map -- MALLCOP_API_KEY must be scoped there:\n%s", runStepSubstring, raw)
	}
	if _, has := stepEnv["MALLCOP_API_KEY"]; !has {
		t.Fatalf("the %q run step's env does not include MALLCOP_API_KEY:\n%s", runStepSubstring, raw)
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestScaffoldDeployAssetsIdempotent proves a re-run never clobbers existing
// deploy-repo assets, mirroring TestInitIdempotent's convention for the base
// scaffold.
func TestScaffoldDeployAssetsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.7.0"); err != nil {
		t.Fatalf("first scaffoldDeployAssets: %v", err)
	}
	goModPath := filepath.Join(dir, "go.mod")
	edited := "module github.com/acme/mallcop-deploy\n\ngo 1.24\n\nrequire github.com/mallcop-app/mallcop v0.7.0\n\nreplace foo => bar\n"
	if err := os.WriteFile(goModPath, []byte(edited), 0o644); err != nil {
		t.Fatalf("edit go.mod: %v", err)
	}

	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.9.0"); err != nil {
		t.Fatalf("second scaffoldDeployAssets: %v", err)
	}

	got, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if string(got) != edited {
		t.Fatalf("re-run clobbered edited go.mod:\n%s", got)
	}
}

// TestSplitOwnerRepo covers the "owner/name" parse used by both runInit's
// --create-repo flag and createAndPushDeployRepo.
func TestSplitOwnerRepo(t *testing.T) {
	cases := []struct {
		in        string
		wantOwner string
		wantName  string
		wantOK    bool
	}{
		{"acme/mallcop-deploy", "acme", "mallcop-deploy", true},
		{"noslash", "", "", false},
		{"/name", "", "", false},
		{"owner/", "", "", false},
		{"owner/name/extra", "", "", false},
	}
	for _, c := range cases {
		owner, name, ok := splitOwnerRepo(c.in)
		if ok != c.wantOK || owner != c.wantOwner || name != c.wantName {
			t.Errorf("splitOwnerRepo(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, owner, name, ok, c.wantOwner, c.wantName, c.wantOK)
		}
	}
}

// TestProAppTokenExchangesInstallationForToken proves the GitHub-App-authorize
// seam's wire shape against an httptest stand-in of mallcop-pro's real POST
// /v1/github/token (see mallcop-pro/internal/server/github_token.go): bearer
// API key in, installation_id in the JSON body, {"token": "..."} out. This is
// the seam described in deployrepo.go's package doc -- not exercised against
// the live api.mallcop.app in this item's proof, but real code, really tested.
func TestProAppTokenExchangesInstallationForToken(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody struct {
		InstallationID int64 `json:"installation_id"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":       "ghs_faketokenfortest",
			"expires_at":  "2026-01-01T00:00:00Z",
			"permissions": map[string]string{"contents": "write"},
		})
	}))
	defer srv.Close()

	tok := proAppToken{endpoint: srv.URL, apiKey: "mallcop-sk-test", installationID: 116376961}
	got, err := tok.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "ghs_faketokenfortest" {
		t.Fatalf("Token = %q, want ghs_faketokenfortest", got)
	}
	if gotAuth != "Bearer mallcop-sk-test" {
		t.Fatalf("Authorization header = %q, want Bearer mallcop-sk-test", gotAuth)
	}
	if gotPath != "/v1/github/token" {
		t.Fatalf("path = %q, want /v1/github/token", gotPath)
	}
	if gotBody.InstallationID != 116376961 {
		t.Fatalf("installation_id = %d, want 116376961", gotBody.InstallationID)
	}
}

// TestProAppTokenSurfacesServerError proves a non-200 from mallcop-pro is a
// loud error, not a silently empty token.
func TestProAppTokenSurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "GitHub App not configured"})
	}))
	defer srv.Close()

	tok := proAppToken{endpoint: srv.URL, apiKey: "mallcop-sk-test", installationID: 1}
	_, err := tok.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error from a 503 response, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error does not mention the status code: %v", err)
	}
}

// TestEnvGitHubTokenMissing proves a clear, loud error (not a silent empty
// token) when the configured env var isn't set.
func TestEnvGitHubTokenMissing(t *testing.T) {
	t.Setenv("MALLCOP_GITHUB_TOKEN_TEST_UNSET", "")
	os.Unsetenv("MALLCOP_GITHUB_TOKEN_TEST_UNSET")
	tok := envGitHubToken{envVar: "MALLCOP_GITHUB_TOKEN_TEST_UNSET"}
	if _, err := tok.Token(context.Background()); err == nil {
		t.Fatal("expected an error when the token env var is unset")
	}
}

// TestScaffoldWorkflowsUseShallowGitOps is the regression test for the v0.10.1
// hang fixes found by the production-path e2e (mallcoppro-5b7, mallcoppro-fce):
//   - a FULL-history checkout (fetch-depth 0) hangs the investigate job on real
//     deploy repos, so mallcop-investigate.yml must use fetch-depth 1;
//   - a non-shallow `git clone` of the store branch pulls the full history of an
//     ever-growing events.jsonl and hangs BOTH scan.yml and investigate.yml, so
//     the store restore must clone with --depth 1.
func TestScaffoldWorkflowsUseShallowGitOps(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.10.1"); err != nil {
		t.Fatalf("scaffoldDeployAssets: %v", err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return string(b)
	}

	// Both workflows restore the store with a BOUNDED shallow clone
	// (mallcoppro-fce), but not depth 1: core/inquest's scan-time correlation
	// falls back to git commit history when the KindScans register is young,
	// and a depth-1 clone starved that fallback to ~1 commit (mallcoppro-cb4).
	// Depth 200 keeps the clone bounded (no full-history hang) while giving
	// the cold-start fallback weeks of scan pushes to correlate against.
	for _, wf := range []string{"scan.yml", "mallcop-investigate.yml"} {
		w := read(wf)
		if !strings.Contains(w, "git clone --quiet --depth 200 --branch") {
			t.Fatalf("%s store restore must use the bounded `git clone --depth 200` (depth 1 starves inquest's scan-time fallback, mallcoppro-cb4; full history hangs on the growing store branch):\n%s", wf, w)
		}
		if strings.Contains(w, "--depth 1 ") {
			t.Fatalf("%s still contains a depth-1 clone:\n%s", wf, w)
		}
	}

	// The investigate workflow must NOT full-history checkout (mallcoppro-5b7).
	inv := read("mallcop-investigate.yml")
	if !strings.Contains(inv, "fetch-depth: 1") {
		t.Fatalf("mallcop-investigate.yml must checkout with fetch-depth: 1:\n%s", inv)
	}
	if strings.Contains(inv, "fetch-depth: 0") {
		t.Fatalf("mallcop-investigate.yml must NOT use fetch-depth: 0 (full-history checkout hangs on large deploy repos):\n%s", inv)
	}
}

// TestScaffoldWorkflowsPinActionsBySHA proves both scaffolded workflows pin
// third-party actions by immutable commit SHA, never a mutable @vN tag
// (mallcoppro-796): these workflows run with contents:write and hold
// MALLCOP_API_KEY, so a repointed tag is a real supply-chain exposure.
func TestScaffoldWorkflowsPinActionsBySHA(t *testing.T) {
	dir := t.TempDir()
	if err := scaffoldDeployAssets(dir, "github.com/acme/mallcop-deploy", "v0.10.1"); err != nil {
		t.Fatalf("scaffoldDeployAssets: %v", err)
	}
	// Every actions/* ref must be @<40 hex>; a mutable @vN tag is forbidden.
	shaPin := regexp.MustCompile(`uses: actions/[^@\s]+@[0-9a-f]{40}\b`)
	mutableTag := regexp.MustCompile(`uses: actions/[^@\s]+@v[0-9]`)
	for _, wf := range []string{"scan.yml", "mallcop-investigate.yml"} {
		b, err := os.ReadFile(filepath.Join(dir, ".github", "workflows", wf))
		if err != nil {
			t.Fatalf("reading %s: %v", wf, err)
		}
		w := string(b)
		if m := mutableTag.FindString(w); m != "" {
			t.Errorf("%s pins an action by a mutable tag %q — must be a commit SHA", wf, m)
		}
		if !shaPin.MatchString(w) {
			t.Errorf("%s has no SHA-pinned actions/* ref:\n%s", wf, w)
		}
		// No bare actions/* @-ref may escape the SHA form.
		for _, line := range strings.Split(w, "\n") {
			if strings.Contains(line, "uses: actions/") && !shaPin.MatchString(line) {
				t.Errorf("%s: unpinned action ref: %q", wf, strings.TrimSpace(line))
			}
		}
	}
}

// TestRefreshDeployWorkflowsAdvancesGenuinelyStaleFile is the mallcoppro-f19
// happy path: a scan.yml that is byte-identical to what mallcop generated at
// an OLD pinned version (never hand-touched since) must advance cleanly to
// the new version — this is the exact live-hit scenario the item names
// (3dl-dev/mallcop-deploy pinned v0.19.0, scan.yml predating the
// doctor-publish step added at sha 718c321).
func TestRefreshDeployWorkflowsAdvancesGenuinelyStaleFile(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := renderScanWorkflow("v0.19.0")
	if err := os.WriteFile(filepath.Join(workflowDir, "scan.yml"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := refreshDeployWorkflows(dir, "v0.20.0", false)
	if err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}

	var scanStatus *WorkflowFileStatus
	for i := range plan {
		if plan[i].Name == "scan.yml" {
			scanStatus = &plan[i]
		}
	}
	if scanStatus == nil {
		t.Fatalf("no status returned for scan.yml: %+v", plan)
	}
	if scanStatus.Diverged {
		t.Fatalf("a genuinely stale (never hand-edited) scan.yml must not be reported as diverged: %+v", scanStatus)
	}
	if scanStatus.FromVersion != "v0.19.0" {
		t.Errorf("FromVersion = %q, want v0.19.0", scanStatus.FromVersion)
	}
	if !scanStatus.Changed {
		t.Errorf("scan.yml should have been advanced (Changed=true): %+v", scanStatus)
	}

	raw := mustRead(t, filepath.Join(workflowDir, "scan.yml"))
	if strings.Contains(raw, `MALLCOP_VERSION: "v0.19.0"`) {
		t.Error("scan.yml still pinned to the old version after refresh")
	}
	if !strings.Contains(raw, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Error("scan.yml was not pinned to the new version")
	}
}

// TestRefreshDeployWorkflowsReportsHandEditedFile is the mallcoppro-f19
// CRITICAL SAFETY check: a managed workflow file that has been hand-edited
// since it was generated (content no longer byte-identical to what mallcop
// would render for its own pinned version) must be left COMPLETELY
// untouched by refreshDeployWorkflows and reported as diverged — never
// silently steamrolled. The sibling mallcop-investigate.yml, which was NOT
// hand-edited, must still advance normally in the same call.
func TestRefreshDeployWorkflowsReportsHandEditedFile(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatal(err)
	}
	handEdited := renderScanWorkflow("v0.19.0") + "\n# operator: added a custom notification step here\n"
	if err := os.WriteFile(filepath.Join(workflowDir, "scan.yml"), []byte(handEdited), 0o644); err != nil {
		t.Fatal(err)
	}
	untouched := renderInvestigateWorkflow("v0.19.0")
	if err := os.WriteFile(filepath.Join(workflowDir, "mallcop-investigate.yml"), []byte(untouched), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := refreshDeployWorkflows(dir, "v0.20.0", false)
	if err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}

	for _, st := range plan {
		switch st.Name {
		case "scan.yml":
			if !st.Diverged {
				t.Errorf("hand-edited scan.yml must be reported Diverged=true: %+v", st)
			}
			if st.Changed {
				t.Errorf("hand-edited scan.yml must not be written (Changed must stay false): %+v", st)
			}
		case "mallcop-investigate.yml":
			if st.Diverged {
				t.Errorf("untouched mallcop-investigate.yml must not be reported diverged: %+v", st)
			}
			if !st.Changed {
				t.Errorf("untouched mallcop-investigate.yml should have advanced: %+v", st)
			}
		}
	}

	// The hand-edited file on disk must be byte-for-byte UNTOUCHED.
	raw := mustRead(t, filepath.Join(workflowDir, "scan.yml"))
	if raw != handEdited {
		t.Errorf("refreshDeployWorkflows clobbered a hand-edited file:\nwant (unchanged):\n%s\ngot:\n%s", handEdited, raw)
	}

	// The untouched sibling file DID advance.
	rawInv := mustRead(t, filepath.Join(workflowDir, "mallcop-investigate.yml"))
	if !strings.Contains(rawInv, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Error("mallcop-investigate.yml was not advanced to v0.20.0")
	}
}

// TestRefreshDeployWorkflowsIsIdempotent proves that refreshing an
// already-current repo writes nothing: re-running at the SAME version a
// second file-write already applied produces byte-identical content and
// Changed=false for every file, so a git-backed deploy repo shows zero diff
// on a repeat run (no empty commit needed).
func TestRefreshDeployWorkflowsIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := refreshDeployWorkflows(dir, "v0.20.0", false); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	scanBefore := mustRead(t, filepath.Join(dir, ".github", "workflows", "scan.yml"))
	invBefore := mustRead(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml"))

	plan, err := refreshDeployWorkflows(dir, "v0.20.0", false)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	for _, st := range plan {
		if st.Changed {
			t.Errorf("second refresh at the same version must be a no-op, but %s reported Changed=true", st.Name)
		}
		if st.Diverged {
			t.Errorf("an untouched file must never be reported diverged: %s", st.Name)
		}
	}
	if got := mustRead(t, filepath.Join(dir, ".github", "workflows", "scan.yml")); got != scanBefore {
		t.Error("scan.yml content changed on an idempotent re-run")
	}
	if got := mustRead(t, filepath.Join(dir, ".github", "workflows", "mallcop-investigate.yml")); got != invBefore {
		t.Error("mallcop-investigate.yml content changed on an idempotent re-run")
	}
}

// renderWorkflowAtHistoricalTag renders a workflow ("scan" or "investigate")
// EXACTLY as tag's own code would have: it extracts cli/deployrepo.go at that
// tag with `git show`, compiles it as a standalone program (it depends on
// nothing outside the Go standard library), and runs it. This proves
// behavior against a REAL historical artifact instead of a fixture seeded
// from HEAD's own template (the mistake the mallcoppro-f19 veracity finding
// caught) -- the historical template is computed transiently in a scratch
// temp dir here and is never vendored into the product.
func renderWorkflowAtHistoricalTag(t *testing.T, tag, workflow, version string) string {
	t.Helper()
	repoRootOut, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel: %v", err)
	}
	root := strings.TrimSpace(string(repoRootOut))

	src, err := exec.Command("git", "-C", root, "show", tag+":cli/deployrepo.go").Output()
	if err != nil {
		t.Fatalf("git show %s:cli/deployrepo.go (tag must exist locally): %v", tag, err)
	}
	code := strings.Replace(string(src), "package cli", "package main", 1)

	var fn string
	switch workflow {
	case "scan":
		fn = "renderScanWorkflow"
	case "investigate":
		fn = "renderInvestigateWorkflow"
	default:
		t.Fatalf("renderWorkflowAtHistoricalTag: unknown workflow %q", workflow)
	}
	// fmt and os are already imported by cli/deployrepo.go itself at every
	// tag this item cares about, so appending a main() that calls them needs
	// no new imports.
	code += fmt.Sprintf("\nfunc main() { fmt.Print(%s(%q)) }\n", fn, version)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(code), 0o644); err != nil {
		t.Fatalf("writing extracted historical source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module historicalrender\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("writing scratch go.mod: %v", err)
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running %s's own %s(%q): %v\n%s", tag, fn, version, err, out)
	}
	return string(out)
}

// TestRefreshDeployWorkflowsHandlesGenuinelyOldUnstampedFile is the
// mallcoppro-f19 REWORK proof, run against a REAL historical artifact (never
// a fixture seeded from HEAD's own template): a scan.yml rendered by
// v0.19.0's OWN renderScanWorkflow -- extracted from the actual v0.19.0 tag
// and executed at test time, exactly like the veracity adversary did -- has
// NO content-hash stamp at all (the marker didn't exist yet). This is the
// live 3dl-dev/mallcop-deploy scenario the item names.
//
// The OLD (broken) check re-rendered HEAD's template at the file's own
// extracted version and compared bytes: HEAD's scan.yml has 19 "doctor"
// occurrences, v0.19.0's has zero, so that comparison always mismatched and
// every such file was misreported as a hand-edit (Diverged) -- refusing to
// ever advance the live case.
//
// The FIX: by default this file is classified Unstamped (mallcop truthfully
// cannot verify whether it was hand-edited -- it predates the marker) and is
// left completely untouched, distinct from Diverged (a positive hand-edit
// detection). Passing adoptUnstamped=true (mallcop migrate
// --adopt-unstamped) is the explicit, non-silent opt-in that advances it
// cleanly to the target version and stamps it going forward.
func TestRefreshDeployWorkflowsHandlesGenuinelyOldUnstampedFile(t *testing.T) {
	old := renderWorkflowAtHistoricalTag(t, "v0.19.0", "scan", "v0.19.0")
	if strings.Contains(old, "MALLCOP_STAMP") {
		t.Fatalf("test setup bug: v0.19.0's OWN rendering already carries a stamp marker -- this historical fixture no longer proves the unstamped case:\n%s", old)
	}
	if strings.Contains(old, "doctor") {
		t.Fatalf("test setup bug: v0.19.0 must predate the doctor-publish step (zero 'doctor' occurrences) for this to be the scenario the item names:\n%s", old)
	}
	if !strings.Contains(old, `MALLCOP_VERSION: "v0.19.0"`) {
		t.Fatalf("test setup bug: historical rendering is not pinned to v0.19.0:\n%s", old)
	}

	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "scan.yml"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default (no --adopt-unstamped): left untouched, reported Unstamped --
	// NEVER Diverged (that would falsely claim a detected hand-edit when
	// mallcop actually has no evidence either way).
	plan, err := refreshDeployWorkflows(dir, "v0.20.0", false)
	if err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}
	scanStatus := mustFindWorkflowStatus(t, plan, "scan.yml")
	if scanStatus.Diverged {
		t.Fatalf("a genuinely stale UNSTAMPED file must NOT be reported Diverged (mallcop has no evidence of a hand-edit, only an absent stamp): %+v", scanStatus)
	}
	if !scanStatus.Unstamped {
		t.Fatalf("a real pre-stamp historical file must be reported Unstamped=true: %+v", scanStatus)
	}
	if scanStatus.Changed {
		t.Fatalf("an unstamped file must NOT be advanced without --adopt-unstamped: %+v", scanStatus)
	}
	if raw := mustRead(t, filepath.Join(workflowDir, "scan.yml")); raw != old {
		t.Fatal("default refresh must leave an unstamped file byte-for-byte untouched")
	}

	// --adopt-unstamped: the mallcoppro-f19 fix actually working -- the SAME
	// real historical file advances cleanly.
	plan2, err := refreshDeployWorkflows(dir, "v0.20.0", true)
	if err != nil {
		t.Fatalf("refreshDeployWorkflows (adopt-unstamped): %v", err)
	}
	scanStatus2 := mustFindWorkflowStatus(t, plan2, "scan.yml")
	if !scanStatus2.Changed {
		t.Fatalf("adopting an unstamped file (--adopt-unstamped) must advance it: %+v", scanStatus2)
	}
	if scanStatus2.Diverged {
		t.Fatalf("an adopted unstamped file must not simultaneously report Diverged: %+v", scanStatus2)
	}
	raw2 := mustRead(t, filepath.Join(workflowDir, "scan.yml"))
	if !strings.Contains(raw2, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Errorf("adopted unstamped file was not advanced to v0.20.0:\n%s", raw2)
	}
	if !strings.Contains(raw2, "MALLCOP_STAMP") {
		t.Errorf("adopted+advanced file should carry a content-hash stamp going forward, closing the migration gap:\n%s", raw2)
	}
}

// TestRefreshDeployWorkflowsAdoptUnstampedIsHonestAboutHandEditedFile is the
// mallcoppro-f19 REWORK defect-2 proof: an unstamped file that has ALSO been
// hand-edited is INDISTINGUISHABLE, by construction, from an unstamped file
// that was never touched -- both carry a MALLCOP_VERSION marker and no
// MALLCOP_STAMP marker, and there is nothing else in the bytes that tells
// them apart (see planWorkflowRefresh's doc). --adopt-unstamped still
// advances it (that is the explicit opt-in the operator asked for), but the
// returned status MUST mark AdoptedUnverified=true so the caller (runMigrate)
// can report the risk plainly instead of a plain "adopted" success line.
//
// Without the AdoptedUnverified guard this test fails: the zero-value bool
// is false, indistinguishable from an ordinary safe adoption, and nothing in
// the returned WorkflowFileStatus would let a caller tell "adopted a file we
// could verify" apart from "adopted a file we could NOT verify and which
// happened to carry a real hand-edit".
func TestRefreshDeployWorkflowsAdoptUnstampedIsHonestAboutHandEditedFile(t *testing.T) {
	dir := t.TempDir()
	workflowDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// An unstamped file (predates mallcoppro-f19 provenance tracking) that
	// has ALSO been hand-edited since generation -- the exact ambiguous case
	// defect 2 names. stripStampMarkerForTest mirrors migrate_test.go's
	// stripStampMarker (kept local to this file to avoid a cross-file test
	// helper dependency): it removes only the MALLCOP_STAMP marker line (and
	// its explanatory comment block), simulating a file that genuinely
	// predates the stamp, while leaving the hand-edit appended below intact.
	unstampedAndHandEdited := stripStampMarkerForTest(renderScanWorkflow("v0.19.0")) +
		"\n# operator: added a custom notification step here\n"
	if strings.Contains(unstampedAndHandEdited, "MALLCOP_STAMP") {
		t.Fatalf("test setup bug: fixture still carries a stamp marker:\n%s", unstampedAndHandEdited)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "scan.yml"), []byte(unstampedAndHandEdited), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default (no --adopt-unstamped): must still be left byte-for-byte
	// untouched and reported Unstamped, exactly like the never-edited case --
	// mallcop has no way to tell these two fixtures apart, so it must not
	// treat this one any differently.
	planDefault, err := refreshDeployWorkflows(dir, "v0.20.0", false)
	if err != nil {
		t.Fatalf("refreshDeployWorkflows: %v", err)
	}
	stDefault := mustFindWorkflowStatus(t, planDefault, "scan.yml")
	if !stDefault.Unstamped || stDefault.Changed || stDefault.AdoptedUnverified {
		t.Fatalf("default (no --adopt-unstamped) run over an unstamped+hand-edited file must be Unstamped=true, Changed=false, AdoptedUnverified=false: %+v", stDefault)
	}
	if raw := mustRead(t, filepath.Join(workflowDir, "scan.yml")); raw != unstampedAndHandEdited {
		t.Fatal("default refresh must leave an unstamped+hand-edited file byte-for-byte untouched")
	}

	// --adopt-unstamped: the operator's explicit opt-in advances the file
	// (per the item's accepted ruling -- the flag itself is consent), but the
	// returned status must be honest that this specific adoption was
	// UNVERIFIED: mallcop could not tell the hand-edit apart from a clean
	// legacy file, and the hand-edit is now gone.
	planAdopt, err := refreshDeployWorkflows(dir, "v0.20.0", true)
	if err != nil {
		t.Fatalf("refreshDeployWorkflows (adopt-unstamped): %v", err)
	}
	stAdopt := mustFindWorkflowStatus(t, planAdopt, "scan.yml")
	if !stAdopt.Changed {
		t.Fatalf("--adopt-unstamped must still advance an unstamped file even if it happens to be hand-edited (that is the accepted opt-in): %+v", stAdopt)
	}
	if !stAdopt.AdoptedUnverified {
		t.Fatalf("adopting an unstamped file must be reported AdoptedUnverified=true -- mallcop cannot tell this hand-edited case apart from a clean one, and that must never be silent: %+v", stAdopt)
	}
	raw := mustRead(t, filepath.Join(workflowDir, "scan.yml"))
	if strings.Contains(raw, "operator: added a custom notification step here") {
		t.Fatal("test setup bug: expected the hand-edit to have been overwritten by the accepted --adopt-unstamped opt-in")
	}
	if !strings.Contains(raw, `MALLCOP_VERSION: "v0.20.0"`) {
		t.Errorf("adopted unstamped+hand-edited file was not advanced to v0.20.0:\n%s", raw)
	}
}

// stripStampMarkerForTest removes the MALLCOP_STAMP marker line and its
// following explanation comment lines from a rendered workflow, WITHOUT
// touching anything else -- simulating a file generated before
// mallcoppro-f19's content-hash provenance tracking existed. Mirrors
// migrate_test.go's stripStampMarker; kept local here so this file has no
// test-helper dependency on migrate_test.go.
func stripStampMarkerForTest(rendered string) string {
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

func mustFindWorkflowStatus(t *testing.T, plan []WorkflowFileStatus, name string) *WorkflowFileStatus {
	t.Helper()
	for i := range plan {
		if plan[i].Name == name {
			return &plan[i]
		}
	}
	t.Fatalf("no status returned for %s: %+v", name, plan)
	return nil
}
