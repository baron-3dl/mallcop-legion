package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
	if err := refreshDeployWorkflows(dir, "v0.9.0"); err != nil {
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
	if err := refreshDeployWorkflows(dir, "v0.9.0"); err != nil {
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
