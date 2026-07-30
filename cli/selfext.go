package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/selfext/autonomy"
	"github.com/mallcop-app/mallcop/selfext/contribback"
	"github.com/mallcop-app/mallcop/selfext/engine"
	"github.com/mallcop-app/mallcop/selfext/gharuntime"
	"github.com/mallcop-app/mallcop/selfext/opencode"
	"github.com/mallcop-app/mallcop/selfext/proposer"
	"github.com/mallcop-app/mallcop/selfext/router"
	"github.com/mallcop-app/mallcop/selfext/sandbox"
	"github.com/mallcop-app/mallcop/selfext/session"
)

// runSelfext implements `mallcop selfext` — the OSS, BYOK (Bring-Your-Own-Key)
// entrypoint to mallcop's self-extension code-authoring engine. It authors a
// net-new detector for a detection gap on the CUSTOMER's OWN inference endpoint
// + key, gates the result in-runner, and — on GREEN — drops a reviewable
// artifact. It NEVER pushes or merges.
//
// # BYOK-only — no donut billing here
//
// This binary has NO commercial/donut billing rail: it wires the public
// selfext/* engine to a session.BYOISession, which authorizes with NO spend
// cap, mints NO run key, and records $0 (never a ledger decrement). The
// customer's own key is the customer's own accepted blast radius. Both
// --inference-url and --inference-key-env are therefore REQUIRED (see
// resolveBYOK) — the donut rail is a commercial add-on that lives in
// mallcop-pro, not in this MIT binary. NOTHING here imports a private/commercial
// package (no internal/donut, internal/forge, internal/subkey, internal/spendcap).
//
// # Landlock jail ON by default
//
// The headless opencode child runs under OS-enforced Landlock confinement
// (selfext/jail) by default — no filesystem writes outside its worktree scratch
// tree, no TCP egress except the inference endpoint's port. It is FAIL-CLOSED:
// on a kernel that cannot establish the jail, authoring refuses to start. The
// launcher re-execs the mallcop binary itself, so cmd/mallcop's main() calls
// jail.MaybeReexec() at startup. --no-jail escapes confinement (accepted risk;
// e.g. a kernel below Landlock ABI v4).
//
// Three modes:
//
//	mallcop selfext --run \
//	   --inference-url https://api.mallcop.app --inference-key-env MALLCOP_API_KEY \
//	   --target-repo ~/checkouts/mallcop --lane heal --code-model coding \
//	   --detector-id authored-deploy-burst --event-type github.deployment \
//	   --artifact-dir ./selfext-proposals --budget-usd 2.00
//	   # --target-family is OPTIONAL and defaults to --detector-id; the emitted
//	   # finding.Type (and the scenarios' must_fire/must_not_fire labels the gate
//	   # matches against) are ALWAYS the detector id, so a family that differs
//	   # from it is a metadata-only tag — do NOT expect it in the labels.
//
//	mallcop collect --store <scan-store> --json > gaps.json
//	mallcop selfext --propose \
//	   --inference-url https://api.mallcop.app --inference-key-env MALLCOP_API_KEY \
//	   --collect-json gaps.json --store-repo ~/checkouts/mallcop \
//	   --target-repo ~/checkouts/mallcop --lane investigate --artifact-dir ./selfext-proposals
//	   # add --contribute-back to emit an OSS-PR artifact for a universal widen (never auto-merged)
//
//	mallcop selfext --scaffold-gha --out ~/checkouts/mallcop
//	   # write the CODE-lane GitHub Actions templates + the operator setup checklist
//
//	mallcop selfext --contribute --artifact-dir ./selfext-proposals \
//	   --store-repo ~/checkouts/mallcop --oss-repo mallcop-app/mallcop
//	   # open a shared-OSS PR (under YOUR OWN `gh auth` identity) for every
//	   # contribute-back artifact --propose emitted; persists a ContribBackRecord
//	   # a later `mallcop scan` polls for the merge/close outcome. Never merges.
func runSelfext(args []string) error {
	fs := flag.NewFlagSet("selfext", flag.ContinueOnError)

	run := fs.Bool("run", false, "author ONE detector build for the gap described by the flags")
	propose := fs.Bool("propose", false, "run the collect→propose→gate→route loop over a `mallcop collect --json` envelope")
	scaffoldGHA := fs.Bool("scaffold-gha", false, "write the CODE-lane GitHub Actions templates + operator setup checklist into --out")
	contribute := fs.Bool("contribute", false, "discover router-emitted contribute-back artifacts under --artifact-dir/oss and open each as a shared-OSS PR under YOUR OWN `gh auth` identity (REQUIRES --store-repo, --oss-repo; never auto-merges — see selfext/contribback)")

	// BYOK (Bring-Your-Own-Key) inference — REQUIRED for --run/--propose. The key
	// is read from the NAMED env var (never a literal flag) so it never appears in
	// argv. There is NO donut/commercial rail in the OSS binary.
	inferenceURL := fs.String("inference-url", "", "BYOK: your inference endpoint base URL (REQUIRED for --run/--propose)")
	inferenceKeyEnv := fs.String("inference-key-env", "", "BYOK: NAME of the env var holding your inference API key (REQUIRED; e.g. MALLCOP_API_KEY, ANTHROPIC_API_KEY)")

	// Shared authoring/gate config.
	targetRepo := fs.String("target-repo", "", "path to the TARGET git repo to author into (or MALLCOP_TARGET_REPO env)")
	baseRef := fs.String("base-ref", "origin/main", "base git ref the worktree jail is checked out from")
	lane := fs.String("lane", "heal", "authoring lane (the model string the endpoint receives, unless --code-model overrides it)")
	codeModel := fs.String("code-model", "", "BYOK: literal model id your endpoint should author with, INSTEAD of the bare --lane string (e.g. \"coding\"); empty sends the lane")
	sovereignty := fs.String("sovereignty", "open", "sovereignty tier label recorded in provenance")
	artifactDir := fs.String("artifact-dir", "./selfext-proposals", "human-review lane dir GREEN proposals land in")
	budgetUSD := fs.Float64("budget-usd", 2.00, "per-build spend estimate (BYOK ignores it for billing; still the anti-runaway hint)")
	autonomyFlag := fs.String("autonomy", string(autonomy.NonAutonomy), "operator autonomy dial: non|semi|fully (only \"fully\" merge-automates a GREEN CODE proposal to a LOCAL branch — never a push)")
	noJail := fs.Bool("no-jail", false, "DISABLE the OS-enforced Landlock authoring jail (accepted risk; jail is ON by default)")
	opencodeBin := fs.String("opencode-bin", "", "path to the opencode binary (default: opencode on PATH)")
	maxOutputTokens := fs.Int("max-output-tokens", 0, "per-request output-token ceiling requested of the authoring model (0 = default 32768; reasoning models bill thinking against it — set lower only if your BYOK endpoint rejects large max_tokens)")
	maxAuthoringAttempts := fs.Int("max-authoring-attempts", 0, "max times to re-drive opencode as a FRESH session when an attempt exits 0 having written NOTHING (the narrate-then-die shape; 0 = default 3). Distinct from the adapter's transient non-zero-exit retry")
	validateBin := fs.String("validate-bin", "", "path to the mallcop binary that runs validate-proposal (default: mallcop on PATH)")
	examRepo := fs.String("exam-repo", "", "path to a REFERENCE mallcop tree used to grade a CUSTOMER-SHAPED target repo (one with no cmd/mallcop of its own)")

	// --run gap description.
	detectorID := fs.String("detector-id", "", "proposed authored detector id (--run; e.g. authored-deploy-burst)")
	eventType := fs.String("event-type", "", "connector event type the detector keys on (--run)")
	targetFamily := fs.String("target-family", "", "OPTIONAL finding-metadata family tag (--run; default: detector id). The emitted finding.Type — and the must_fire/must_not_fire labels the gate matches against — are ALWAYS the detector id, so the default is almost always right; a value differing from --detector-id only tags metadata, it does NOT become the label the gate checks")
	severity := fs.String("severity", "medium", "structural severity of the gap exemplar (--run)")
	actor := fs.String("actor", "", "structural actor field of the gap exemplar (--run)")
	source := fs.String("source", "", "structural source field of the gap exemplar (--run)")

	// --propose K8 loop.
	collectJSON := fs.String("collect-json", "", "path to a `mallcop collect --json` envelope (--propose)")
	storeRepo := fs.String("store-repo", "", "customer store repo the tenant overlay is persisted into (--propose; overlays land under <store-repo>/detectors)")
	consent := fs.Bool("consent", false, "explicit per-build consent to emit an OSS contribute-back PR artifact for a universal widen (--propose; never auto-merged)")
	contributeBack := fs.Bool("contribute-back", false, "alias for --consent (--propose)")
	gateJSON := fs.String("gate-json", "", "optional path to a pre-computed `mallcop validate-proposal --json` GateResult (--propose)")

	// --contribute.
	ossRepo := fs.String("oss-repo", "", "shared OSS repo contribute-back PRs target, \"owner/name\" (REQUIRED for --contribute; e.g. mallcop-app/mallcop)")

	// --scaffold-gha.
	scaffoldOut := fs.String("out", "", "scaffold-gha: your mallcop fork checkout to write templates into (REQUIRED for --scaffold-gha)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Exactly one mode.
	modes := 0
	for _, on := range []bool{*run, *propose, *scaffoldGHA, *contribute} {
		if on {
			modes++
		}
	}
	if modes == 0 {
		return errors.New("selfext: pass exactly one of --run, --propose, --scaffold-gha, or --contribute (see -h)")
	}
	if modes > 1 {
		return errors.New("selfext: --run, --propose, --scaffold-gha, and --contribute are mutually exclusive")
	}

	// --scaffold-gha needs no inference at all.
	if *scaffoldGHA {
		return runSelfextScaffold(*scaffoldOut)
	}

	autonomyDial, aerr := autonomy.Parse(*autonomyFlag)
	if aerr != nil {
		return fmt.Errorf("selfext: %w", aerr)
	}

	// --contribute needs no inference either — it opens PRs for artifacts an
	// earlier --propose run already authored, under the operator's own `gh`
	// identity (never a standing credential, design ruling R8).
	if *contribute {
		return runSelfextContribute(contributeArgs{
			artifactDir: *artifactDir,
			storeRepo:   *storeRepo,
			ossRepo:     *ossRepo,
			autonomy:    autonomyDial,
		})
	}

	if *propose {
		return runSelfextPropose(proposeArgs{
			inferenceURL:    *inferenceURL,
			inferenceKeyEnv: *inferenceKeyEnv,
			collectJSON:     *collectJSON,
			storeRepo:       *storeRepo,
			consent:         *consent || *contributeBack,
			gateJSON:        *gateJSON,
			targetRepo:      *targetRepo,
			baseRef:         *baseRef,
			lane:            *lane,
			artifactDir:     *artifactDir,
			validateBin:     *validateBin,
			examRepo:        *examRepo,
			budgetUSD:       *budgetUSD,
			autonomy:        autonomyDial,
			// CODE-lane bridge config (mallcoppro-0e9, design §Gap B): a
			// reported_miss GapCandidate seeds the SAME opencode/engine
			// authoring path --run drives by hand-typed flags, so it needs
			// the same authoring knobs. These flags are already parsed above
			// for --run; --propose simply forwards them too.
			opencodeBin:          *opencodeBin,
			codeModel:            *codeModel,
			sovereignty:          *sovereignty,
			noJail:               *noJail,
			maxOutputTokens:      *maxOutputTokens,
			maxAuthoringAttempts: *maxAuthoringAttempts,
		})
	}

	return runSelfextRun(runArgs{
		inferenceURL:         *inferenceURL,
		inferenceKeyEnv:      *inferenceKeyEnv,
		targetRepo:           *targetRepo,
		baseRef:              *baseRef,
		lane:                 *lane,
		codeModel:            *codeModel,
		sovereignty:          *sovereignty,
		artifactDir:          *artifactDir,
		opencodeBin:          *opencodeBin,
		maxOutputTokens:      *maxOutputTokens,
		maxAuthoringAttempts: *maxAuthoringAttempts,
		validateBin:          *validateBin,
		examRepo:             *examRepo,
		budgetUSD:            *budgetUSD,
		autonomy:             autonomyDial,
		noJail:               *noJail,
		detectorID:           *detectorID,
		eventType:            *eventType,
		targetFamily:         *targetFamily,
		severity:             *severity,
		actor:                *actor,
		source:               *source,
	})
}

// selfextAuthorClass is the stable class recorded in a run's provenance for
// self-extension authoring. It matches the engine's internal default.
const selfextAuthorClass = "selfext-author"

// resolveBYOK resolves the customer's Bring-Your-Own-Key inference endpoint and
// key. BYOK is REQUIRED in the OSS binary — there is NO donut/commercial billing
// rail here — so both --inference-url and --inference-key-env must be present and
// the named env var must resolve non-empty. The key is sourced by ENV VAR NAME
// (never a literal flag) so the secret never appears in argv.
func resolveBYOK(inferenceURL, inferenceKeyEnv string, getenv func(string) string) (url, key string, err error) {
	if strings.TrimSpace(inferenceURL) == "" || strings.TrimSpace(inferenceKeyEnv) == "" {
		return "", "", errors.New(
			"selfext requires BYOK inference: pass --inference-url <endpoint> AND " +
				"--inference-key-env <ENV_VAR_NAME> (the named env var holds your key). " +
				"The OSS binary has no donut/commercial billing rail — donut billing is a commercial add-on elsewhere")
	}
	key = getenv(inferenceKeyEnv)
	if key == "" {
		return "", "", fmt.Errorf("selfext: --inference-key-env %q names an empty or unset env var", inferenceKeyEnv)
	}
	return inferenceURL, key, nil
}

// runArgs bundles the resolved flags the BYOK authoring (--run) loop needs.
type runArgs struct {
	inferenceURL         string
	inferenceKeyEnv      string
	targetRepo           string
	baseRef              string
	lane                 string
	codeModel            string
	sovereignty          string
	artifactDir          string
	opencodeBin          string
	maxOutputTokens      int
	maxAuthoringAttempts int
	validateBin          string
	examRepo             string
	budgetUSD            float64
	autonomy             autonomy.Dial
	noJail               bool
	detectorID           string
	eventType            string
	targetFamily         string
	severity             string
	actor                string
	source               string
}

// runSelfextRun assembles the engine on the BYOK rail and executes ONE authoring
// build. It NEVER pushes or merges: a GREEN gate drops a reviewable artifact
// (and, only at --autonomy fully, force-updates a LOCAL branch); a RED gate
// poisons the fingerprint.
func runSelfextRun(a runArgs) error {
	repo := a.targetRepo
	if repo == "" {
		repo = os.Getenv("MALLCOP_TARGET_REPO")
	}
	if repo == "" {
		return errors.New("selfext --run: --target-repo or MALLCOP_TARGET_REPO is required")
	}
	a.targetRepo = repo
	if a.detectorID == "" || a.eventType == "" {
		return errors.New("selfext --run: --detector-id and --event-type are required")
	}

	endpoint, key, berr := resolveBYOK(a.inferenceURL, a.inferenceKeyEnv, os.Getenv)
	if berr != nil {
		return berr
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Warn("selfext --run: BYOK mode — inference billed to YOUR OWN endpoint (NO spend cap, NO minted key; your key, your blast radius)", "endpoint", endpoint)

	eng, err := buildCodeLaneEngine(a, endpoint, key, log)
	if err != nil {
		return fmt.Errorf("selfext --run: %w", err)
	}

	gap := opencode.TrustedGap{
		DetectorID:   a.detectorID,
		EventType:    a.eventType,
		TargetFamily: a.targetFamily,
		Severity:     a.severity,
		Actor:        a.actor,
		Source:       a.source,
	}

	jailBanner := "Landlock jail ON"
	if a.noJail {
		jailBanner = "jail OFF (--no-jail)"
	}
	fmt.Fprintf(os.Stderr, "selfext --run: authoring one build (BYOK — no cap, %s, budget hint $%.2f)...\n", jailBanner, a.budgetUSD)

	out, err := eng.Run(context.Background(), gap)
	if err != nil {
		return fmt.Errorf("selfext --run: %w", err)
	}
	printSelfextOutcome(out)
	return nil
}

// buildCodeLaneEngine assembles the CODE-lane authoring engine.Engine exactly
// as --run's hand-typed flags do (jail, adapter, reject set, gate, and the
// Autonomy dial). It is the ONE construction path both cli entry points
// share: --run builds its opencode.TrustedGap from flags; --propose's
// reported_miss route (mallcoppro-0e9, design §Gap B) builds the SAME
// opencode.TrustedGap shape from a collector GapCandidate via
// gapCandidateToTrustedGap and feeds it through this identical engine, so the
// dial-gated GREEN/no-novel-gap merge-automation rule is never
// re-implemented — a seed's origin (hand-typed vs. operator-reported) cannot
// change how it is gated.
func buildCodeLaneEngine(a runArgs, endpoint, key string, log *slog.Logger) (*engine.Engine, error) {
	// BYOISession: authorizes with no cap, records $0, no ledger, no run key.
	sess := &session.BYOISession{BaseURL: endpoint, Key: key, Logger: log}

	rejects, err := engine.LoadRejectSet("")
	if err != nil {
		return nil, fmt.Errorf("load reject set: %w", err)
	}

	return &engine.Engine{
		Session: sess,
		Jail:    &sandbox.Jail{TargetRepo: a.targetRepo, BaseRef: a.baseRef},
		Adapter: &opencode.Adapter{
			Bin:             a.opencodeBin,
			Lane:            a.lane,
			Model:           a.codeModel, // BYOK: empty sends the bare lane; the customer opts into a literal id
			Provider:        sandbox.ProviderName,
			ForgeBaseURL:    endpoint,
			Confine:         !a.noJail, // Landlock jail ON by default; --no-jail escapes
			MaxOutputTokens: a.maxOutputTokens,
			Logger:          log,
		},
		Fingerprints:         rejects,
		ValidateBin:          a.validateBin,
		ExamRepo:             a.examRepo,
		ArtifactDir:          a.artifactDir,
		Class:                selfextAuthorClass,
		AuthoringLane:        a.lane,
		Sovereignty:          a.sovereignty,
		BudgetUSD:            a.budgetUSD,
		MaxAuthoringAttempts: a.maxAuthoringAttempts,
		Autonomy:             a.autonomy,
		Logger:               log,
	}, nil
}

// printSelfextOutcome renders the terminal engine Outcome for the operator.
func printSelfextOutcome(out engine.Outcome) {
	switch {
	case out.Skipped:
		fmt.Printf("SKIPPED  known-reject fingerprint %s (spent $0)\n", out.Fingerprint)
	case out.Refused:
		fmt.Printf("REFUSED  %s (spent $0)\n", out.Reason)
	case out.Proposed:
		fmt.Printf("PROPOSED GREEN gate — reviewable artifact: %s\n", out.ArtifactPath)
		if out.Applied {
			fmt.Printf("         autonomy=fully — merge-automated to LOCAL branch %s (no push)\n", out.AppliedBranch)
		}
		fmt.Printf("         cost $%.4f — review and merge MANUALLY; the engine never pushes.\n", out.CostUSD)
	case out.Rejected:
		fmt.Printf("REJECTED RED gate — %s\n", out.Reason)
		fmt.Printf("         cost $%.4f — fingerprint %s recorded (skipped next time).\n", out.CostUSD, out.Fingerprint)
	case out.Failed:
		fmt.Printf("FAILED   %s (cost $%.4f)\n", out.Reason, out.CostUSD)
	default:
		fmt.Printf("UNKNOWN outcome: %+v\n", out)
	}
}

// runSelfextScaffold writes the CODE-lane GitHub Actions runtime templates into
// outDir (an operator's mallcop fork checkout) and prints the operator setup
// checklist. It needs no inference and no key.
func runSelfextScaffold(outDir string) error {
	if strings.TrimSpace(outDir) == "" {
		return errors.New("selfext --scaffold-gha: --out <dir> is required (your mallcop fork checkout)")
	}
	written, err := gharuntime.Scaffold(outDir)
	if err != nil {
		return fmt.Errorf("selfext --scaffold-gha: %w", err)
	}
	fmt.Printf("selfext --scaffold-gha: wrote %d CODE-lane template(s) into %s:\n", len(written), outDir)
	for _, rel := range written {
		fmt.Printf("  %s\n", rel)
	}
	fmt.Print(gharuntime.OperatorChecklist())
	return nil
}

// contributeArgs bundles the resolved flags `mallcop selfext --contribute` needs.
type contributeArgs struct {
	artifactDir string
	storeRepo   string
	ossRepo     string
	autonomy    autonomy.Dial

	// cloneSpec overrides the git clone target pushContribBranch clones from
	// and pushes the head branch to. Empty (the production default, left
	// unset by every CLI-flag-driven call) resolves to
	// "https://github.com/<ossRepo>.git" via resolveCloneSpec. Only tests set
	// this — to a REAL local bare repo path, so pushContribBranch's git
	// clone/checkout/commit/push sequence runs for real with no network.
	cloneSpec string
}

// resolveCloneSpec returns the git clone target for this contribute-back
// run's head-branch push: the explicit override if set (tests only), else
// the shared OSS repo's github.com HTTPS URL, which `git clone`/`git push`
// resolve through the operator's own `gh`-configured git credential helper
// (`gh auth login` wires this up for github.com) — no token is ever read or
// set into the child environment (design ruling R8).
func (a contributeArgs) resolveCloneSpec() string {
	if strings.TrimSpace(a.cloneSpec) != "" {
		return a.cloneSpec
	}
	return "https://github.com/" + strings.TrimSpace(a.ossRepo) + ".git"
}

// contributeSummary tallies what one `mallcop selfext --contribute` run did, for
// the CLI to report. Mirrors the shape of contribback.PollSummary (mallcoppro-003):
// non-fatal per-artifact outcomes are tallied, not swallowed.
type contributeSummary struct {
	// Considered is how many *.json files were found under --artifact-dir/oss.
	Considered int
	// Opened is how many resulted in a NEWLY opened shared-OSS PR this run.
	Opened int
	// Skipped is how many were not opened: the store already held a
	// ContribBackRecord for that fingerprint (fingerprint-keyed dedupe — a
	// re-run over the same artifact directory must not attempt to reopen a PR
	// that already has a record, open or otherwise), or Contribute itself
	// declined (not consented / not universal — defense in depth; the router
	// should never emit such a file, but Contribute re-checks anyway).
	Skipped int
	// Failed is how many could not be loaded/decoded, or whose OpenPR call
	// errored. Each is reported, never silently dropped.
	Failed int
}

// runSelfextContribute is `mallcop selfext --contribute`'s production entry
// point — the missing caller that turns a router-emitted contribute-back
// artifact into an actual pull request (mallcoppro-a6c). Until this command
// existed, `selfext/contribback.Opener.Contribute` was fully built and tested
// but never invoked outside its own test suite: the router emitted a
// reviewable oss-pr-*.json and nothing ever read it back.
//
// It wires the PRODUCTION PROpener (contribback.NewGHOpener — shells out to
// `gh pr create` under the operator's own ambient `gh auth` identity; NO
// standing write credential is ever set into the child environment, design
// ruling R8) and a REAL *store.Store opened on --store-repo (the SAME
// git-backed store `mallcop scan`'s post-scan poll reads — mallcoppro-003),
// then delegates to contributeArtifacts, the testable core.
//
// Invoking --contribute at all IS the operator's explicit opt-in for this run
// (mirroring --run/--propose, which are likewise only reachable by explicit
// invocation) — there is no additional hidden dial. Opener.Contribute itself
// has NO merge path at any autonomy setting: every contributed PR is left OPEN
// for the shared repo's own CI + CODEOWNERS review, always (R3/R8).
func runSelfextContribute(a contributeArgs) error {
	if strings.TrimSpace(a.storeRepo) == "" {
		return errors.New("selfext --contribute: --store-repo is required (the git-backed store the opened PR's ContribBackRecord persists into; the same store `mallcop scan` polls)")
	}
	if strings.TrimSpace(a.ossRepo) == "" {
		return errors.New("selfext --contribute: --oss-repo is required (the shared OSS repo, \"owner/name\", contribute-back PRs target)")
	}
	st, err := store.Open(a.storeRepo)
	if err != nil {
		return fmt.Errorf("selfext --contribute: open store %s: %w", a.storeRepo, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	sum, cerr := contributeArtifacts(context.Background(), a, st, contribback.NewGHOpener(""), log)
	fmt.Fprintf(os.Stderr, "selfext --contribute: %d artifact(s) considered, %d opened, %d skipped, %d failed\n",
		sum.Considered, sum.Opened, sum.Skipped, sum.Failed)
	return cerr
}

// contributeArtifacts is the testable core of `mallcop selfext --contribute`.
// It discovers router-emitted contribute-back artifacts under
// <artifact-dir>/oss (the exact directory selfext --propose's Router.ArtifactDir
// writes into), loads each via contribback.LoadArtifact, and — for every one
// the store has not already recorded a ContribBackRecord for — FIRST creates,
// commits to, and pushes the PR's head branch (pushContribBranch), THEN calls
// Opener.Contribute (which calls PROpener.OpenPR and persists the record).
//
// The push-before-open ordering is load-bearing (mallcoppro-a6c veracity
// rework): `gh pr create` fails outright ("Head sha can't be blank") if asked
// to open a PR from a branch that does not exist or carries no commits ahead
// of base, so the branch must be real BEFORE Contribute ever reaches OpenPR.
//
// pr is injected so a test can assert against a fake without shelling out to a
// real `gh`; the only production caller (runSelfextContribute) always passes
// contribback.NewGHOpener(""). The git push step itself is NOT faked by pr —
// see pushContribBranch and contribPushRunner for how tests exercise it for
// real against a local bare repo.
func contributeArtifacts(ctx context.Context, a contributeArgs, st *store.Store, pr contribback.PROpener, log *slog.Logger) (contributeSummary, error) {
	var sum contributeSummary

	paths, derr := discoverContribArtifacts(a.artifactDir)
	if derr != nil {
		return sum, fmt.Errorf("selfext --contribute: discover artifacts under %s: %w", a.artifactDir, derr)
	}
	sum.Considered = len(paths)
	if sum.Considered == 0 {
		return sum, nil
	}

	existing, lerr := st.LoadContribBackRecords()
	if lerr != nil {
		return sum, fmt.Errorf("selfext --contribute: load existing contribback records: %w", lerr)
	}
	seen := make(map[string]bool, len(existing))
	for _, rec := range existing {
		seen[rec.Fingerprint] = true
	}

	opener := &contribback.Opener{
		Config: contribback.Config{Enabled: true, Repo: a.ossRepo},
		PR:     pr,
		Store:  st,
		Logger: log,
	}

	var errs []error
	for _, path := range paths {
		art, aerr := loadContribArtifact(path)
		if aerr != nil {
			sum.Failed++
			errs = append(errs, fmt.Errorf("%s: %w", path, aerr))
			continue
		}
		if seen[art.Fingerprint] {
			sum.Skipped++
			log.Info("selfext --contribute: already recorded, skipping", "path", path, "fingerprint", art.Fingerprint)
			continue
		}
		// Create + commit + push the PR's head branch BEFORE opening the PR —
		// `gh pr create` cannot open a PR from a branch that doesn't exist or
		// has no commits ahead of base (mallcoppro-a6c veracity rework).
		if perr := pushContribBranch(ctx, a.resolveCloneSpec(), opener.Config.ResolvedBaseBranch(), art); perr != nil {
			sum.Failed++
			errs = append(errs, fmt.Errorf("%s: %w", path, perr))
			continue
		}
		out, cerr := opener.Contribute(ctx, a.autonomy, art)
		if cerr != nil {
			sum.Failed++
			errs = append(errs, fmt.Errorf("%s: %w", path, cerr))
			continue
		}
		seen[art.Fingerprint] = true
		if out.Opened {
			sum.Opened++
			log.Info("selfext --contribute: opened shared-OSS PR", "path", path, "url", out.PRURL)
		} else {
			sum.Skipped++
			log.Info("selfext --contribute: not opened", "path", path, "reason", out.SkipReason)
		}
	}
	if len(errs) > 0 {
		return sum, fmt.Errorf("selfext --contribute: %d of %d artifact(s) failed: %w", len(errs), sum.Considered, errors.Join(errs...))
	}
	return sum, nil
}

// discoverContribArtifacts lists the *.json files under <artifactDir>/oss,
// sorted for determinism. A missing directory (nothing has been --propose'd
// with --consent yet) is not an error — zero artifacts.
func discoverContribArtifacts(artifactDir string) ([]string, error) {
	dir := filepath.Join(artifactDir, "oss")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// loadContribArtifact loads path as a contribback.Artifact via
// contribback.LoadArtifact — the DATA lane (mapping/tuning widen), the only
// lane any producer in this repo ever emits (selfext/router.emitOSSArtifact).
//
// contribback.LoadCodeArtifact (the CODE lane: promoting a merged authored
// detector into OSS core) deliberately has NO caller here. It was wired in an
// earlier revision of this function (sniffing a top-level "kind" ==
// "authored_detector" field) despite there being no producer anywhere in the
// repo for that shape — grepping for "authored_detector"/"code-pr-" only ever
// matched contribback's own decode logic and its unit test, never anything
// that writes one. A dispatch branch a real artifact can never reach is
// speculative dead code on a security-sensitive path (this repo's hard
// invariant: no code-first component ships a branch nothing can drive), so it
// is removed here rather than kept "in case a producer shows up later" — building
// that producer (an authored-detector promotion pipeline: reading the
// customer's own thin-embed repo, verifying the merged gate, staging the
// files) is a real, separately-scoped feature, not something to guess the
// shape of speculatively. contribback.LoadCodeArtifact/artifact_code.go
// themselves are left in place (still unit-tested, decode logic that a real
// producer could wire up later) — only this dead caller branch is gone.
func loadContribArtifact(path string) (contribback.Artifact, error) {
	return contribback.LoadArtifact(path)
}

// proposeArgs bundles the resolved flags the BYOK K8 propose loop needs.
type proposeArgs struct {
	inferenceURL    string
	inferenceKeyEnv string
	collectJSON     string
	storeRepo       string
	consent         bool
	gateJSON        string
	targetRepo      string
	baseRef         string
	lane            string
	artifactDir     string
	validateBin     string
	examRepo        string
	budgetUSD       float64
	autonomy        autonomy.Dial

	// CODE-lane bridge config (mallcoppro-0e9, design §Gap B) — the SAME
	// authoring knobs runArgs carries for --run's hand-typed path, forwarded
	// here so a reported_miss GapCandidate seeds an IDENTICAL engine build
	// (see buildCodeLaneEngine). Optional: a reported_miss gap with
	// targetRepo unset simply cannot author (see runSelfextPropose) — every
	// other field defaults harmlessly (empty opencodeBin -> PATH lookup,
	// empty codeModel -> bare lane, etc.), exactly as --run's flag defaults do.
	opencodeBin          string
	codeModel            string
	sovereignty          string
	noJail               bool
	maxOutputTokens      int
	maxAuthoringAttempts int
}

// runSelfextPropose runs the K8 self-extension DATA lane end to end on the BYOK
// rail:
//
//	mallcop collect --json  →  proposer.Propose (ONE inference per gap on YOUR key)
//	   →  gate (apply overlay to a jail worktree + `mallcop validate-proposal`,
//	       OR a supplied --gate-json, OR escalate)  →  router.Route.
//
// It NEVER pushes or merges: a clean widen lands in the tenant overlay under
// <store-repo>/detectors; an OSS-eligible widen (with --consent/--contribute-back)
// additionally emits a reviewable OSS-PR artifact; a net-new/critical proposal or
// a non-GREEN gate escalates to a human-review artifact.
func runSelfextPropose(a proposeArgs) error {
	if a.collectJSON == "" {
		return errors.New("selfext --propose: --collect-json is required (a `mallcop collect --json` envelope)")
	}
	if a.storeRepo == "" {
		return errors.New("selfext --propose: --store-repo is required (where the tenant overlay is persisted)")
	}

	endpoint, key, berr := resolveBYOK(a.inferenceURL, a.inferenceKeyEnv, os.Getenv)
	if berr != nil {
		return berr
	}

	raw, err := os.ReadFile(a.collectJSON)
	if err != nil {
		return fmt.Errorf("selfext --propose: read collect envelope: %w", err)
	}
	env, err := proposer.DecodeCollectEnvelope(raw)
	if err != nil {
		return err
	}
	tuningGaps := filterTuningGapCandidates(env.GapCandidates)
	reportedMissGaps := filterReportedMissGapCandidates(env.GapCandidates)
	if len(env.MappingGaps) == 0 && len(tuningGaps) == 0 && len(reportedMissGaps) == 0 {
		fmt.Println("selfext --propose: no mapping gaps, override/dissent gap candidates, or reported-miss gap candidates in the envelope — nothing to propose.")
		return nil
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("selfext --propose: BYOK mode — inference billed to YOUR OWN endpoint (NO cap, NO minted key)", "endpoint", endpoint)

	rejects, err := engine.LoadRejectSet("")
	if err != nil {
		return fmt.Errorf("selfext --propose: load reject set: %w", err)
	}

	sess := &session.BYOISession{BaseURL: endpoint, Key: key, Logger: log}

	p := &proposer.Proposer{
		Session:      sess,
		Fingerprints: rejects,
		Lane:         a.lane,
		BudgetUSD:    a.budgetUSD,
		Logger:       log,
	}

	knownTypes := vocabularySet(env.MappingGaps)
	rt := &router.Router{
		KnownEventTypes: knownTypes,
		OverlayDir:      filepath.Join(a.storeRepo, "detectors"),
		ArtifactDir:     filepath.Join(a.artifactDir, "oss"),
		ProvenanceDir:   filepath.Join(a.artifactDir, "provenance"),
		Fingerprints:    rejects,
		Autonomy:        a.autonomy,
		Logger:          log,
	}

	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "selfext --propose: %d mapping gap(s), %d override/dissent gap candidate(s); BYOK (no cap), budget hint $%.2f/gap\n",
		len(env.MappingGaps), len(tuningGaps), a.budgetUSD)

	var proposed, routed int
	for _, mg := range env.MappingGaps {
		out, err := p.Propose(ctx, mg)
		if err != nil {
			return fmt.Errorf("selfext --propose: propose %s/%s: %w", mg.Source, mg.RawAction, err)
		}
		printProposeOutcome(mg, out)
		if !out.Proposed || out.Proposal == nil {
			continue
		}
		proposed++

		g, gerr := resolveProposeGate(ctx, a, knownTypes, *out.Proposal)
		if gerr != nil {
			fmt.Printf("         gate step failed: %v (routing with a non-GREEN gate → human-gate)\n", gerr)
		}
		dec, rerr := rt.Route(*out.Proposal, g, a.consent)
		if rerr != nil {
			return fmt.Errorf("selfext --propose: route %s/%s: %w", mg.Source, mg.RawAction, rerr)
		}
		routed++
		printRouteDecision(dec)
	}

	// GapCandidates (mallcoppro-b42, design §Gap B): override_fp/dissent gaps —
	// operator/committee judgment core/collect.DetectorGaps already surfaces —
	// route into the SAME DATA-lane proposal → gate → route pipeline as a
	// mapping gap, just tuning-shaped instead of mapping-shaped. detect_miss has
	// no finding to tune against; reported_miss is the CODE-lane's own seed
	// (mallcoppro-0e9, below) and is deliberately excluded here — see
	// filterReportedMissGapCandidates.
	for _, gc := range tuningGaps {
		out, err := p.ProposeGap(ctx, gc)
		if err != nil {
			return fmt.Errorf("selfext --propose: propose gap %s %s/%s: %w", gc.Kind, gc.DetectorFamily, gc.Source, err)
		}
		printProposeGapOutcome(gc, out)
		if !out.Proposed || out.Proposal == nil {
			continue
		}
		proposed++

		g, gerr := resolveProposeGate(ctx, a, knownTypes, *out.Proposal)
		if gerr != nil {
			fmt.Printf("         gate step failed: %v (routing with a non-GREEN gate → human-gate)\n", gerr)
		}
		dec, rerr := rt.Route(*out.Proposal, g, a.consent)
		if rerr != nil {
			return fmt.Errorf("selfext --propose: route gap %s %s/%s: %w", gc.Kind, gc.DetectorFamily, gc.Source, rerr)
		}
		routed++
		printRouteDecision(dec)
	}

	// reported_miss GapCandidates (mallcoppro-0e9, design §Gap B): the
	// CODE-lane's own seed — an operator's `mallcop feedback report-miss`
	// asserted the loop missed a (source, event_type[, actor]) it should
	// have flagged. This is an AUTHORING signal (a net-new/widened
	// detector), never a tuning-widen of an existing detector (that is the
	// override_fp/dissent DATA lane above, mallcoppro-b42) — the two filters
	// are disjoint by Kind, so a gap is never double-consumed on both lanes.
	// The CODE lane needs a target repo to author into; when --target-repo
	// is unset there is nothing to do but say so and continue (never a fatal
	// error — the DATA lane above may still have proposed/routed something).
	var codeProposed, codeApplied int
	if len(reportedMissGaps) > 0 {
		if a.targetRepo == "" {
			fmt.Printf("SKIPPED  %d reported-miss gap candidate(s) — CODE lane needs --target-repo to author into (spent $0)\n", len(reportedMissGaps))
		} else {
			runA := runArgs{
				inferenceURL:         a.inferenceURL,
				inferenceKeyEnv:      a.inferenceKeyEnv,
				targetRepo:           a.targetRepo,
				baseRef:              a.baseRef,
				lane:                 a.lane,
				codeModel:            a.codeModel,
				sovereignty:          a.sovereignty,
				artifactDir:          a.artifactDir,
				opencodeBin:          a.opencodeBin,
				maxOutputTokens:      a.maxOutputTokens,
				maxAuthoringAttempts: a.maxAuthoringAttempts,
				validateBin:          a.validateBin,
				examRepo:             a.examRepo,
				budgetUSD:            a.budgetUSD,
				autonomy:             a.autonomy,
				noJail:               a.noJail,
			}
			// buildCodeLaneEngine is the EXACT construction --run uses (see
			// its doc comment) — the dial-gated GREEN/no-novel-gap
			// merge-automation rule is the engine's, unchanged, never
			// re-implemented here.
			codeEng, cerr := buildCodeLaneEngine(runA, endpoint, key, log)
			if cerr != nil {
				return fmt.Errorf("selfext --propose: code lane: %w", cerr)
			}
			for _, gc := range reportedMissGaps {
				gap := gapCandidateToTrustedGap(gc)
				fmt.Fprintf(os.Stderr, "selfext --propose: reported_miss %s/%s — seeding CODE-lane authoring run (detector-id %s)...\n", gc.Source, gc.EventType, gap.DetectorID)
				out, rerr := codeEng.Run(ctx, gap)
				if rerr != nil {
					return fmt.Errorf("selfext --propose: code lane run for reported_miss %s/%s: %w", gc.Source, gc.EventType, rerr)
				}
				printSelfextOutcome(out)
				if out.Proposed {
					codeProposed++
				}
				if out.Applied {
					codeApplied++
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "selfext --propose: done — %d proposed, %d routed, %d code-lane proposed (%d merge-automated).\n", proposed, routed, codeProposed, codeApplied)
	return nil
}

// filterTuningGapCandidates selects the GapCandidates this DATA-lane propose
// pass consumes: override_fp (an operator's suppress-verb disagreed with the
// agent's stored decision) and dissent (a consensus committee did not fully
// agree). Both are judgment signals that should WIDEN what the committee sees
// (R9 — never a force-escalate/suppress rule). detect_miss carries no finding
// to tune a detector against. reported_miss is intentionally excluded: it is
// the CODE-lane's own seed (mallcoppro-0e9, a separate item) — routing it here
// too would double-consume the same operator signal on two lanes.
func filterTuningGapCandidates(gaps []proposer.GapCandidate) []proposer.GapCandidate {
	var out []proposer.GapCandidate
	for _, g := range gaps {
		if g.Kind == "override_fp" || g.Kind == "dissent" {
			out = append(out, g)
		}
	}
	return out
}

// filterReportedMissGapCandidates selects the GapCandidates that seed the
// CODE lane's own authoring run: an operator-reported miss
// (`mallcop feedback report-miss`) is a recall-red the loop already knows it
// missed (core/collect.GapCandidate.IsRecallRed) — an AUTHORING signal (a
// net-new/widened detector), never a tuning-widen of an existing detector's
// keyword list (that's the override_fp/dissent DATA lane,
// filterTuningGapCandidates above; mallcoppro-b42). Sibling filter, disjoint
// by Kind: a GapCandidate is selected by exactly one of the two filters, so
// the same operator signal is never double-consumed on both lanes
// (mallcoppro-0e9, design §Gap B).
func filterReportedMissGapCandidates(gaps []proposer.GapCandidate) []proposer.GapCandidate {
	var out []proposer.GapCandidate
	for _, g := range gaps {
		if g.Kind == "reported_miss" {
			out = append(out, g)
		}
	}
	return out
}

// reportedMissSlugPattern collapses anything outside [a-z0-9] to a single "-"
// when deriving a stable detector id from a reported_miss gap's family.
var reportedMissSlugPattern = regexp.MustCompile(`[^a-z0-9]+`)

// reportedMissDetectorID derives a stable, DetectorID-legal detector id from a
// reported_miss gap's family string. Never hand-typed: the CODE lane's own
// seed has no operator-supplied --detector-id (mallcop feedback report-miss
// takes no such flag), so the id must be reproducibly derived from the SAME
// structured fields the gap already carries — two reports of the same family
// derive the same id, which is what lets Engine.Fingerprints/anti-thrash
// (opencode.TrustedGap.Fingerprint) skip a known-reject without re-spending
// inference.
func reportedMissDetectorID(family string) string {
	slug := reportedMissSlugPattern.ReplaceAllString(strings.ToLower(strings.TrimSpace(family)), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "gap"
	}
	return "authored-" + slug
}

// gapCandidateToTrustedGap seeds a CODE-lane opencode.TrustedGap from a
// reported_miss GapCandidate (mallcoppro-0e9, design §Gap B) — the bridge
// that lets runSelfextPropose's reported_miss route feed runSelfextRun's
// existing CODE-lane engine (buildCodeLaneEngine) instead of the hand-typed
// --detector-id/--event-type/... flags --run reads. Family falls back
// Source -> EventType because `mallcop feedback report-miss` only requires
// at least ONE of --source/--event-type (core/collect's GapReportedMiss
// construction leaves DetectorFamily empty when the operator gave neither a
// finding source nor scoped it via a family-bearing source), so a gap always
// derives a stable, non-empty detector id. Only structured GapCandidate
// fields cross this boundary — never raw operator free text: the collector
// already drops --description before this GapCandidate exists (see
// core/collect.GapEvidence's doc comment).
func gapCandidateToTrustedGap(gc proposer.GapCandidate) opencode.TrustedGap {
	family := strings.TrimSpace(gc.DetectorFamily)
	if family == "" {
		family = strings.TrimSpace(gc.Source)
	}
	if family == "" {
		family = strings.TrimSpace(gc.EventType)
	}
	severity := strings.TrimSpace(gc.Severity)
	if severity == "" {
		severity = "medium" // reported_miss carries no finding, so no finding severity; matches --run's own --severity default
	}
	return opencode.TrustedGap{
		DetectorID:   reportedMissDetectorID(family),
		EventType:    gc.EventType,
		TargetFamily: family,
		Severity:     severity,
		Actor:        gc.Evidence.ExpectedActor,
		Source:       gc.Source,
	}
}

// resolveProposeGate obtains the GateResult for a proposal. Preference order:
//  1. --target-repo present → apply the overlay to a throwaway jail worktree,
//     commit, and run the trusted `mallcop validate-proposal` inline.
//  2. --gate-json present → decode the operator-supplied GateResult.
//  3. neither → a zero GateResult (not GREEN), which the router escalates to a
//     human — the fail-safe default.
func resolveProposeGate(ctx context.Context, a proposeArgs, knownTypes map[string]bool, prop proposer.Proposal) (engine.GateResult, error) {
	if a.targetRepo != "" {
		return proposeGateViaWorktree(ctx, a, knownTypes, prop)
	}
	if a.gateJSON != "" {
		raw, err := os.ReadFile(a.gateJSON)
		if err != nil {
			return engine.GateResult{}, fmt.Errorf("read --gate-json: %w", err)
		}
		var gr engine.GateResult
		if err := json.Unmarshal(raw, &gr); err != nil {
			return engine.GateResult{}, fmt.Errorf("decode --gate-json: %w", err)
		}
		return gr, nil
	}
	return engine.GateResult{}, nil
}

// proposeGateViaWorktree applies the proposal's overlay to a jail worktree of the
// target repo, commits it, and runs the merged gate over base..HEAD. The
// worktree is force-removed on return.
func proposeGateViaWorktree(ctx context.Context, a proposeArgs, knownTypes map[string]bool, prop proposer.Proposal) (engine.GateResult, error) {
	jail := &sandbox.Jail{TargetRepo: a.targetRepo, BaseRef: a.baseRef}
	wt, err := jail.Open(ctx)
	if err != nil {
		return engine.GateResult{}, fmt.Errorf("open worktree jail: %w", err)
	}
	defer func() { _ = wt.Close() }()

	if _, err := router.WriteOverlay(filepath.Join(wt.Dir, "detectors"), prop, knownTypes); err != nil {
		return engine.GateResult{}, fmt.Errorf("apply overlay to worktree: %w", err)
	}
	if _, err := wt.CommitAuthored(ctx, "selfext: apply add-only proposal "+prop.Fingerprint); err != nil {
		return engine.GateResult{}, fmt.Errorf("commit overlay: %w", err)
	}
	bin := a.validateBin
	if bin == "" {
		bin = "mallcop"
	}
	gr, _, err := engine.RunValidateProposal(ctx, bin, wt.Dir, wt.BaseSHA, a.examRepo)
	if err != nil {
		return engine.GateResult{}, fmt.Errorf("gate: %w", err)
	}
	return gr, nil
}

// vocabularySet unions the closed SuggestedVocabulary across all gaps into a
// canonical membership set for the router's net-new-type check.
func vocabularySet(gaps []proposer.MappingGap) map[string]bool {
	set := map[string]bool{}
	for _, g := range gaps {
		for _, v := range g.SuggestedVocabulary {
			set[strings.ToLower(strings.TrimSpace(v))] = true
		}
	}
	return set
}

// printProposeOutcome renders one proposer outcome for the operator.
func printProposeOutcome(mg proposer.MappingGap, out proposer.Outcome) {
	head := fmt.Sprintf("%s/%s (%dx)", mg.Source, mg.RawAction, mg.Count)
	switch {
	case out.Skipped:
		fmt.Printf("SKIPPED  %s — known-reject fingerprint (spent $0)\n", head)
	case out.Refused:
		fmt.Printf("REFUSED  %s — %s (spent $0)\n", head, out.Reason)
	case out.Proposed:
		fmt.Printf("PROPOSED %s — %s $%.4f\n", head, describeProposal(out.Proposal), out.CostUSD)
	case out.Rejected:
		fmt.Printf("REJECTED %s — %s (fingerprint poisoned; cost $%.4f)\n", head, out.Reason, out.CostUSD)
	case out.Failed:
		fmt.Printf("FAILED   %s — %s (cost $%.4f)\n", head, out.Reason, out.CostUSD)
	default:
		fmt.Printf("UNKNOWN  %s — %+v\n", head, out)
	}
}

// printProposeGapOutcome renders one proposer outcome for a GapCandidate
// (override_fp/dissent) propose run — the tuning-lane sibling of
// printProposeOutcome for the mapping lane.
func printProposeGapOutcome(gc proposer.GapCandidate, out proposer.Outcome) {
	head := fmt.Sprintf("gap:%s %s/%s", gc.Kind, gc.DetectorFamily, gc.Source)
	switch {
	case out.Skipped:
		fmt.Printf("SKIPPED  %s — known-reject fingerprint (spent $0)\n", head)
	case out.Refused:
		fmt.Printf("REFUSED  %s — %s (spent $0)\n", head, out.Reason)
	case out.Proposed:
		fmt.Printf("PROPOSED %s — %s $%.4f\n", head, describeProposal(out.Proposal), out.CostUSD)
	case out.Rejected:
		fmt.Printf("REJECTED %s — %s (fingerprint poisoned; cost $%.4f)\n", head, out.Reason, out.CostUSD)
	case out.Failed:
		fmt.Printf("FAILED   %s — %s (cost $%.4f)\n", head, out.Reason, out.CostUSD)
	default:
		fmt.Printf("UNKNOWN  %s — %+v\n", head, out)
	}
}

func describeProposal(p *proposer.Proposal) string {
	if p == nil {
		return "(nil)"
	}
	switch p.Kind {
	case proposer.KindMapping:
		if p.Mapping != nil {
			return fmt.Sprintf("map %s/%s → %s", p.Mapping.Source, p.Mapping.RawAction, p.Mapping.EventType)
		}
	case proposer.KindTuning:
		if p.Tuning != nil {
			return fmt.Sprintf("tune %s.%s += %v", p.Tuning.Detector, p.Tuning.Key, p.Tuning.AddedValues)
		}
	}
	return string(p.Kind)
}

// printRouteDecision renders one router decision for the operator.
func printRouteDecision(dec router.Decision) {
	fmt.Printf("         → %s: %s\n", strings.ToUpper(string(dec.Destination)), dec.Reason)
	if dec.OverlayPath != "" {
		fmt.Printf("           overlay: %s\n", dec.OverlayPath)
	}
	if dec.ArtifactPath != "" {
		fmt.Printf("           OSS-PR artifact (review + open PR MANUALLY): %s\n", dec.ArtifactPath)
	}
}
