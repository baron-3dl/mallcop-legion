// Package cli implements the full mallcop CLI as an importable package. An
// external module can embed the entire CLI with:
//
//	import "github.com/mallcop-app/mallcop/cli"
//	func main() { cli.Main() }
//
// The embedder controls its own detector linkage the same way cmd/mallcop
// does: blank-import whatever detect.Register-ing package(s) it wants before
// calling cli.Main() (core/detect/authored, or an external equivalent). This
// package intentionally does NOT import core/detect/authored itself — that
// blank import is the human-wired registration seam and belongs to the
// binary's main package, not to this reusable library.
//
// Usage:
//
//	mallcop scan        [--config <mallcop.yaml>] | --store <dir> [--events <file> | --connector github --github-org <org>] [--tuning <yaml>] [--json]
//	mallcop detect      [--baseline <path>] [--tuning <yaml>]   < events.jsonl   > findings.jsonl
//	mallcop exam-detect [--json] [--tuning <yaml>]
//	mallcop eval        [--json] [--scenarios-dir <dir>] [--tuning <yaml>]
//	mallcop validate-proposal --base <ref> [--head <ref>] [--guard-only] [--allow-no-coverage-gain] [--json]
//	mallcop collect     --store <dir> [--fidelity <json>] [--json]
//	mallcop init        [--dir <path>] [--pro] [--create-repo owner/name] [--mallcop-version <tag>] [--github-token-env <VAR>]
//	mallcop migrate     [--dir <path>] [--mallcop-version <tag>] [--config-only] [--dry-run]
//	mallcop status      --store <dir> [--gate --max-age <dur>]
//	mallcop config
//	mallcop config set connector --kind=file|github|cloud --id=<id> [...]
//	mallcop config set autonomy <non|semi|fully>
//	mallcop config set org.owned --match=<id|arn|role-segment> [--name=] [--relationship=]
//	mallcop feedback    <finding_id> approve|dismiss --store <dir> [--reason <text>] [--by <name>]
//	mallcop feedback    report-miss --store <dir> --source <src> --event-type <type> [--actor <a>] [--window <w>] [--description <text>]
//	mallcop case        close|age <case_id> --store <dir> [--reason <text>] [--by <name>]
//	mallcop scenario    capture --store <dir> [--event-ids <ids>] [--actor <a> --window <dur>] --must-fire <family>|--must-not-fire <family> [--reserved] [--scenarios-dir <dir>]
//	mallcop scenario    lint [--scenarios-dir <dir>] [--json]
//	mallcop scenario    contribute [--yes] [--dry-run] [--allow-authored] [--repo owner/name] [--reference-repo <path>] <scenarios/file.yaml>
//	mallcop improve     "<free text>" | --detector-id <id> --event-type <type> [--target-family <f>] [--rail <r>] [--json]
//	mallcop investigate --question <text> --store <dir> [--baseline <path>] | --serve --inbox <file> --outbox <file> --store <dir>
//	mallcop selfext     --run | --propose | --scaffold-gha  (BYOK self-extension: author detectors on YOUR OWN inference)
package cli

import (
	"flag"
	"fmt"
	"os"
)

// Main is the CLI entrypoint. It parses os.Args (via the flag package's
// default CommandLine), dispatches to the requested subcommand, and calls
// os.Exit with the same exit codes cmd/mallcop has always used:
//
//	0  success
//	1  findings detected (scan / detect / exam-detect / validate-proposal)
//	2  any other command failure
//
// Callers (cmd/mallcop's main.go, or an external embedder) are expected to
// blank-import their detector registration package(s) before calling Main,
// then simply call cli.Main() as their entire main().
func Main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	var err error
	switch cmd {
	case "scan":
		err = runScan(args)
	case "detect":
		err = runDetect(args)
	case "exam-detect":
		err = runExamDetect(args)
	case "eval":
		err = runEval(args)
	case "validate-proposal":
		err = runValidateProposal(args)
	case "collect":
		err = runCollect(args)
	case "init":
		err = runInit(args)
	case "migrate":
		err = runMigrate(args)
	case "status":
		err = runStatus(args)
	case "config":
		if len(args) > 0 && args[0] == "set" {
			err = runConfigSet(args[1:])
		} else {
			err = runConfig(args)
		}
	case "feedback":
		err = runFeedback(args)
	case "case":
		err = runCase(args)
	case "scenario":
		err = runScenario(args)
	case "improve":
		err = runImprove(args)
	case "investigate":
		err = runInvestigate(args)
	case "selfext":
		err = runSelfext(args)
	default:
		fmt.Fprintf(os.Stderr, "mallcop: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		if isFindingsError(err) {
			// exit 1 = findings detected (not an error condition)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "mallcop %s: %v\n", cmd, err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mallcop — security scan CLI

Commands:
  scan    Run a one-shot agentic security scan (connect -> detect -> cascade -> store)
    --config     Path to mallcop.yaml (overrides discovery/$MALLCOP_CONFIG). The
                 zero-flag path: run 'mallcop init' then bare 'mallcop scan' —
                 store/connector/inference all resolve from the discovered
                 mallcop.yaml. Absent config => today's flag-only behavior.
    --store      Path to the git-repo store for findings/resolutions (required
                 only when no config resolves a store path)
    --events     Events JSONL source (file path, or "-" for stdin; default: "-")
    --connector  "file" (default, reads --events) or "github"
    --github-org GitHub org to scan (required when --connector github)
    --baseline   Optional path to a baseline JSON file
    --base-url   Inference endpoint base URL (overrides $MALLCOP_INFERENCE_URL)
    --workers    Bounded resolve-pool size (0 = pipeline default)
    --tuning     Optional detector tuning YAML (widen-only extra_* knobs)
    --json       Output the summary as JSON
                 Inference auth: $MALLCOP_INFERENCE_URL + $MALLCOP_API_KEY
                 (BYOK: vendor URL+key; Forge: forge URL + mallcop-sk-* key).
                 With no URL, every finding force-escalates (fail-safe).

  detect  Run offline detection over events JSONL on stdin (no inference key)
    --baseline  Optional path to a baseline JSON file
    --tuning    Optional detector tuning YAML (widen-only extra_* knobs)
               Reads events JSONL from stdin, writes findings JSONL to stdout.

  exam-detect  Grade the offline detect layer against the labeled exam corpus
    --json        Output the report as JSON
    --tuning      Optional detector tuning YAML (widen-only extra_* knobs) —
                  grades the corpus WITH the tuning applied, so a tuning
                  proposal can be evaluated before it is committed.
    --sidecar-src Optional Go package directory built to a wasip1 .wasm module
                  and graded through the real detecthost host IN ADDITION to
                  any configured sidecars — the CUSTOMER-TREE exam mode: the
                  detector need not live in this repo's own tree, only be a
                  valid package implementing core/detect.Detector via
                  pkg/detectorhost.
               Runs core/detect over every exam scenario labeled with an
               expected_detection block (must_fire / must_not_fire detector
               families) and reports per-scenario pass/fail. Offline and
               deterministic — no inference key. Exit 1 = detection gap(s).

  eval  Run the recall-first eval INSIDE your own deploy repo (mallcoppro-bc2)
    --json          Output the reference+local reports as JSON
    --scenarios-dir Path to your own scenarios/ directory (default:
                    <repo-root>/scenarios; missing default dir = empty union,
                    not an error)
    --tuning        Optional detector tuning YAML (widen-only extra_* knobs)
               Grades the EMBEDDED reference corpus (no exams/scenarios/ needed
               on disk) UNIONED with your OWN scenarios/ scenarios, through the
               SAME fleet 'mallcop scan' runs (configured WASM sidecars
               included). Prints the recall/precision split TWICE — once for
               the reference corpus, once for "MY MISSED ATTACKS" / "MY FALSE
               ALARMS" over just your own scenarios, so your own coverage is
               never blended with the shipped reference number. Reserved
               scenarios (reserved: true) in your scenarios/ dir for a family
               with no detector yet show as tracked gaps, not hard failures.
               No network, no inference key. Exit codes mirror exam-detect.

  validate-proposal  Run the FREE-TIER gate over a self-extension proposal diff
    --base       Base git ref the proposal diffs against (required)
    --head       Head git ref of the proposal (default: HEAD)
    --guard-only Run only the static invariant guard stage
    --allow-no-coverage-gain
                 Waive the coverage-+1 requirement (plumbing/no-op diffs)
    --json       Output the full versioned GateResult as JSON
                 Ordered $0 stages, short-circuiting on the first failure:
                 (1) guard — the static invariant guard: protected paths are
                 untouchable, existing detector code / exam scenarios are
                 frozen, and YAML data (detectors/tuning.yaml, operator-
                 decision routes) may only WIDEN what the detection committee
                 sees; (2) structural — the head tree builds and the authored
                 detector tree passes the import allow-list; (3) exam-detect —
                 base vs head exam reports must show no regression, at least
                 one closed detection gap, and no undeclared new firings.
                 Run from inside the repo being validated. Exit 1 = rejected.

  collect  Mine a scan's store for coverage gaps (the self-extension feedstock)
    --store     Path to the git-repo store written by 'mallcop scan' (required)
    --fidelity  Optional JSON array of eval.DetectFidelityRow (an exam-detect
                fidelity dump's 'rows') — enables the detect_miss gap kind the
                store cannot produce on its own. Absent, only the store-pure
                gap kinds (override_fp, dissent, reported_miss) are surfaced.
    --gate      Exit 1 when a RECALL RED is present (a missed known attack — a
                detect_miss or an operator report-miss). Precision gaps
                (override_fp, dissent) never gate. The scheduled-scan
                fail-on-miss switch (Baron ruling).
    --json      Emit the versioned envelope {schema_version, mapping_gaps,
                gap_candidates} — the stable process boundary the mallcop-pro
                proposer consumes. Offline, deterministic, no inference key.
                Human-readable summary otherwise. Exit 2 = failure.

  init    Scaffold mallcop.yaml + a findings store + sample events, print next steps
    --dir               Directory to initialize (default: current directory)
    --pro               Generate mallcop.yaml on the managed donut inference rail
                        (api.mallcop.app) instead of the offline fail-safe default
    --create-repo       owner/name -- also scaffold deployment-repo assets (go.mod
                        pin, detectors/, connectors/, .github/workflows/scan.yml)
                        and create+push a real customer deployment repo to GitHub
                        (see cli/deployrepo.go)
    --mallcop-version   Release tag to pin the deployment repo's go.mod + scheduled
                        Action to (default: query the latest GitHub release)
    --github-token-env  Env var holding a GitHub token with repo-create scope,
                        used with --create-repo (default: MALLCOP_GITHUB_TOKEN)

  migrate Upgrade an EXISTING deploy repo in place to the current schema + pinned release
    --dir               Deploy-repo directory to upgrade (default: current directory)
    --mallcop-version   Release tag to pin workflows + go.mod to (default: latest GitHub release)
    --config-only       Only migrate mallcop.yaml; leave workflows + go.mod untouched
    --dry-run           Print what would change without writing any files
                Rewrites a pre-v0.10 mallcop.yaml (secrets/routing/pro blocks,
                connectors-as-map) to the current strict schema, force-refreshes
                .github/workflows/{scan,mallcop-investigate}.yml, and bumps the
                go.mod mallcop pin. Loudly reports every dropped legacy key.
                Commit + push is the operator's step (printed next-steps).

  status  Report findings/resolutions + coverage gaps recorded in a store
    --store    Path to the git-repo store written by 'mallcop scan' (required)
               Also surfaces the store-pure coverage gaps (operator report-miss
               reports + override/dissent) and flags any RECALL RED.

  config  Print the effective scan config merged from a discovered mallcop.yaml + the environment
  config set connector --kind=file|github|cloud --id=<id> [--path=][--org=][--source=][--binary=][--since=][--args=a,b][--env=NAME1,NAME2]
                Add a connector to mallcop.yaml (strict-validated, atomic write).
                Rejects a duplicate id, an unknown kind, or an inline secret in --env.
                THE SHARED PRIMITIVE any driver of this change (this command, a
                chat surface) must call — see core/config.AddConnector.
  config set autonomy <non|semi|fully>
                Set learning.autonomy in mallcop.yaml (strict enum, atomic write).
                THE SHARED PRIMITIVE — see core/config.SetAutonomy.
  config set org.owned --match=<id|arn|role-segment> [--name=][--relationship=]
                Name one of YOUR OWN accounts/roles/relays in mallcop.yaml's org.owned
                block so the next scan resolves a recurring, baseline-known actor as
                owned (by name/relationship) instead of an unknown external actor —
                naming only, never a verdict override. Strict-validated, atomic write.
                THE SHARED PRIMITIVE the record_owned chat tool also calls — see
                core/config.AddOwned.

  feedback  Record an operator decision on a finding; the next scan honors it
    <finding_id> approve|dismiss   approve = activity known-good; dismiss = not actionable
    --store    Path to the git-repo store written by 'mallcop scan' (required)
    --reason   Operator rationale (free text, recorded for audit)
    --by       Operator identity (defaults to $USER)
               Both verbs persist a 'suppress' directive keyed on the finding's
               source/type/actor, so future findings of that class are dropped.

  feedback report-miss  Record an operator-asserted FALSE-NEGATIVE (a miss)
    --store       Path to the git-repo store (required)
    --source      Source id the miss concerns (required unless --event-type given)
    --event-type  Event/action type the loop should have flagged (required unless --source given)
    --actor       Optional actor the miss concerns
    --window      Optional structured time window (e.g. "24h", "off-hours")
    --description Optional free-text rationale (AUDIT only — never forwarded into a proposal)
    --by          Operator identity (defaults to $USER)
               Persists a 'report-miss' directive; 'mallcop collect' surfaces it
               as a recall gap and 'mallcop status' counts it. The description is
               NEVER forwarded raw into a proposal — only the structured fields.

  scenario capture  Grow scenarios/ from YOUR OWN real telemetry (no hand-writing YAML)
    --store         Path to the git-repo store written by 'mallcop scan' (required)
    --event-ids     Comma-separated explicit event IDs to capture
    --actor         Actor to select events for (requires --window)
    --window        Duration (e.g. "24h") of the actor's own activity, measured
                    back from that actor's latest matching event in the store
                    (requires --actor)
    --must-fire     Comma-separated detector family token(s) this event set
                    MUST trigger — an attack the operator saw or fears
    --must-not-fire Comma-separated detector family token(s) this event set
                    must NOT trigger — a benign activity that was false-alarmed
                    (pairs with 'mallcop feedback dismiss')
    --reserved      Mark --must-fire as a RESERVED TEST (a detector for it may
                    not exist yet); invalid with --must-not-fire
    --id            Scenario id (default: auto-generated LOCAL-<family>-<hash>)
    --title         Finding title (default: derived from family + actor)
    --severity      Finding severity (default: medium)
    --scenarios-dir Directory to write into (default: <repo-root>/scenarios)
    --force         Overwrite an existing scenario file at the resolved path
    --by            Operator identity recorded in the file header (default: $USER)
               Reads the REAL stored events + the store's DERIVED baseline (the
               SAME projection the scan pipeline gates on) and writes a
               schema-valid, provenance:captured scenario YAML into scenarios/.
               No inference calls; the output is DATA (a test fixture), never a
               detector or lookup rule. Secret-shaped metadata values are
               redacted; actors/targets are kept — this file stays LOCAL to your
               own repo. Run 'mallcop eval' to grade it, or 'mallcop scenario
               lint' to check benign-twin coverage.

  scenario lint  Validate scenarios/*.yaml and nudge toward benign-twin coverage
    --scenarios-dir Directory to lint (default: <repo-root>/scenarios)
    --json          Output the lint result as JSON
               Every file must parse via internal/exam.Load (the SAME loader
               'mallcop eval' uses) — a parse failure is a hard error. Every
               LOCALLY-CAPTURED must_fire family without a must_not_fire twin
               ANYWHERE in the directory prints a WARNING with the exact family
               and a one-line capture recipe — never a block (authoring-time
               guidance, not a gate).

  scenario contribute  Offer a local scenario to the shared, shipped corpus (opt-in commons)
    <scenarios/file.yaml> Path to the local scenario to contribute (flags MUST
                          precede this positional argument)
    --yes            Confirm: open a PR with the content shown below (required
                      unless --dry-run)
    --dry-run        Print the redaction diff + would-be PR content; NEVER
                      opens a PR or touches the network, regardless of --yes
    --allow-authored Allow contributing a provenance:authored scenario
                      (refused by default — author-independence)
    --repo           Target owner/name (default: mallcop-app/mallcop)
    --reference-repo Local checkout used as the base corpus for pin regen
                      (default: this binary's own embedded reference corpus)
               Sanitizes a copy of the local scenario: actors/identifiers
               (UUIDs, emails, hostnames, IPs, account ids) canonicalized
               EVERYWHERE — including every metadata value and key at any
               nesting depth — secret-shaped metadata redacted, raw payloads
               stripped, timestamps shifted onto the corpus's 2026-03 window
               preserving relative deltas. Shows the FULL redaction ledger +
               would-be PR content, residue-checks every original against the
               outgoing bytes, then — ONLY on --yes — opens a normal REVIEWED
               pull request (uses the gh CLI if available, else prints exact
               manual instructions). Nothing auto-merges. The local scenario
               file is NEVER modified — contribution is always a copy.

  improve  Turn a request into a PROPOSE-ONLY self-extension proposal (gated PR)
    "<free text>"    Free-text mode: ONE inference call structures the request
                     into a strict-JSON proposal (same extraction as the chat
                     surface); an out-of-scope request honestly refuses.
    --detector-id    Flags mode (no inference): the detector id to propose
    --event-type     Flags mode: the dotted event type it gates on
    --target-family  Optional detector family the proposal targets
    --rail           Optional self-extension rail forwarded to the dispatcher
    --base-url       Free-text mode inference endpoint (overrides $MALLCOP_INFERENCE_URL)
    --json           Emit the versioned proposal envelope as JSON
               Propose-only (R3): emits the structured proposal a gated dispatcher
               turns into a REVIEWED PR — this command never applies anything.
               Free-text auth: $MALLCOP_INFERENCE_URL + $MALLCOP_API_KEY.

  investigate  Run a real tool-calling analyst over the store (search_events,
               search_findings, check_baseline, lookup_rules)
    --question   Ask ONE question and print the answer (single-shot mode)
    --serve      Run the long-lived loop: read questions from --inbox, stream
                 trace+answers to --outbox, exit after --idle-timeout with no
                 new question (default 90s)
    --inbox      Questions+control JSONL to read from (required with --serve)
    --outbox     Trace JSONL to append to (required with --serve)
    --store      Path to the git-repo store to investigate (required)
    --baseline   Optional path to a baseline JSON file
    --repo-root  Optional repo root for lookup_rules' operator-decisions corpus
    --base-url   Inference endpoint base URL (overrides $MALLCOP_INFERENCE_URL)
    --json       Single-shot mode: print the answer + citations as JSON
                 Inference auth: $MALLCOP_INFERENCE_URL + $MALLCOP_API_KEY, same
                 as scan — but unlike scan, a missing endpoint is FATAL here
                 (there is no useful "investigate offline" degraded mode).

  selfext  BYOK self-extension: author net-new detectors on YOUR OWN inference (no donut billing)
    --run          Author ONE detector for a gap (--detector-id, --event-type,
                   --target-family, --lane, --code-model, --target-repo,
                   --exam-repo, --base-ref, --artifact-dir, --budget-usd, --autonomy)
    --propose      Run the collect->propose->gate->route loop over a
                   'mallcop collect --json' envelope (--collect-json, --store-repo,
                   --consent/--contribute-back, --gate-json, --target-repo)
    --scaffold-gha Write the CODE-lane GitHub Actions templates + operator setup
                   checklist into --out (no inference key needed)
    --contribute   Open a shared-OSS PR (under YOUR OWN 'gh auth' identity) for
                   every contribute-back artifact --propose emitted under
                   --artifact-dir/oss (--store-repo, --oss-repo; no inference
                   key needed; never auto-merges)
    --inference-url      BYOK inference endpoint base URL (REQUIRED for --run/--propose)
    --inference-key-env  NAME of the env var holding your inference key (REQUIRED;
                         the key is read by name so it never appears in argv)
    --no-jail            Disable the OS-enforced Landlock authoring jail (ON by default)
                 BYOK is REQUIRED: this MIT binary has NO donut/commercial billing
                 rail (that is a commercial add-on elsewhere). The engine authors
                 in a sandboxed git worktree, gates in-runner, and on GREEN drops a
                 reviewable artifact — it NEVER pushes or merges.

Exit codes (scan):
  0  No findings
  1  Findings present
  2  Scan failure`)
}
