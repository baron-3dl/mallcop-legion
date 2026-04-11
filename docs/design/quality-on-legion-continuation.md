# Quality-on-legion — Session Continuation

**Last session:** 2026-04-11 (long swarm session, waves 1–5 closed)
**Session token:** expired — swarm state persisted via root campfire
**Parent rd item:** `mallcoppro-9fd` (Quality-on-legion: Academy Exam + investigation team + bakeoff + improvement loop)
**Design doc:** `docs/design/quality-on-legion.md`
**Swarm manifest:** `docs/design/quality-on-legion-swarm.json` (60 items; stale, needs refresh from rd)

## tl;dr for the next session

Phase 1 of quality-on-legion is implemented and merged. Phase 2 is partially shipped. **The end-to-end capstone is blocked on three upstream bugs in `legion v0.1.1`** that prevent `we start --exit-on-idle` from completing a full scenario chain. When legion ships v0.1.2 with the fixes, the path to a real exam run + bakeoff + `lanes.yaml` population unblocks.

If you're resuming this session:

1. **Check legion v0.1.2 status** — is it tagged and released?
   ```bash
   gh release list --repo 3dl-dev/legion --limit 5
   ```
   - If v0.1.2 exists: go to §Unblock-path below.
   - If not: check `/tmp/wt-legion-v012` (branch `fix/we-v0.1.3-exam-unblock`) — a legion agent may be mid-work. If the worktree has uncommitted changes or unmerged work, evaluate where they got to. The prompt for that agent is preserved at the bottom of this doc (§Legion agent prompt).
   - If legion work hasn't started: use §Legion agent prompt to dispatch it.

2. **Run the gating test** (the single load-bearing proof that legion v0.1.2 actually fixed the blockers):
   ```bash
   cd ~/projects/mallcop-legion
   # If using a local legion build, symlink it:
   # go build -o bin/we ~/projects/legion/cmd/we
   export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
   go test -tags e2e ./test/quality/... -run TestExamID01 -v -timeout 5m
   ```
   - Must PASS with `verdict == "pass"` and rubric thresholds ≥ 3. **Do not weaken these assertions.**
   - If it fails, find the next legion bug. Don't tag v0.1.2 (or pull the tag) until this test is green.

3. **Once TestExamID01 is green**, proceed to §Bakeoff sequence below.

## Current state (mallcop-pro + mallcop-legion)

### Repos and main HEADs (at session end)

| Repo | Main SHA | Key recent commit |
|---|---|---|
| `mallcop-pro` (github.com/3dl-dev/mallcop-pro) | `a143f95` | Merge lane rename + Config.ModelForLane wire-up |
| `mallcop-legion` (github.com/baron-3dl/mallcop-legion) | `381a254` | Merge Wave 5 hook binaries + exam.yml CI workflow |
| `legion` (github.com/3dl-dev/legion) | `792e513` | fix mallcoppro-a9b [inference].forge_api_url chart field (Wave 1) |
| `mallcop` (Python, github.com/3dl-dev/mallcop) | no new commits this session | — |

### Worktrees

- `/tmp/wt-legion-v012` — branch `fix/we-v0.1.3-exam-unblock` in `~/projects/legion`. Status at session end: unknown; created either by a legion agent mid-session or left from earlier. If it has committed work, inspect before resuming.
- No stray worktrees in `mallcop-pro` or `mallcop-legion` (cleaned up).

### What landed this session

**Waves 1–5 of the Phase 1+2 tree — 29 items closed under `mallcoppro-9fd`:**

| Wave | Items closed | Notable outcomes |
|---|---|---|
| 1 | `e9b, e93, b86, a9b, d77` + `41d` hotfix + lint-underscore followup, `e94` cancelled | 56 scenarios ported, chart template + renderer, judge POST.md + lint, legion forge_api_url field, Phase 1 veracity |
| 2 | `c4f, 61f, 3d6, 853` | Scenario struct + 4 sentinel errors, report aggregator, reviewer **caught identity-format boot-fail bug that Wave 1 veracity missed** (fixed via `41d` hotfix) |
| 3 | `d0f, 3a8, bfc, db2` | exam-seed with trap-strip enforcement, transcript-dump with defense-in-depth sanitization |
| 4 | `6cd, 8d6, b40, c75, a694` | investigate-tools, **b40 security sweep caught 2 HIGH structural defects in trap-strip that landed as c75 hardening**, a694 TestExamID01 capstone (assertions intact but blocked on legion upstream bugs) |
| 5 | `9e3, f15, 027, dd3` + `8e0` lane rename/wire | mallcop-checklist-verify binary, mallcop-credential-theft-verify binary, exam.yml CI workflow, a694 review, **lane rename + `Config.ModelForLane` wired into `handleMessages`** |

**Pattern worth preserving for future waves:** every wave produced at least one reactive hotfix from the downstream review/sweep layer catching something the in-wave veracity adversary missed. The adaptive tree + hostile reviewer/sweeper protocol is doing real work. Don't skip it.

### What is NOT landed yet (but designed + unblocked)

- **Python mallcop actor manifest adoption of lane names.** Files: `mallcop/src/mallcop/actors/{triage,investigate,heal,judge}/manifest.yaml`. Currently they use `model: sonnet` (literal). Should use `model: triage`, `model: investigate`, etc. Touches: the Python client + whatever tests reference those manifests. Unblocked today — no legion dep.
- **mallcop-legion chart template using lane names per capability seed.** File: `mallcop-legion/charts/exam.toml.tmpl`. Each `[[capabilities.seed]]` should declare its lane in its `model=` field. Cosmetic today (since mallcop-pro resolves the lane), but required for the bakeoff to exercise the real routing path. Unblocked.

### What is blocked on legion v0.1.2

- **End-to-end TestExamID01 pass** — blocked on bugs `mallcoppro-9df`, `mallcoppro-ee3`, `mallcoppro-a85` (see §Open followups).
- **Real bakeoff run** — needs `we` to actually complete a scenario chain.
- **Populating `lanes.yaml` with real model assignments** — the current matrix is hallucinated (see §Hallucinated lanes.yaml warning).
- **G2 / external-command hook dispatch** — the two veracity-gate hooks (`mallcop-checklist-verify`, `mallcop-credential-theft-verify`) ship as standalone binaries but legion's `[[hooks]] command=` field is a dead field in v0.1.1. Filed as `mallcoppro-3d4`. Workaround: exam.yml CI workflow calls the binaries as explicit steps, bypassing the HookEngine.

## The three legion upstream bugs

Full details in each rd item; here's the short version for context.

### `mallcoppro-9df` — curator stream-json requires --verbose

- **Symptom:** `we`'s curator spawns `claude --print --output-format=stream-json`, which fails with stderr `Error: When using --print, --output-format=stream-json requires --verbose`. Curator retries 3×, falls back to synthetic response.
- **Likely fix:** add `--verbose` to the `claude` subprocess argv. Grep legion for `"stream-json"` or `"--print"` to find the invocation site.
- **Scope:** one-line change + one test. Easiest of the three.

### `mallcoppro-ee3` — claude-code worker doesn't commit campfire messages

- **Symptom:** `we` spawns the worker, canned backend returns plain text, worker exits in ~1s without issuing `cf send` or `work:close`. Campfire items stay open, `--exit-on-idle` never fires.
- **Investigation required:** legion's worker prompt template + tool allowlist + subprocess invocation mode. The reference test `TestWeStartsAndExitsOnIdle` in `mallcop-legion/test/budget/chain_budget_test.go:323` is green — whatever is different between THAT chart and the exam chart is where the fix lives. **Don't guess; cross-reference those two charts first.**
- **Hypothesis to try:** tool allowlist on the exam chart's capability seeds may be missing `Bash(cf:*)` or an equivalent, so the worker literally can't issue commits even if the prompt tells it to. If so, the fix might be in `mallcop-legion/charts/exam.toml.tmpl`, NOT in legion itself.

### `mallcoppro-a85` — `max_tasks_per_session=1` blocks same-session follow-on dispositions

- **Symptom:** exam chart has `[autonomy] max_tasks_per_session=1` (to defuse A-04 single-scenario retry loops). After the scenario worker consumes the 1 task, the exam-report disposition is perpetually skipped with "task cap reached". `--exit-on-idle` never fires.
- **Fix (design decision):** scope `max_tasks_per_session` per-disposition rather than per-session. OR add `max_tasks_per_disposition` as a separate knob. Option (a) is cleanest per the design intent.
- **Touch points:** legion's scheduler (grep `"task cap reached"` for the emission site), `ParseLifecycle` / autonomy struct.

## Unblock-path (run this sequence when legion v0.1.2 is live)

Assumes: legion v0.1.2 is tagged and released with fixes for all three bugs; binaries are on GitHub releases.

1. **Bump `mallcop-legion/.we-version`**:
   ```bash
   cd ~/projects/mallcop-legion
   echo "v0.1.2" > .we-version
   rm -f bin/we  # force re-download on next bin/we invocation
   ./bin/we --version  # confirms new version
   ```

2. **Re-run the capstone test end-to-end**:
   ```bash
   export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
   go test -tags e2e ./test/quality/... -run TestExamID01 -v -timeout 5m
   ```
   Must PASS. If it fails, there's another bug; file as `mallcoppro-*` and dispatch another legion fix round.

3. **Close the three legion upstream items** in rd:
   ```bash
   rd done mallcoppro-9df --reason "fixed in legion v0.1.2 (<SHA>); TestExamID01 green"
   rd done mallcoppro-ee3 --reason "fixed in legion v0.1.2 (<SHA>); TestExamID01 green"
   rd done mallcoppro-a85 --reason "fixed in legion v0.1.2 (<SHA>); TestExamID01 green"
   ```

4. **Flip exam.yml out of continue-on-error**:
   - File: `mallcop-legion/.github/workflows/exam.yml`
   - Remove `continue-on-error: true` from the `Run TestExamID01` step
   - Add `pull_request:` to the `on:` block (keep `workflow_dispatch`)
   - Commit as `ci(exam): enable pull_request trigger now that legion v0.1.2 is live`
   - Push, verify the workflow runs green on the next PR

5. **Consider G2 / external hooks** (`mallcoppro-3d4`):
   - If legion v0.1.2 ALSO fixed `[[hooks]] command=` dispatch, the veracity-gate hooks now fire automatically. Update exam.yml to stop calling the binaries explicitly and let the chart hooks do it.
   - If NOT, keep the explicit step invocation and leave `mallcoppro-3d4` open.

## Bakeoff sequence (run after Unblock-path is green)

Budget: **$200 approved**. Keep under $100 in practice.

### Pre-flight

- **Provision a dedicated bakeoff account** via mallcop-pro's programmatic signup (`cmd/mallcop-register`):
  - Email: something like `bakeoff@thirdiv.com` (or a throwaway)
  - Sovereignty: `open` (so it can use GLM / qwen)
  - Donut budget cap: equivalent to ~$100 (well under the $200 total budget)
  - Save the `mallcop-ak-bakeoff-*` key to `~/.cf/bakeoff.key` (gitignored, NOT in any repo)
- **Verify the real product path works** with a single-scenario smoke test:
  ```bash
  curl -X POST https://api.mallcop.app/v1/messages \
    -H "Authorization: Bearer $BAKEOFF_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model":"triage","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}'
  ```
  Should return HTTP 200 with a real Claude response AND should prove lane routing (inspect Forge logs to confirm the request landed on `zai.glm-4.7-flash` for an open customer).

### Run the bakeoff

**Use `we` as the driver** (not a custom Go harness — see §Why not a custom harness below). Reference design:

- Chart per model: `charts/exam-bakeoff-<model>.toml.tmpl` (per `mallcoppro-a3a`, still open)
- Render N charts (one per model tier), seed the same 56 scenarios via `exam-seed` into N separate campfires, spawn N `we start --chart` subprocesses in parallel, let each produce its `report.json`, then aggregate via `cmd/mallcop-bakeoff-report` (`mallcoppro-ea2`, still open).

The items `a3a` and `ea2` still need to be implemented in a future wave. They were deferred from Wave 4 when a694 took the full token budget. Their specs are in the rd items.

### Populate lanes.yaml from real results

1. Parse the bakeoff output JSON: `per_model.<model>.pass_rate` per scenario bucket
2. Apply the threshold algorithm (from `mallcop/tests/shakedown/bakeoff.py:148`):
   ```
   triage:      cheapest model with pass_rate >= 0.70
   investigate: cheapest model with pass_rate >= 0.80
   heal:        cheapest model with pass_rate >= 0.85
   ```
3. Update BOTH `mallcop-pro/internal/config/lanes.yaml` AND `mallcop-pro/config/lanes.yaml` (there are two copies — the embedded one and the one used by `TestLoad_AllLanesResolvable`)
4. Commit the bakeoff result JSON to `mallcop-legion/bakeoffs/bakeoff-YYYYMMDD-HHMMSS.json` as evidence
5. Remove the UNVERIFIED header comment from `lanes.yaml`

### Budget enforcement

- The bakeoff driver (when implemented) MUST have a hard cost cap of $150
- Per-call cost estimation from token counts + catalog, accumulated across the run
- If the cap is hit mid-run, halt and write partial results — do not spend past the cap
- Resume-from-partial must be atomic (per-scenario verdict JSONL written before moving to the next)

### Why not a custom inference-layer harness

In the previous session, the orchestrator proposed building `cmd/mallcop-bakeoff-runner` as a Go binary that would hit `/v1/messages` directly, bypassing `we` entirely. **The user vetoed this** (correctly): "legion should do this, but currently can't. Let's fix what we need to fix." The right path is to fix legion v0.1.2 so `we` can drive the bakeoff, not to duplicate legion's job.

**If you are tempted to write a custom runner again: don't.** Fix legion first. The extra effort is worth it because the bakeoff infrastructure then also validates the production path (customer → mallcop-pro → forge → bedrock → judge).

## Hallucinated lanes.yaml warning

**The current `lanes.yaml` values are NOT from a real bakeoff.** Another agent filled them in based on vibes; the `bakeoff: 2026-03-28` comment is aspirational and there is no stored bakeoff result JSON anywhere on disk. The matrix is logically inconsistent with the bakeoff algorithm:

- `heal.open = qwen3-32b` AND `investigate.open = qwen3-32b` — same model for two lanes with different thresholds. Impossible under cheapest-that-passes.
- `heal.us_only = claude-haiku-3-5` is SMALLER than `investigate.us_only = nova-pro`. Impossible — if nova-pro passes 80% but haiku-3-5 passes 85%, that contradicts model-quality ordering.

A bold UNVERIFIED header is in place at the top of `internal/config/lanes.yaml` (and `/config/lanes.yaml` — two copies). **Do not trust those values.** The bakeoff (above) is the only thing that should write to that matrix. Until then, customers asking for lane names will get the wrong model; this is a KNOWN issue tracked by the bakeoff sequence.

## Lane rename changes (this session)

Lane names renamed from `patrol/detective/forensic` → `triage/investigate/heal` to match the mallcop actor names. Files updated:

- `mallcop-pro/internal/config/lanes.yaml` + `mallcop-pro/config/lanes.yaml`
- `mallcop-pro/internal/config/config.go` (constants, struct fields, `knownLanes`, validation, `ModelForLane`)
- `mallcop-pro/internal/config/config_test.go`
- `mallcop-pro/internal/forge/client.go` — added `KeyInfo()` returning `(accountID, sovereigntyFloor, error)`. `AccountID()` delegates to `KeyInfo()`.
- `mallcop-pro/internal/server/server.go` — deleted dead `laneToModel` hardcoded map, wired `Config.ModelForLane(lane, sovereignty)` into `handleMessages`, fail-closed on garbage sovereignty
- `mallcop-pro/internal/server/lane_routing_test.go` — 6 new tests (open × triage, us_only × investigate, allied × heal, literal passthrough, unknown lane passthrough, bogus sovereignty fail-closed)
- `mallcop-pro/internal/provisioning/tree.go` + `tree_test.go` — lane list + struct literals
- `mallcop-pro/cmd/mallcop-ops/*.go` — lane iteration + assertions
- `mallcop-pro/docs/design/boundary-design.md` + `pricing-operations.md`
- `mallcop/tests/shakedown/bakeoff.py` — threshold dict keys (still Python — the Python repo hasn't been pushed yet, see §Python mallcop pending below)

**One external reference NOT renamed** (intentional): `mallcop-pro/internal/forge/client_test.go:160` uses `"patrol"` as test data for the Forge alias HTTP client — it's arbitrary string test data for the alias API, not a mallcop lane name. Left alone.

**Python mallcop pending:** the `bakeoff.py` threshold rename was done but the Python repo's actor manifests (`mallcop/src/mallcop/actors/*/manifest.yaml`) still use `model: sonnet` (literal). Those need to be updated to use `model: triage` / `model: investigate` / `model: heal` so the Python client asks mallcop-pro for lane routing. Unblocked today; not done this session because it needs a full Python test run and wasn't on the critical path. Follow-up in §Open followups.

## Open followups (rd items)

### Blocked on legion v0.1.2 (must wait)

| ID | Title | Blocker |
|---|---|---|
| `mallcoppro-9df` | curator stream-json fallback — needs `--verbose` | legion code fix |
| `mallcoppro-ee3` | worker must commit campfire messages from plain-text responses | legion design decision |
| `mallcoppro-a85` | `max_tasks_per_session=1` blocks follow-on dispositions | legion scheduler fix |
| `mallcoppro-3d4` | wire `[[hooks]] command=` dispatch in legion (G2) | legion feature |

### Unblocked (ready to work now)

| ID | Title | Priority |
|---|---|---|
| `mallcoppro-a97` | internal/exam capture `actor_roles` + validate required fields | p2 |
| `mallcoppro-a57` | exam-seed workclient spec deviation (decide import vs shell-out) | p2 |
| `mallcoppro-31d` | exam-seed cf subprocess error path coverage + partial-seed idempotency | p3 |
| `mallcoppro-918` | exam-render-chart: validate rendered chart against legion chart.LoadChart | p2 |
| `mallcoppro-419` | exam-seed fixture path must be absolute (sandbox regression) | p1 |
| `mallcoppro-ad7` | mallcop-exam-report: full fix_target enum coverage + report.md content assertion | p3 |

### Phase 2 implementation items (waves 6–10)

Not yet started. Key ones in rough order:

- `mallcoppro-a3a` — `charts/exam-bakeoff-{haiku,sonnet,opus}.toml.tmpl` + renderer (Wave 6 candidate)
- `mallcoppro-ea2` — `cmd/mallcop-bakeoff-report` aggregator (Wave 6 candidate)
- `mallcoppro-c417` — `mallcop-exam-report --seed-fix-suggestions`
- Triage/investigate/heal POST.md items (parallel to existing Python POST.md)
- `mallcoppro-f48` — Phase 2 veracity audit (runs after Phase 2 impl lands)
- `mallcoppro-3e8` — `TestExamFull` + `TestExamBakeoff` (56 scenarios × 3 models) — blocked on legion v0.1.2 end-to-end pipeline

### Scope for a future dedicated session

- **Python mallcop actor manifest adoption of lane names** (triage/investigate/heal/judge). Touches: the `mallcop/src/mallcop/actors/*/manifest.yaml` files, plus any test that asserts the model field value. Also consider: `mallcop/src/mallcop/config.py` `RouteConfig` — does it validate model names against a whitelist?

## Key file paths (so next session doesn't have to grep)

**mallcop-pro**

- `internal/config/lanes.yaml` — lane → sovereignty → Bedrock model matrix (HALLUCINATED — see warning)
- `internal/config/config.go:Config.ModelForLane()` — the lookup function
- `internal/config/config.go:433` — `ModelForLane` switch (triage/investigate/heal)
- `internal/forge/client.go:KeyInfo()` — new in this session, returns `(accountID, sovereigntyFloor, error)`
- `internal/server/server.go` `handleMessages()` — uses `Config.ModelForLane(lane, sovereignty)` now (no more hardcoded map)
- `internal/server/lane_routing_test.go` — 6 routing tests
- `cmd/mallcop-register` — programmatic signup CLI (pre-existing; use for bakeoff account provisioning)

**mallcop-legion**

- `docs/design/quality-on-legion.md` — 26 KB design doc, 9 question adversarial output
- `docs/design/quality-on-legion-swarm.json` — 60-item manifest (stale; refresh from rd before next wave)
- `docs/design/quality-on-legion-swarm.md` — dispatch entry point
- `internal/exam/scenario.go` — `Scenario` struct, `Load()` + sentinel errors
- `exams/scenarios/*/` — the 56 real scenarios (ported from Python mallcop Wave 1)
- `charts/exam.toml.tmpl` — exam chart template with veracity_gate hooks (currently dead in v0.1.1 — see G2 gap)
- `cmd/exam-render-chart/main.go` — chart renderer (fixed in Wave 2 for identity.Save compat)
- `cmd/exam-seed/main.go` — scenario seeder, hardened in Wave 4 (c75) with metadata allowlist + fixture scrubbing + positive-control test
- `cmd/exam-transcript-dump/main.go` — heal disposition transcript renderer with defense-in-depth sanitization
- `cmd/mallcop-exam-report/main.go` — judge-verdict aggregator with NaN guard
- `cmd/mallcop-investigate-tools/main.go` — check-baseline / search-events / search-findings multi-tool binary
- `cmd/mallcop-checklist-verify/main.go` — pre-resolution checklist gate (5 or 7 items depending on disposition)
- `cmd/mallcop-credential-theft-verify/main.go` — credential-theft-test gate
- `test/quality/judge_prompt_lint_test.go` — blind-judge regex lint, tightened in Wave 2 for underscore variants
- `test/quality/exam_smoke_test.go` — `TestExamID01` capstone (e2e build tag; blocked on legion v0.1.2)
- `internal/testutil/cannedbackend/cannedbackend.go` — promoted from `test/budget/` in Wave 4; shared between test/budget and test/quality
- `.github/workflows/exam.yml` — CI workflow (workflow_dispatch only + continue-on-error until legion v0.1.2)
- `.we-version` — legion binary pin (currently `v0.1.1`; bump to `v0.1.2` when ready)
- `bin/we` — legion binary wrapper that downloads from the pinned GitHub release

**legion (github.com/3dl-dev/legion)**

- `cmd/we/boot.go` — where to look for the `claude` subprocess invocation (bug 9df) and the `effectiveRouterCfg` path (Wave 1 `a9b` work)
- `cmd/we/boot_inference.go` — `applyInferenceChartFields()` helper extracted in Wave 1 `a9b` rework (AST guard test lives in `forge_api_url_wiring_test.go`)
- `internal/chart/chart.go` — `InferenceSection.ForgeAPIURL` field (Wave 1)
- `internal/automaton/hooks.go:147` — HookEngine.RunHooks entry point (bug 3d4 fix goes here)
- Scheduler / task-cap enforcement — grep `"task cap reached"` (bug a85)

## Glossary (quick reminder)

- **Lane** — mallcop routing tier: `triage` (cheapest, pass_rate >= 0.70), `investigate` (mid, >= 0.80), `heal` (deepest, >= 0.85)
- **Sovereignty** — `open` (any origin), `allied` (Meta/US), `us_only` (US-origin only). Strictness: `us_only > allied > open`.
- **Lane × Sovereignty → Model ID** — resolved by `Config.ModelForLane()` in mallcop-pro, referenced in `lanes.yaml`
- **Disposition** — legion chart `capability_seed` name; the runtime unit of work. Exam uses: triage, investigate, heal, judge, report.
- **Veracity gate** — a pre_bead_close hook that denies a bead close if the closing disposition didn't emit required checkpoint messages. Implemented in the two hook binaries from Wave 5. Currently NOT invoked automatically because legion's `[[hooks]] command=` field is dead (G2 gap).
- **Capstone test** — `TestExamID01` in `test/quality/exam_smoke_test.go`. One scenario (ID-01), full chain, real `we` subprocess, real canned backend, assert `verdict == "pass"`. The gating test for Phase 1 "done".

## Legion agent prompt (for re-dispatch if needed)

If the legion worktree at `/tmp/wt-legion-v012` is empty or the work needs to restart, the original dispatch prompt is in the prior session transcript. Brief version:

> You are fixing legion v0.1.2. Three bugs:
>
> 1. `mallcoppro-9df` — curator stream-json invocation needs `--verbose` (one-line fix)
> 2. `mallcoppro-ee3` — claude-code worker doesn't commit campfire messages (investigate prompt template + tool allowlist; cross-ref `TestWeStartsAndExitsOnIdle` which IS green)
> 3. `mallcoppro-a85` — `max_tasks_per_session` should scope per-disposition not per-session (scheduler fix)
>
> **Gating test:** `cd ~/projects/mallcop-legion && go build -o bin/we ~/projects/legion/cmd/we && go test -tags e2e ./test/quality/... -run TestExamID01 -v -timeout 5m`. Must return PASS with `verdict == "pass"` and rubric thresholds ≥ 3. No assertion weakening.
>
> Ship criteria: all three bugs fixed with unit tests, mallcop-legion TestExamID01 green, legion v0.1.2 tagged + released via CI, `mallcop-legion/.we-version` bumped on a branch (not merged — orchestrator merges after verifying).
>
> Full context: `mallcop-legion/docs/design/quality-on-legion-continuation.md`.

## Known pre-existing failures (not introduced this session)

- `mallcop-pro/internal/proonline/*` tests require Azurite (Azure Table Storage emulator) running at `127.0.0.1:10002`. When absent, 8 tests fail. CI runs Azurite separately. **Not a regression from this session's changes.**
- `mallcop-pro/test/` has a test (possibly `TestE2e_ProOnline_RegisterWebhookSmoke` or similar) that reported "campfire provisioning unavailable" during the rename+wire agent's `go test ./...`. I fixed `TestE2e_ProOnline_RegisterWebhookSmoke` earlier in the session (commit `e7387dd` — hermetic `CAMPFIRE_REMOTE_URL=""` pin), so if this is a different test name, it's a separate issue worth investigating. **Not this session's fault but worth a ~10-minute triage before the next push.**

## Commit trail (this session, most recent first)

### mallcop-pro

- `a143f95` — Merge `work/lanes-rename-wire` (rename + wire fix)
- `4a58882` — feat(lanes): rename to triage/investigate/heal and wire Config.ModelForLane
- `e7387dd` — test(proonline): clear CAMPFIRE_REMOTE_URL in e2e fixture (hermetic baseline)
- `dc955c2` — fix(auth): validate customer bearer against Forge on /v1/messages + /v1/github/token

### mallcop-legion (post-Wave 1 baseline was `24330da`)

- `381a254` — Merge Wave 5 (9e3 + f15 + 027)
- Wave 5 merges: checklist-verify, credential-theft-verify, exam.yml
- `9a3e38f` — Merge Wave 4 a694 capstone
- `7615899` — Merge Wave 4 c75 security hardening
- `8518a9c` — Merge Wave 4 6cd investigate-tools
- `b4251c6` — Merge Wave 2 c4f + 61f
- `0db0839` — Merge Wave 2 lint tightener
- `83935f5` — Merge Wave 3 d0f + 3a8
- `6546ad7` — Merge Wave 1 b86
- `6efbbad` — Merge Wave 1 e93
- `f93e403` — Merge Wave 1 e9b

### legion

- `792e513` — Merge Wave 1 a9b (forge_api_url chart field)
- No session changes in legion itself; bug fixes pending in v0.1.2.

## First three things to do when resuming

1. **`cat docs/design/quality-on-legion-continuation.md`** (this file — make sure you're reading the current version)
2. **`gh release view v0.1.2 --repo 3dl-dev/legion`** — if that succeeds, proceed to Unblock-path. If it 404s, check `/tmp/wt-legion-v012` state and either resume the legion agent's work or re-dispatch via §Legion agent prompt.
3. **`rd ready --view my-work`** — the rd queue knows more than this doc does about priorities; trust it for sequencing.

Good luck. This was a productive session.
