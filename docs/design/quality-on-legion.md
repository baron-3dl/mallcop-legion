# Quality on Legion — Academy Exam, Investigation Team, Improvement Loop

<!-- design-campfire: 74560d7d779998a781657b37a053e2501e07a382933e4ebe909883bc01f9fd50 -->

## Executive summary

Port mallcop's Academy Exam + investigation-team quality bar + improvement loop onto legion as a native subsystem. Scenarios live as YAML files on disk; a small `exam-seed` Go subcommand walks the tree, validates, strips ground-truth fields, and posts each as a `work:create` convention message to an ephemeral per-run ready campfire. An exam automaton (ephemeral chart + identity) boots with `--exit-on-idle`, claims items via capability `match`-tag routing, chains triage → investigate → heal → judge → report as independent claim steps. Bakeoff = N sibling `we start` processes against sibling charts, one per model. Production `scan.sh` is untouched — the exam chart is additive and CI-facing. One required legion upstream fix (`[inference].forge_api_url`), three nice-to-have purist gaps with workarounds. Phase 1 first-scenario-green in 3-4 days.

## Decisions (the 9 questions, answered)

### Q1 — Where do scenarios live?
**Answer.** YAML files in `mallcop-legion/exams/scenarios/**/*.yaml`, schema cloned from `mallcop/tests/shakedown/scenarios/_schema.yaml`. `exam-seed` walks the tree; chart never touches the filesystem directly.
- **Capability**: `ReadyWorkSource` + `work:create` tag (`legion/pkg/workclient/ready_worksource.go:230`).
- **Defuses**: A-14 (seeder validates YAML against Go struct before any send, fails loud).
- **Adopts**: C-01 (universal work-item shape). **Rejects**: pure campfire-native scenarios (breaks "declarative YAML" operator constraint).
- **Theorem**: T1 (chart authoritative via ready worksource), T2 (worksource is only intake).
- **Tradeoff**: YAML and work:create snapshots both represent the scenario; YAML is truth, work:create is a per-run frozen copy.

### Q2 — How are scenarios dispatched?
**Answer.** `exam-seed --run R1` posts N `work:create` messages to `exam-R1` BEFORE `we start --exit-on-idle --chart .run/exam-R1/chart.toml` boots. Legion's existing `pollAndDispatch` claims items, capability `match=["exam:scenario"]` routes to triage. On queue drain, `HasScheduleEntries()=false` → idle-exit (`legion/cmd/we/main.go:684`).
- **Capability**: `ReadyWorkSource.PollForWork`; capability `match` tag routing (`legion/internal/automaton/capability.go`); `--exit-on-idle` (`legion/cmd/we/main.go:118`).
- **Defuses**: A-03 (the t.Skip seeding gap at `chain_budget_test.go:462` — solved by a Go CLI using existing `workclient.ReadySender.SendWithAntecedents` with a `workCreatePayload`); A-11 (ready-only intake, no schedule entries, idle-exit tracks drain cleanly).
- **Adopts**: C-04 (sibling automaton race, modified to per-sibling queues). **Rejects**: schedule-future seeding (fails T8) and bash-loop-per-scenario (recreates scan.sh bypass).
- **Theorem**: T2, T3, T8.
- **Tradeoff**: Seeder needs a signing identity. Generated fresh per run, thrown away with the run dir.

### Q3 — Where does the judge run?
**Answer.** A separate disposition (`exam:judge`) claimed as a downstream `work:create` item the heal step emits. Judge tools = `["read"]`. Judge jail's filesystem mount includes `exams/transcripts/<run>/` but NOT `exams/scenarios/` — blindness enforced by sandbox, not prompt.
- **Capability**: T3 claim chain; capability `match=["exam:judge"]`; sandbox `extra_ro` filesystem scoping; `TelemetryEmitter`.
- **Defuses**: A-01 (fresh worker, fresh context window — no carry-over from triage/investigate); A-02 (seeder strips `trap_description` and `trap_resolved_means` before `work:create`; `exam-transcript-dump` writes only sanitized transcript).
- **Adopts**: C-03 (judge reads reasoning artifact). **Rejects**: the HintDemuxer reasoning-artifact hint gap (~30 LOC upstream) — heal instead posts the judge item via a bash helper in its tool allowlist. Zero legion coupling.
- **Theorem**: T3, T4 (blindness is structural filesystem denial, not honor-system prompt).
- **Tradeoff**: Until G1 (per-capability sandbox) ships, the exam chart's `extra_ro` is single-list chart-wide — we split fixtures vs transcripts into separate directories and the judge agent prompt refuses to read outside `transcripts/`. Soft-enforced. Flagged OPEN.

### Q4 — Test isolation
**Answer.** Each run gets its own chart (rendered from `charts/exam.toml.tmpl`), its own `.run/exam-<id>/identity.json` (fresh), its own `.run/exam-<id>/campfires/` transport. Production `mallcop-vertical-slice` untouched. Run directory torn down at exit.
- **Capability**: `[identity].key_file` and `[campfire].transport_dir` are per-chart.
- **Defuses**: A-05 (no shared capabilities campfire — per-run constellation); A-13 (per-run ephemeral identity has no knowledge of production campfire IDs; directory + key isolation is the blast-radius boundary).
- **Theorem**: T4, T9.
- **Tradeoff**: Identity churn. Cheap on filesystem transport.

### Q5 — Bakeoff (multi-model)
**Answer.** One chart per model (`charts/exam-bakeoff-{haiku,sonnet,opus}.toml.tmpl`), N parallel `we start` processes, each with its own ephemeral identity, its own run campfire, its own Forge endpoint. Each chart's `capabilities.seed.model` fixes the model tier. Final aggregation step reads N report.json files.
- **Capability**: Process-parallel `we start` (legion supports repeated `--chart` already, we use repeated processes for clean isolation); `capabilities.seed.model` (`legion/internal/chart/chart.go:338-364`); chart-level `[inference].forge_api_url` (NEW — see Gap 1).
- **Defuses**: A-08 (model identity — per-process Forge endpoint + per-chart model tier; attribution is process-scoped, not env-race-scoped); A-12 (CI cost — wall time is MAX of sibling runs, ≈ 25 min for 3 models × 56 scenarios at `max_workers=3`).
- **Adopts**: C-04 (sibling pattern, modified — per-sibling queues not shared queue, avoids cross-model claim races). **Rejects**: "one chart N FORGE_API_URLs" (fails T9, T5).
- **Theorem**: T5 (budget per chart), T9 (N charts = N lifecycles).
- **Tradeoff**: 3× seeding cost. Acceptable — seeding is milliseconds per scenario.

### Q6 — Investigation tools
**Answer.** `check-baseline`, `search-events`, `search-findings` ship as plain Go binaries in `mallcop-legion/cmd/`, installed into the jail's `NativeBinDir`, allowlisted in the investigate disposition's `capabilities.seed.tools`. Single binary with `--mode=exam|production` flag: exam mode reads from `exams/fixtures/<run>/<scenario>/`, production reads from connectors. Chart's `extra_ro` picks the filesystem view.
- **Capability**: `JailConfig.NativeBinDir` (`legion/internal/worker/jail_create.go`) — already pattern used for `rd` and `cf`. `capabilities.seed.tools` is the safety ceiling.
- **Defuses**: A-07 (no connector-query:* in exam investigate allowlist; exam-mode binary reads filesystem fixtures only; no network egress from jail; no credentials).
- **Adopts**: purist Q6 (NativeBinDir bash tools). **Rejects**: C-05 (convention ops for investigation tools — too heavy for a per-call hot path; no convention ownership story).
- **Theorem**: T7.
- **Tradeoff**: One binary with two modes. Mode flag set by chart env injection. Simple and auditable.

### Q7 — Improvement loop
**Answer.** Phase 1: post-exam `exam:report` item (seeded by `exam-seed` as the last item, with `depends_on` = all scenario items) claimed by a `report` disposition; it walks `judge:verdict` messages on the run campfire, aggregates by `fix_target`, writes `exams/reports/<run>/report.{md,json}`. No auto-fix. Phase 3: sibling `charts/exam-fixer.toml` polls a separate `exam-fix-suggestions` ready campfire seeded by the report step, emits unified diffs to a human gate.
- **Capability**: Ready worksource (both phases), human gate (Phase 3).
- **Defuses**: A-09 (contradictions — Phase 1 does not auto-apply; Phase 3 fixer refuses to emit a diff if two failures in a cluster demand opposite changes, closes item with refusal reason).
- **Adopts**: C-06 (fixer-as-disposition, human gate). **Rejects**: any auto-merge variant.
- **Theorem**: T2, T3.
- **Tradeoff**: Contradiction detection within a cluster is a Phase 3+ prompt concern, not an infrastructure concern.

### Q8 — Pre-Resolution Checklist + Credential Theft Test
**Answer.** Enforced via `pre_bead_close` `veracity_gate` hooks declared in the exam chart. The investigate/heal dispositions must emit structured messages tagged `checklist:item:1`..`checklist:item:7` and one `credential-theft-test:considered` with a non-empty `event_ids` payload. Hook blocks close if any are missing. Production chart declares the same hooks — an exam pass proves the production invariant machinery, not just the prompt.
- **Capability**: `HookEngine.RunHooks` (`legion/internal/automaton/hooks.go:147`); `veracity_gate` is registered by default; chart `[[hooks]]` with `point="pre_bead_close"`.
- **Defuses**: **A-10 partially CONCEDED.** The hook IS part of the system under test. Rationale: the production deployment runs with the hook; an exam that disables the hook measures a different system. Phase 3+ optional "prompt-only calibration" sidecar addresses the pure-prompt measurement question.
- **Theorem**: T6.
- **Tradeoff**: The veracity-gate rubric is baked into Go per-hook (G2 workaround). We ship `mallcop-checklist-verify` and `mallcop-credential-theft-verify` as plain Go CLIs in `mallcop-legion/cmd/`, registered via `command=` in the hook entry. G2 upstream proposal moves the rubric to TOML later.

### Q9 — Interactive/chat actor
**Forward reference only.** Interactive chat is a separate chart with persistent worksource, no `--exit-on-idle`, `task:chat` disposition. Legion gap (IntentEvaluator relay-message-received, ~80 LOC) is the eventual unblock. Until then, `mallcop investigate` direct-LLM path stays as the hot debug tool; the exam chart proves the batch quality bar. A-15 latency regression is real; we defer it and flag OPEN.

## The canonical data flow

```
  exams/scenarios/**/*.yaml  (git truth)
         │
         │  exam-seed --run R1 --campfire exam-R1
         │     · validate YAML against Go struct
         │     · strip trap_description, trap_resolved_means
         │     · materialise exams/fixtures/R1/<id>/events.json,baseline.json
         │     · post N × work:create(skill=exam:scenario, tag=scenario:<id>)
         │     · post 1 × work:create(skill=exam:report, depends_on=all)
         ▼
  ready campfire: exam-R1
         │
         │  we start --chart .run/exam-R1/chart.toml --exit-on-idle
         ▼
  Exam automaton (ephemeral identity, ephemeral constellation)
         │  pollAndDispatch → capability match → claim
         ▼
  triage (haiku/sonnet, read + check-baseline + search-events)
         │  closes (resolved) OR emits work:create(task:investigate)
         ▼
  investigate (sonnet, +search-findings +load-skill)
         │  pre_bead_close: checklist + credential-theft hooks gate close
         │  closes OR emits work:create(task:heal)
         ▼
  heal (sonnet, stubbed write tools + exam-transcript-dump)
         │  writes exams/transcripts/R1/<id>.md (sanitized, no ground truth)
         │  posts work:create(exam:judge, transcript=<path>) via bash helper
         │  closes task:heal
         ▼
  judge (sonnet/opus, read-only, jail sees transcripts/ only)
         │  reads transcript, grades blind, closes with tag judge:verdict
         ▼
  All scenario+judge items closed → exam:report unblocks
         ▼
  report (haiku, read + bash)
         │  walks judge:verdict messages, aggregates by fix_target
         │  writes exams/reports/R1/report.{md,json}, closes
         ▼
  Queue empty, HasScheduleEntries()=false → we exits (--exit-on-idle)
         ▼
  CI reads report.json, gates merge on pass threshold
```

## The chart topology

### `charts/exam.toml.tmpl`

```toml
[identity]
name     = "mallcop-exam-{{RUN_ID}}"
type     = "worker"
key_file = ".run/exam-{{RUN_ID}}/identity.json"    # fresh per run

[[worksources]]
type     = "ready"
campfire = "exam-{{RUN_ID}}"
skills   = ["exam:scenario", "task:investigate", "task:heal", "exam:judge", "exam:report"]

[budget]
max_tokens_per_session = 50000       # per scenario ceiling (A-04)
max_tokens_per_task    = 15000

[autonomy]
max_tasks_per_session  = 1           # one scenario per session; budget resets between (A-04)

[capabilities]
gate_policy    = "gated"
authority      = "baron@3dl.dev"
tool_allowlist = ["bash", "read", "grep", "glob"]

[[capabilities.seed]]
name = "triage"
match = ["exam:scenario", "task:triage"]
tools = ["bash", "read", "check-baseline", "search-events"]
model = "sonnet"

[[capabilities.seed]]
name = "investigate"
match = ["task:investigate"]
tools = ["bash", "read", "check-baseline", "search-events", "search-findings", "load-skill"]
model = "sonnet"

[[capabilities.seed]]
name = "heal"
match = ["task:heal"]
tools = ["bash", "read", "exam-transcript-dump"]   # NO real write tools in exam
model = "sonnet"

[[capabilities.seed]]
name = "judge"
match = ["exam:judge"]
tools = ["read"]                      # jail sees transcripts/ only (see [sandbox])
model = "sonnet"

[[capabilities.seed]]
name = "report"
match = ["exam:report"]
tools = ["read", "bash"]
model = "haiku"

[[hooks]]
point   = "pre_bead_close"
type    = "veracity_gate"
command = "mallcop-checklist-verify"      # Go CLI in mallcop-legion/cmd/

[[hooks]]
point   = "pre_bead_close"
type    = "veracity_gate"
command = "mallcop-credential-theft-verify"

[lifecycle]
max_workers   = 3
time_limit    = "90m"
poll_interval = "2s"

[inference]
forge_api_url = "{{FORGE_API_URL}}"       # NEW legion field — Gap 1
[inference.local_model_mapping]
local = "qwen3-coder-30b"

[agents]
dir = "agents"

[campfire]
transport_dir = ".run/exam-{{RUN_ID}}/campfires"

[sandbox]
extra_ro = [
  "exams/fixtures/{{RUN_ID}}/",      # chain steps read fixtures here
  "exams/transcripts/{{RUN_ID}}/",   # judge reads transcripts here
  "agents/",
]
```

### `charts/exam-bakeoff-{haiku,sonnet,opus}.toml.tmpl`

Identical to `exam.toml.tmpl` except:
- `[identity].name = "mallcop-exam-bakeoff-{MODEL}-{{RUN_ID}}"`
- All `capabilities.seed.model` set to the sibling's model tier
- Each sibling run seeds its own campfire (`exam-R1-{MODEL}`)

### `charts/exam-fixer.toml` (Phase 3, stretch)

```toml
[identity]
name     = "mallcop-exam-fixer"
key_file = "~/.legion/automata/mallcop-exam-fixer/identity.json"

[[worksources]]
type     = "ready"
campfire = "exam-fix-suggestions"
skills   = ["exam:fix-cluster"]

[[capabilities.seed]]
name  = "fixer"
match = ["exam:fix-cluster"]
tools = ["read", "grep", "glob"]        # NO write
model = "sonnet"

[[hooks]]
point   = "pre_bead_close"
type    = "veracity_gate"
command = "mallcop-fixer-no-auto-apply"  # refuses close if diff touches tracked file without gate
```

## The disposition surface

| Disposition | Claims (skill) | Tools | Emits | pre_bead_close hook | POST.md |
|---|---|---|---|---|---|
| **triage** | `exam:scenario`, `task:triage` | bash, read, check-baseline, search-events | closes OR `task:investigate` | checklist + credential-theft | `agents/triage/POST.md` (exists) |
| **investigate** | `task:investigate` | +search-findings, +load-skill | closes OR `task:heal` | checklist strict 7/7 + credential-theft | `agents/investigate/POST.md` (exists, needs expansion) |
| **heal** | `task:heal` | +exam-transcript-dump, stubbed writes | closes; `exam:judge` via bash helper | credential-theft + transcript-dumped | `agents/heal/POST.md` (exists) |
| **judge** | `exam:judge` | read only | `judge:verdict` tag + rubric payload | none | `agents/judge/POST.md` (NEW — blind prompt) |
| **report** | `exam:report` | read, bash | writes `exams/reports/<run>/report.json` | none | `agents/report/POST.md` (NEW) |
| **fixer** (Phase 3) | `exam:fix-cluster` | read, grep, glob | unified diff campfire messages | no-auto-apply | `agents/fixer/POST.md` (NEW) |

## Legion gaps

### REQUIRED (critical path)

**Gap 1: Chart-level `[inference].forge_api_url`.**
- **Why**: Bakeoff needs per-process Forge endpoint; env-var-only (`legion/cmd/we/main.go:251`) forces wrapper scripts and blocks multi-sibling parallel runs in one shell.
- **Where**: `legion/internal/chart/chart.go:91-97` (add field to InferenceSection); `legion/cmd/we/boot.go:319-323` (consume in effectiveRouterCfg, fall back to env).
- **LOC**: ~10.
- **Interim workaround**: Wrapper script per sibling with `FORGE_API_URL=... we start ...`. Functional but brittle.

**Gap 2: `exam-seed` Go subcommand.** (Not a legion gap — a mallcop-legion TODO.)
- **Why**: This is the t.Skip at `mallcop-legion/test/budget/chain_budget_test.go:462`. Someone has to post `work:create` messages.
- **Where**: `mallcop-legion/cmd/exam-seed/main.go` (NEW).
- **LOC**: ~200 (YAML walker + Go schema validator + fixtures materialiser + trap-strip + campfire join + `work:create` sender using existing `pkg/workclient`).
- **No upstream coupling.** Uses `workclient.ReadySender.SendWithAntecedents` with tag `work:create` and payload matching `workCreatePayload` (`legion/pkg/workclient/ready_worksource.go:230`).

### NICE-TO-HAVE (workarounds identified)

**Gap 3 (purist G1): Per-capability sandbox allowlist.** `legion/internal/worker/jail_create.go` + `sandbox_policy.go`, ~80 LOC.
- **Workaround**: Chart-wide `extra_ro` includes both `fixtures/<run>/` and `transcripts/<run>/`. Blindness soft-enforced by directory layout + judge prompt discipline. Phase 4 hardens to structural.

**Gap 4 (purist G2): Structured veracity gate with chart-declarable required-tag schema.** ~150 LOC.
- **Workaround**: Ship `mallcop-checklist-verify` / `mallcop-credential-theft-verify` as Go CLIs and hook via `command=`. Rubric lives in mallcop-legion, not in legion TOML. Phase 4 moves it upstream.

**Gap 5 (purist G3): Directory worksource primitive.** ~200 LOC.
- **Workaround**: `exam-seed` IS the workaround. Phase 4 elegance win, not on critical path.

### Explicitly DROPPED

- Creative C-03's reasoning-artifact HintType (~30 LOC) — heal bash helper replaces it.
- Creative C-07's relay-message-received intent (~80 LOC) — Q9 out of scope.

## The v2-deploy bridge

`mallcop-v2-deploy/scan.sh` is ~180 lines of bash that calls `curl` against `api.mallcop.app`. It does not boot legion. **This design is purely additive** — nothing here imports or rewrites `scan.sh`.

**Coexistence rules**:
1. Exam chart runs on mallcop-legion PRs, gates merge.
2. scan.sh runs on cron/webhook in mallcop-v2-deploy, gates tenant deploys.
3. Both paths reference the same `agents/*/POST.md` files — a prompt change affects both.
4. No cross-imports. No shared runtime.

**Path from "scan.sh is prod" to "legion chart is prod"**:
- **Now (Phase 1-2)**: scan.sh is prod, legion chart is exam-only.
- **Phase 3**: parity smoke test — one scenario run through both paths, diff triage outputs.
- **Phase 4 (out of scope)**: dual-write on real webhooks, divergence tracking, eventual cutover gated on 30 days ≥95% exam pass + <1% parity divergence + operator approval.

## Build phases

### Phase 1 — First scenario end-to-end (3-4 days)

**Done when**: `go test ./test/quality/... -run TestExamID01` seeds `ID-01-new-actor-benign-onboarding.yaml` into an `exam-R1` campfire, boots `we start --chart .run/exam-R1/chart.toml --exit-on-idle`, triage → (resolve, no escalate) → transcript dump → judge → report fires, report.json contains `verdict=pass`, test asserts pass, `we` exits cleanly. No veracity-gate hooks yet. No bakeoff.

**Work items (outcome-shaped, for /swarm-plan)**:
1. Scenario Go struct + YAML validator (`mallcop-legion/internal/exam/scenario.go`) — loads `ID-01`, fails loudly on schema violations.
2. `cmd/exam-seed/main.go` — validates scenarios, strips trap fields, materialises fixtures/, posts `work:create` per scenario + final `exam:report`.
3. `cmd/exam-transcript-dump/main.go` — tool the heal disposition calls to dump a sanitized transcript.
4. `charts/exam.toml.tmpl` authored + `cmd/exam-render-chart/main.go` renderer.
5. `agents/judge/POST.md` authored with blind prompt (no scenario-category vocabulary).
6. `agents/report/POST.md` authored (walks verdicts, writes report.json).
7. `test/quality/exam_smoke_test.go` — ID-01 end-to-end green test.
8. CI: GitHub Actions runs `go test ./test/quality/...`, uploads report.json as artifact.

**Depends on**: nothing upstream; runs on legion HEAD.

### Phase 2 — Full suite + hooks + first bakeoff (4-5 days)

**Done when**: `go test -run TestExamFull` runs all 56 scenarios with `mallcop-checklist-verify` + `mallcop-credential-theft-verify` hooks active; 3-model bakeoff (`charts/exam-bakeoff-{haiku,sonnet,opus}.toml.tmpl`) completes and emits a diffable bakeoff report; wall time under 25 min.

**Work items**:
1. Upstream legion PR: `[inference].forge_api_url` (Gap 1).
2. `cmd/mallcop-checklist-verify` + `cmd/mallcop-credential-theft-verify` hook CLIs.
3. Port all 56 scenarios from `mallcop/tests/shakedown/scenarios/` to `exams/scenarios/`.
4. Port Python evaluator rubric to `agents/judge/POST.md` verbatim + Go rubric struct.
5. `charts/exam-bakeoff-*.toml.tmpl` + renderer support.
6. `cmd/bakeoff-report` — reads N report.json files, emits bakeoff.{md,json}.
7. CI parallel bakeoff job, pinned to legion release with Gap 1 merged.
8. scan.sh parity smoke test: one scenario, both paths, diff outputs.

**Depends on**: Phase 1 complete; legion Gap 1 merged; `.we-version` bumped.

### Phase 3 — Improvement-loop fixer (stretch, 3-4 days)

**Done when**: A failing exam emits `fix_clusters`, `charts/exam-fixer.toml` boots, claims clusters, emits unified diffs as campfire messages, human gates fire, operator reviews via `cf`.

**Work items**:
1. `charts/exam-fixer.toml` + `agents/fixer/POST.md`.
2. Report step seeds `exam-fix-suggestions` with one item per cluster.
3. Diff emission protocol (campfire message format).
4. `cmd/mallcop-fixer-no-auto-apply` hook.
5. Operator docs for reviewing diffs.

**Depends on**: Phase 2 complete.

### Phase 4 — Hardening (stretch, out of scope for /swarm-plan)

Upstream G1 (per-capability sandbox), G2 (structured veracity tags), G3 (directory worksource); parity dual-write; scan.sh cutover plan.

## Known tradeoffs and non-goals

**Accepted tradeoffs**:
- Phase 1 blindness is soft-enforced via directory layout + judge prompt discipline. G1 hardens in Phase 4.
- The veracity gate is part of the system under test (A-10 partial concession). An optional prompt-only sidecar is Phase 3+.
- Bakeoff CI wall time ~25 min at full scale. Smoke on PR, full nightly.
- Ephemeral per-run identities — no cross-run telemetry aggregation without a join step. Phase 4.

**Explicit non-goals**:
- Interactive/chat actor (Q9).
- scan.sh rewrite or migration.
- Contradiction detection in fix clusters (Phase 3+).
- Cross-run telemetry joins (Phase 4).
- Real connector live-test mode.

## Open questions for the operator

1. **A-10 partial**: Want an optional prompt-only calibration sidecar (hooks disabled), or accept hook-inclusive grading as the only measurement?
2. **Q9 / A-15**: Extend the design with a chat subsystem chapter, or keep explicitly out?
3. **G1 workaround**: Phase 1 ships soft blindness. Upstream G1 on critical path, or accept as Phase 4?
4. **CI gating**: Exam failure blocks PR merge, or posts a comment? Threshold ≥90% pass?
5. **Bakeoff cadence**: Every PR (25 min) or nightly only?
6. **Phase 3 fixer**: Valuable vs human editing prompts directly from the Phase 1 report?
7. **Seeder signing identity**: Reuse the exam automaton's fresh identity (seeder reads the same key file), or separate short-lived seed identity admitted to the run campfire?

## Attack disposition

| ID | Attack | Status | How |
|---|---|---|---|
| A-01 | Judge context pollution | DEFUSED | Fresh worker claim; zero inherited context |
| A-02 | trap_description leaks | DEFUSED | exam-seed strips before `work:create`; transcript dump sanitized |
| A-03 | Work-seeding gap | DEFUSED | `cmd/exam-seed` Go CLI via existing workclient |
| A-04 | Budget across scenarios | DEFUSED | `max_tasks_per_session=1` resets budget per scenario |
| A-05 | Shared capabilities campfire | DEFUSED | Ephemeral per-run identity + constellation |
| A-06 | Production Forge bleed | DEFUSED | Chart `forge_api_url` (Gap 1) forces canned backend in exam |
| A-07 | connector_tools enforcement | DEFUSED | Exam chart excludes connector-query:*; exam-mode tool binary reads fixtures only; no egress |
| A-08 | Bakeoff model identity | DEFUSED | Per-process Forge endpoint + `capabilities.seed.model` |
| A-09 | Improvement-loop contradictions | PARTIAL | Fixer refuses contradictory clusters; detection Phase 3+ |
| A-10 | Hook changes experimental variable | CONCEDED | Test the bundle; optional prompt-only sidecar is Phase 3+. Flagged OPEN. |
| A-11 | exit-on-idle semantics | DEFUSED | Ready-only intake, no schedule entries, drain → idle exit |
| A-12 | CI cost at bakeoff scale | DEFUSED | Parallel siblings, ~25 min; smoke-on-PR + nightly full |
| A-13 | Production campfire blast radius | DEFUSED | Per-run identity has no production campfire knowledge |
| A-14 | Contributor scenario validation | DEFUSED | Go schema validator in exam-seed, fails loud |
| A-15 | Interactive actor regression | DEFERRED | Q9 forward reference; flagged OPEN |

**13/15 defused, 1 partial (A-09), 1 conceded with mitigation (A-10), 1 deferred (A-15).**

## Creative proposals adopted

| ID | Proposal | Status |
|---|---|---|
| C-01 | Universal work-item shape | ADOPTED |
| C-02 | Disposition = tool allowlist | ADOPTED |
| C-03 | Judge on reasoning artifact | ADOPTED (without HintDemuxer gap; heal bash helper replaces it) |
| C-04 | Bakeoff as sibling automatons | ADOPTED (modified: per-sibling queues) |
| C-05 | Investigation tools as convention ops | REJECTED (per purist T7 — NativeBinDir bash tools instead) |
| C-06 | Improvement loop as propose-fix | ADOPTED (Phase 3) |
| C-07 | Chat as legion disposition | DEFERRED (Q9 out of scope) |

## Theorems satisfied

**T1–T9 all satisfied.** T4 is soft-satisfied in Phase 1 (directory-convention blindness), hard-satisfied when G1 ships. T6 honored via mallcop-specific veracity-gate hook binaries; G2 upstream proposal moves the schema to TOML in Phase 4.
