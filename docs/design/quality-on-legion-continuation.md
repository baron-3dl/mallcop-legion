# Quality-on-legion — Session Continuation

**Updated:** 2026-04-12
**Parent rd item:** `mallcoppro-9fd`
**Design doc:** `docs/design/quality-on-legion.md`
**Swarm manifest:** `docs/design/quality-on-legion-swarm.json` (60 items total; 30 closed, 12 ready, 27 blocked)

## tl;dr

Phase 1 is **proven end-to-end.** `TestExamID01` passes in 6.99s: verdict=pass, reasoning=4, thoroughness=4, 8 canned-backend calls. Legion v0.1.3 shipped all three upstream fixes. The next session should:

1. **Run the real bakeoff** — $200 budget approved. Use `we` as the driver via bakeoff chart variants. Populate `lanes.yaml` from actual data. See §Bakeoff below.
2. **Continue Phase 2 implementation** — 3 implementer items + 9 reviewer/sweeper items are ready NOW. See §Wave 6 below.

## Current state

### Repos

| Repo | Main SHA | Key state |
|---|---|---|
| `mallcop-pro` | `a143f95` | Lane rename landed (triage/investigate/heal). `Config.ModelForLane` wired into `handleMessages`. 6 lane-routing tests green. Auth bypass fixed. `lanes.yaml` values are HALLUCINATED — needs real bakeoff. |
| `mallcop-legion` | `b052e78` | Waves 1–5 merged. `.we-version = v0.1.3`. TestExamID01 GREEN. 32 items closed under `mallcoppro-9fd`. Continuation doc committed. |
| `legion` | `63e284a` | v0.1.3 tagged + released. All 3 upstream bugs fixed. |
| `mallcop` (Python) | no changes | Actor manifests still use `model: sonnet` (not lane names). Pending adoption. |

### What's verified end-to-end

- **TestExamID01**: chart render → exam-seed → `we start --exit-on-idle` → triage/investigate/heal/judge/report → report.json → verdict=pass. Green in 6.99s.
- **Auth bypass**: `curl -H "Bearer foo" api.mallcop.app/v1/messages` → 401. Fixed + deployed.
- **Lane routing**: customer with `sovereignty_floor=open` asking for `model=triage` → resolved to cheapest open-tier model via `Config.ModelForLane`. 6 tests.
- **Trap-strip enforcement**: 56 scenarios through exam-seed with metadata allowlist + fixture scrubbing + positive-control test. Hardened by b40 security sweep.
- **Judge blindness**: lint test blocks 17 forbidden patterns with word-boundary + case-folding + underscore variants.

### What's NOT verified yet

- **Real inference through the product stack** (only tested against canned backend)
- **lanes.yaml model assignments** (hallucinated, see §Hallucinated lanes.yaml)
- **Python mallcop actor manifests** (still `model: sonnet`, not lane names)
- **G2 command-hook dispatch** (`mallcoppro-3d4`): veracity-gate hooks ship as standalone binaries but legion's `[[hooks]] command=` field is dead. Workaround: exam.yml CI calls them as explicit steps.

## Bakeoff ($200 budget)

### Why

`mallcop-pro/internal/config/lanes.yaml` currently has hallucinated model assignments that violate the bakeoff algorithm. A `heal` row smaller than the `investigate` row is logically impossible under the "cheapest model that passes the threshold" rule. The values must be populated from an actual run.

### How

Use `we` as the driver — NOT a custom inference-layer harness (user explicitly vetoed that approach). The design items already exist:

- `mallcoppro-a3a` — `charts/exam-bakeoff-{haiku,sonnet,opus}.toml.tmpl` + renderer (renders N chart variants, one per model)
- `mallcoppro-ea2` — `cmd/mallcop-bakeoff-report` (aggregates N per-model report.json files into bakeoff.json with routing recommendation)

**Sequence:**

1. **Implement a3a + ea2** (Wave 6, no spend)
2. **Provision bakeoff account** via `cmd/mallcop-register`:
   - `sovereignty_floor = open` (to test GLM + Qwen)
   - Donut cap: ~$100 equivalent
   - Save key to `~/.cf/bakeoff.key` (gitignored)
3. **Run the bakeoff**:
   - Render N charts (one per model from the candidate list)
   - Seed each campfire via `exam-seed` with all 56 scenarios
   - Spawn N `we start --chart` subprocesses in parallel
   - Each produces its own `report.json`
   - Aggregate via `cmd/mallcop-bakeoff-report`
4. **Apply threshold algorithm** (`mallcop/tests/shakedown/bakeoff.py:148`):
   ```
   triage:      cheapest model with pass_rate >= 0.70
   investigate: cheapest model with pass_rate >= 0.80
   heal:        cheapest model with pass_rate >= 0.85
   ```
5. **Update `lanes.yaml`** from real results. Commit `bakeoff-YYYYMMDD.json` as evidence. Remove UNVERIFIED header.

### Candidate models (from `forge/internal/catalog/models.yaml`)

| Model | Sovereignty | Blended $/mtok | Notes |
|---|---|---|---|
| `glm-4.7-flash` | open | $0.16 | Cheapest open; expected triage winner |
| `glm-4.7` | open | ~$0.40 | Mid-tier open |
| `qwen3-32b` | open | $0.42 | Alt mid-tier open |
| `nova-lite` | us_only | $0.10 | Cheapest us_only |
| `nova-pro` | us_only | $1.44 | Mid us_only |
| `llama-4-maverick` | allied | $0.56 | Allied tier |
| `claude-haiku-4-5` | us_only | ~$1.60 | Strong cheap us_only |
| `claude-sonnet-4-6` | us_only | $9.00 | Quality reference (also the judge) |

**Estimated spend**: 56 scenarios × 8 models × ~3K worker tokens + 1344 judge calls at sonnet → ~$75-85. Hard cap of $150 in the runner binary.

### Budget enforcement (must be built into a3a/ea2)

- Hard cost cap of $150 in the binary
- Per-call cost estimation from token counts + catalog, accumulated
- If cap hit mid-run: halt, write partial results
- Resume-from-partial: per-scenario verdict JSONL written atomically

## Hallucinated lanes.yaml

The current `lanes.yaml` values are NOT from a real bakeoff. An agent fabricated them. A bold UNVERIFIED header comment is in place. The matrix is logically inconsistent:

- `heal.open = qwen3-32b` AND `investigate.open = qwen3-32b` — same model for different thresholds
- `heal.us_only = claude-haiku-3-5` smaller than `investigate.us_only = nova-pro` — impossible under cheapest-that-passes

**Do not trust these values.** The bakeoff above is the only thing that should write to that matrix.

## Wave 6 ready set (12 items, immediate dispatch candidates)

### Implementers (3)

| ID | Title | Tier | Notes |
|---|---|---|---|
| `mallcoppro-3a3` | agents/investigate/POST.md — full port | sonnet | Phase 2 core |
| `mallcoppro-a3a` | charts/exam-bakeoff-{haiku,sonnet,opus}.toml.tmpl + renderer | sonnet | Bakeoff pre-req |
| `mallcoppro-ea2` | cmd/mallcop-bakeoff-report aggregator | sonnet | Bakeoff pre-req |

### Reviewers (7)

| ID | Reviews | Notes |
|---|---|---|
| `mallcoppro-5aa` | Q_P2_01 (legion forge_api_url) | Low priority — veracity already covered this deeply |
| `mallcoppro-fb8` | Q_P1_03 (transcript-dump) | |
| `mallcoppro-0e1` | Q_P2_10 (investigate-tools) | |
| `mallcoppro-cea` | Q_P1_08 (exam.yml CI) | |
| `mallcoppro-a83` | Q_P2_02 (checklist-verify) | |
| `mallcoppro-f23` | Q_P2_03 (credential-theft-verify) | |

### Sweepers + veracity (2)

| ID | Title | Tier |
|---|---|---|
| `mallcoppro-b9d` | Security sweep: checklist hook gate | opus |
| `mallcoppro-562` | Security sweep: credential-theft hook gate | opus |
| `mallcoppro-f48` | Veracity audit — Phase 2 wave | opus |

### Recommended dispatch

With 4 workers: **a3a + ea2** (bakeoff infra, critical path to running real bakeoff) + **3a3** (investigate POST.md, unblocks Phase 2 chain) + **batch 2-3 reviewers** as a parallel sonnet sweep.

## Open followups (not in the 60-item manifest)

### Unblocked, ready to work

| ID | Title | Priority |
|---|---|---|
| `mallcoppro-419` | exam-seed fixture path must be absolute (sandbox regression) | p1 |
| `mallcoppro-a97` | internal/exam capture `actor_roles` + validate required fields | p2 |
| `mallcoppro-918` | exam-render-chart: validate against legion chart.LoadChart | p2 |
| `mallcoppro-a57` | exam-seed workclient spec deviation (decide import vs shell-out) | p2 |
| `mallcoppro-ad7` | mallcop-exam-report: full fix_target enum + report.md content assertion | p3 |
| `mallcoppro-31d` | exam-seed cf subprocess error paths + partial-seed idempotency | p3 |

### Blocked on legion (may be fixed in v0.1.3, verify)

| ID | Title |
|---|---|
| `mallcoppro-3d4` | wire `[[hooks]] command=` dispatch in legion (G2) |

## Key file paths

### mallcop-pro

- `internal/config/lanes.yaml` — lane matrix (HALLUCINATED)
- `internal/config/config.go` — `ModelForLane()` at line ~433
- `internal/forge/client.go` — `KeyInfo()` returns (accountID, sovereignty)
- `internal/server/server.go` — `handleMessages` with lane resolution
- `internal/server/lane_routing_test.go` — 6 routing tests

### mallcop-legion

- `test/quality/exam_smoke_test.go` — **TestExamID01** (the capstone, GREEN)
- `charts/exam.toml.tmpl` — exam chart template
- `cmd/exam-seed/main.go` — trap-strip enforcement (hardened with metadata allowlist)
- `cmd/exam-render-chart/main.go` — chart renderer (uses campfire identity.Save)
- `cmd/mallcop-exam-report/main.go` — judge-verdict aggregator
- `cmd/mallcop-investigate-tools/main.go` — check-baseline/search-events/search-findings
- `cmd/mallcop-checklist-verify/main.go` — pre-resolution checklist gate
- `cmd/mallcop-credential-theft-verify/main.go` — credential-theft gate
- `internal/exam/scenario.go` — Scenario struct + Load()
- `internal/testutil/cannedbackend/cannedbackend.go` — shared test backend
- `.github/workflows/exam.yml` — CI (workflow_dispatch + continue-on-error until PR-gating is enabled)
- `.we-version` — `v0.1.3`
- `exams/scenarios/` — 56 real scenarios
- `docs/design/quality-on-legion.md` — 26KB design doc

### Python mallcop

- `tests/shakedown/bakeoff.py` — bakeoff algorithm (threshold dict now renamed to triage/investigate/heal)
- `src/mallcop/actors/*/manifest.yaml` — actor manifests (still `model: sonnet`, needs lane adoption)

## First three things to do

1. **Read this doc** — you're doing it
2. **Pick your lane**: either (a) dispatch Wave 6 to continue Phase 2 implementation + bakeoff infra, or (b) focus on the bakeoff sequence exclusively (implement a3a + ea2 first, then provision + run). Option (b) is the shortest path to populating `lanes.yaml` with real data.
3. **`rd ready`** — the rd queue knows priorities; trust it for sequencing after you've read this doc
