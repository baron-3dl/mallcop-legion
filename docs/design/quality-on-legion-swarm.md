# Quality-on-legion swarm manifest

Companion to [quality-on-legion.md](quality-on-legion.md). This file is the
**dispatch entry point** — it's small enough to fit in any context window and
captures everything `/swarm-dispatch` needs without recursing into rd's tree
printer (which produces ~35K lines for this swarm due to the cross-cutting
sweep dependencies).

## Parent

`mallcoppro-9fd` — Quality-on-legion: Academy Exam + investigation team + bakeoff + improvement loop

## How to dispatch this swarm

The dispatcher must NOT use `rd dep tree mallcoppro-9fd` as the entry point —
the fan-in pattern (5 sweep items each blocked by 24 implementation items, 1
e2e item blocked by 5 sweeps) makes the recursive walk produce ~35K lines of
duplicated subtree text. Use the JSON manifest instead:

```bash
# 1. Read the manifest
cat docs/design/quality-on-legion-swarm.json

# 2. Find ready items
jq '.summary.ready_now' docs/design/quality-on-legion-swarm.json

# 3. Per item: get its agent type + spec from .claude/agents/
jq -r '.items[] | select(.id == "<id>") | .agent_type' \
  docs/design/quality-on-legion-swarm.json

# 4. Dispatch
/delegate <agent-type> "/work <item-id>"
```

The manifest fields per item:
- `id` — rd item ID
- `title` — short description
- `type` — task | review
- `status` — inbox | active | done | ...
- `blocked_by` — array of upstream item IDs (empty = ready now)
- `agent_type` — implementer | reviewer | veracity-adversary | sweeper-* | (gate)
- `test_depth` — feature | bugfix | refactor | test-only | review | e2e
- `model_tier` — haiku | sonnet | opus
- `artifact_type` — code | spec | ops | design

The manifest is generated from rd state. To refresh after wave completions:

```bash
python3 docs/design/quality-on-legion-swarm-refresh.py > /tmp/new.json && \
  mv /tmp/new.json docs/design/quality-on-legion-swarm.json
```

(refresh script will be added in Phase 1 work — for now, regenerate by hand
from `rd list --all --json` filtered to children of `mallcoppro-9fd`)

## Agent specs

Required `.claude/agents/` (symlinked into both mallcop-pro and mallcop-legion
from `~/projects/resonant/docs/practice/agents/`):

| Agent type | Spec file | Used for |
|---|---|---|
| `implementer` | implementer.md | All Phase 0-3 task items |
| `reviewer` | reviewer.md | All review items + the e2e verification item (test-depth: e2e) |
| `veracity-adversary` | veracity-adversary.md | Phase 1/2/3 in-wave veracity audits |
| `sweeper-security` | sweeper-security.md | Per-gate security reviews + parent security sweep |
| `sweeper-bugs` | sweeper-bugs.md | Parent bug sweep |
| `sweeper-deadcode` | sweeper-deadcode.md | Parent dead-code sweep |
| `sweeper-antipatterns` | sweeper-antipatterns.md | Parent antipattern sweep |
| `sweeper-testcoverage` | sweeper-testcoverage.md | Parent test-coverage sweep |

**No `e2e-verification` agent spec exists** — the canonical agent set has no
dedicated e2e verifier. The e2e item (`mallcoppro-bd8`) is annotated with
`agent-type: reviewer, test-depth: e2e`. The dispatcher dispatches it as a
reviewer; the test-depth annotation tells the agent to do an end-to-end
verification rather than a code review.

## Wave plan (from quality-on-legion.md)

**Wave 1 (now — 5 ready items)**:
- `mallcoppro-e9b` Q_P0_01: 56 scenarios YAML port → implementer/haiku
- `mallcoppro-e93` Q_P1_04: charts/exam.toml.tmpl + renderer → implementer/sonnet
- `mallcoppro-b86` Q_P1_05: agents/judge/POST.md blind prompt → implementer/sonnet
- `mallcoppro-d77` Q_P1_V: Phase 1 veracity audit → veracity-adversary/opus (in-wave)
- `mallcoppro-a9b` Q_P2_01: legion upstream forge_api_url → implementer/sonnet (parallel critical path)

**Wave 2** (after Q_P0_01 + Q_P1_05 close): Q_P1_01 (scenario struct), Q_P1_06 (report aggregator)

**Wave 3** (after Phase 1 chain pieces): Q_P1_02, Q_P1_03 (exam-seed, transcript-dump)

**Wave 4** (after Phase 1 core): Q_P1_07 (TestExamID01 e2e), then Q_P1_08 (CI workflow), then `mallcoppro-d77` veracity verdict closes the wave

**Wave 5** (Phase 2): unlocks after Phase 1 veracity passes — 9 implementation items in parallel where deps allow, the legion upstream PR (`mallcoppro-a9b`) must be merged before Q_P2_05

**Wave 6** (Phase 2 hooks): Q_P2_02, Q_P2_03 (hook CLIs) → Q_P2_04 (investigate POST.md)

**Wave 7** (Phase 2 full suite): Q_P2_07, Q_P2_08, Q_P2_09 → Phase 2 veracity

**Wave 8** (Phase 3): Q_P3_01..05 in dependency order → Phase 3 veracity

**Wave 9** (sweeps): all 5 parent-level sweeps in parallel after every implementation closes

**Wave 10** (e2e): `mallcoppro-bd8` after all sweeps close

## Open items the swarm must NOT touch

These are pre-existing P0/P1 items in mallcop-pro that pre-date this swarm
and have nothing to do with Academy/investigation work. The dispatcher
should filter to children of `mallcoppro-9fd` only:

- `mallcoppro-035` Pro-online container bootstrap
- `mallcoppro-47f` Telegram flood fix
- `mallcoppro-eb1` Greenfield mallcop rebuild on legion (the parent epic this swarm helps deliver)
- `mallcoppro-fd5` Message queue for webhook-driven daemon workers
- All `mallcoppro-1??` `mallcoppro-3??` `mallcoppro-c39` `mallcoppro-43d` items — older work waves

The manifest's `items` array contains ONLY the 60 children of `mallcoppro-9fd`.
The dispatcher uses the manifest, not `rd ready` (which mixes in unrelated items).

<!-- design-campfire: 74560d7d779998a781657b37a053e2501e07a382933e4ebe909883bc01f9fd50 -->
<!-- swarm-parent: mallcoppro-9fd -->
<!-- swarm-manifest: docs/design/quality-on-legion-swarm.json -->
