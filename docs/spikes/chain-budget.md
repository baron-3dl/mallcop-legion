# Spike: Chain-Wide Token Budget Across Playbook Steps

**Verdict: PARTIAL**

Legion's budget system has the infrastructure for chain-wide budget composition, but it does NOT compose across playbook steps by default. Each `SkillEngine`-executed step dispatches a worker independently, and `RecordInferenceResult` accumulates spend on the per-item intent — so the token total grows across steps. However, the budget check before spawning a new step/worker is a **session-level gate** (`MaxTokensPerSession`), not a per-chain or per-playbook gate. The phase-based intent budget exists but is only registered for MISSION-horizon items, not for short-horizon playbook steps. The gap is described below.

---

## Code Paths Traced

### 1. Budget Allocation (per intent/task)

`internal/automaton/budget.go:336–343`

```go
func AllocateBudget(intentID string, parentBudget *TokenBudget, config *AutomatonConfig) *TokenBudget {
    total := resolveTotal(parentBudget, config)   // line 337
    allocs := resolveAllocations(config)          // line 338
    budget := buildTokenBudget(total, allocs)     // line 340
    return &budget
}
```

`resolveTotal` (`budget.go:363–374`) uses `parentBudget.remaining` when a parent is provided, or falls back to `config.Budget.DefaultTokenBudget` (default: 100,000 tokens). This is the mechanism for budget inheritance — **it exists**, but callers must explicitly pass a `parentBudget`.

### 2. Token Spend Recording (per worker exit)

`cmd/we/main.go:1191–1196`

```go
if err := svcs.budgetTracker.RecordInferenceResult(w.ItemID, "execution", inferResult.InputTokens, inferResult.OutputTokens); err != nil {
    slog.Debug("budget: RecordInferenceResult", "item_id", w.ItemID, "error", err)
}
svcs.budgetTracker.RecordSpendEntry(time.Now(), inferResult.InputTokens, inferResult.OutputTokens)
```

Tokens are keyed to `w.ItemID` — the rd item ID for the task being worked. In a three-step playbook (triage → investigate → heal), each step works the **same** rd item ID (or creates separate child item IDs). If steps share an item ID, spend accumulates on the same intent and the phase-based check (`CheckBudget`) would compose. If steps create separate item IDs (which playbooks do via the `SkillEngine` dispatcher), each step gets an independent intent with its own fresh budget allocation.

### 3. Session-Level Budget Check (before each dispatch)

`cmd/we/main.go:729–747`

```go
if svcs.cfg.Budget.MaxTokensPerSession > 0 {
    sessionTokens := svcs.budgetTracker.SessionTokensUsed(svcs.cfg.Identity.Name)
    if ok, reason := automaton.CheckSessionBudget(sessionTokens, svcs.cfg.Budget.MaxTokensPerSession); !ok {
        // creates gate:budget rd item, stops dispatch for this poll cycle
        break
    }
}
```

`CheckSessionBudget` (`internal/automaton/invariants.go:78–89`) checks cumulative session tokens against `MaxTokensPerSession`. `RecordSessionTokens` is called after every worker exit, so this DOES accumulate across all workers (and therefore across all steps). **This is the only cross-step guard that is actually wired end-to-end.**

### 4. Intent-Level Phase Budget Check (per-item)

`internal/automaton/budget.go:507–571` — `CheckBudget` reads phase allocations and checks `Used > Allocated` per phase, plus task counts. This is registered and checked for MISSION-horizon items (`handleMediumHorizon`, `cmd/we/horizon.go:105–106`):

```go
func allocateMissionBudget(item model.Item, svcs *lifecycleServices) {
    budget := automaton.AllocateBudget(item.ID, nil, svcs.cfg)  // line 226
    svcs.budgetTracker.RegisterIntent(item.ID, budget)           // line 227
}
```

For short-horizon items (which playbook steps are), `RegisterIntent` is **not called** in the dispatch loop. The intent tracker fails open for unregistered intents (`budget.go:508–514`): if intentID is not registered, `CheckBudget` returns `OK: true`. Phase-budget enforcement is therefore inert for playbook steps.

### 5. SkillEngine Step Dispatch — No Budget Check Between Steps

`internal/automaton/skill_engine.go:251–298`

The `ExecuteSkill` loop dispatches steps sequentially:

```go
for _, step := range steps {
    // ...
    for round := 0; round < maxRounds; round++ {
        sr, err := e.DispatchStep(step, params, round, dispatcher)
        // ...
        result.TotalTokens += sr.InputTokens + sr.OutputTokens
    }
    result.StepsCompleted++
}
```

`TotalTokens` is accumulated across steps in `SkillResult`, but this is purely telemetric — it is not checked against any budget ceiling before dispatching the next step. There is no `CheckBudget` call inside the step loop.

### 6. Budget Inheritance Mechanism (exists but unused for chains)

`budget.go:346–358` — `AllocateTaskBudget` and `AllocateBudget` both accept a `parentBudget *TokenBudget`. When non-nil, the child inherits the parent's remaining tokens. The signature is wired, but call sites in the `SkillEngine` dispatcher (`cmd/we/main.go` spawn path) always call `AllocateBudget(item.ID, nil, svcs.cfg)` — passing `nil` for `parentBudget`. No chain inheritance is set up.

---

## How Budget Flows Between Playbook Steps

| Layer | What is tracked | Scope | Enforced before step N+1? |
|---|---|---|---|
| `MaxTokensPerSession` (`I3`) | Cumulative session tokens across all workers | Automaton session | YES — checked in poll loop before each dispatch |
| `MaxTokensPerWindow` (`L3`) | Rolling 24h token spend | Automaton-wide rolling window | YES — checked in poll loop |
| Intent phase budget (`CheckBudget`) | Per-phase tokens for a registered intent | Per rd item | NO — not registered for playbook steps |
| `SkillResult.TotalTokens` | Sum across all steps in one skill invocation | Skill invocation | NO — telemetry only, not checked |

For a triage → investigate → heal chain:
- Tokens from triage are recorded in `RecordSessionTokens` on worker exit.
- Before investigate dispatches, `MaxTokensPerSession` (if configured) will block further dispatch if cumulative session tokens are exhausted.
- The intent-level phase budget does NOT fire because playbook steps do not call `RegisterIntent`.
- The step loop in `SkillEngine.ExecuteSkill` has no budget gate between steps.

**Summary: the only cross-step budget fence that fires is `MaxTokensPerSession`, a blunt session-wide gate. It will halt further dispatches after the session budget is exhausted — but it produces a `gate:budget` rd item and stops all workers, not a graceful per-chain escalation.**

---

## Exceeding Budget: Graceful Escalation vs Silent Truncation

When `MaxTokensPerSession` is hit (`cmd/we/main.go:729–747`):
1. `CheckSessionBudget` returns false.
2. `CreateBudgetGate` creates a `gate:budget` rd item (type: review, priority: P1) via the rd API.
3. The poll loop breaks — no further workers are spawned for this poll cycle.
4. Inflight workers (already dispatched) continue to completion; their output is not truncated.
5. The gate item requires human approval or config change to unblock.

This is **graceful escalation** (halts new dispatch, creates human gate) — not silent truncation. However, the escalation is session-wide, not per-chain. A three-step chain that hits the session budget after step 2 will halt investigate and never reach heal — without any chain-specific diagnostic.

For the phase-based intent budget (`RecordUsage` in `budget.go:583–614`): when a phase is exceeded, `BudgetExceededError` is returned, logged at DEBUG level (`cmd/we/main.go:1192–1193`), and execution continues. This is silent: the error is not propagated to a gate or halt.

---

## Gap Description and Estimated Fix (PARTIAL → YES)

### Gap 1: `RegisterIntent` not called for playbook/short-horizon items

**Problem**: The phase-based budget (`CheckBudget`) is only registered for MISSION-horizon items. Playbook steps fail-open.

**Fix**: In the short-horizon dispatch path, call `AllocateBudget` and `RegisterIntent` for each playbook item before spawning. Approximately **15–20 LOC** in `cmd/we/main.go` around line 855 (the item dispatch block), mirroring `allocateMissionBudget` in `horizon.go:222–231`.

### Gap 2: No per-chain budget with inheritance across steps

**Problem**: Each step creates a fresh budget from `DefaultTokenBudget`; there is no chain-wide ceiling that decrements across steps.

**Fix**: When a playbook creates step items, pass the parent item's remaining budget as `parentBudget` to `AllocateBudget`. The mechanism already exists (`budget.go:336–343`, `resolveTotal:363–374`). Callers need to: (a) snapshot the parent intent's remaining budget via `SnapshotIntent` (`budget.go:696–711`), (b) pass it as `parentBudget`. Approximately **30–40 LOC** split between the playbook step creation path and the budget allocation call site.

### Gap 3: No pre-step budget check in `SkillEngine`

**Problem**: `ExecuteSkill` has no budget check before dispatching the next step, so a step that blows the budget does not halt the chain gracefully.

**Fix**: Add a `BudgetChecker` interface injection to `SkillEngineConfig` (the interface `CheckBudgetOK(intentID string) bool` already exists at `budget.go:576`). Call it before `DispatchStep` for each step. Return `ErrBudgetExceeded` to halt execution and let the caller create a gate. Approximately **25–35 LOC** in `internal/automaton/skill_engine.go`.

### Total estimated LOC to close gap: ~70–95 LOC across three files

- `cmd/we/main.go`: 15–20 LOC
- `internal/automaton/skill_engine.go`: 25–35 LOC
- Call site for `AllocateBudget` with parent inheritance: 30–40 LOC

---

## References

- Budget allocation: `internal/automaton/budget.go:336–374`
- Budget inheritance mechanism: `internal/automaton/budget.go:363–374` (`resolveTotal`)
- Intent registration: `internal/automaton/budget.go:421–442` (`RegisterIntent`)
- Session budget check: `cmd/we/main.go:729–747`, `internal/automaton/invariants.go:78–121`
- Token recording on exit: `cmd/we/main.go:1191–1196`
- MISSION-only intent registration: `cmd/we/horizon.go:222–231`
- SkillEngine step dispatch loop: `internal/automaton/skill_engine.go:251–298`
- Phase-budget exceeded error: `internal/automaton/budget.go:583–614` (silent at caller)
- Budget gate creation: `internal/automaton/invariants.go:91–121`
