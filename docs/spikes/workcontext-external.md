# Spike: WorkContext External Population via Chart Config

Item: mallcoppro-b96
Date: 2026-04-10

---

## Question A: Does legion today support populating WorkContext.ExternalMessages and WorkContext.StandingFacts from a chart-configured shell command (pre-worker hook)?

**VERDICT: NO.**

### Evidence

There is no mechanism in legion today for a chart-configured shell command to inject content into `WorkContext.ExternalMessages` or `WorkContext.StandingFacts` before a worker spawns.

#### How ExternalMessages is actually populated

`WorkContext.ExternalMessages` is populated exclusively from campfire reads.

- `internal/automaton/context.go:242` — `externalCampfireIDs := cs.externalCampfireIDs(task)`
- `internal/automaton/context.go:273-277` — `external, err := cs.readExternalMessages(externalCampfireIDs)` → `wctx.ExternalMessages = external`
- `internal/automaton/context.go:601-616` — `externalCampfireIDs()` reads campfire IDs from the task's JSON `context` field (`{"campfires": ["abc123", ..."]}`). It parses JSON, returns IDs, and `readExternalMessages` calls `cfRunner.ReadMessages()` on each. There is no branch for a shell command.

#### How StandingFacts is actually populated

`WorkContext.StandingFacts` is populated from the configured memory campfire, tagged `memory:standing`.

- `internal/automaton/context.go:244-256` — `readAllStandingFacts(memoryCampfireID)` reads from `cfRunner.ReadMessages(memoryCampfireID, "memory:standing", 0)`, then `selectRelevantFacts()` filters to top 20. No shell command path exists.

#### The "command" hook type is a dead field

`internal/chart/chart.go:504-505` defines a `Command string` field in `HookEntry` with comment "shell command to execute for 'command' type hooks." Validation at `chart.go:926-928` rejects `type = "command"` with empty `Command`. This looks promising but is a dead end:

1. `internal/automaton/hooks.go:30-40` — Only three `HookType` constants exist: `veracity_gate`, `domain_guard`, `done_condition_verify`. There is no `"command"` constant and no registered implementation.
2. `internal/chart/chart.go:1124-1137` — `convertHooks()` converts `HookEntry → automaton.HookConfig` but drops the `Command` field entirely: `result[i] = automaton.HookConfig{Point: ..., Type: ..., Domain: ...}`. `Command` is not in `automaton.HookConfig` at all.
3. `internal/automaton/hooks.go:126-163` — `NewHookEngine` is only instantiated in test files (`hooks_test.go`), never in production dispatch code. Grep of all `.go` files outside `_test.go` finds zero `NewHookEngine` calls in production paths.

Conclusion: the `Command` field was scaffolded for a future feature but is unimplemented. Even if you set `type = "command"` and `command = "my-tool"` in a chart, nothing runs it.

#### Pre-dispatch hooks do not touch WorkContext

`HookPreDispatch` (`hooks.go:19-20`) fires before spawning a worker, but its only registered implementation is `domain_guard` (path filtering). Hooks receive a `HookContext` (`hooks.go:56-78`) which has no `WorkContext` field — there is no mechanism for a hook to inject data into the WorkContext the worker will receive.

### Gap (what's missing, estimated LOC)

To enable chart-configured shell command injection into WorkContext, three changes are needed:

1. **`HookConfig` extension** (~10 LOC): Add `Command string` to `automaton.HookConfig` in `internal/automaton/hooks.go`.
2. **Command HookType implementation** (~30 LOC): Register a new `HookType = "command_inject"` in `NewHookRegistry` that runs `exec.Command(shell)`, captures stdout, and stores it somewhere. The tricky part is threading the output back into WorkContext.
3. **WorkContext injection path** (~40 LOC): Either (a) add an `InjectedFacts []string` field to `WorkContext` and have `AssembleContext` call the command hook before returning, or (b) add a pre-spawn step in the dispatch loop that runs configured commands and appends their output to `wctx.ExternalMessages`. Option (b) is cleaner: it keeps `ContextService.AssembleContext` pure and adds an explicit `runPreSpawnCommands(cfg, wctx)` call in the dispatch path.
4. **Chart validation fix** (~5 LOC): Wire the `Command` field through `convertHooks()` so it isn't silently dropped.

Total estimate: ~85 LOC additive, all in `internal/automaton/` and `internal/chart/`. Zero breaking changes to existing chart users.

---

## Question B: Can legion's PromptExtension + StableExtension + WorkContext interfaces express mallcop's full prompt shape if we link to legion as a Go module?

**VERDICT: YES, with one minor gap.**

### Evidence

`internal/worker/prompt.go` defines the full interface surface:

- **`WorkContext` struct** (`prompt.go:68-179`): Contains every field mallcop would need to inject custom context:
  - `ExternalMessages []CampfireMessage` (line 134) — for runtime context from external sources
  - `StandingFacts []CampfireMessage` (line 122) — for persistent domain knowledge
  - `Spec string` (line 112) — agent spec, already the right place for product-specific instructions
  - `Constraints string` (line 115) — budget/scope constraints
  - `HumanMessages []CampfireMessage` (line 152) — human operator messages

- **`PromptExtension` interface** (`prompt.go:11-17`): `Name() string` + `Extend(ctx WorkContext) string`. Any Go struct implementing this can inject variable-suffix content into every worker prompt.

- **`StableExtension` interface** (`prompt.go:20-32`): `StableExtend(ctx WorkContext) string`. Allows injection of stable prefix content that is identical across all workers of the same type, maximizing Claude API prefix-cache hits.

- **`PromptBuilder`** (`prompt.go:193-341`): `NewPromptBuilder(extensions ...PromptExtension)` composes extensions. Stable extensions write to the stable prefix (lines 253-263); variable extensions write to the variable suffix (lines 331-338).

### What mallcop needs to express

| mallcop need | Interface available | Notes |
|---|---|---|
| Inject mallcop product context (donut model, model routing rules) | `StableExtension.StableExtend()` | Identical across workers — good for cache |
| Inject per-task external data (customer tier, balance) | `PromptExtension.Extend()` or `WorkContext.ExternalMessages` | Both work |
| Inject standing facts (e.g., Forge API endpoints) | `WorkContext.StandingFacts` | Already rendered by BuildPrompt |
| Inject custom CLAUDE.md / agent spec | `WorkContext.Spec` | Set before calling BuildPrompt |

### Minor gap

`BuildPrompt` renders `WorkContext.StandingFacts` as-is (each `CampfireMessage.Payload` is appended). There is no way to override the section header text ("STANDING FACTS") or the rendering format without modifying `BuildPrompt` itself. This is a cosmetic constraint, not a blocker — mallcop's content can be formatted inside the payloads.

There is also no `PromptExtension` registration mechanism in `AutomatonConfig` or chart TOML today. Extensions are registered in Go code at process start (`NewPromptBuilder(extensions...)`). If mallcop links to legion as a Go module, it can register its own extensions at startup — no problem. If mallcop wants extensions from a config file without Go linkage, that path does not exist today (see Question A).

---

## Concrete next action recommendation

**Question A is NO.** The shell-command injection path does not exist. This forecloses the "pure config + external CLI tools, zero Go linkage" architecture for context injection.

**Recommended path:** Make the small additive legion contribution (~85 LOC) to implement a `pre_spawn_inject` hook type that runs a chart-configured shell command and appends its stdout to `WorkContext.ExternalMessages`. This keeps mallcop-legion as pure config with no Go linkage.

**Alternative path:** Link mallcop-pro to legion as a Go module and register a `MallcopPromptExtension` that implements `StableExtension` + `PromptExtension`. This works cleanly today (Question B is YES), costs ~50 LOC in mallcop-pro, but couples mallcop-pro's build to legion's module version.

**Decision gate:** The right choice depends on whether Third Division Labs wants legion to be an embeddable Go library (module path) or remain an opaque binary (config + external tools). That's an architecture decision for the Legion PM, not mallcop-pro. File an rd item in the legion project requesting the `pre_spawn_inject` hook type, or accept the Go module coupling as a deliberate trade-off.

**If going the legion-contribution route**, the implementation target is:
- `internal/automaton/hooks.go` — add `HookCommandInject HookType = "command_inject"` and implementation
- `internal/automaton/config.go` — add `Command string` to `HookConfig`
- `internal/chart/chart.go` — wire `Command` through `convertHooks()`
- `internal/automaton/context.go` — call command-inject hooks before returning from `AssembleContext`
