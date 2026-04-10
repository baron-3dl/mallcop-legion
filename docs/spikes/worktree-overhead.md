# Spike: Worktree Overhead at 200-Finding Scan Volume

**Status:** Verdict reached  
**Date:** 2026-04-10  
**Item:** mallcoppro-138  
**Method:** Code path analysis (not measurement — no legion end-to-end run performed)

---

## 1. Code Path Analysis of Jail + Worktree Setup

Legion does NOT use `git worktree add` for workers. Each worker gets a full independent
clone via `CreateJail`. This is an important distinction: the cost profile is clone-based,
not worktree-based. Where the CLAUDE.md says "worktree overhead," the actual mechanism is
`git clone --reference --dissociate`.

### Step-by-step trace through `CreateJail` (jail_create.go)

**Phase 1: Directory structure creation** (lines 162–177)
Seven directories created via `os.MkdirAll`:
- `<jailRoot>/active/<workerID>/clone/`
- `<jailRoot>/active/<workerID>/home/.claude/`
- `<jailRoot>/active/<workerID>/home/.legion/tokens/`
- `<jailRoot>/active/<workerID>/campfire/`
- `<jailRoot>/active/<workerID>/transport/`
- `<jailRoot>/active/<workerID>/tmp/`
- `<jailRoot>/active/<workerID>/logs/`

Cost: 7 `mkdir` syscalls. Sub-millisecond, negligible.

**Phase 2: File copies** (lines 179–200)
- `identity.json` → campfire dir (one `ReadFile` + `WriteFile`)
- `.claude/settings.json` written (one `WriteFile`, 28 bytes)
- `~/.claude/.credentials.json` → jail home (one `ReadFile` + `WriteFile`, logged-but-skipped if absent)

Cost: 2–4 file I/O ops, each sub-millisecond. Negligible.

**Phase 3: Pool repo ensure + fetch** (lines 205–208, jailEnsurePoolRepo lines 469–498)

This is the first potentially significant step:

- On first call ever: `git clone --mirror <originURL> <poolDir>` — a full network clone. One-time cost per origin URL, not per worker.
- On all subsequent calls: `git fetch --all --prune` inside the bare mirror, serialized via `syscall.Flock` (lines 502–531). **This is a network operation with a 60-second timeout** (line 460: `poolFetchTimeout = 60 * time.Second`).

The fetch is SERIALIZED across concurrent workers (exclusive flock). Only one worker can refresh the pool at a time. If a second worker arrives while the first is fetching, it blocks on the flock until the fetch completes.

**[ESTIMATE]** On a local repo (no network): `git fetch --all --prune` completes in 50–200ms.  
**[ESTIMATE]** On a remote GitHub repo: 500ms–3s depending on network and repo size.

**Phase 4: Clone from pool** (lines 211–213, jailCloneFromPool lines 536–553)

```
git clone --reference <poolDir> --dissociate <originURL> <clonePath>
```

The `--reference` flag means git copies objects from the local poolDir instead of the network. `--dissociate` copies all referenced objects into the new clone so it's fully independent after creation. This is the DOMINANT I/O COST: dissociate copies all objects from pool into the worker clone.

**[ESTIMATE]** For a small-to-medium repo (mallcop OSS: ~500 commits, ~20MB objects):
- With `--reference --dissociate`: 200–800ms (local disk I/O, no network).
- Without the pool (cold): 2–10s (network fetch).
- The pool amortizes the network cost but not the disk copy.

**Phase 5: Branch creation** (lines 218–220, jailCreateBranch lines 556–563)

```
git checkout -b work/<item-id>
```

One git process invocation. Cost: ~30–100ms (git startup + branch creation). Negligible relative to clone.

**Phase 6: Metadata write + env build** (lines 225–256)

JSON marshal + one `WriteFile` + env slice construction. Sub-millisecond. Negligible.

### Total per-worker setup time (ESTIMATE)

| Step | Estimated Duration | Notes |
|---|---|---|
| Dir creation (7 dirs) | 1–5ms | Pure syscalls |
| File copies (2–3 files) | 1–5ms | Small files |
| Pool fetch | 50–200ms (local), 500ms–3s (remote) | Serialized via flock |
| Clone --dissociate | 200–800ms | Dominant cost; local disk I/O |
| Branch checkout | 30–100ms | git process startup |
| Metadata/env | <1ms | Negligible |
| **Total (local repo)** | **~300ms–1.1s** | Pool already warm |
| **Total (remote repo, cold pool)** | **~700ms–4s** | Rare after first worker |

**[ESTIMATE — NOT MEASURED]** These figures are derived from typical git performance characteristics for small-to-medium repos. Actual times will vary with disk speed (SSD vs HDD), repo size, and network latency. The pool fetch dominates on remote repos; the `--dissociate` clone dominates on local repos.

### Teardown cost

`DestroyJail` (lines 266–275) calls `os.RemoveAll(jailPath)`. For a small repo clone, this removes ~20–50MB of files.

**[ESTIMATE]** Teardown: 50–200ms on SSD.

---

## 2. Key Architecture Finding: No Worktrees

Legion does NOT use `git worktree add`. Worker clones are full independent clones with `--reference --dissociate`. This means:
- No worktree registration in the parent repo's `.git/worktrees/`
- No per-worktree git overhead
- Clone is fully self-contained after creation
- The MERGE path uses one shared merge worktree (`EnsureMergeWorktree`, git.go lines 84–99), created once at startup — not per worker

The pool repo (`<jailRoot>/pool/<hash>/`) is a bare mirror, created once per origin URL. All subsequent workers clone from the pool with a local disk copy (no network). The pool fetch serialization via flock means concurrent workers stall behind each other for the fetch step, but the clone step runs concurrently.

---

## 3. Extrapolation to 200-Finding Scan Volume

### Scenario definition

A "200-finding scan" means mallcop produces 200 security findings. Each finding is a work item. The question is: do we dispatch one worker per finding, or batch?

**Config baseline (from charts/legion/chart.toml, line 35):**
- `max_workers = 3` (default; configurable)
- `time_limit = 30m` per worker

For this analysis, "parallel-max-workers" means `max_workers = 3` unless otherwise noted.

### Serial mode (1 worker at a time)

Setup overhead per finding: ~300ms–1.1s (ESTIMATE)  
Teardown per finding: ~50–200ms (ESTIMATE)  
Total overhead per finding: ~350ms–1.3s

At 200 findings serial:
- **Overhead total: ~70s–260s (1.2–4.3 minutes)**
- Worker idle time (waiting for prior worker to complete) is not included — this is pure setup overhead, not queue wait.

Worker runtime for a scan finding: highly variable. A mallcop actor that remediates a finding might run 2–20 minutes (it's a full Claude Code session). At 5 minutes median, 200 findings serial = ~17 hours of wall-clock time, with overhead adding 1–4 minutes. **Overhead is negligible (<1%) of total scan time in serial mode.**

### Parallel mode (max_workers = 3, then scaling)

At `max_workers = 3`:
- 200 findings / 3 concurrent = ~67 waves
- The `poolFetchTimeout` flock means only 1 worker refreshes the pool at a time per wave start
- Actual clone operations run concurrently (no flock on clone, only on fetch)
- **[ESTIMATE]** Overlap reduces effective overhead per finding to ~200–600ms

At `max_workers = 20` (hypothetical high-parallelism config):
- 200 findings / 20 concurrent = 10 waves
- Pool fetch serialization becomes a bottleneck: 20 workers racing for the flock means ~18 workers waiting behind the 1 fetching; estimated wait: 50–200ms per worker
- Clone operations still concurrent
- **[ESTIMATE]** Total setup time per wave: ~400ms–2s (serialized fetch) + ~300ms–900ms (concurrent clone overhead)

The flock serialization on pool fetch is the only true serialization point in parallel setup. At 3 workers, it's negligible. At 20+ workers, it could add 1–4s per wave, but scans are async so this doesn't block the user.

### Summary table (ESTIMATES)

| Mode | Workers | Overhead per finding | Total overhead (200 findings) | % of 5min/finding runtime |
|---|---|---|---|---|
| Serial | 1 | ~300ms–1.1s | ~60s–220s | <0.4% |
| Parallel | 3 | ~200ms–600ms | ~13s–40s (amortized) | <0.2% |
| High-parallel | 20 | ~400ms–2s (per wave) | ~4s–20s total | <0.1% |

**In all configurations, setup overhead is less than 1% of total scan runtime.**  
The dominant cost is Claude Code execution time per finding, not jail setup.

---

## 4. Decision: ACCEPT

**Chosen option: ACCEPT — overhead is tolerable because scans run async.**

### Reasoning

1. **Overhead is proportionally tiny.** At 300ms–1.1s per jail setup against 2–20 minute worker sessions, jail overhead is 0.1–0.5% of total scan time. It does not appear in any user-visible latency.

2. **Scans are already async.** mallcop scans run in the background and post results. The user does not wait on a blocking call for 200 findings. A 4-minute overhead on a multi-hour scan is invisible.

3. **The pool design amortizes the expensive part.** `git clone --mirror` (the one-time cost) runs once. All workers get `--reference --dissociate` copies from local disk. Network is not in the hot path once the pool is warm.

4. **The flock serialization is not a problem at `max_workers = 3`.** At the default concurrency, pool fetch serialization adds effectively zero latency (50–200ms staggered across 3 workers max).

5. **BATCH would add complexity without benefit.** Batching N findings per worker would require a custom driver that sequences findings, handles partial failures, and resurfaces per-finding outcomes — all complexity that legion's jail model gives you for free when you do one-finding-per-worker. The savings would be on jail setup overhead that costs <1% of runtime.

6. **OPTIONAL (read-only mode) is premature.** There is no evidence that findings are read-only operations in all cases. Some mallcop actors write files (remediation), commit changes, and push branches. Removing worktree isolation for any "read-only" subclass would require careful classification of findings and would undermine NDI guarantees. Not worth the complexity.

### When to revisit

Revisit ACCEPT if:
- Repo size grows to >500MB objects (--dissociate clone cost increases to 3–10s per worker)
- `max_workers` is raised to >20 and pool fetch serialization is observed in telemetry
- Telemetry (`CloneDurationMs` in `JailLifecycleRecord`, jail_create.go lines 43–44) shows sustained p99 > 5s

The `JailLifecycleRecord` (jail_create.go lines 34–45) emits `clone_duration_ms` = `ReadyTime - CreateTime` to the telemetry campfire. This covers phases 1–4 (dirs + pool fetch + clone). Use this telemetry to validate estimates once legion runs against the mallcop OSS repo at volume.

---

## 5. Concrete Next Action

**Wire the mallcop-pro connector factory chart to use the existing legion pool mechanism.**

When configuring `grid/chart.toml`:
- Set `max_workers = 3` (default) for initial factory runs
- Point `origin_url` to `~/projects/mallcop` so the pool warms on the first worker
- Enable telemetry campfire so `clone_duration_ms` is captured
- After the first 10 workers run, query telemetry for p50/p95 `clone_duration_ms` to validate estimates

Do NOT implement BATCH or read-only mode. ACCEPT the overhead and instrument it.

---

## Appendix: Key File References

| File | Lines | What |
|---|---|---|
| `internal/worker/jail_create.go` | 129–258 | `CreateJail` — full setup sequence |
| `internal/worker/jail_create.go` | 460 | `poolFetchTimeout = 60s` |
| `internal/worker/jail_create.go` | 469–498 | `jailEnsurePoolRepo` — pool init + refresh |
| `internal/worker/jail_create.go` | 502–531 | `jailFetchPoolRepo` — flock + git fetch |
| `internal/worker/jail_create.go` | 536–553 | `jailCloneFromPool` — `--reference --dissociate` |
| `internal/worker/jail_create.go` | 34–45 | `JailLifecycleRecord` — telemetry schema including `clone_duration_ms` |
| `internal/worker/jail_create.go` | 260–275 | `DestroyJail` — `os.RemoveAll` teardown |
| `internal/worker/git.go` | 84–99 | `EnsureMergeWorktree` — single shared merge worktree (not per-worker) |
| `internal/worker/config.go` | 86–93 | `DefaultConfig` — `max_workers=3`, `time_limit=30m` |
| `charts/legion/chart.toml` | 35–37 | `max_workers = 3`, `time_limit = 30m` |
