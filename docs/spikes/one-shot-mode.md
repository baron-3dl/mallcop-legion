# Spike: Legion One-Shot Execution Mode

**Date:** 2026-04-10
**Item:** mallcoppro-cd9
**Verdict:** No native one-shot mode exists. Proposal: wrapper binary.

---

## What Was Read

### Binary rename status

The rename from `bang` → `we` is **complete** in the source. The CLI entry point lives at:

```
~/projects/legion/cmd/we/main.go
```

The package is `main`. The binary name in all help text and comments is `we`. No `cmd/bang/` directory exists. All PID file infrastructure, usage strings, and subcommand names use `we`. The rename is fully landed.

### CLI surface (`cmd/we/main.go`, lines 74–122)

`we start` is the only subcommand that boots an automaton. Its flags (lines 183–199):

```
--chart <path>             path to chart.toml (required)
--max-workers <n>          maximum concurrent workers (default: 3)
--time-limit <duration>    per-worker time limit (default: 30m)
--poll-interval <duration> poll interval (default: 10s)
--agent-dir <path>
--use-systemd
--transport-dir <path>
--project-root <path>
--project-path <k=v,...>
--instance <name>
-v
```

There is **no `--once` flag**, no `--max-tasks` flag, no `--run-once` flag, and no `--exit-when-idle` flag.

### Lifecycle architecture (`cmd/we/main.go`, lines 317–368)

After booting, `main()` blocks on `<-ctx.Done()` (line 362). The only way the process exits is via:

- SIGTERM or SIGINT → `cancel()` → `<-ctx.Done()` → runtimes stop → process exits
- Explicit `we stop [<name>]` → sends SIGTERM to the PID

There is no signal or code path that causes `we` to exit after completing a finite set of tasks. It is daemon-only by design.

### Runtime poll loop (`cmd/we/runtime.go`, lines 496–591)

`run()` starts `runPollLoop(...)` in a goroutine, then blocks on `<-rt.ctx.Done()` (line 578). The poll loop runs indefinitely, sleeping `PollInterval` between polls. It does not count tasks and stop.

### Chart config for lifecycle (`internal/chart/chart.go`, lines 378–398)

`LifecycleSection` fields:

```toml
[lifecycle]
max_workers    = 3
time_limit     = "30m"
poll_interval  = "10s"
max_fleet_depth = 0
```

No `max_tasks_total` or `exit_when_idle` field exists in `LifecycleSection`.

`BudgetSection` does have `max_tasks_total` (line 200–202), but this is a **per-task task-generation budget** (how many follow-on tasks an intent may spawn), not a "stop the engine after N items" control. It does not cause process exit.

`AutonomySection` has `max_tasks_per_session` (line 244–246) — this caps tasks per session for an individual Claude Code worker, not the engine.

---

## Verdict

**Legion has no one-shot execution mode.** `we start` is a daemon. It runs forever until SIGTERM. There is no `--once`, `--max-tasks`, or lifecycle field that causes the engine to exit after completing a work queue.

### Why This Matters for mallcop-laptop

For a customer running `mallcop` on their laptop, a daemonized `we start` is hostile UX:
- Customer runs `mallcop scan` expecting it to finish and return control.
- `we start` parks a process in the background polling forever.
- No clean exit signal when the scan completes.

---

## Proposal: Wrapper Binary in mallcop-legion

The cleanest path is a small `mallcop-run` binary in this repo (`mallcop-legion/cmd/mallcop-run/`) that:

1. Boots a `we`-compatible automaton runtime **directly** via the legion internal packages.
2. Polls for work until the queue is empty.
3. Exits cleanly with status 0.

### Why not a `--once` flag contribution to legion?

A `--once` flag on `we start` is the cleaner long-term contribution, but:
- It requires a legion PR, review cycle, and release — not in our control.
- `mallcop-run` needs product-specific behavior anyway (e.g., no campfire, no constellation, no campfire identity ceremony for customer laptops).
- The internal packages are importable: `github.com/3dl-dev/legion/internal/automaton`, `github.com/3dl-dev/legion/internal/chart`, `github.com/3dl-dev/legion/pkg/workclient`.

### Concrete implementation plan

**File:** `mallcop-legion/cmd/mallcop-run/main.go`

**Logic:**

```go
// 1. Load chart from --chart flag (same as we start)
ch, _ := chart.LoadChart(chartPath)
cfg, _ := ch.ToAutomatonConfig()

// 2. Build WorkSource (rd-backed or local filesystem)
ws := workclient.NewHTTPClient(cfg.Worksource.ServerURL, cfg.Worksource.APIKey)

// 3. Poll until empty — drain loop, not daemon loop
for {
    item, err := ws.ClaimNext(ctx, cfg.Identity.Name)
    if err == workclient.ErrNoWork {
        break // queue empty, exit cleanly
    }
    runWorker(ctx, item, cfg)
}

os.Exit(0)
```

**Key differences from `we start`:**
- No PID file, no SIGTERM handler, no campfire grid registration.
- No goroutine waiting on `<-ctx.Done()` — main() drives the drain loop directly.
- No `--poll-interval` delay between tasks (customer sees instant task chaining).
- `ErrNoWork` from `workclient` → clean exit.

**Reference files for the workclient drain pattern:**
- `~/projects/legion/pkg/workclient/` — WorkSource interface + HTTP client implementation.
- `~/projects/legion/internal/chart/chart.go` — LoadChart, ToAutomatonConfig.
- `~/projects/legion/internal/automaton/config.go` — AutomatonConfig struct.
- `~/projects/legion/cmd/we/boot.go` — bootAutomatonFromChart reference implementation.
- `~/projects/legion/cmd/we/main.go` lines 180–368 — full start subcommand for reference.

### Alternative: contribute `--once` to legion

If we want to upstream this, the minimal change is:

**File:** `~/projects/legion/cmd/we/main.go`
**After line 199** (after all flag declarations), add:

```go
once = flag.Bool("once", false, "drain the work queue once and exit (no daemon loop)")
```

**In `run()` in `runtime.go` (line 496):**
Replace the `<-rt.ctx.Done()` block with a drain-and-exit path when `once=true`. The poll loop would need to signal "queue empty" upward — currently `runPollLoop` has no such signal. This requires threading a channel through `runPollLoop` to notify when `ErrNoWork` is returned, then cancelling the context.

**Estimate:** 3–4 file changes, ~80 lines. Upstreamable but not in our control for timing.

---

## Recommendation

Build `mallcop-legion/cmd/mallcop-run/main.go` as a thin wrapper using legion's internal packages directly. It owns the drain loop, avoids daemon ceremony, and ships independently of legion releases.

File the legion `--once` contribution as a separate rd item for later if the pattern proves useful for other automaton operators.
