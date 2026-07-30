# mallcop

> Open-source security monitoring for small cloud operators. AI-native. Go.

mallcop is a Go-native security monitoring CLI. It ingests your cloud and SaaS
audit events, runs 17 deterministic detectors that look for real-world attack
patterns, then drives each finding through an LLM-backed investigation cascade
(triage → investigate → deep panel → committee consensus) before paging a human.
Findings and decisions are written to a git-native store, so every verdict is
durable, replayable, and auditable. mallcop reads one file — `mallcop.yaml` —
and needs zero flags for the common path.

## Install

**One line (Linux & macOS):**

```bash
curl -fsSL https://mallcop.app/install.sh | sh
```

Downloads the prebuilt binary for your platform, verifies its checksum, and
installs it to `/usr/local/bin` or `~/.local/bin` (no sudo).

**Go toolchain:**

```bash
go install github.com/mallcop-app/mallcop/cmd/mallcop@latest
```

**Release binaries:**

Pre-built binaries for Linux (amd64/arm64) and macOS (Apple Silicon) are
attached to each [GitHub release](https://github.com/mallcop-app/mallcop/releases).
Download the archive for your platform, extract, and place `mallcop` on your `PATH`.

## Quickstart

**1. Install mallcop** (see above).

**2. Initialize:**

```bash
mallcop init
```

```
mallcop init: created <dir>/mallcop.yaml (config — offline inference)
mallcop init: created <dir>/store/ (findings store)
mallcop init: created <dir>/events.jsonl (sample events)

Next steps:
  1. Run the scan (reads mallcop.yaml — no flags needed):
       mallcop scan
  2. Add a source: edit mallcop.yaml -> connectors:
     (a github org, or a cloud source like aws/azure)
  3. For managed LLM resolution (offline is the fail-safe default):
       mallcop init --pro  &&  export MALLCOP_API_KEY=mallcop-sk-...
```

`init` writes the one file mallcop reads (`mallcop.yaml`), a git-backed
`store/` for findings + decisions, and a sample `events.jsonl` so the next
step runs with zero credentials. Re-running `init` is a no-op — it never
overwrites a file that already exists.

**3. Run the scan — no flags:**

```bash
mallcop scan
```

```
Scan complete
  Events scanned:     1
  Findings detected:  2
  Escalated:          2
  Resolved:           0
  Investigated:       0
  Investigations degraded: 2
```

`scan` discovers `mallcop.yaml`, reads its `connectors:`/`store:`/`inference:`
settings, runs the detector fleet, drives each finding through the cascade,
and commits findings + decisions into `store/`. With no inference endpoint
configured (the OSS default), every finding force-escalates — the documented
fail-safe — so the sample scan above runs end to end with zero credentials.
Exit code `1` means findings were detected, not that the scan failed.

Every escalated finding is also investigated at detection time: a
deterministic evidence chain (actor provenance, timing recurrence, baseline
history, scan-schedule correlation) is committed beside the finding at
`store/investigations/<finding-id>.json`, on by default. With no inference
endpoint configured the model narrative degrades honestly (`Investigations
degraded` above) — the evidence still ships. See `investigate:` in
`mallcop.yaml` to tune or disable it.

(The old flag-only invocation — `mallcop scan --events events.jsonl --store
store` — still works and takes precedence over the config for any flag you
pass explicitly. Flags exist for scripting; `mallcop.yaml` is the primary path.)

**4. Add a source.** Edit `mallcop.yaml`'s `connectors:` list directly, or use
the config primitive:

```bash
mallcop config set connector --kind=github --id=my-org --org=my-org
```

**5. (Optional) Enable managed LLM resolution.** `mallcop init --pro` points
`mallcop.yaml` at the donut rail (Forge-managed inference); set your key and
re-scan:

```bash
mallcop init --pro
export MALLCOP_API_KEY=mallcop-sk-...
mallcop scan
```

BYOK/BYOI (your own vendor URL + key) works the same way — set
`inference.endpoint`/`inference.key_env` in `mallcop.yaml` (`inference.mode`
is a label, e.g. `byoi`; `endpoint`+`key_env` are what the scan actually
resolves), or the `MALLCOP_INFERENCE_URL`/`MALLCOP_API_KEY` env pair, which
always wins over the config.

**6. Inspect what was recorded:**

```bash
mallcop status --store store
```

```
Store:      store
Findings:   2 recorded
Decisions:  2 recorded
Cases:      2 open (0 recurring)
  injection-probe  entity=(no entity)  count=1  cadence=no established cadence  status=open
  new-actor  entity=(no entity)  count=1  cadence=no established cadence  status=open
Coverage gaps:   0 (0 reported miss)
State:      idle
```

`status`'s "Decisions" is every resolution ever recorded in the store
(escalations included) — not the same number as `scan`'s per-run "Resolved"
line above, which counts only that run's non-escalate (auto-resolved)
findings. A store can show decisions recorded even when its last scan
resolved none of them itself — both got escalated to a human instead.

## Deploy as a repo (scheduled, unattended scanning)

`mallcop init --create-repo owner/name` turns the local scaffold above into a
**customer-owned deployment repo**, pushed to a real GitHub repo, that scans
on a schedule without you running anything locally:

```bash
export MALLCOP_GITHUB_TOKEN=$(gh auth token)   # or your own --github-token-env
mallcop init --create-repo my-org/my-mallcop --pro
```

What gets scaffolded, on top of `mallcop.yaml`/`store/`/`events.jsonl`:

- **`go.mod`** pinning `github.com/mallcop-app/mallcop` at a specific release
  tag (`--mallcop-version`, default: latest) — a THIN-EMBED dependency pin,
  never a fork or vendored copy.
- **`detectors/`** — write your own detector here as a Go package
  (`package main`, one subdirectory per detector); the scheduled Action builds
  each one to a `wasip1`/`wasm` module under `detectors/bin/`, and `mallcop
  scan` loads it exactly like a built-in framework detector via
  `detectors.sidecars.dir`. See `detectors/README.md` (scaffolded into the
  repo) and `examples/sidecar-detector` in this repo for a worked example.
- **`connectors/`** — write your own connector as a standalone Go binary
  (same shape as the shipped sibling connectors below) and point
  `mallcop.yaml`'s `connectors:` at it with `kind: cloud`. See
  `connectors/README.md` (scaffolded into the repo).
- **`.github/workflows/scan.yml`** — runs on a schedule: installs the pinned
  **prebuilt** `mallcop` release binary (never rebuilds the core binary from
  repo content), builds any `detectors/*` to `.wasm`, runs `mallcop scan`, and
  pushes the resulting `store/` history back to this same repo on a dedicated
  `mallcop-findings` branch (kept off `main` by `.gitignore`) so findings
  persist across ephemeral runner instances.

The core binary is always the pinned prebuilt release; only your own
`detectors/*` ever compile from repo content, and only to `wasip1/wasm`. You
never need a local Go toolchain to run the deployment — only to author a new
detector or connector for it.

## The autonomy dial

`learning.autonomy` in `mallcop.yaml` controls how much of mallcop's own
self-extension loop applies automatically, versus waiting for you:

```bash
mallcop config set autonomy semi   # non | semi | fully
```

| Setting | DATA changes (tuning/mapping widen) | CODE changes (authored detectors/connectors) |
|---|---|---|
| `non` (default) | wait for human approval | wait for human approval |
| `semi` | auto-apply on a gate-GREEN clean widen | wait for human approval |
| `fully` | auto-apply on a gate-GREEN clean widen | auto-apply on a gate-GREEN clean widen |

Every proposal — data or code — still has to pass the same gate first (see
below); the dial only decides what happens to a result that already passed.
**Contribute-back to the shared OSS pool is never auto-merged at any
setting** — an opt-in PR to the upstream `mallcop` repo always waits for
human/maintainer review, regardless of where the dial is set.

## Code-first: authored detectors and connectors

New detection/connection surface is **AI-written Go code**, gated, never a
declarative spec interpreted by a generic loader. Both proposal shapes — a
new detector or a data widen (tuning/mapping) — go through the same
`validate-proposal` gate before anything lands:

```
(1) guard        — static invariant guard: protected paths (the committee,
                    consensus logic) are untouchable; YAML data may only
                    WIDEN what's seen, never narrow or add a suppress rule
(2) structural    — the change builds; authored code passes the import
                    allow-list (no net/file/exec in a detector)
(3) exam-detect   — base vs. head labeled-exam comparison: no regression,
                    at least one closed detection gap, no undeclared new
                    firings on the benign corpus
```

Run it yourself against any diff:

```bash
mallcop validate-proposal --base <ref> --head <ref> --json
```

A rejected result never touches the committee or the consensus vote — mallcop
only ever widens what the detection committee sees; it can never learn to
suppress or auto-approve a real attack pattern.

## Chat-driven reconfiguration

Every `mallcop config set ...` primitive (`connector`, `autonomy`) is the
same mutation surface a chat interface drives in the hosted product
(mallcop-pro): "watch our Linear activity" or "turn on auto-apply for data
changes" resolves to a **propose → approve → apply** step that calls the
identical `core/config` mutation this CLI calls directly. There is no
separate code path for chat versus the command line.

## Chat-driven investigation

`mallcop investigate` (`core/investigate`) is the same contract applied to
read/report tools, not just mutation. Every tool it advertises to the model
is a thin adapter over a real CLI command — never a second implementation —
so a chat session and a terminal always agree:

| Chat phrasing | Same code path as |
|----------------|--------------------|
| "what's my miss rate?" / "am I missing any real attacks?" | `mallcop eval --json` (the `run-eval` tool) |
| "flag things like this as `<family>`" | `mallcop scenario capture ...` (the `flag-like-this` tool) |

`run-eval` is read-only: it changes nothing and answers with the SAME
recall-first split `mallcop eval` prints, the operator's own `scenarios/`
corpus always reported separately from the shipped reference corpus, never
blended. `flag-like-this` writes a scenario YAML file, but only into the
operator's own repo (`scenarios/`, see `mallcop init --create-repo`'s
scaffolded `scenarios/README.md`) — it changes no runtime detection
behavior, so unlike a config mutation it needs no propose → approve → apply
gate; it is safe at every autonomy dial setting. Both tools return an honest
error rather than a fabricated number when the operator's repo/corpus can't
be resolved.

## Commands

| Command | Purpose |
|---------|---------|
| `mallcop scan` | Full agentic scan: connect → detect → cascade → store. Reads `mallcop.yaml` when present; `--store`/`--events`/etc. override or substitute for it. |
| `mallcop detect` | Offline detection only. Reads events JSONL on stdin, writes findings JSONL on stdout. No inference key. |
| `mallcop init` | Scaffold `mallcop.yaml` + a findings store + sample events; `--create-repo` also scaffolds and pushes a deployment repo. |
| `mallcop status` | Report findings/decisions recorded in a store. Requires `--store`. |
| `mallcop config` | Print the effective scan config resolved from `mallcop.yaml` + the environment. |
| `mallcop config set` | Mutate `mallcop.yaml` (`connector`, `autonomy`) via a strict, atomic-write primitive. |
| `mallcop feedback` | Record an operator decision (`approve`/`dismiss`) on a finding so future scans honor it. |
| `mallcop validate-proposal` | Run the free-tier self-extension gate over a proposal diff (guard + structural + exam-detect). |
| `mallcop collect` | Mine a scan's store for coverage gaps — the self-extension feedstock. |
| `mallcop exam-detect` | Grade the offline detect layer against the labeled exam corpus. |

### `mallcop scan`

```bash
# Zero-flag (reads mallcop.yaml from the current dir or an ancestor)
mallcop scan

# File connector, explicit flags (no config needed)
mallcop scan --events events.jsonl --store store

# GitHub connector (built into the core binary): scan a GitHub org's audit log
export GITHUB_APP_ID=...
export GITHUB_APP_PRIVATE_KEY=...      # PEM, or a path to it
export GITHUB_INSTALLATION_ID=...
mallcop scan --connector github --github-org my-org --store store
```

Flags: `--config` (explicit `mallcop.yaml` path), `--store`, `--events`
(file path or `-` for stdin), `--connector` (`file` | `github`),
`--github-org`, `--baseline`, `--tuning`, `--learned-mappings`,
`--max-findings`, `--workers`, `--json`, `--base-url`. Precedence is
flag > env > `mallcop.yaml` > built-in default; an absent config leaves
today's flag-only behavior unchanged.

Exit codes: `0` no findings, `1` findings present, `2` scan failure.

## Architecture

```
mallcop scan
  → connector        — fetch/ingest audit events (file, github, or a
                        standalone cloud-connector binary)
  → detectors        — 17 built-in deterministic detectors + any
                        configured wasip1/wasm sidecar detectors
  → cascade          — triage → investigate → deep panel → committee consensus
  → git store        — durable, replayable findings + decisions
```

The cascade resolves each finding through escalating tiers and ends in a
committee **consensus** vote: on every RESOLVE, the gate re-runs the cascade
and **any-escalate-wins** — a safety-first, asymmetric policy because a
missed attack (false negative) is catastrophic while an over-escalation
merely pages a human. The 17 built-in detectors are embedded in the binary;
authored detectors extend that fleet as sidecars (above) without ever
touching the committee/consensus code the guard protects.

## Connectors

The core binary ships two **built-in** connectors:

- **file** (default) — reads normalized event JSONL from `--events` or
  `mallcop.yaml`'s `connectors:` (`kind: file`).
- **github** — pulls a GitHub org's audit log directly, using
  `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY` / `GITHUB_INSTALLATION_ID`.

Additional connectors ship as **standalone binaries** in the sibling repo
[mallcop-app/mallcop-connectors](https://github.com/mallcop-app/mallcop-connectors),
wired into `mallcop.yaml` as `kind: cloud`, or piped directly:

```bash
# install the AWS connector and name it per mallcop's exec convention
go install github.com/mallcop-app/mallcop-connectors/cmd/aws@latest
mv "$(go env GOPATH)/bin/aws" "$(go env GOPATH)/bin/mallcop-connector-aws"

mallcop-connector-aws --since 2026-07-01T00:00:00Z \
  | mallcop scan --events - --store store
```

Currently shipped standalone connectors: AWS CloudTrail, Azure Activity Log,
GCP Cloud Logging, GitHub Audit Log, M365 Management Activity, Okta System Log.

**Not yet ported:** `container_logs`, `supabase`, `vercel`.

Your own connector for a source not listed above is a standalone Go binary
you author (same shape as the shipped ones — see the "Deploy as a repo"
section) and wire in via `kind: cloud`; there is no declarative
connector-spec format — a connector is always real code.

## Detectors

17 deterministic detectors run on every scan (and via `mallcop detect`):

```
auth-failure-burst       config-drift            dependency-tamper
exfil-pattern            git-oops                injection-probe
log-format-drift         malicious-skill         new-actor
new-external-access      priv-escalation         rate-anomaly
secrets-exposure         unusual-login           unusual-resource-access
unusual-timing           volume-anomaly
```

Content-only detectors (e.g. `injection-probe`, `secrets-exposure`, `git-oops`,
`config-drift`, `dependency-tamper`, `malicious-skill`) fire without any history.
The baseline-dependent detectors (`new-actor`, `priv-escalation`, `unusual-login`,
`unusual-timing`, `volume-anomaly`, `rate-anomaly`, `exfil-pattern`) use an
optional `--baseline` JSON file for historical context.

## License

MIT. See [LICENSE](LICENSE).
