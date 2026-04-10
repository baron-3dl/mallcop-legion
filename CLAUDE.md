# CLAUDE.md — mallcop-legion

> Go binary: mallcop security scanner on legion runtime.
> Scaffolded under work item mallcoppro-eb1.

## Cross-Repo Architecture

See ~/projects/mallcop-pro/CLAUDE.md for full cross-repo architecture, including:
- mallcop-pro tenant service (Forge integration, Polar checkout, donut billing)
- mallcop OSS CLI (connectors, detectors, skills, actors)
- Forge inference proxy (accounts, billing, metering, Bedrock routing)

## This Repo

mallcop-legion integrates the mallcop scanner with the legion automaton runtime:
- `chart.toml` — legion automaton config for the connector factory
- `cmd/mallcop-legion/` — CLI binary entrypoint
- Legion workers invoke mallcop-specific tools from this repo

## Related Items

- Parent work item: mallcoppro-eb1
- mallcop-connectors: ~/projects/mallcop-connectors
- mallcop-skills: ~/projects/mallcop-skills

## Spikes

Prior spike research is in docs/spikes/ — do not delete.
