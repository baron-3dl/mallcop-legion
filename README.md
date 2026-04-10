# mallcop-legion

Go binary — mallcop security scanner on legion runtime. Contains chart config, CLI wrapper, and mallcop-specific tools invoked by legion workers.

## Overview

mallcop-legion integrates the mallcop security scanner with the legion automaton runtime. It provides:

- Chart configuration for legion-based connector factory workers
- CLI wrapper that dispatches mallcop scans via legion
- Mallcop-specific tool implementations invoked by legion workers

## Architecture

```
mallcop CLI
  → mallcop-legion (this repo)
    → legion runtime
      → mallcop-connectors (data fetching)
      → mallcop-skills (detection, analysis)
        → Forge API (metering, inference)
```

## Related

- Cross-repo architecture: ~/projects/mallcop-pro/CLAUDE.md
- Parent work item: mallcoppro-eb1
- mallcop OSS: https://github.com/thirdiv/mallcop
- mallcop-connectors: https://github.com/thirdiv/mallcop-connectors
- mallcop-skills: https://github.com/thirdiv/mallcop-skills

## License

MIT — Copyright (c) 2026 Third Division Labs
