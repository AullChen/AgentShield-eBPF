# Control-plane packages

| Package | Responsibility |
| --- | --- |
| `api` | Registration, checkpoints, lifecycle, runtime pipeline, and authenticated read routes |
| `bpfmgr` | Object loading, hook attachment, scope probe, and ring-buffer consumption |
| `scope` | Exact-leaf identity, held descriptors, registration, and monitoring |
| `events` | Binary ABI validation and typed kernel-event decoding |
| `policy` | Strict loading, compilation, matching, precedence, and generation contracts |
| `killer` | Authorized descriptor-relative cgroup containment |
| `correlator` | Trusted Run attribution and scored same-Run checkpoint association |
| `evidence` | Source-aware timeline construction and sample fixtures |
| `store` | Redaction, SQLite persistence, bounded writer, and recovery diagnostics |
| `stream` | Authenticated WebSocket fan-out and bounded cursor recovery |
| `envcheck` | Host capability inspection |
| `timebase` | Receipt clock support |
| `config`, `logging`, `version` | CLI configuration, structured logging, and build metadata |

Tests live beside their implementation. Start with the [architecture](../docs/architecture.md) to follow the runtime through these packages.
