# internal

Private Go packages for the AgentShield control plane.

Package responsibilities are split by runtime concern:

- `api`: Run/checkpoint management plus the read-only Dashboard Overview API.
- `bpfmgr`
- `config`
- `correlator`: two-stage Run attribution and deterministic checkpoint matching.
- `envcheck`
- `events`
- `evidence`: provenance-safe evidence timeline construction and P4 sample.
- `killer`
- `logging`
- `policy`
- `scope`
- `stream`: authenticated resumable WebSocket fan-out with bounded clients.
- `store`: redacted SQLite evidence persistence and isolated bounded writer.
- `version`
