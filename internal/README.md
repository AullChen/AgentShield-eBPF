# internal

Private Go packages for the AgentShield control plane.

Package responsibilities are split by runtime concern:

- `api`
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
- `store`: redacted SQLite evidence persistence and isolated bounded writer.
- `version`
