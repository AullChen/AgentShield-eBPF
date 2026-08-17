# internal

Private Go packages for the AgentShield control plane.

Package responsibilities are split by runtime concern:

- `api`
- `bpfmgr`
- `config`
- `correlator`
- `envcheck`
- `events`
- `killer`
- `logging`
- `policy`
- `scope`
- `store`: redacted SQLite evidence persistence and isolated bounded writer.
- `version`
