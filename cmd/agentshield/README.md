# cmd/agentshield

Main entrypoint for the AgentShield control-plane binary.

Current commands:

- `agentshield audit --bpf-object ./bpf/agentshield.bpf.o`
- `agentshield diagnose`
- `agentshield version`
- `agentshield health`

`audit` is Linux-only. It expects a compiled BPF object and streams file/exec
attempt events as JSON Lines. The legacy `audit-openat` spelling remains an
alias for now.

The current probes are host-wide and may print sensitive path/argv fragments.
Run them only on an isolated VM or dedicated test host.
