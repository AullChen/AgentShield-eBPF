# cmd/agentshield

Main entrypoint for the AgentShield control-plane binary.

Current commands:

- `agentshield audit --bpf-object ./bpf/agentshield.bpf.o --scope-cgroup PATH`
- `agentshield diagnose`
- `agentshield version`
- `agentshield health`

`audit` is Linux-only. It expects a compiled BPF object and streams file/exec
attempt events plus TCP connect attempts only for the registered exact leaf as
JSON Lines. It also emits Go-synthesized per-type drop notices and receipt
clock fields. The legacy `audit-openat` spelling remains an alias for now.

Scoped path/argv fragments may still be sensitive and must remain owner-only.
