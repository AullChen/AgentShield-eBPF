# cmd/agentshield

Main entrypoint for the AgentShield control-plane binary.

Current commands:

- `agentshield audit-openat --bpf-object ./bpf/agentshield.bpf.o`
- `agentshield diagnose`
- `agentshield version`
- `agentshield health`

`audit-openat` is Linux-only. It expects a compiled BPF object and streams
ring buffer events as JSON Lines.
