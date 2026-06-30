# AgentShield-eBPF

AgentShield-eBPF is a Linux eBPF based runtime security and audit system for AI Agent sandboxes.

The project is currently in early initialization. The repository contains the public project scaffold and the first Go control-plane command skeleton. Local planning documents and proposal drafts are kept outside Git under `.local-docs/`.

## Current Scope

MVP development will focus on this path:

1. Register a controlled AI Agent sandbox by cgroup v2.
2. Capture file, process, and network events with eBPF.
3. Consume kernel events in a Go control plane.
4. Match events against runtime security policies.
5. Correlate Agent checkpoints with kernel events.
6. Display live evidence chains in a web dashboard.

## Repository Layout

```text
bpf/                 eBPF programs and shared kernel/user event definitions
cmd/agentshield/     Go control-plane entrypoint
internal/            Go internal packages
dashboard/           Next.js dashboard
sdk/python/          Python Agent adapter SDK
sandbox/             Demo Agent sandbox and attack scenarios
deploy/              Local deployment files
configs/             Default runtime and policy configs
docs/                Public project documentation
scripts/             Developer and demo helper scripts
tests/               Integration, security, and performance tests
```

## Development

Run the current control-plane skeleton:

```sh
go run ./cmd/agentshield version
go run ./cmd/agentshield health
```

Run the current Go checks:

```sh
go test ./...
go build -o ./bin/agentshield ./cmd/agentshield
```

Generate the current BPF source binding and run the local BPF syntax check:

```sh
make generate
make check-bpf-syntax
```

## Development Plan

Day 1 initialized the project framework and repository hygiene:

- Create the module directory layout.
- Keep local planning documents out of Git.
- Add a root README and directory placeholders.
- Initialize Git and create the first project commit.

Day 2 initializes the Go module and the first `cmd/agentshield` executable skeleton.

## Environment Target

The intended runtime target is Linux with:

- Kernel 5.15 or newer.
- cgroup v2 enabled.
- BTF available.
- Permission to load eBPF programs.

Windows/macOS can be used for editing, but kernel feature development must run on a compatible Linux environment.
