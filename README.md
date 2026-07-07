# AgentShield-eBPF

AgentShield-eBPF is a Linux eBPF based runtime security and audit system for AI Agent sandboxes.

The project is currently in early MVP development. The repository already contains the Go control-plane skeleton, a bootstrap eBPF source layout, an `openat` file-access audit tracepoint, local diagnostics, and a Next.js dashboard scaffold. Runtime eBPF loading, cgroup scoping, policy enforcement, event correlation, and live dashboard streaming are still under development.

## Current Status

| Area | Status | Notes |
| --- | --- | --- |
| Go control plane | Started | `agentshield version`, `health`, and `diagnose` commands are available. |
| Environment diagnostics | Started | Detects host OS and reports Linux-only kernel capability checks. |
| eBPF source layout | Started | `bpf/agentshield.bpf.c`, `events.h`, and `maps.h` exist. |
| File audit probe | Started | `tracepoint/syscalls/sys_enter_openat` emits a file-open event shape. |
| BPF build flow | Bootstrap | `make generate` embeds BPF source text for Go-side development; real object compilation is scheduled later. |
| Dashboard | Scaffolded | Next.js App Router pages exist with mock data. |
| Runtime BPF loading | Started | `agentshield audit-openat` can load a compiled BPF object on Linux. |
| Ring buffer consumption | Started | `audit-openat` decodes file-open ring buffer events as JSON Lines. |
| Kernel Event v1 | Started | Go-side decoding now validates schema version, action fields, timestamps, strings, and truncation flags. |
| cgroup scoping | Not implemented | Planned after the first audit loop. |
| Policy engine | Not implemented | Planned after cgroup-scoped event capture. |

## MVP Direction

The MVP is scoped around this path:

1. Register a controlled AI Agent sandbox by cgroup v2.
2. Capture file, process, and network events with eBPF.
3. Consume kernel events in a Go control plane.
4. Match events against runtime security policies.
5. Correlate Agent checkpoints with kernel events.
6. Display live evidence chains in a web dashboard.

The current codebase has only the first pieces of that path. It is not yet a usable sandbox or enforcement tool.

## Repository Layout

```text
bpf/                 eBPF programs, maps, and shared event definitions
cmd/agentshield/     Go control-plane CLI entrypoint
cmd/bpfgen/          Local BPF source binding generator
internal/            Go internal packages
dashboard/           Next.js dashboard scaffold
sdk/python/          Future Python Agent adapter SDK
sandbox/             Future demo Agent sandbox and attack scenarios
deploy/              Future local deployment files
configs/             Runtime and policy configuration examples
docs/                Public project documentation
scripts/             Future developer and demo helper scripts
tests/               Future integration, security, and performance tests
```

Local planning documents and proposal drafts are intentionally kept outside Git under `.local-docs/`.

## Requirements

For current development:

- Go 1.22 or newer
- Node.js 20 or newer
- npm 10 or newer
- GNU Make
- clang, for the local BPF syntax check

For real kernel feature work:

- Linux kernel 5.15 or newer
- cgroup v2 enabled
- BTF available at `/sys/kernel/btf/vmlinux`
- Permission to load eBPF programs

Windows and macOS are fine for editing, Go unit tests, dashboard work, and the bootstrap syntax check. Real eBPF loading and runtime validation must happen on Linux.

## Quick Start

Install dashboard dependencies once:

```sh
cd dashboard
npm install
cd ..
```

Run the current control-plane CLI:

```sh
go run ./cmd/agentshield version
go run ./cmd/agentshield health
go run ./cmd/agentshield diagnose
```

On non-Linux hosts, `diagnose` prints a capability report and exits with status `1` because AgentShield kernel features require Linux.

On Linux, after compiling a real BPF object, start the current `openat` audit loop with:

```sh
go run ./cmd/agentshield audit-openat --bpf-object ./bpf/agentshield.bpf.o
```

This command attaches `syscalls/sys_enter_openat`, reads `agentshield_events`, and prints one JSON object per file-open event. On non-Linux hosts it exits with an unsupported-platform error.

## Checks

Run the Go and BPF bootstrap checks:

```sh
make generate
make check-bpf-syntax
make check-linux-bpfmgr
make test
make build
```

Or run the aggregate Go/BPF check:

```sh
make check
```

Run the dashboard checks:

```sh
cd dashboard
npm run typecheck
npm run build
```

The current P0 integration status is recorded in [docs/p0-integration-check.md](docs/p0-integration-check.md).

## Current eBPF Probe

The current BPF program includes:

- `tracepoint/syscalls/sys_enter_openat`
- Event type: `AGENTSHIELD_EVENT_FILE_OPEN`
- Captured fields: pid, tgid, uid, comm, filename, open flags, timestamp, cgroup id placeholder
- Go consumer: `agentshield audit-openat --bpf-object ./bpf/agentshield.bpf.o`
- Go event model: `internal/events.KernelEvent` with schema version `1`

Day 8 intentionally does not filter by cgroup or PID yet. Scope filtering is scheduled for a later milestone.

The local syntax check uses a bootstrap stub:

```sh
clang -DAGENTSHIELD_BPF_SYNTAX_CHECK -fsyntax-only bpf/agentshield.bpf.c
```

This is not a replacement for compiling and loading a real CO-RE BPF object on Linux.

## Dashboard

The dashboard currently exposes static App Router pages with mock data:

- Overview
- Live Trace
- Policies
- History
- Diagnostics

Start it locally with:

```sh
cd dashboard
npm run dev
```

The dashboard does not yet connect to the Go control plane.

## Development Timeline

Completed:

- Day 1: repository scaffold and Git hygiene
- Day 2: Go control-plane CLI skeleton
- Day 3: initial eBPF source and map skeleton
- Day 4: BPF source binding generation flow
- Day 5: environment diagnostics
- Day 6: Next.js dashboard scaffold
- Day 7: P0 integration check documentation
- Day 8: `openat` audit tracepoint skeleton
- Day 9: Go-side `openat` audit command and ring buffer event decoder
- Day 10: `KernelEvent v1` schema validation and string/truncation decoding

Next planned work:

- Add a real Linux CO-RE object compilation path
- Validate `audit-openat` end-to-end on a Linux host
- Add `execve` audit coverage for process execution events
- Add cgroup/PID filtering after the first audit loop is stable

## Limitations

- The repository does not yet compile `bpf/agentshield.bpf.c` into a real `.bpf.o` object.
- The Linux `audit-openat` runtime path is implemented but not end-to-end validated in this Windows workspace.
- The project does not yet enforce policies or block behavior.
- The project does not yet isolate Agent runs by cgroup.
- The dashboard currently uses mock data.
- The generated BPF source binding embeds source text only; it is not a compiled BPF object.

## License

License information will be added before the first public release.
