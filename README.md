# AgentShield-eBPF

AgentShield-eBPF is a Linux eBPF based runtime security and audit system for AI Agent sandboxes.

The project is currently in early MVP development. The repository already contains the Go control-plane skeleton, file and process audit tracepoints, a unified ring-buffer consumer, a reproducible Linux CO-RE object build, local diagnostics, and a Next.js dashboard scaffold. Kernel load/attach acceptance, cgroup scoping, policy enforcement, event correlation, and live dashboard streaming are still under development.

## Current Status

| Area | Status | Notes |
| --- | --- | --- |
| Go control plane | Started | `agentshield version`, `health`, and `diagnose` commands are available. |
| Environment diagnostics | Started | Validates the minimum kernel and supported little-endian architectures; reports BPF load permission as unknown until a real syscall probe exists. |
| eBPF source layout | Started | `bpf/agentshield.bpf.c`, `events.h`, and `maps.h` exist. |
| File audit probe | Started | `tracepoint/syscalls/sys_enter_openat` emits a file-open event shape. |
| Process audit probe | Started | `tracepoint/syscalls/sys_enter_execve` captures executable and bounded argv summaries. |
| BPF build flow | Implemented, Linux evidence pending | `make bpf-object` compiles a CO-RE ELF and records object/BTF hashes, exact tool versions, and parsed program/map specs. |
| Dashboard | Scaffolded | Next.js App Router pages exist with mock data. |
| Runtime BPF loading | Started | `agentshield audit` loads a compiled BPF object and attaches file/exec probes on Linux. |
| Ring buffer consumption | Started | `audit` decodes file and process ring buffer events as JSON schema v2 Lines carrying wire schema v2 records. |
| Kernel Event v2 | Started | Go-side decoding validates schema/size, preserves JavaScript-unsafe `uint64` values as JSON strings, bounds consecutive malformed records, and rejects legacy/incompatible wire schemas. |
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
scripts/             Developer helpers; currently includes the audit trigger
tests/               Future integration, security, and performance tests
```

Local planning documents and proposal drafts are intentionally kept outside Git under `.local-docs/`.

## Requirements

For current development:

- Go 1.25 or newer (use a currently supported Go 1.25/1.26 toolchain)
- Node.js 24 LTS recommended; Node.js 22 LTS is also supported
- npm 10 or newer
- GNU Make
- clang, for the local BPF syntax check

For real kernel feature work:

- Linux kernel 5.15 or newer
- cgroup v2 enabled
- BTF available at `/sys/kernel/btf/vmlinux`
- Permission to load eBPF programs

The reproducible object build additionally fixes clang/llvm 18.x as its
supported compiler baseline. See [docs/bpf-build.md](docs/bpf-build.md).

Windows and macOS are fine for editing, Go unit tests, dashboard work, and the bootstrap syntax check. Real eBPF loading and runtime validation must happen on Linux.

## Quick Start

Install dashboard dependencies once:

```sh
cd dashboard
npm ci
cd ..
```

Run the current control-plane CLI:

```sh
go run ./cmd/agentshield version
go run ./cmd/agentshield health
go run ./cmd/agentshield diagnose
```

`diagnose` exits with status `1` whenever a required capability is failed **or still unknown**; warnings alone do not fail readiness. Until the planned active BPF load/attach probe exists, `bpf_permissions` remains `unknown`, so the current command also exits `1` on otherwise suitable Linux hosts. The JSON report distinguishes `unknown` from `fail`; this prevents automation from treating an incomplete probe as proof of readiness.

On a supported Linux build host, compile and inspect the real BPF object with:

```sh
make bpf-object
```

This produces ignored object and manifest artifacts; it does not load the
object into the kernel. Then start the unified audit loop with:

> **Safety warning:** the current probes are not cgroup-filtered. They observe matching
> syscalls from the whole host and print raw path/argv fragments that may contain
> secrets. Run this prototype only in an isolated VM or dedicated test host, never on
> a shared or production machine.

```sh
go run ./cmd/agentshield audit --bpf-object ./bpf/agentshield.bpf.o
```

This command attaches `syscalls/sys_enter_openat` and `syscalls/sys_enter_execve`, reads `agentshield_events`, and prints one JSON object per event. Run `./scripts/test-audit.sh` in another terminal to trigger both event types. See [docs/file-exec-audit.md](docs/file-exec-audit.md) for field semantics and current limitations. On non-Linux hosts the audit command exits with an unsupported-platform error.

The strict Day 14 verifier/load/attach and edge-case gate is
`sudo ./scripts/accept-file-exec.sh`; see
[docs/file-exec-acceptance.md](docs/file-exec-acceptance.md). Its status remains
pending until a supported isolated Linux host produces a passing evidence set.

Both probes run at syscall entry. Their events mean “attempt observed”; `action_result`
is `none`, not `allowed`, because the current program does not observe the syscall result.

## Checks

Run the Go and BPF bootstrap checks:

```sh
make generate
make verify-generated
make check-bpf-syntax
make check-linux-bpfmgr
make test
go vet ./...
make build
```

Or run the aggregate Go/BPF check:

```sh
make check
```

`make check` is non-mutating: it verifies that the checked-in generated binding
already matches the BPF source contents and SHA-256 values. Run `make generate`
explicitly after an intentional BPF source change.

Run the dashboard checks:

```sh
cd dashboard
npm run typecheck
npm run build
npm audit --audit-level=moderate --registry=https://registry.npmjs.org
```

The current P0 integration status is recorded in [docs/p0-integration-check.md](docs/p0-integration-check.md).

## Current eBPF Probe

The current BPF program includes:

- `tracepoint/syscalls/sys_enter_openat`
- `tracepoint/syscalls/sys_enter_execve`
- Event types: `AGENTSHIELD_EVENT_FILE_OPEN` and `AGENTSHIELD_EVENT_EXEC_ATTEMPT`
- Captured fields: pid, tgid, ppid, uid, comm, filename or executable, bounded argv, flags, timestamp, cgroup id placeholder
- Go consumer: `agentshield audit --bpf-object ./bpf/agentshield.bpf.o`
- Go event model: `internal/events.KernelEvent` with wire schema v2 and JSON schema v2

Day 8 intentionally does not filter by cgroup or PID yet; events record the observed cgroup ID, but it is not a security boundary until the later scope-filtering milestone. The timestamp is a kernel monotonic timestamp, not Unix epoch time. JSON schema v2 encodes `timestamp_ns` and `cgroup_id` as decimal strings so a future JavaScript client does not lose 64-bit precision; `wire_schema_version` independently identifies the BPF ABI (currently v2). Legacy v1 objects are rejected because the corrected attempt-result and argv-count semantics are not compatible.

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

Source milestones completed:

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
- Day 11: `execve` audit probe with executable, bounded argv, and parent pid capture
- Day 12: unified file/exec audit loop, trigger script, and tracepoint field notes

Days 8-12 have source and unit-test artifacts, but their Linux runtime acceptance is
still pending because the repository cannot yet build a real CO-RE object. They must
not be described as end-to-end verified.

Current gate:

- Validate file/exec end-to-end on a supported isolated Linux host before starting network work
- Publish a syscall/hook coverage matrix and sanitized runtime evidence

Subsequent work:

- Add network connection audit coverage
- Add cgroup filtering after the first audit loop is stable; PID-only scope remains a diagnostic Roadmap item

## Limitations

- The CO-RE build path must still be run on a supported Linux host; this Windows workspace cannot produce or load the object.
- The Linux unified `audit` runtime path is implemented but not end-to-end validated in this Windows workspace.
- Current file/exec records are syscall-entry attempts; they do not prove success or file contents read.
- Current audit output is host-wide and may contain sensitive path/argv fragments.
- The project does not yet enforce policies or block behavior.
- The project does not yet isolate Agent runs by cgroup.
- The dashboard currently uses mock data.
- The generated Go source binding embeds source text only; `make bpf-object` is the separate real ELF build.

## License

License information will be added before the first public release.
