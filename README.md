# AgentShield-eBPF

AgentShield-eBPF is a Linux eBPF based runtime security and audit system for AI Agent sandboxes.

The project is currently in early MVP development. The repository contains the Go control-plane skeleton, exact-leaf cgroup filtering and registration, file/process/network audit probes, a minimal demo sandbox, a reproducible Linux CO-RE object build, local diagnostics, and a Next.js dashboard scaffold. Kernel load/attach evidence, policy enforcement, event correlation, and live dashboard streaming are still under development.

## Current Status

| Area | Status | Notes |
| --- | --- | --- |
| Go control plane | Started | `agentshield version`, `health`, and `diagnose` commands are available. |
| Environment diagnostics | Started | Validates the minimum kernel and supported little-endian architectures; reports BPF load permission as unknown until a real syscall probe exists. |
| eBPF source layout | Started | `bpf/agentshield.bpf.c`, `events.h`, and `maps.h` exist. |
| File audit probe | Started | `tracepoint/syscalls/sys_enter_openat` emits a file-open event shape. |
| Process audit probe | Started | `tracepoint/syscalls/sys_enter_execve` captures executable and bounded argv summaries. |
| Network audit probe | Source complete, Linux evidence pending | Explicit-cgroup `connect4/connect6` hooks emit TCP destination IP/port/family and always allow. |
| BPF build flow | Implemented, Linux evidence pending | `make bpf-object` compiles a CO-RE ELF and records object/BTF hashes, exact tool versions, and parsed program/map specs. |
| Dashboard | Scaffolded | Next.js App Router pages exist with mock data. |
| Runtime BPF loading | Started | `agentshield audit` loads a compiled BPF object and attaches file/exec probes on Linux. |
| Ring buffer consumption | Started | `audit` decodes file, process, and network ring-buffer events and emits Go-synthesized loss notices as JSON schema v2 Lines. |
| Audit reliability | Source complete, Linux saturation pending | Per-type per-CPU reserve failures become Go-synthesized `drop_notice` records; SIGINT/SIGTERM close and join the reader/monitor path. |
| Kernel Event v3 | Started | Go-side decoding validates schema/size, preserves all 64-bit scope/time identities as JSON strings, adds receipt calibration, and rejects incompatible wire schemas. |
| cgroup scoping | Source complete, Linux evidence pending | Scope-map lookup precedes ring-buffer reserve; trusted registration rejects duplicate/subtree bindings and monitors child cgroups and member escape. |
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
sandbox/             Minimal hardened demo Agent and repository-owned fake secret
deploy/              Future local deployment files
configs/             Runtime and policy configuration examples
docs/                Public project documentation
scripts/             Developer helpers; currently includes the audit trigger
tests/               Future integration, security, and performance tests
```

Local planning documents and proposal drafts are intentionally kept outside Git under `.local-docs/`.

## Requirements

For current development:

- Go 1.25.12+, Go 1.26.5+, or a newer supported release
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

> **Safety warning:** raw scoped events still contain bounded path/argv fragments
> that may contain secrets. Use only a trusted exact leaf cgroup and retain raw
> evidence as owner-only data.

```sh
go run ./cmd/agentshield audit \
  --bpf-object ./bpf/agentshield.bpf.o \
  --scope-cgroup /sys/fs/cgroup/agentshield-demo-leaf
```

This command registers the trusted leaf in `agentshield_scope_map`, attaches the
file/exec tracepoints and connect hooks, then prints only matching events. A map
miss returns before ring-buffer reservation. See
[docs/cgroup-scope-acceptance.md](docs/cgroup-scope-acceptance.md) for the
boundary and current evidence status.

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
- `cgroup/connect4` and `cgroup/connect6` when an explicit cgroup path is supplied
- Event types: `AGENTSHIELD_EVENT_FILE_OPEN`, `AGENTSHIELD_EVENT_EXEC_ATTEMPT`, and `AGENTSHIELD_EVENT_NET_CONNECT`
- Captured fields: pid, tgid, ppid, uid, comm, filename or executable, bounded argv, flags, timestamp, and binary cgroup/instance/cookie scope identity
- Go consumer: `agentshield audit --bpf-object ... --scope-cgroup ...`
- Go event model: `internal/events.KernelEvent` with wire schema v3 and JSON schema v2

`kernel_monotonic_ns` is the authoritative kernel event time, while Go adds
same-host receipt monotonic/Unix fields and a calibration error bound. JSON
schema v2 encodes time, cgroup ID, instance ID, and scope cookie as decimal
strings; `wire_schema_version` independently identifies the v3 BPF ABI.

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
still pending. Day 13-17 add the real CO-RE build, automated kernel gate,
connect4/connect6 source, drop/time reliability, and combined coverage harness,
but this Windows snapshot cannot execute the Linux verifier/load/attach gate.
They must not be described as end-to-end verified.

Additional source milestones:

- Day 13: reproducible clang 18 CO-RE build and parsed object/hash manifest
- Day 14: automated file/exec verifier, attach, empty-argv, truncation, and ABI gate
- Day 15: explicit-cgroup TCP connect4/connect6 audit source and Go decoding
- Day 16: per-type per-CPU drop stats, synthesized notices, calibrated receipt clocks, and SIGTERM shutdown
- Day 17: single-run P1 pre-M1 acceptance harness and sanitized coverage matrix

Current gate:

- Run `make accept-p1` on a supported isolated Linux host. This one command
  rebuilds the object and binary, then invokes `scripts/accept-p1.sh`; running
  `make bpf-object` followed by the script directly is the equivalent manual path.
- Preserve environment/toolchain/object hashes and sanitized runtime evidence.
- Require file and exec as the two P1 pre-M1 baseline classes. Network is the
  optional third class and is stable only when both IPv4 and IPv6 pass. Final
  MVP still requires all three classes.

Subsequent work:

- Obtain supported-Linux connect4/connect6 runtime evidence and later extend
  network coverage beyond TCP IPv4/IPv6
- Obtain supported-Linux exact-scope and Docker sandbox runtime evidence

## Limitations

- The CO-RE build path must still be run on a supported Linux host; this Windows workspace cannot produce or load the object.
- The Linux unified `audit` runtime path is implemented but not end-to-end validated in this Windows workspace.
- The tracked P1 coverage matrix is a pending source matrix, not Linux runtime evidence; see [docs/p1-coverage.md](docs/p1-coverage.md).
- Current file/exec records are syscall-entry attempts; they do not prove success or file contents read.
- Current exact-scope audit output may still contain sensitive path/argv fragments from the registered sandbox.
- The project does not yet enforce policies or block behavior.
- The source enforces exact-leaf cgroup capture, but supported-Linux runtime evidence is still pending.
- The dashboard currently uses mock data.
- The generated Go source binding embeds source text only; `make bpf-object` is the separate real ELF build.

## License

License information will be added before the first public release.
