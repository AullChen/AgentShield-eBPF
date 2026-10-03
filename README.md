# AgentShield-eBPF

AgentShield-eBPF is a Linux eBPF based runtime security and audit system for AI Agent sandboxes.

The project is currently in early MVP development. The repository contains exact-leaf cgroup filtering and registration, file/process/network audit probes, a strict policy loader, a minimal demo sandbox, a reproducible Linux CO-RE object build, local diagnostics, and a Next.js dashboard. The managed `serve` entry connects checkpoints, correlation, SQLite evidence, and post-event containment. Supported-Linux runtime evidence, broader enforcement, general container supervision, and durable Run/history listing remain pending.

## Current Status

| Area | Status | Notes |
| --- | --- | --- |
| Go control plane | Started | `agentshield version`, `health`, and `diagnose` commands are available. |
| Environment diagnostics | Started | Validates the minimum kernel and supported little-endian architectures; reports BPF load permission as unknown until a real syscall probe exists. |
| eBPF source layout | Started | `bpf/agentshield.bpf.c`, `events.h`, and `maps.h` exist. |
| File audit probe | Started | `tracepoint/syscalls/sys_enter_openat` emits a file-open event shape. |
| Process audit probe | Started | `tracepoint/syscalls/sys_enter_execve` captures executable and bounded argv summaries. |
| Network audit/enforcement | Source complete, Linux evidence pending | Explicit-cgroup `connect4/connect6` hooks audit TCP and can synchronously block tuples absent from one exact-host/port default-deny profile. |
| BPF build flow | Implemented, Linux evidence pending | `make bpf-object` compiles a CO-RE ELF and records object/BTF hashes, exact tool versions, and parsed program/map specs. |
| Dashboard | P5 source complete, Linux evidence pending | Overview, Live Trace, evidence detail, loaded policies, and actual-process diagnostics use authenticated read APIs without mock fallback; durable history remains pending. |
| Runtime BPF loading | Started | `agentshield audit` loads a compiled BPF object and attaches file/exec probes on Linux. |
| Ring buffer consumption | Started | `audit` decodes file, process, and network ring-buffer events and emits Go-synthesized loss notices as JSON schema v2 Lines. |
| Audit reliability | Source complete, Linux saturation pending | Per-type per-CPU reserve failures become Go-synthesized `drop_notice` records; SIGINT/SIGTERM close and join the reader/monitor path. |
| Kernel Event v3 | Started | Go-side decoding validates schema/size, preserves all 64-bit scope/time identities as JSON strings, adds receipt calibration, and rejects incompatible wire schemas. |
| cgroup scoping | P2 source gate complete, Linux evidence pending | Exact-leaf registration, finish/TTL tombstones, ID reuse isolation, Core self-protection, and host-negative filtering have automated coverage. |
| Policy engine | P3 source gate complete, runtime pending | `make test-p3` distinguishes audit, alert, synchronous block, and post-event containment; failed A/B attempts retain the active generation and the reporting updater exposes structured failure data. Concrete BPF activation, persistence, policy CRUD, and Linux evidence remain pending. |
| Fallback containment | Managed dispatch source complete, Linux evidence pending | `serve` runs the coordinator in a bounded worker and revalidates exact scope/Core identity before descriptor-relative `cgroup.kill`, with a separate result. Standalone `audit` does not contain. |
| Checkpoint ingest | Managed integration source complete, Linux evidence pending | The isolated Run-scoped endpoint binds Bearer tokens to the route, records calibrated receipt clocks, and hands off once before sequence acknowledgement. Agent `run_finished` remains non-authoritative. |
| Agent SDK/supervisor | Source examples complete | The Python client exposes only checkpoint writes; the trusted supervisor keeps management on an owner-only Unix socket and requires registered-scope identity plus complete leaf exit before finish. Production task adapters are pending. |
| Event store | Managed integration source complete, Linux evidence pending | SQLite/WAL receives sanitized checkpoint/kernel/decision/containment payloads; bounded per-Run queries survive reopen. Durable Run listing and active recovery are pending. |
| Correlation | Managed integration source complete, Linux evidence pending | Instance/cookie identity resolves the Run first; bounded same-Run checkpoints are scored by tool semantics and server-monotonic proximity. Equal candidates remain explicitly ambiguous. |
| Evidence timeline | Managed integration source complete, Linux evidence pending | Evidence separates Agent claims, kernel facts, policy decisions, synchronous block, and post-event containment with attribution and correlation rationale. |
| Realtime stream | Audit integration source complete, Linux evidence pending | The optional loopback audit API adds redacted JSON fan-out, decimal-string cursors, one-time browser tickets, bounded recovery, and slow-client isolation. Durable snapshot/history is pending. |
| Isolated demo | Source complete, Linux evidence pending | `scripts/demo.sh` joins the host Core, loopback Compose Dashboard, and a gated unprivileged Sandbox using only the repository fake secret; a pass proves only the standalone audit path. |

## MVP Direction

The MVP is scoped around this path:

1. Register a controlled AI Agent sandbox by cgroup v2.
2. Capture file, process, and network events with eBPF.
3. Consume kernel events in a Go control plane.
4. Match events against runtime security policies.
5. Correlate Agent checkpoints with kernel events.
6. Display live evidence chains in a web dashboard.

The repository now has deterministic source gates and a guarded standalone
audit demo harness, but no reviewed supported-Linux end-to-end evidence is
checked in. It is not a production sandbox or complete enforcement tool.

## Repository Layout

```text
bpf/                 eBPF programs, maps, and shared event definitions
cmd/agentshield/     Go control-plane CLI entrypoint
cmd/dashboardcheck/  Deterministic non-kernel P5 browser acceptance fixture
cmd/bpfgen/          Local BPF source binding generator
internal/            Go internal packages
dashboard/           Next.js dashboard scaffold
sdk/python/          Checkpoint-only Python Agent adapter SDK
sandbox/             Minimal hardened demo Agent and repository-owned fake secret
deploy/              Isolated demo Compose assets (not production deployment)
configs/             Runtime and policy configuration examples
docs/                Public project documentation
scripts/             Developer, acceptance, release, and demo helpers
tests/               Integration, security, and performance test layout
```

Local planning documents and proposal drafts are intentionally kept outside Git under `.local-docs/`.

For the registered runtime entry, separated management/ingest/read surfaces,
durable per-Run evidence, and isolated acceptance fixture, see
[docs/managed-runtime.md](docs/managed-runtime.md).

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

The complete standalone demo is intentionally separate from this
cross-platform quick start. On a disposable supported Linux VM, follow
[docs/demo-guide.md](docs/demo-guide.md) and run:

```sh
sudo ./scripts/demo.sh --isolated-vm
```

Do not run it on a workstation or with a real host secret.

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
make check-linux-killer
make check-linux-api
make test
make test-p2
make test-checkpoint
make test-sdk
make test-supervisor
go test ./internal/store
go test ./internal/correlator
go test ./internal/evidence -run '^TestP4Acceptance$'
go test ./internal/stream
go test ./cmd/dashboardcheck
go vet ./...
make build
```

Or run the aggregate Go/BPF check:

```sh
make check
```

The Makefile defaults `CLANG=clang-18` to match the supported CO-RE baseline.
On a non-Linux editing host where the same compiler is installed only as
`clang`, use `make check CLANG=clang`; that remains a source/cross-build gate,
not a real BPF object or kernel acceptance.

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

On a clean, disposable supported Ubuntu VM, the final automated source,
dependency, build, and three-event demo gate is:

```sh
sudo make release-check
```

It requires `govulncheck` and network access to the official npm audit endpoint.
A pass still does not choose a license, review raw evidence, or replace the
manual real-Dashboard screenshot review described in the local test guide.

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

The dashboard exposes these App Router pages:

- Overview
- Live Trace
- Policies
- History
- Diagnostics

Overview, evidence detail, Policies, and Diagnostics read authenticated
control-plane snapshots. Live Trace obtains a same-origin one-time ticket and
connects to `/api/v1/stream`; the bearer token remains server-only in
`AGENTSHIELD_READ_TOKEN`. History currently indexes Runs in the bounded live
recovery window and does not claim durable SQLite queries. See
[docs/dashboard-overview.md](docs/dashboard-overview.md),
[docs/dashboard-live-trace.md](docs/dashboard-live-trace.md), and
[docs/p5-dashboard-integration.md](docs/p5-dashboard-integration.md).

Start it locally with:

```sh
cd dashboard
npm run dev
```

Set the three server-side values documented in `dashboard/README.md` to connect
to the optional loopback API exposed by `agentshield audit`. The guarded demo
does this automatically. Durable history and production control-plane fan-in
remain pending.

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
- Day 34: independent exact-scope `cgroup.kill` containment executor with Core
  self-protection, reuse-safe authorization, and separate result semantics
- Day 35: trusted Run-aware policy/containment coordination, four-semantics P3
  source gate, structured update failures, and an A/B recovery primitive
- Day 36: isolated Run-scoped checkpoint ingest with token binding, calibrated
  receipt clocks, strict limits, atomic replay, and non-authoritative finish claims
- Day 37: checkpoint-only Python client plus a separate trusted supervisor
  contract for register, exact-leaf exit confirmation, and finish
- Day 38: SQLite/WAL evidence store with pre-queue redaction, bounded fan-out,
  capacity controls, drop diagnostics, and circuit recovery
- Day 39: deterministic two-stage Run attribution and within-Run checkpoint
  correlation with explicit factors, conflict reporting, and 0–100 clamping
- Day 40: P4 evidence timeline schema, tracked JSON sample, provenance and
  attribution/correlation rationale, with syscall/block/containment separation
- Day 41: authenticated resumable WebSocket stream, single-use browser ticket,
  bounded recovery history, filters, and slow-client isolation
- Day 42: authenticated Overview snapshot API and dashboard Run/count/
  capability rendering without mock fallback
- Day 43: redacted audit-to-WebSocket bridge and bounded Live Trace with
  run/severity/type filters and string-safe `u64` formatting
- Day 44: bounded evidence detail API and five-column provenance UI with
  explicit attempt-versus-outcome and correlation limits
- Day 45: loaded policy catalog and read-only refresh with generation and
  enabled-state visibility
- Day 46: process diagnostics with architecture/byte order, environment checks,
  actual Go load/attach state, hooks, generation, and per-type drops
- Day 47: deterministic P5 replay plus production-mode desktop/mobile browser
  acceptance across the complete dashboard flow
- Day 48: guarded isolated demo orchestration for host Core, Compose Dashboard,
  and a fake-secret Sandbox; supported-Linux execution remains pending
- Day 49: demo, troubleshooting, support/coverage, and release-boundary docs
- Day 50: reproducible release-check harness and Roadmap; clean Linux evidence,
  screenshots, dependency review, and the owner-selected license remain gates

Current gate:

- Run `make test-p3` on any development host for the P3 source semantics and
  update/recovery contract. This is not Linux runtime evidence.
- Run `make accept-p1` on a supported isolated Linux host. This one command
  rebuilds the object and binary, then invokes `scripts/accept-p1.sh`; running
  `make bpf-object` followed by the script directly is the equivalent manual path.
- Preserve environment/toolchain/object hashes and sanitized runtime evidence.
- The current P1 combined gate requires file, exec, IPv4, and IPv6 evidence;
  use the narrower file/exec script only for diagnosis. Final MVP requires all
  three event classes and must not turn a network failure into a partial pass.

Subsequent work:

- Follow [docs/support-matrix.md](docs/support-matrix.md) for current claims and
  [docs/roadmap.md](docs/roadmap.md) for the ordered release/runtime backlog.
- Use [docs/troubleshooting.md](docs/troubleshooting.md) without weakening an
  exact-scope, authentication, or evidence-integrity check to force a pass.

## Limitations

- The CO-RE build path must still be run on a supported Linux host; this Windows workspace cannot produce or load the object.
- The Linux unified `audit` runtime path is implemented but not end-to-end validated in this Windows workspace.
- The tracked P1 coverage matrix is a pending source matrix, not Linux runtime evidence; see [docs/p1-coverage.md](docs/p1-coverage.md).
- Current file/exec records are syscall-entry attempts; they do not prove success or file contents read.
- Current exact-scope audit output may still contain sensitive path/argv fragments from the registered sandbox.
- Only the exact-tuple TCP cgroup network path has synchronous block source;
  its Linux evidence is pending. File/exec matching remains post-event. The
  trusted containment coordinator is connected to the managed `serve` worker,
  but real Linux acceptance is pending; standalone `audit` does not contain.
- A/B recovery is currently an abstract `BankStore` contract. There is no
  concrete persistent eBPF bank, persistent policy bundle, unified kernel/user
  activation transaction, or raw-event generation field, so process restart
  and block hot-update recovery are not claimed.
- Checkpoint replay state remains bounded and in memory. `serve` hands accepted
  claims to the asynchronous evidence writer; acknowledgement is not an fsync
  guarantee. Restart-safe checkpoint idempotency is not claimed.
- The Day 37 supervisor is a tested orchestration contract, not a production
  container adapter. A concrete stopped Linux acceptance fixture now exists;
  a general adapter must hold the exact-leaf descriptor,
  verify registration identity, and observe the root workload exit plus an
  empty leaf before management finish.
- The source enforces exact-leaf cgroup capture, but supported-Linux runtime evidence is still pending.
- Dashboard read APIs and P5 browser integration are source-complete, but
  supported-Linux runtime evidence and durable Run listing/resync remain
  pending. `serve` provides bounded SQLite evidence by saved Run ID; the
  deterministic `dashboardcheck` replay is explicitly not kernel proof.
- The generated Go source binding embeds source text only; `make bpf-object` is the separate real ELF build.

## License

No repository license has been selected. The eBPF program's `Dual MIT/GPL`
kernel declaration does not license the repository as a whole. The repository
owner must add an explicit license before public release or redistribution;
this is a release blocker, not an implied license grant.
