# Support and coverage matrix

This matrix distinguishes implemented source, deterministic tests, and actual
kernel evidence. “Pending” is not a degraded form of “verified.”

## Environment baseline

| Area | Supported baseline | Other environments |
| --- | --- | --- |
| Real CO-RE build/load/demo | Ubuntu 24.04, kernel 5.15+, little-endian x86_64 or arm64, cgroup v2, readable `/sys/kernel/btf/vmlinux`, clang/LLVM 18.x, bpftool, Docker Compose v2 | Not claimed. Preserve failures as evidence rather than expanding the support statement. |
| Go source checks | Versions listed in `go.mod` and [bpf-build.md](bpf-build.md) | Windows/macOS may run unit tests but cannot establish eBPF runtime support. |
| Dashboard | Node.js 24 LTS recommended; Node.js 22 LTS supported; npm 10+ | Node.js 20 and older are outside the project baseline. |
| Browser fixture | Playwright/Chromium supplied by the test environment; the repository does not yet declare a pinned installation | This is deterministic UI/API evidence, not kernel evidence; a clean-host run is `NOT RUN` until a reproducible dependency entry is added. |

No supported-Linux release evidence is checked into this repository yet.
Execute the procedures in the local test guide and review their outputs before
changing that statement.

## Capability coverage

| Capability | Source/test state | Linux runtime state | Boundary or degradation |
| --- | --- | --- | --- |
| Exact-leaf file `openat` attempt | Implemented and unit tested | Pending supported-host evidence | A record proves an attempt, not success or contents read. |
| Exact-leaf `execve` attempt | Implemented and unit tested | Pending supported-host evidence | Executable/argv are bounded and may be truncated; `execveat` is not covered. |
| TCP IPv4/IPv6 connect attempt | Implemented and unit tested | Pending supported-host evidence | UDP, Unix sockets, DNS semantics, and non-TCP protocols are not covered. |
| Ring-buffer loss accounting | Per-type counters and synthetic notices implemented | Saturation evidence pending | Reserve failure is fail-open for observation and must surface as a drop notice when readable. |
| Policy audit/alert | Deterministic policy tests and standalone audit integration implemented | Pending supported-host evidence | Evaluation is post-event and cannot prevent file/exec syscalls. |
| Synchronous network block | Exact-tuple/default-deny source gate implemented | Pending privileged acceptance | Unsupported/missing network enforcement must not be described as blocked. |
| Post-event containment | Exact-scope executor/coordinator and managed bounded dispatch implemented | Linux evidence pending | Standalone audit does not invoke `cgroup.kill`; a hint is not an outcome. |
| Registration and lifecycle | Exact-leaf identity, TTL, finish, reuse, and managed entry implemented | Real identity probe/fixture pending; general container adapter absent | Agent `run_finished` is non-authoritative. |
| Checkpoint ingest | Auth/token/replay/limit tests and managed store handoff implemented | Linux acceptance pending | Acknowledgement is not an fsync guarantee; replay state is bounded and in memory. |
| SQLite evidence store | Managed fan-in, bounded per-Run reads/reopen, redaction, queue/capacity, gap, and circuit tests implemented | Linux acceptance pending | Store failure does not stop kernel auditing but creates an explicit evidence gap. |
| Correlation/timeline | Attribution, scoring, provenance tests and managed worker implemented | Linux acceptance pending | Time proximity is not causal proof; checkpoint candidates are bounded. |
| Dashboard live views | Authenticated APIs/UI and deterministic browser gate implemented | End-to-end Linux evidence pending | `serve` evidence detail is SQLite-backed; History Run listing and WebSocket recovery remain in memory. |
| Isolated demo orchestration | Compose and guarded host script implemented | Must be run and reviewed on the supported VM | Demonstrates standalone audit only; it is not a production supervisor. |

## Security and operational semantics

- Exact cgroup scope is mandatory. Missing map entries produce no scoped event;
  subtree and symlinked paths are rejected.
- File/exec observation and ring-buffer evidence are fail-open. Event loss is
  reported separately; it is never rewritten as a successful allow decision.
- Only a matching attached cgroup network hook can synchronously block, and its
  record must say `action_result=blocked`. Policy `deny`, `alert`, and
  `containment_hint` alone are not enforcement outcomes.
- Raw evidence can contain bounded paths and argv fragments. Runtime scripts
  use owner-only directories, but operators must still review before sharing.
- Dashboard bearer tokens remain server-side; browser access uses a separate
  Basic-auth token. The demo binds both Core and Dashboard to loopback.
- Store, stream, and checkpoint limits deliberately shed or reject work with
  explicit errors/gaps instead of allowing unbounded memory or disk growth.

## Release blockers

The repository is not ready to claim a public MVP release until all of these
are resolved with real evidence:

1. supported-Linux build, demo, and three-event capture pass;
2. privileged network-block and containment acceptance, or explicit removal
   of those capabilities from the MVP claim;
3. real-host managed lifecycle/checkpoint/store/correlation acceptance, plus a
   documented boundary for durable Run listing and crash reconciliation;
4. dependency audit reviewed with no unresolved high-severity finding;
5. repository owner selects and adds a project license;
6. sanitized screenshots and hashes are reviewed without publishing secrets.
