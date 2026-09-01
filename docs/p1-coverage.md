# P1 pre-M1 Coverage Gate

Repository status: **source gate implemented; Linux runtime acceptance pending**.
The current Windows host has no installed WSL distribution, its clang 11 build
has no BPF target, and the Docker daemon is unavailable. Therefore this
snapshot contains no legitimate verifier/load/attach or capture evidence and
must not be labeled P1 runtime accepted.

## Current matrix

| Event path | Source/unit status | Runtime evidence | Fallback/Roadmap |
| --- | --- | --- | --- |
| `openat` file attempt | Implemented; decoder/edge tests pass | Pending supported isolated Linux | No silent fallback |
| `execve` process attempt | Implemented; empty argv/truncation tests pass | Pending supported isolated Linux | `execveat` Roadmap |
| TCP IPv4 `connect4` | Implemented; Go IPv4 decode passes | Pending supported isolated Linux cgroup | A verifier, attach, or capture failure fails this combined gate |
| TCP IPv6 `connect6` | Implemented; Go IPv6 decode passes | Pending supported isolated Linux cgroup | A verifier, attach, or capture failure fails this combined gate |
| `openat2` | Not implemented | Not covered | Roadmap |
| `execveat` | Not implemented | Not covered | Roadmap |
| UDP / `AF_UNIX` | Not implemented | Not covered | Roadmap |

## Reproducible acceptance

The script rejects non-Ubuntu-24.04 hosts, kernels older than 5.15,
unsupported architectures, missing BTF, non-cgroup-v2 systems, non-root users,
and object/manifest mismatches. Use either the one-command target:

```sh
make accept-p1
```

or its equivalent manual sequence:

```sh
make bpf-object
sudo ./scripts/accept-p1.sh
```

The script requests file/exec plus connect4/connect6 in one collection. A
network verifier, attach, or capture failure fails the combined gate; it does
not silently retry a narrower collection. Use `scripts/accept-file-exec.sh` to
diagnose the narrower tracepoint path, without describing that result as P1 or
network acceptance. The combined script triggers file/exec/TCP IPv4/TCP IPv6,
terminates the reader with SIGTERM, and validates attempt semantics, empty argv,
truncation, exact destinations, JSON/wire schemas, and non-negative calibrated
receipt timing.

Each invocation atomically creates a distinct owner-only directory under
ignored `tmp/acceptance/day17/`, including for concurrent runs. Its evidence
includes:

- distribution, kernel/config subset, BTF availability, architecture;
- BPF object and manifest hashes plus verified object/manifest correspondence;
- reproduction commands and Go ABI/robustness test output;
- runtime/verifier/attachment log;
- raw exact-scope JSON Lines (never commit because paths/argv may be sensitive);
- sanitized summary and coverage matrix.

The current combined gate passes only with file, exec, IPv4, and IPv6 evidence,
reported as three stable event classes. Forced ring-buffer saturation and
kernel drop aggregation are a separate pending Day 16 Linux reliability test,
not implied by a Day 17 pass.

This is not the formal M1 scope boundary. Day 18-25 must still add exact
leaf-cgroup filtering, host-negative evidence, and lifecycle/reuse tests. Final
MVP event coverage requires file + exec + network, and the complete MVP also
requires policy/enforcement, correlation, persistence, and live Dashboard
paths described in the root README.

The script only writes owner-only ignored evidence. It never changes this
tracked file or Git status. After a reviewer validates the sanitized summary
and matrix, a maintainer must update public acceptance claims explicitly.
