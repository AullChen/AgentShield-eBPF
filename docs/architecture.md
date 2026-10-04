# Architecture

AgentShield prepares workloads in offline, resource-bounded containers, assigns a trusted Run identity, and connects local request checks with kernel observations. The design separates workload-supplied context from authority over task identity, approval, and lifecycle.

## Trust boundaries

| Component | Authority |
| --- | --- |
| Trusted supervisor | Prepares a stopped task, registers its exact cgroup leaf, releases execution, and confirms complete exit |
| Go Core | Owns registration identities, policy configuration, kernel maps, evidence storage, and management credentials |
| Docker launcher and trusted init | Establish offline network/filesystem/resource boundaries and release the application after registration |
| Local inspection checker | Validates full request bodies and trusted approvals, then records local preflight receipts |
| Agent and Python SDK | Submit descriptive checkpoints using a short-lived token for one Run |
| Kernel probes | Record observed syscall/connect attempts and synchronous TCP policy outcomes |
| Dashboard | Reads redacted evidence and diagnostics through authenticated APIs |

The management plane uses an owner-only Unix socket for registration, finish, and inspection approval. A separate workload socket exposes Run-authenticated checkpoint and local check routes. The trusted init relays container-loopback requests through an individual bind mount of that socket. Checkpoint TCP ingestion and read APIs retain separate listeners. The dashboard keeps its Core read token server-side and uses single-use tickets for browser WebSocket connections.

## Controlled workload boundary

`sandbox/container_launcher.py` implements the supervisor's `PreparedTask` interface for rootful Linux Docker. It selects an already installed immutable image, a root-owned static init, and an approved read-only project copy. The container uses `network=none`, UID/GID 65532, dropped capabilities, a read-only root filesystem, and bounded temporary storage.

The trusted init stops itself during preparation. The supervisor verifies its stopped threads, the held exact leaf, CPU/memory/swap/task-limit readback, and the read-only cgroupfs mount. A launch envelope containing Run credentials is delivered after registration. The application and ordinary stdio child processes then inherit the scope and container boundaries.

Docker's network namespace supplies IPv4/IPv6 TCP/UDP isolation, including during Core downtime. eBPF connect hooks independently supply TCP observation and configured tuple decisions. Timeout ends the container; trusted finish checks Docker exit state and held-leaf emptiness. See [controlled launch](controlled-launch.md).

## Identity and lifecycle

The supervisor holds a descriptor for a dedicated cgroup v2 leaf while its task is stopped. Core resolves the leaf's filesystem identity and independently checks the kernel cgroup ID through a short-lived `clone3(CLONE_INTO_CGROUP)` probe. Registration binds that ID to a Core `instance_id` and a fresh `scope_cookie` in the BPF scope map.

Each event carries the capture-time identity. The pair `{instance_id, scope_cookie}` resolves its Run; cgroup ID provides a further consistency check. This also distinguishes successive tasks when the kernel reuses a cgroup ID. A bounded tombstone retains attribution for delayed records after a Run ends.

Core protects its own cgroup and ancestor paths during registration and containment. The deployment gives cgroup hierarchy control to the supervisor and Core. The task receives its Run ID and checkpoint credential after successful registration.

At finish, the supervisor first observes root-task exit and an empty held leaf. Core removes the scope-map entry, ends the Run, and revokes its ingest credential. Agent `run_finished` messages remain descriptive checkpoints in the evidence timeline.

The monitor handles the interval between root exit and finish explicitly. A missing root PID plus `populated 0` read through the trusted held descriptor permits the Run to remain active. Child-cgroup checks continue; remaining members, live-root migration, and invalid state still fail inspection. Only trusted finish or the existing expiry path completes the Run lifecycle.

## Local request inspection

The init relay buffers the complete request up to 256 KiB, strips caller credentials, and binds the request to its own Run token. Core validates one strict JSON object, checks decoded strings for configured exact sensitive values and selected credential patterns, and applies route-specific rules.

MCP routes validate a `tools/call` body against a trusted definition-file digest, a tool allowlist, required string arguments, and path or exact-value rules. A trusted approval binds active Run, route, raw-body SHA-256, expiry, and one consumption. Content and tool rules run before the approval is consumed.

Per-Run attempt counts and checker-wide concurrent slots bound processing. Accepted approvals and check outcomes synchronously append minimal evidence to SQLite before success, then publish to the existing stream. These records use `local_inspection` under `policy_decision`, mechanism `local_preflight_only`, and `enforced=false`. Responses describe checks with `forwarded=false` and `executed=false`. See [local inspection](local-inspection.md).

## Kernel observation and enforcement

| Hook | Data | Meaning |
| --- | --- | --- |
| `sys_enter_openat` | Path fragment, flags, process and scope identity | File-open attempt |
| `sys_enter_execve` | Executable, bounded argv, truncation flags | Process-execution attempt |
| `cgroup/connect4` | IPv4 TCP destination and policy result | Connection attempt; synchronous rejection when blocked |
| `cgroup/connect6` | IPv6 TCP destination and policy result | Connection attempt; synchronous rejection when blocked |

Scope-map lookup occurs before ring-buffer reservation. The capture ABI includes version and size validation; public JSON encodes 64-bit identities and clocks as decimal strings. Per-type, per-CPU reserve-failure counters support loss diagnostics.

The TCP enforcement compiler produces exact address/port map entries for a default-deny profile. The hook decides whether to allow the connection synchronously, independently of successful audit-event delivery. File and exec tracepoints capture syscall entry; completion remains a separate event semantic.

IPv6 destination reads use four explicit 32-bit field accesses. Keeping each access tied to the original context pointer gives the verifier a valid access shape while preserving CO-RE field relocations. See [BPF build](bpf-build.md).

## Control-plane pipeline

`cmd/agentshield/managed.go` wires the registered runtime. The ring reader decodes kernel records and hands them to a 256-input queue shared with accepted checkpoints. A worker attributes events, evaluates policies, correlates checkpoints, and submits derived evidence. The reader has an independent raw JSONL output.

Policy matching operates on a compiled immutable generation. Trusted Run/cgroup/label context determines applicability; scope specificity, priority, and stable policy ID determine precedence. A final exec containment decision reaches the executor through the worker. The executor revalidates the registered identity and writes `1` to `cgroup.kill` relative to the held directory descriptor.

Kernel/checkpoint evidence uses a bounded asynchronous writer; each live subscriber also has a bounded queue. Storage uses SQLite/WAL, batching, retention limits, a circuit breaker, and a bounded recovery buffer. Local inspection uses the separate synchronous append path described above. Diagnostics expose ring loss, pipeline drops, storage state, and actual hook attachment. Filesystem and socket writes stay off the ring-reader path.

## Evidence semantics

The timeline keeps four sources:

1. `agent_claim`: the agent's account of its current step.
2. `kernel_fact`: an observed operation and any outcome supplied by its hook.
3. `policy_decision`: runtime matching/action information or an explicitly labeled local inspection receipt.
4. `containment_result`: the identity and outcome of a separate task-isolation action.

Correlation first establishes the Run from trusted identity, then scores recent same-Run checkpoints using tool semantics and server-monotonic proximity. Equal top candidates retain an explicit ambiguous result. Scores express heuristic association strength. [Correlation](correlation.md) describes the factors.

Redaction happens before records enter storage or broadcast queues. Managed evidence queries read SQLite by Run ID, including after a clean restart. They return bounded snapshots, with dangling checkpoint links removed when the referenced claim falls outside the snapshot.

## Source map

Follow `managed.go` → `internal/scope` and `internal/api/registration.go` → `bpf/agentshield.bpf.c` → `internal/bpfmgr` and `internal/events` → `internal/api/runtime_pipeline.go` → `internal/policy`, `internal/correlator`, `internal/killer` → `internal/store`, `internal/evidence`, and `internal/stream`.

For offline execution, follow `sandbox/container_launcher.py` → `sandbox/supervisor.py` → `cmd/sandbox-init`. For local checks, follow its relay → `internal/inspection` → `internal/api/inspection.go` → SQLite and the stream hub.

[Validation](validation.md) connects these mechanisms to the recorded experiments. [Development plans](roadmap.md) describe extensions and open evaluation questions.
