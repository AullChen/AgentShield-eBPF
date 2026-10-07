# Development plans

The controlled x86_64 Linux 6.8 workflow has been validated for offline Docker execution, local model/MCP inspection, trusted registration and finish, kernel observation, TCP enforcement, containment, and persistent evidence. Planned work covers reliability under load and support for more environments.

## Reliability and security maintenance

- Reproduce the initial Linux 7.0 event-delivery and containment failure with the Ubuntu-built object, retaining evidence from both the failure and its successful unchanged rerun. Instrument exec-event delivery and dispatch to explain the missed containment before extending the operating baseline.
- Resolve the recorded npm audit findings (nine affected package entries: one critical, seven high, one moderate), then repeat build, browser, and vulnerability checks. Re-run Go vulnerability scanning with the selected release toolchain. These findings come from the recorded audit snapshot; affected-package counts can include propagation through transitive dependencies.
- Measure event throughput, ring reserve failures, queue loss, CPU/memory overhead, storage growth, and tail latency under controlled workload rates. Exercise shutdown and storage recovery during sustained load.

## Durable lifecycle and history

- Persist the Run catalog and add paginated History queries. Current SQLite evidence survives restart and is accessible through a saved Run ID; the Overview/History list is in memory.
- Define restart recovery for active tasks, credentials, checkpoint replay state, and scope reconciliation. The operating procedure currently finishes workloads before stopping Core.
- Define restart semantics for pending approvals and inspection-attempt counters, which currently live in memory. Prepare new containers after restart to bind the new workload-socket inode.
- Persist stream cursors and implement durable snapshot/resync. Live recovery currently uses a bounded in-memory window.

## Policy and runtime integration

- Add policy CRUD, hot reload, and a persistent implementation of the tested A/B activation contract. Runtime policies currently load at startup, with one global synchronous TCP profile.
- Extend the validated [rootful Docker adapter](controlled-launch.md) to additional platform and identity-mapping configurations while preserving stopped-before-registration, protected init/source inputs, resource-limit readback, and complete-leaf-exit invariants.
- Add approved editable work-copy export. The current adapter mounts source read-only and provides bounded temporary storage for task-created files.
- Extend eBPF observation/enforcement coverage to UDP and Unix sockets, `execveat`, and suitable synchronous file/process hooks. Offline container network isolation already covers IPv4/IPv6 TCP/UDP external traffic; kernel event coverage remains file/exec attempts and TCP connects.
- Evaluate subtree registration separately from the current exact-leaf model, with explicit identity and delegation rules.

## Inspection and executor integration

- Integrate trusted remote model forwarding and MCP backend execution with a clearly specified approval-to-execution boundary. Current endpoints return local preflight receipts; they are neither model-provider API replacements nor complete MCP protocol proxies.
- Expand MCP transport and schema coverage beyond a single `tools/call` body and configured string-argument rules. Add authenticated live definition discovery, backend filesystem/symlink enforcement, and isolation for shared or privileged MCP services. Current pins describe trusted local snapshots.
- Extend sensitive-content evaluation beyond exact configured values and selected credential/private-key patterns. Test fragments, encodings, transformations, and false positives using a labeled corpus.
- Add model output/token/cost accounting and tool-execution budgets. Existing limits count local inspection attempts per Run and simultaneous checks across the checker.

## Portability and presentation

- Run native ARM64 and additional kernel/toolchain combinations; current runtime evidence covers x86_64 guests on the recorded 6.8 and 7.0 kernels.
- Improve narrow-screen evidence layout and add long-path regression fixtures. The recorded 390 px view overflowed by 237 px; the current presentation target is desktop.
- Package a reproducible kernel lab with pinned guest images and dependencies, and publish reviewed evidence bundles for subsequent releases.

## Research evaluation

Build a labeled workload corpus to evaluate checkpoint association precision, recall, and ambiguity as concurrency and checkpoint delay vary. Compare attribution by PID, cgroup ID, and instance/cookie identity under reuse and delayed delivery. Measure synchronous TCP rejection, local inspection latency, and event-to-containment latency separately. Evaluate offline isolation with positive-control receivers across launch, timeout, and Core-stop transitions.
