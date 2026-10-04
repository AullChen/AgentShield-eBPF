# Development plans

The demonstrated baseline is the controlled x86_64 Linux 6.8 workflow: trusted registration, scoped observation, TCP enforcement, post-event containment, and persistent per-Run evidence. The next work extends its operating range and measures its behavior under load.

## Reliability and security maintenance

- **Linux 7.0 event delivery and containment:** retain and reproduce the initial Ubuntu-built-object failure alongside its successful unchanged rerun. Instrument exec-event delivery and dispatch to explain the missed containment before extending the operating baseline.
- **Dependency maintenance:** resolve the recorded npm audit findings (nine affected package entries: one critical, seven high, one moderate), then repeat build, browser, and vulnerability checks. Re-run Go vulnerability scanning with the selected release toolchain. Findings are tied to the recorded audit snapshot; affected-package counts can include propagation through transitive dependencies.
- **Load and soak evaluation:** measure event throughput, ring reserve failures, queue loss, CPU/memory overhead, storage growth, and tail latency under controlled workload rates. Exercise shutdown and storage recovery during sustained load.

## Durable lifecycle and history

- Persist the Run catalog and add paginated History queries. Current SQLite evidence survives restart and is accessible through a saved Run ID; the Overview/History list is in memory.
- Define restart recovery for active tasks, credentials, checkpoint replay state, and scope reconciliation. The operating procedure currently finishes workloads before stopping Core.
- Persist stream cursors and implement durable snapshot/resync. Live recovery currently uses a bounded in-memory window.

## Policy and runtime integration

- Add policy CRUD, hot reload, and a persistent implementation of the tested A/B activation contract. Runtime policies currently load at startup, with one global synchronous TCP profile.
- Validate the initial [offline single-container adapter](controlled-launch.md) on a dedicated rootful Linux/Docker host, then extend production platform coverage while preserving stopped-before-registration and complete-leaf-exit invariants. The new adapter has unit/cross-build coverage, not yet real-container acceptance evidence.
- Integrate trusted model/MCP executors with the [local-only inspection checker](local-inspection.md). External forwarding and backend execution are intentionally absent in this increment; a check receipt alone is not an enforcement boundary. Extend protocol coverage, approved editable work-copy export, model output/cost budgets and backend isolation only with scoped acceptance tests.
- Extend coverage to UDP and Unix sockets, `execveat`, and suitable synchronous file/process enforcement hooks. Current `openat`/`execve` tracepoints record entry attempts, and containment follows the event.
- Evaluate subtree registration separately from the current exact-leaf model, with explicit identity and delegation rules.

## Portability and presentation

- Run native ARM64 and additional kernel/toolchain combinations; current runtime evidence covers x86_64 guests on the recorded 6.8 and 7.0 kernels.
- Improve narrow-screen evidence layout and add long-path regression fixtures. The recorded 390 px view overflowed by 237 px; the current presentation target is desktop.
- Package a reproducible kernel lab with pinned guest images and dependencies, and publish reviewed evidence bundles for subsequent releases.

## Research evaluation

Build a labeled workload corpus to evaluate checkpoint association precision, recall, and ambiguity as concurrency and checkpoint delay vary. Compare attribution by PID, cgroup ID, and instance/cookie identity under reuse and delayed delivery. Measure synchronous TCP rejection separately from event-to-containment latency. These experiments would quantify the design choices already represented in the implementation.
