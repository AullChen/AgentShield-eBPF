# docs

Public project documentation belongs here.

Current notes:

- `audit-reliability.md`: Day 16 per-type drop counters, Go-synthesized loss
  notices, double-clock receipt fields, and shutdown/failure semantics.
- `agent-registration.md`: trusted Agent Run registration contract, identity
  ownership, and short-lived ingest tokens.
- `bpf-build.md`: supported CO-RE toolchain, BTF provenance, object manifest,
  and ELF/spec versus kernel-load acceptance boundary.
- `cgroup-scope-acceptance.md`: exact-leaf positive/host-negative gate,
  subtree rejection, and escape monitoring.
- `containment.md`: Day 34 exact-scope `cgroup.kill` fallback executor,
  identity revalidation, Core self-protection, and result semantics.
- `file-exec-acceptance.md`: reproducible Day 14 Linux kernel load/attach and
  file/exec semantic acceptance gate.
- `file-exec-audit.md`: current Day 12 file/exec attempt-event semantics and safety limits.
- `network-audit.md`: Day 15 cgroup connect4/connect6 semantics, fixture, and
  explicit coverage/fallback matrix.
- `network-enforcement.md`: Day 33 exact-tuple cgroup connect default-deny
  compiler, synchronous block semantics, and privileged acceptance gate.
- `p0-integration-check.md`: historical Day 1-6 integration snapshot.
- `p1-coverage.md`: Day 17 pre-M1 source/runtime coverage matrix, reproducible
  Linux evidence command, and current pending acceptance status.
- `p2-acceptance.md`: Day 25 register/capture/finish/TTL/reuse/host-negative
  lifecycle gate and supported-Linux evidence procedure.
- `policy-schema.md`: policy bundle schema, strict loader limits, compile
  preview classes, deterministic scope precedence, and enforcement semantics.
- `p3-policy-integration-check.md`: Day 32 multi-policy resolution, immutable
  generation switching, live audit JSON Lines integration, and current limits.

Local planning documents, drafts, and proposal materials are kept in `.local-docs/` and ignored by Git.
