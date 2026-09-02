# Roadmap

The next work is ordered by evidence and trust boundaries, not by UI surface.

## Release gate

- Run the complete clean-host procedure in the local test guide on a disposable
  supported Linux VM; retain tool versions, BTF/object/image hashes, raw logs,
  authenticated snapshots, and sanitized screenshots.
- Review dependency-audit output. A command completing is not equivalent to
  “no high-severity findings”; the recorded result must be inspected.
- Choose a repository license. The eBPF `Dual MIT/GPL` loader declaration is
  kernel metadata and does not license the repository as a whole.
- Publish only the evidence and capability claims that the reviewed run proves.

## Runtime integration

- Implement a concrete stopped-task cgroup/container adapter for the trusted
  supervisor contract, including descriptor-held identity and `populated 0`
  exit confirmation.
- Wire lifecycle registration, checkpoint ingest, SQLite persistence,
  correlator output, and evidence projection into one bounded production
  control-plane process.
- Add durable Run/history queries with gap and retention semantics. Keep the
  current in-memory WebSocket recovery window distinct.
- Connect final containment decisions to a bounded production worker, preserve
  exact-scope revalidation, and expose independent attempt/outcome evidence.

## Policy and enforcement

- Add authenticated policy CRUD with validation, authorization, audit records,
  and optimistic generation control.
- Implement concrete persistent BPF A/B banks plus policy-bundle recovery as
  one transaction; test crash points and generation reconciliation.
- Obtain kernel evidence for exact-tuple IPv4/IPv6 blocking and containment.
  Extend beyond TCP only after current semantics are stable.

## Coverage and reliability

- Add `openat2` and `execveat` with the same attempt-versus-result clarity.
- Decide explicit coverage for UDP, Unix sockets, DNS attribution, and
  namespace boundaries; do not infer it from TCP connect hooks.
- Run controlled ring-buffer saturation and verify per-type drop deltas,
  shutdown draining, and user-visible diagnostics under load.
- Add restart, disk-full, corrupt-store, expired-token, and slow-client chaos
  gates after the production fan-in exists.

Every item that depends on a real kernel, container runtime, privilege, browser,
or network service must ship with a reproducible procedure and retained
evidence. Deterministic fixtures remain valuable, but must keep their fixture
label.
