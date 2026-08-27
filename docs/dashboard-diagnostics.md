# Dashboard runtime diagnostics

`GET /api/v1/diagnostics` is an authenticated, read-only snapshot produced by
the running Go process. It reports:

- operating system, architecture, and the process's native byte order;
- the existing kernel, BTF, cgroup v2, container, and bpffs visibility checks;
- a separate actual BPF load/attach result;
- each configured tracepoint and cgroup hook;
- the active policy generation when a bundle is configured; and
- accumulated per-event-type loss notices as decimal strings.

The distinction between environment checks and the actual loader result is a
security boundary. BTF or bpffs file presence does not prove that the process
can load BPF programs. `load_attach.status` starts as `unknown`, becomes
`available` only from `bpfmgr.AuditOptions.OnReady` after all configured hooks
attach, and becomes `unavailable` if audit exits with an error before readiness.

Per-type counts are summed from the Go-synthesized `drop_notice` deltas. Drop
notices are diagnostic records: they are not counted as kernel facts in
Overview and do not appear as operation evidence.
