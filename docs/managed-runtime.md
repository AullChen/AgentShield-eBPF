# Managed Core runtime

`agentshield serve` connects the existing registration, checkpoint, correlator,
policy coordinator, containment executor, SQLite writer, and read APIs in one
process. `audit` remains the smaller standalone exact-scope capture command;
the Compose demo still uses that command, not this managed lifecycle.

This is implemented source with integration tests. Actual supported-Linux
verifier, cgroup identity probe, and containment acceptance remain pending.
Neither a successful cross-build nor the deterministic tests establishes
kernel support.

## Entry and trust boundaries

On the dedicated supported Linux VM, build with cgo and system SQLite, compile
the BPF object, then launch Core in its own stable exact-leaf cgroup. The
operator supplies owner-only directories and a read token file:

```sh
bin/agentshield serve \
  --bpf-object bpf/agentshield.bpf.o \
  --cgroup-root /sys/fs/cgroup \
  --management-socket /run/agentshield/management.sock \
  --ingest-listen 127.0.0.1:8081 \
  --api-listen 127.0.0.1:8080 \
  --read-token-file /run/agentshield/read.token \
  --store /var/lib/agentshield/evidence.db \
  --policy-file configs/default-policies.yaml
```

The paths above are operator-created inputs, not files distributed by the
repository. See the local real-host guide for a complete isolated setup.

- Management register/finish routes are served only on the owner-only Unix
  socket. Do not mount that socket or the read token into an Agent.
- The separate loopback ingest listener exposes only Run-token checkpoint
  writes. The read listener exposes only authenticated Dashboard APIs and
  WebSocket tickets/stream. Both listeners reject public plaintext bindings.
- Registrations must be beneath the network attachment root and still pass
  the existing exact-leaf, namespace, root PID, and Core protection checks.
- A short-lived copy of Core is born directly in the held leaf using
  `clone3(CLONE_INTO_CGROUP)` and triggers a PID-filtered `sys_enter_getpid`
  tracepoint using the BPF cgroup-ID helper. Core itself
  never moves cgroups. Probe failure rejects registration; it does not fall
  back to accepting an unverified inode.
- The trusted supervisor prepares the workload stopped, holds the leaf
  descriptor, verifies the registration response, and releases it only after
  receiving Run credentials. It finishes only after root exit and an empty
  held leaf. An Agent `run_finished` checkpoint cannot do this.

Core must retain host cgroup namespace visibility, BPF privileges, access to
`clone3`, and descriptor-relative cgroupfs access. A seccomp profile blocking
the probe or a kernel without the required helper/tracepoint support is a failed
acceptance result, not grounds to bypass identity checks.

The probe uses a tracepoint rather than socket-filter test-run because the
baseline helper dispatch differs by program type; see the
[Linux 5.15 network helper table](https://github.com/torvalds/linux/blob/v5.15/net/core/filter.c)
and [tracing helper table](https://github.com/torvalds/linux/blob/v5.15/kernel/trace/bpf_trace.c).

## Evidence and containment flow

1. Registration and terminal lifecycle callbacks update Overview and submit
   sanitized lifecycle metadata to the writer.
2. New authenticated checkpoints enter a 256-input bounded nonblocking
   checkpoint/kernel queue before their sequence is acknowledged. A full or
   closing queue returns HTTP 503 without consuming that sequence; an
   idempotent replay does not enqueue again.
3. Kernel records keep their independent raw JSONL output. Handoff failure
   also emits `derived_record_error`; it does not discard or alter that raw
   record. A worker resolves instance/cookie identity first and cross-checks
   cgroup ID before scoring same-Run checkpoints.
4. The worker retains at most 1,024 recent checkpoint claims globally and
   considers the newest 64 in the attributed Run. Correlation uses server
   monotonic receipt time and is a heuristic, not causal proof or syscall
   success. Agent metadata cannot authorize a scope or select a kill target.
5. Only the final active-Run containment decision invokes the existing
   exact-scope executor. A separate `containment_result` carries the target
   identity and outcome. It never turns the triggering syscall attempt into
   `blocked` or `succeeded`. Delayed terminal-Run events may still be attributed
   but cannot authorize containment.
6. Sanitized evidence is submitted to SQLite and broadcast to the live hub.
   Checkpoints, kernel facts, policy decisions, and containment results remain
   distinct sources. Decision/result timestamps are newly captured server
   receipt times, not invented kernel completion timestamps.

The ring reader does not wait for SQLite or `cgroup.kill`. Store submission is
asynchronous: HTTP 201 means checkpoint acceptance and bounded handoff, not
an fsync guarantee. Process crashes, overload, disk errors, or capacity pruning
can leave gaps. `/api/v1/diagnostics` reports pipeline and store drop counters,
store circuit state, and actual per-type ring-buffer loss deltas. The raw log
remains sensitive operator evidence, even though Dashboard/store projections
are redacted.

On shutdown, listeners and scope monitoring stop, the pipeline drains while
its scope maps remain open, scopes unregister, then the writer flushes and the
database closes. This is not restart-safe workload supervision: active Runs,
credentials, checkpoint replay state, and correlation cache are not restored.
The trusted supervisor/operator must stop or reconcile workloads if Core dies.

## Durable read boundary

With `serve`, `GET /api/v1/evidence/{run_id}` reads sanitized SQLite payloads,
including after Core restarts. Queries are limited to the newest 1,000 records,
4 MiB, and four concurrent snapshots. Decimal strings are used for public
64-bit clocks. If a referenced checkpoint is outside retention/query bounds,
the dangling link is removed and status becomes `checkpoint_outside_snapshot`.

This is a bounded per-Run evidence query, not a complete archival API. There is
no durable Run listing/pagination, active-Run recovery, restart-safe idempotency,
or durable WebSocket cursor. Dashboard History still starts from the in-memory
Overview Run list; an old Run can be opened directly by its saved ID. With
standalone `audit`, the same evidence route still uses the live recovery window.

Policies are loaded once at startup. One compiled global synchronous network
block profile is bound by Core to every registered leaf; arbitrary Agent profile
IDs and scoped block policies are rejected. Run/cgroup/label audit, alert, and
contain policies use trusted registration context. Policy CRUD, persistent A/B
activation, and hot reload remain outside this entry's scope.

## Verification

```sh
make test-runtime
go test ./internal/store ./internal/bpfmgr ./internal/stream -count=1
python3 -m unittest discover -s sandbox/tests -v
python3 -m unittest discover -s sdk/python/tests -v
python3 scripts/check-managed-runtime.py --help
```

The integration test uses real HTTP handlers, real SQLite/reopen, and a
synthetic kernel record/fake containment executor. The separate
`scripts/check-managed-runtime.py` uses a real stopped Linux leaf, the actual
supervisor and SDK, and `/bin/sleep` with
`configs/managed-test-policies.yaml`. It requires root and `--isolated-vm`.
It checks SIGKILL exit and leaf emptiness, but the operator must also review
persisted policy/containment evidence, target identity, and diagnostics. It is
an acceptance fixture, not a general Docker/container task adapter. Its full
procedure and restart/negative checks are in the ignored local real-host guide.
