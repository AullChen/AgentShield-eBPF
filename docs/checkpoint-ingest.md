# Checkpoint ingest

Day 36 adds a Run-scoped, write-only checkpoint surface:

```text
POST /ingest/v1/runs/{run_id}/checkpoints
Authorization: Bearer <ingest token>
Content-Type: application/json
```

`CheckpointHandler.Routes()` is deliberately separate from the management
router. The listener exposed to an Agent must use only this handler; the
registration and finish routes remain on an owner-only management transport.
An ingest token is accepted only for the exact Run named in the route.

## Request contract

The request accepts these Agent-authored fields:

- `sequence`: optional positive `uint64`, encoded as a decimal string.
- `idempotency_key`: optional stable key matching
  `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`.
- `type`: one of `run_started`, `llm_request`, `llm_response`,
  `tool_planned`, `tool_started`, `tool_finished`, `run_finished`, or
  `run_failed`.
- `phase`, `tool_name`, and `summary`: bounded descriptive fields.
- `labels` and `metadata`: bounded string maps.
- `client_reported_unix_ns`: optional untrusted decimal-string timestamp.

At least one of `sequence` or `idempotency_key` is required. Unknown fields,
trailing JSON, empty bodies, and bodies larger than 64 KiB are rejected. A
request cannot supply trusted identity, policy, source, or server clock fields.

The server serializes token authorization, active/non-terminating Run checks,
rate accounting, replay detection, sequence advancement, and insertion under
the Run store lock. The first accepted request returns `201`. An exact replay
returns the original record with `200` and `Idempotency-Replayed: true`; it does
not resample clocks or consume retention capacity. Every authenticated request,
including a replay or conflict, is still request-rate limited. A reused sequence/key with a
different payload, or a gap/stale sequence, returns `409`.

Authenticated writes are limited to 20 new checkpoints per Run per second and
1,024 retained checkpoints, an estimated 4 MiB retained per Run, and an
estimated 64 MiB retained across the store in this source-stage implementation.
The conservative estimate charges the encoded request plus fixed Go object/map
overhead.
Rate-limited and temporarily unavailable responses include `Retry-After: 1`.
Failed clock or identity generation does not consume a sequence or idempotency
key.

## Trusted receipt fields

The response binds the record to the authenticated Run and adds:

- `checkpoint_id` and trusted `run_id`;
- `server_received_monotonic_ns`;
- `server_received_unix_ns`;
- `clock_calibration_error_ns`; and
- `source: "agent_claim"`.

All 64-bit values are decimal strings. On Linux, the monotonic receipt time is
the midpoint of `CLOCK_MONOTONIC` samples taken immediately before and after
`CLOCK_REALTIME`; half of that interval is recorded as the calibration error.
Only the server monotonic time is suitable for later ordering. Client time is
preserved as an untrusted claim and never replaces a server clock.

## Lifecycle and persistence boundary

`run_finished` and `run_failed` are ordinary Agent claims. They do not call the
management finish operation, unregister a cgroup, revoke a token, or change Run
status. A trusted supervisor must confirm actual process/container exit before
using the management finish route.

Checkpoint replay state is currently bounded in memory and is removed when the
Run is terminated. It is not restart-persistent; the Day 38 store is responsible
for durable records and storage failure isolation. The handler does not log the
Authorization header or request body, but callers must still send only
redacted summaries and metadata.

## Verification

Run the source-level gate with:

```sh
make test-checkpoint
```

The tests cover exact Run binding, isolated routing, strict input limits,
stable replay, conflicts and gaps, concurrent replay, failure rollback, rate
limiting, termination rejection, and the non-authoritative `run_finished`
semantics.
