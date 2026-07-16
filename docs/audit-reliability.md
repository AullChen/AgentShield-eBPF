# Audit Reliability and Clock Semantics

Day 16 makes event loss and receipt timing explicit without changing the
336-byte wire-v2 record.

## Reserve-failure counters

`agentshield_stats_map` is a per-CPU array. Slots `0 + event_type` count
successful reservations and slots `16 + event_type` count ring-buffer reserve
failures. Each probe updates the slot for its own event type. A failed reserve
returns immediately; the network audit hook still returns allow, so telemetry
pressure cannot change its decision.

The Go reader aggregates every possible CPU at a five-second default interval.
It emits a synthetic `drop_notice` only for the delta since the previous
snapshot. The notice is written directly by the Go JSON emitter, never back to
the ring buffer that may be full. A counter decrease is treated as a map reset,
and the current value becomes the next delta.

`drop_notice` records contain `dropped_event_type`, its name, and
`dropped_count`. They have no precise kernel occurrence timestamp because a
counter represents an interval; use their server receipt fields for ordering.

## Clocks

For a kernel event:

- `timestamp_ns` remains a deprecated compatibility alias.
- `kernel_monotonic_ns` is the authoritative raw `bpf_ktime_get_ns()` value.
- `server_received_monotonic_ns` is sampled from `CLOCK_MONOTONIC` after the
  ring-buffer read.
- `server_received_unix_ns` is an adjacent `CLOCK_REALTIME` sample for display.
- `clock_calibration_error_ns` is half the interval between monotonic samples
  bracketing the realtime read, rounded up.

All time fields are JSON decimal strings to preserve 64-bit precision. Kernel
monotonic and server monotonic values may be compared on the supported
same-host model. Unix time is for display and persistence, not authoritative
event ordering. A synthetic drop notice has no kernel occurrence time.

## Shutdown and malformed data

- SIGINT and SIGTERM cancel the audit context and close the ring-buffer reader.
- The drop monitor is canceled and joined before `RunAudit` returns.
- Isolated malformed wire-v2 records remain bounded and skippable; three
  consecutive malformed records stop the reader.
- A future or legacy wire schema still fails immediately.
- A stats-map read or clock-sampling error stops the audit process visibly
  rather than silently hiding loss or emitting uncalibrated timestamps.

Unit tests cover counter deltas, monitor cancellation, receipt fields, reader
closure, malformed-record limits, future-schema fail-fast behavior, and
JavaScript-safe timestamp encoding. Forced ring-buffer saturation and kernel
counter aggregation remain part of the isolated Linux integration gate.
