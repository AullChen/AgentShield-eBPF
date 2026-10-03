# Dashboard evidence detail

The dashboard evidence page reads `GET /api/v1/evidence/{run_id}` with the
same server-side read token used by Overview. With standalone `audit`, the endpoint projects the
authenticated WebSocket recovery buffer into evidence schema v1; it is bounded
to the newest 1,000 records, 4 MiB of payload, and five minutes and is not
durable history. At most four snapshots are projected concurrently. Request
cancellation stops selection, copying, and decoding, and payload allocation is
performed after releasing the live publisher lock. Projected item IDs combine
the source record ID with the stream sequence, so repeated source records remain
separate timeline entries instead of invalidating the Run.

The page keeps five concepts visually separate:

- `agent_claim`: an Agent statement, never kernel proof;
- `kernel_fact`: an observed attempt plus the hook's action result;
- attribution and correlation: displayed only when those records exist;
- `policy_decision`: requested action, final decision, enforcement flag, and
  mechanism;
- block or containment: displayed only from an explicit kernel action result,
  enforced decision, or containment result. Containment fields come directly
  from the production result schema, including the exact scope identity tuple.

Standalone `agentshield audit --run-id ...` supplies a stream label but does
not by itself establish exact causal attribution. Consequently the live
projection leaves attribution and correlation empty until a trusted Run
registration and checkpoint pipeline supplies them. The UI explicitly states
this limitation and never translates `exec_attempt`, `file_open`, or an action
result of `none` into operation success.

With managed `serve`, the endpoint instead reads sanitized SQLite evidence,
with the same 1,000-record/4-MiB/four-snapshot bounds but without a five-minute
live-window limit. It preserves registered attribution, checkpoint correlation,
and separate policy/containment outcomes across database reopen. Missing retained
checkpoint references are explicitly marked `checkpoint_outside_snapshot`.

History still indexes Runs from the in-memory Overview list. Durable Run listing,
pagination, restart-safe credentials, and WebSocket cursor recovery are not
implemented; saved Run IDs can be queried directly after restart. See
[managed-runtime.md](managed-runtime.md).
