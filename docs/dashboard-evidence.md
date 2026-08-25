# Dashboard evidence detail

The dashboard evidence page reads `GET /api/v1/evidence/{run_id}` with the
same server-side read token used by Overview. The endpoint projects the
authenticated WebSocket recovery buffer into evidence schema v1; it is bounded
to 10,000 records and five minutes and is not durable history.

The page keeps five concepts visually separate:

- `agent_claim`: an Agent statement, never kernel proof;
- `kernel_fact`: an observed attempt plus the hook's action result;
- attribution and correlation: displayed only when those records exist;
- `policy_decision`: requested action, final decision, enforcement flag, and
  mechanism;
- block or containment: displayed only from an explicit kernel action result,
  enforced decision, or containment result.

Standalone `agentshield audit --run-id ...` supplies a stream label but does
not by itself establish exact causal attribution. Consequently the live
projection leaves attribution and correlation empty until a trusted Run
registration and checkpoint pipeline supplies them. The UI explicitly states
this limitation and never translates `exec_attempt`, `file_open`, or an action
result of `none` into operation success.

History currently indexes live Runs from Overview and links to their bounded
evidence snapshots. Durable SQLite history queries are intentionally not
claimed by this endpoint.
