# Checkpoint correlation

Day 39 adds a deterministic two-stage correlator in `internal/correlator`.

## Stage 1: Run attribution

The caller supplies the authoritative scope resolver used by the Run lifecycle
manager. A kernel event is first resolved from its captured
`{instance_id, scope_cookie}` tuple to an `exact`, `stale`, or `unknown`
attribution. Only an exact attribution with a Run ID advances to checkpoint
matching. The score does not add points for both cgroup and Run ID: those are
the same attribution fact, not independent confidence evidence.

## Stage 2: candidates inside one Run

Candidates are restricted to the attributed Run and the configured same-host
server-monotonic window (default: event from 1.5 seconds before a checkpoint
through 5 seconds after it). Client wall-clock claims are retained as data but
never used for ordering or scoring.

The initial bounded score uses distinct evidence:

- same TGID, or same PID when TGID is unavailable;
- normalized tool-name match;
- checkpoint/event semantic compatibility; and
- server-monotonic proximity.

Scores are clamped to 0–100 and every contribution is returned as a named
factor. Candidates are sorted by score, absolute time delta, then checkpoint
ID. If the best candidates remain equal on score and delta, the result is
`ambiguous`: all candidates remain visible and none is silently selected based
on map/slice traversal order.

This is correlation evidence, not proof of causality and not a replacement for
the exact Run attribution status.

## Verification

```sh
go test ./internal/correlator -count=1
```

The tests cover cross-Run exclusion, non-duplicated attribution evidence,
untrusted client-time exclusion, stale/out-of-window rejection, score clamping,
and stable conflict results under shuffled inputs.
