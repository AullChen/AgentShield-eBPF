# Dashboard Live Trace

Day 43 connects the existing Linux `audit` JSON Lines path to the bounded
WebSocket Hub and the Live Trace page. Enable the optional loopback API with all
three flags:

```sh
agentshield audit \
  --bpf-object ./bpf/agentshield.bpf.o \
  --scope-cgroup /sys/fs/cgroup/agentshield-demo-leaf \
  --api-listen 127.0.0.1:8080 \
  --read-token-file /run/agentshield/dashboard-read-token \
  --run-id demo-run
```

The token file must contain 24–512 non-whitespace bytes and, on Unix, have no
group/other permissions. Plain HTTP is restricted to an explicit loopback IP.
For a non-loopback deployment, put a TLS reverse proxy in front and configure
`AGENTSHIELD_STREAM_URL=wss://.../api/v1/stream` in the dashboard server.

The Next.js same-origin ticket route uses `AGENTSHIELD_READ_TOKEN` server-side
to obtain a 30-second, single-use ticket. The browser never receives the
long-lived token. Cross-site ticket requests are rejected.

Live Trace provides exact filters for Run, severity, and event type plus an
audit toggle. It keeps at most 500 rendered rows, reconnects with the last
decimal-string cursor, and clears stale rows if the five-minute/10,000-message
window requires resynchronization. All `u64` clocks, sequences, and cgroup IDs
are validated and formatted from strings/`BigInt`, never JavaScript `number`.

Before fan-out, the JSON Lines sink caps each record at 64 KiB, removes Prompt
and credential fields, redacts configured/token-like values, and rejects deep
or trailing JSON. The sink always consumes its input and Hub publishing never
waits for a browser client. The owner-only stdout audit stream remains raw and
retains the existing sensitive-data warning.

Automated source tests cover the bridge, redaction, filtering, cursor recovery,
and slow subscribers. Supported-Linux load/attach and sandbox-trigger evidence
is still required before describing this as runtime accepted.
