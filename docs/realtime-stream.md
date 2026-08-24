# Authenticated realtime stream

Day 41 adds a bounded RFC 6455 stream at `GET /api/v1/stream`. The server
accepts either a read-only Bearer token or a short-lived, single-use ticket.
Browser clients should obtain the ticket through
`POST /api/v1/stream-ticket`; a trusted same-origin backend supplies the
Bearer token so it never becomes browser-visible configuration.

Each message carries decimal-string `sequence`, `resume_cursor`,
`server_monotonic_ns`, and `server_unix_ns` fields. A reconnecting client sends
its last committed cursor as `?cursor=...`. The in-memory recovery window is
bounded to at most 10,000 messages and five minutes. If the cursor is outside
that window, the server sends `resync_required` with the oldest/latest cursor
and `/api/v1/snapshot`, then closes the connection.

Optional exact-match filters are `run_id`, `severity`, `event_type`, and
`include_audit`. Filtering does not change global sequence numbers: gaps can
therefore mean filtered messages, not data loss.

Every subscriber has a bounded queue. Publishing never waits for a WebSocket
writer; a slow subscriber is detached and receives a best-effort
`resync_required` message. Payloads must already be redacted and valid JSON and
are capped at 64 KiB before entering the hub.

Run the source gate with:

```sh
go test ./internal/stream -count=1
```

Day 43 wires the Hub to the optional loopback listener and Linux audit JSON
Lines sink; see `dashboard-live-trace.md`. A durable `/api/v1/snapshot` and
supported-Linux runtime evidence remain pending.
