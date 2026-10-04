# Authenticated realtime stream

Core exposes a bounded RFC 6455 stream at `GET /api/v1/stream`. The server
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

The handler also limits active connections to 128 by default and closes each
connection after five minutes, so consuming tickets cannot create an unbounded
set of idle sockets. Both values are bounded server-side options. Browser
clients send no application data; text, binary, and fragmented client frames
are rejected before their payload is allocated, while bounded close/ping/pong
control frames remain supported.

Run the source gate with:

```sh
go test ./internal/stream -count=1
```

Both runtime entries publish through the authenticated read listener. Managed
Core publishes checkpoint, kernel, policy, and containment records, including
`local_inspection` decisions after their synchronous SQLite append; standalone
audit publishes its redacted event stream. See the [dashboard guide](../dashboard/README.md)
and [development plans](roadmap.md) for durable snapshot and cursor work.
