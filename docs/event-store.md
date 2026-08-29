# Event store

Day 38 introduces `internal/store`, a source-stage SQLite evidence store behind
a non-blocking, bounded writer.

## SQLite boundary

The store creates a real SQLite database, enables WAL, uses `synchronous=NORMAL`
and a bounded busy timeout, and caps page growth. Capacity accounting includes
the database, WAL, and shared-memory files. Above the soft limit it removes the
oldest low-severity records first and checkpoints the WAL; high and critical
records are preferred but remain bounded by the hard limit.

No downloaded Go driver is required. Windows uses the system
`winsqlite3.dll`; supported Unix cgo builds link the system `libsqlite3`.
Non-Windows builds without cgo return `ErrSQLiteUnavailable` instead of
silently writing another format. Production images therefore need the SQLite
runtime/development library when building with cgo.

The initial schema contains the design tables plus a normalized
`evidence_records` ingestion table. Every record stores decimal-string
monotonic/Unix and scope identities, an explicit source, and bounded redacted
summary/labels. Arbitrary raw payloads are not accepted. Redaction occurs before
records enter any queue, recent buffer, log, or database. Label names are
normalized before sensitive-key matching, and common API-key, token, cookie,
authorization, password, and cloud-secret assignments are removed from text.

## Reader isolation and degradation

`Writer.Submit` is non-blocking. A full queue drops only the store copy and
updates an in-memory gap diagnostic. Batches are written on a separate goroutine.
On a SQLite error the writer opens a circuit breaker and moves already-sanitized
records into a count-and-byte-bounded recent buffer. Further overflow increments
`store_drops`; it never blocks the ring reader, changes a policy generation,
or ends a Run.

Periodic probes flush the recent buffer and close the circuit after recovery.
The diagnostic snapshot exposes circuit state, queue/recent depth, per-stage
drops, and the first/latest missing record IDs. A generic degraded message is
also written to the configured trusted diagnostic stream without the backend
error or record content, so storage failure remains visible without leaking
secrets or depending on the failed database.

## Verification

```sh
go test ./internal/store -count=1
```

Tests verify a real SQLite header and reopen/count path, WAL-safe redaction,
non-blocking failure behavior, bounded gaps, and circuit recovery.
