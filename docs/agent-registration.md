# Agent Run registration

`POST /api/v1/agents/register` is a management-plane endpoint intended only for
the trusted supervisor over an owner-only Unix socket. The socket must be
created inside a non-symlink directory owned by Core's effective UID with
permissions no broader than `0700`; the socket itself is restricted to `0600`.
The sandbox and Agent must not receive the directory, socket, or write access
to cgroupfs.

The request selects exactly one trusted lookup input:

```json
{
  "agent_name": "demo-agent",
  "container_id": "container-1",
  "cgroup_path": "/sys/fs/cgroup/agentshield/demo/leaf",
  "profile_id": 7,
  "scope_mode": "leaf_exact",
  "labels": {"purpose": "demo"}
}
```

The management API requires `cgroup_path`; PID-based scope selection remains a
diagnostic/Roadmap capability and is rejected by registration. A trusted
supervisor may add `root_pid` for migration monitoring, but it does not select
or redefine the cgroup. The API rejects unknown fields, so a client cannot
provide its own `run_id`, `cgroup_id`, `instance_id`, or `scope_cookie`. The
trusted scope manager resolves and opens the leaf, compares its filesystem
identity with an independent `bpf_get_current_cgroup_id()` observation, and
only then writes the scope map.

A successful response uses decimal strings for all 64-bit identities:

```json
{
  "run_id": "e0b15b53d5cc2a83bf9d1fdb9c58458a",
  "cgroup_id": "9007199254740993",
  "instance_id": "12345678901234567890",
  "scope_cookie": "12345678901234567891",
  "cgroup_path": "/sys/fs/cgroup/agentshield/demo/leaf",
  "scope_mode": "leaf_exact",
  "ingest_token": "<returned once>",
  "token_expiry": "2026-07-23T12:15:00Z"
}
```

Core generates the run and scope identities. The ingest token is HMAC-signed,
expires after 15 minutes by default, and is stored only as a SHA-256 hash.
Successful credential responses set `Cache-Control: no-store`.
Duplicate cgroup IDs and parent/child overlaps with an active binding return
HTTP 409. Core resolves its own cgroup when the manager starts and refuses to
register that cgroup or any ancestor. Non-leaf paths and all subtree requests
are also rejected.

## Finishing and delayed events

After the trusted supervisor has confirmed that the task or container exited,
it calls:

```text
POST /api/v1/agents/{run_id}/finish
```

Core deletes the cgroup entry from `scope_map` before changing the Run to
`finished`, so no later operation in that cgroup is captured under the old
Run. The operation is idempotent for an already-ended Run. Agent ingest tokens
cannot call this management endpoint and become invalid as soon as the Run is
no longer active.

Events already reserved in the ring buffer retain the capture-time
`{instance_id, scope_cookie}`. Core keeps an exact attribution tombstone for
10 minutes by default, with a hard default capacity of 10,000 entries; both
limits may only be configured downward. A matching delayed event remains
attributed to its ended Run. After expiration or capacity eviction, an
unmatched identity from the current Core instance is `stale`; identities from
another Core instance are `unknown`. Neither case falls back to the current
cgroup owner.

`CleanupExpiredRuns` applies the same map-first cleanup and tombstone behavior
to active Runs whose server-issued lifetime has expired. The caller should run
it from the trusted lifecycle scheduler.
