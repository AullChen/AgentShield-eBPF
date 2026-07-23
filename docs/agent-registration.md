# Agent Run registration

`POST /api/v1/agents/register` is a management-plane endpoint intended only for
the trusted supervisor over an owner-only Unix socket. The sandbox and Agent
must not receive the socket or write access to cgroupfs.

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

`pid` may replace `cgroup_path`. The API rejects unknown fields, so a client
cannot provide its own `run_id`, `cgroup_id`, `instance_id`, or `scope_cookie`.
The trusted scope manager resolves and opens the leaf, compares its filesystem
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
Duplicate cgroup IDs and parent/child overlaps with an active binding return
HTTP 409.
