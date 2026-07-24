# Network Connect Audit

Day 15 adds cgroup sock-address audit programs for TCP IPv4 and IPv6:

- `cgroup/connect4` (`agentshield_connect4`)
- `cgroup/connect6` (`agentshield_connect6`)

Both programs are audit-only and always return `1` (allow), even if the ring
buffer is full. They emit `net_connect` attempt events with destination IP,
destination port, address family, protocol, process identity, and cgroup ID.
The hook cannot see the DNS name. `action_result=none` means the later socket
connection result was not observed.

Network hooks and the scope map use the same exact leaf supplied through
`audit --scope-cgroup PATH`. There is no subtree or host-wide fallback.

## Manual fixture

Create a disposable cgroup v2 directory and start the audit process:

```sh
sudo mkdir /sys/fs/cgroup/agentshield-day15
sudo ./bin/agentshield audit \
  --bpf-object ./bpf/agentshield.bpf.o \
  --scope-cgroup /sys/fs/cgroup/agentshield-day15
```

From a second shell, run the fixture inside that cgroup (the exact supervisor
command depends on the distribution). The fixture itself is:

```sh
./scripts/test-network.sh
```

It attempts TCP connections to `127.0.0.1:18080` and `[::1]:18080`. No server
is required: the cgroup hook observes the connect request before a possible
`ECONNREFUSED`. A valid result has one IPv4 and one IPv6 `net_connect` event.

The network payload occupies the first 24 bytes of the wire-v3 data
area; the overall C/Go record is 352 bytes. IP bytes remain in network
order; port and family are stored in little-endian host order. A network event
sets `fields_unavailable=true` because the current cgroup program does not
capture `ppid`; zero must not be interpreted as a real parent PID.

## Coverage matrix

| Path | Source status | Runtime status in this Windows snapshot | Fallback |
| --- | --- | --- | --- |
| TCP IPv4 `connect4` | Implemented with Go decode tests | Pending isolated Linux attach/capture | None; attach failure is explicit |
| TCP IPv6 `connect6` | Implemented with Go decode tests | Pending isolated Linux attach/capture | None; attach failure is explicit |
| UDP send/connect | Not implemented | Not covered | Roadmap |
| `AF_UNIX` | Not implemented | Not covered | Roadmap |
| DNS/domain name | Unavailable at cgroup sock_addr hook | Not covered | User-space observe/alert only |

The Day 17 gate writes an ignored, per-run evidence matrix. After review, a
maintainer must manually update this tracked matrix with sanitized evidence
paths; the script intentionally never commits or rewrites public claims.
