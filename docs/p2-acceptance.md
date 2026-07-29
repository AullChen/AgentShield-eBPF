# P2 exact-scope lifecycle acceptance

Repository status: **automated lifecycle gate implemented; supported-Linux
runtime evidence pending**. This Windows development host cannot load eBPF and
has no running Docker daemon, so it cannot honestly produce the kernel or
sandbox portions of formal M1 evidence.

## Automated lifecycle gate

Run the cross-platform control-plane gate with:

```sh
make test-p2
```

`TestP2LifecycleAcceptance` executes one ordered scenario:

1. register an exact leaf and confirm its cgroup ID passes the scope-map filter;
2. confirm an unregistered host cgroup is a map miss;
3. attribute the capture to the active `{instance_id, scope_cookie}`;
4. finish the Run and confirm the cgroup immediately becomes a map miss;
5. attribute a queued old event through the bounded tombstone;
6. reuse the same path and cgroup ID with a new scope cookie;
7. prove old and new events remain attributed to different Runs;
8. expire the old tombstone and return `stale`, never the reused Run.

The same test suite covers subtree and PID scope rejection, non-overlapping
exact leaves, Core cgroup/ancestor self-protection, child-cgroup creation,
root-PID migration, tombstone capacity, and cleanup failure rollback. The BPF
source gate separately verifies every event path checks `scope_map` before
reserving ring-buffer space.

## Supported Linux evidence gate

On an isolated Ubuntu 24.04 host with kernel 5.15+, cgroup v2, BTF, Docker
Compose v2, and BPF privileges, run:

```sh
make accept-p2
```

This builds and verifies the CO-RE object, runs the lifecycle integration test,
runs exact-leaf kernel file/exec/IPv4/IPv6 capture with host-negative markers,
and verifies the repository-owned read-only sandbox fixture. It writes raw
owner-only evidence below ignored `tmp/acceptance/day25/` and a sanitized
summary alongside it.

Passing source tests alone is not Linux runtime acceptance. Do not change the
status above until `make accept-p2` produces a reviewed evidence directory on
the supported host.
