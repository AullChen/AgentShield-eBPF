# Sandbox

The minimal demo Agent deliberately performs four auditable actions:

- opens the repository-owned fake fixture at `/demo-secrets/example-token`;
- executes `/bin/echo`;
- attempts TCP connections to IPv4 and IPv6 loopback.

No host credential or real secret may be mounted. `compose.yaml` fixes the only
bind source to `fixtures/demo-secrets/example-token`, mounts it read-only, runs
as an unprivileged user, drops all capabilities, and uses a read-only root
filesystem.

Run the reproducible Linux acceptance:

```sh
./scripts/accept-sandbox.sh
```

The command pulls the configured base image before building and records the
resulting sandbox image ID alongside the repository fixture's host path and
SHA-256. It then records the container mount namespace, mount ID/options, and
device/inode without printing the fixture content. Raw evidence is owner-only under
`tmp/acceptance/day20/` and must not be committed.

## Trusted supervisor example

[`supervisor.py`](supervisor.py) demonstrates the Day 37 lifecycle boundary. A
platform adapter must first create the dedicated exact-leaf cgroup and prepare a
stopped task inside it. `supervise()` then follows this order:

1. verify that the task is already prepared and stopped;
2. register the leaf through the owner-only Unix-socket management client;
3. verify the response identity against the still-held exact-leaf descriptor
   and confirm the root task remains stopped;
4. pass only the Run ID, checkpoint URL, and ingest token to the task, then start it;
5. call `finish` only after the root workload exits and the held exact leaf is empty.

The Agent never receives the management client or socket path. Its
`run_finished` checkpoint is an untrusted claim and is not an input to this
lifecycle. The adapter's `wait_for_scope_exit()` must observe both workload exit
and `cgroup.events` `populated 0` using the held leaf, so a forked child cannot
outlive scope monitoring. On failure the supervisor attempts TERM plus a
bounded wait, then KILL plus a bounded wait. It finishes the Run only if one of
those waits confirms complete scope exit. Otherwise it deliberately leaves the
management Run active for trusted investigation or bounded TTL cleanup.

The example intentionally leaves OS-specific cgroup/process preparation and
bounded waiting to a small `PreparedTask` adapter: attempting to launch first
and stop later would introduce an unmonitored execution race. The included
management client never logs response bodies, rejects redirects, bounds
responses, verifies the owner-only socket and peer UID on Linux, and redacts
the one-time ingest token from representations.

Run the stdlib-only tests from the repository root:

```sh
python -m unittest discover -s sandbox/tests -v
```
