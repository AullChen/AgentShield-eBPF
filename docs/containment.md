# Post-event cgroup containment

Status date: 2026-08-11 (Day 34)

AgentShield's fallback containment is an independent user-space action. It does
not make the triggering syscall blocked and does not mutate the raw kernel
event. A `containment_result` retains the original `syscall_result` and records
`enforcement_method: cgroup_kill` with `enforcement_result` equal to
`not_attempted`, `killed`, or `failed`.

## Authorization and execution boundary

The executor accepts an exact `{cgroup_id, instance_id, scope_cookie}` identity.
PID and TGID are retained only for correlation and never select the target.
Before the action, it:

1. locks the active scope registration against unregister and reuse;
2. compares the complete instance/cookie identity;
3. resolves AgentShield-Core's current cgroup and rejects the same cgroup or
   any target ancestor that would contain Core;
4. duplicates the original close-on-exec cgroup directory descriptor held by
   scope registration, verifies its current path, inode, cgroup v2 filesystem,
   and exact-leaf state, and never reopens the target by path;
5. rechecks Core placement and the leaf invariant immediately before opening
   `cgroup.kill` relative to the stable descriptor and writing `1`.

Invalid or stale identity, Core protection, and non-leaf safety refusals produce
`not_attempted`. Once an active identity has been authorized, capability,
filesystem, context, or `cgroup.kill` I/O failures produce `failed`. The
executor never falls back to `kill(pid)`.

Core placement and child-cgroup checks are deliberately repeated next to the
write, but userspace cannot make those observations atomic with a cgroupfs
write. The deployment boundary must therefore prevent the sandbox from moving
cgroups, creating descendants, or changing Core membership; only the trusted
orchestrator may mutate that hierarchy.

The current authorization window deliberately holds the manager-wide scope
lifecycle lock across the short procfs/cgroupfs checks and write. This prevents
unregister or ID reuse from overtaking containment. A later per-scope lease can
reduce cross-scope contention, but must preserve the same in-flight lifetime.

## Why the Day 34 path does not use pidfd

The current kernel event ABI records PID/TGID but not process start time. A
pidfd opened after an event can therefore refer to a process that reused the
numeric PID between capture and containment. The exact Run cgroup identity is
already lifecycle-bound and can be revalidated safely, so Day 34 deliberately
uses whole-scope `cgroup.kill`. A future process-only path must carry a trusted
process identity such as PID plus start time and verify it around pidfd
acquisition; numeric PID alone remains forbidden.

## Integration status

`internal/killer` is intentionally not called from the policy matcher or ring
buffer reader. Those paths remain side-effect free and non-blocking. A trusted
Run-aware coordinator must explicitly opt into containment and persist/emit the
returned result; that integration belongs to the P3 acceptance work.

The orchestration and failure paths have automated tests. Linux-only tests cover
descriptor-relative leaf inspection and the `cgroup.kill` write, and are
cross-compiled here for CI execution. This Windows workspace cannot execute
those tests against a real cgroup v2 hierarchy, so real Linux containment
evidence remains pending and must not be inferred from unit tests or
cross-compilation.

Reproducible source checks:

```sh
go test ./internal/killer ./internal/scope
make check-linux-killer
go test ./...
```
