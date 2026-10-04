# Post-event containment

Containment is a separate action against the exact registered cgroup leaf. A triggering exec record remains an observed syscall attempt; a `containment_result` records the executor's outcome and target identity.

## Authorization

The coordinator resolves the event's `{instance_id, scope_cookie}` to an active Run and evaluates policy using trusted Run/cgroup/label context. Only the final applicable `deny + contain` decision invokes the executor. Delayed events for ended Runs retain attribution through tombstones.

The executor:

1. holds the scope lifecycle lock against unregister and reuse;
2. verifies the full `{cgroup_id, instance_id, scope_cookie}` identity;
3. checks Core's current cgroup and ancestor relationships;
4. duplicates the registration's held directory descriptor and verifies path, inode, cgroup v2 filesystem, and exact-leaf state;
5. rechecks Core placement and leaf state, then opens `cgroup.kill` relative to the held descriptor and writes `1`.

Results distinguish `not_attempted`, `killed`, and `failed`. Each result retains the original operation's semantics and is tied to the Run, scope, event, policy, rule, and generation. The managed pipeline captures receipt clocks for derived evidence.

## Design rationale

Numeric PID reuse makes a delayed PID-only action ambiguous. The registered cgroup already has a lifecycle-bound identity and a held descriptor, so containment uses the whole task scope. The trusted deployment controls hierarchy mutation throughout this operation.

The ring reader hands off to a bounded worker. The worker performs policy coordination and cgroup I/O; the raw event retains its independent output path. Storage and live evidence receive the decision and result as separate records.

The supervisor completes the lifecycle by observing root exit and `cgroup.events` reporting `populated 0`. This check also accounts for child processes inside the leaf.

## Verification

```sh
go test ./internal/killer ./internal/scope
make test-policy
make check-linux-killer
```

The [managed runtime fixture](managed-runtime.md) checks a real SIGKILL exit. The recorded Linux 6.8 runs additionally checked persisted results, scope identity, WebSocket delivery, and evidence after restart. See [validation](validation.md) and [development plans](roadmap.md).
