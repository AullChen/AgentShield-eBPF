# Synchronous network enforcement

Status date: 2026-08-10 (Day 33)

AgentShield's first synchronous enforcement path is a cgroup
`connect4/connect6` default-deny profile. The policy compiler accepts one
applicable network policy with `policy_decision: deny`,
`requested_action: block`, and `default: default_deny`. Exact IPv4 `/32` and
IPv6 `/128` hosts and exact ports are compiled into a bounded allow-tuple map.
An omitted address or port dimension becomes a family or port wildcard. An
entirely empty allowlist denies every TCP connection.

CIDR ranges, port ranges, and more than one applicable network policy when a
block policy is present are currently reported as `network enforcement
unsupported`. The conservative single-policy limit prevents a lower-priority
kernel block profile from contradicting a higher-priority user-space decision.
The command stops before hook attachment instead of silently running such a
policy as though it were enforced. Observe/audit policies without an applicable
block continue to use post-event matching.

The loader writes all allow tuples before publishing the profile and registers
the cgroup scope only after both maps are ready. The cgroup hook reads the
profile selected by `scope.profile_id`. A tuple absent from the allow map makes
the hook return `0`, so the kernel rejects the connection. The emitted raw
event carries `action_name: block`, `action_result_name: blocked`, stable
numeric policy/rule IDs, and the derived policy decision reports
`enforced: true` only when both IDs match. Ring-buffer pressure can lose
evidence but does not turn a computed denial into an allow.

Run the privileged acceptance gate on a supported isolated Linux host:

```sh
make accept-network-block
```

The gate builds the object and CLI, creates one exact leaf cgroup, starts audit
with `configs/strict-network-profile.yaml`, moves a test process into the
cgroup, verifies that a loopback TCP connect returns `EPERM`/`EACCES`, and then
requires both the blocked kernel event and its enforced decision record.

This source tree has automated compiler, ABI, decoder, decision-reconciliation,
and cross-compiled Linux loader coverage. A successful local syntax check or
ELF parse is not real verifier/load/attach evidence; the privileged gate result
must still be captured on the target Linux kernel.
