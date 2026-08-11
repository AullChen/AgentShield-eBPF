# P3 policy acceptance record

Status date: 2026-08-12 (Day 35)

Verdict: the repeatable source-level P3 gate is complete. Real Linux block and
containment execution, a concrete persistent eBPF A/B store, and production
dispatch wiring remain pending; this record is not an M2 runtime acceptance.

## Four action semantics

`make test-p3` exercises one exact active Run and checks these independent
outcomes:

| Semantic | Decision record | Execution evidence | Original operation |
| --- | --- | --- | --- |
| `audit` | requested/effective `audit`, `enforced: false` | no containment call | the raw syscall-entry event is unchanged |
| `alert` | requested/effective `alert`, `enforced: false` | no containment call; notification delivery is not claimed | the raw syscall-entry event is unchanged |
| synchronous `block` | final `block`, `enforced: true` | matching kernel `policy_id` and `rule_id`, plus `cgroup_connect_hook_blocked` | raw `action_result: blocked` records the hook result |
| post-event `contain` | final `contain` only after a successful action | a separate, policy-correlated `containment_result` with `cgroup_kill` and `killed`, `failed`, or `not_attempted` | `syscall_result: not_observed`; containment never rewrites it to blocked |

The coordinator accepts only an event whose cgroup, instance, and scope cookie
resolve to the same non-terminating active Run. It evaluates with that Run ID,
cgroup, and label snapshot. Containment requires the final winning
`policy_id`/`rule_id` hit to be `deny + contain` with an explicit containment
hint; an allowlisted network tuple, a lower-priority contain hit, or an already
blocked operation cannot trigger it. Execution failures stay visible as a
correlated result instead of becoming a derived-record error that discards the
decision.

For a denied network event followed by successful containment, the final
policy action is enforced as `contain`, while the network disposition remains
`enforced: false` with `synchronous_enforcement_not_connected`. This prevents a
later cgroup kill from being displayed as though the original connect syscall
had been synchronously rejected.

The coordinator can perform cgroup filesystem I/O, so it is deliberately not
called by the policy matcher or synchronous ring-buffer reader. A production
consumer must place it behind a bounded worker after raw evidence emission.
The standalone `audit` command does not yet own the registration Manager and
therefore does not have the lifecycle authority required to wire this safely.

## Failed update and recovery contract

The A/B generation updater already writes and verifies the inactive bank
before a compare-and-switch activation. Day 35 adds an opt-in reporting
constructor whose callback receives a `policy_update_failed` record containing
the known active and attempted generations. Validation, reset, rule/profile
write, readback, cancellation, and activation failures leave the active
selector unchanged. A production persistence sink is still pending.

`Recover` accepts only a non-zero committed active generation, validates and
returns that active image, and clears the inactive staging bank. Tests simulate
a restart after a partially written inactive bank and verify that the old image
is recovered before revision advancement resumes. Generation zero is rejected
rather than guessed.

This is a `BankStore` recovery contract, not evidence of process-persistent BPF
maps. The repository still lacks a concrete pinned eBPF BankStore and a single
transaction that activates the kernel image and user-space bundle together.
The current CLI instead performs a clean cold start from a strictly validated
policy file and creates fresh maps/links. Cross-process generation recovery
must not be claimed until persistence and that unified transaction exist.

## Reproducible checks

```sh
make test-p3
make check
```

The first command covers the four semantic cases, exact Run rejection,
containment failure evidence, winner/hint safety, all policy unit tests, update
failure, and recovery. The second also runs generated-source checks, BPF C
syntax validation, Linux-only cross-compilation, the full Go suite, and the CLI
build.

On a supported isolated Linux host, runtime evidence is still required:

```sh
make accept-network-block
make accept-p2
```

A controlled exact-leaf `cgroup.kill` acceptance harness is also still needed.
Toolchain checks, cross-compilation, and fake executors do not substitute for
verifier/load/attach or real containment evidence.

## Remaining P3/M2 gaps

- No policy CRUD management API or persistent policy bundle store exists yet.
- Runtime block hot updates are unsupported: raw kernel events do not carry a
  generation, so old events cannot yet be safely reconciled with a new bundle.
- Only one applicable exact-tuple TCP network policy is representable by the
  current kernel profile. Any additional applicable network policy makes the
  block compiler fail closed to avoid disagreeing with user-space precedence.
- Alert means a policy decision in this checkpoint, not delivery through a
  notification channel.
- The coordinator is active-Run only. Terminating or tombstoned delayed events
  remain an attribution/evidence concern and do not yet receive this Run-aware
  derived decision; they can never trigger containment.
- Linux runtime block/containment evidence and production containment dispatch
  are pending, so the broader M2 milestone is not marked accepted.
