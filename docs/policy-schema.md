# Policy bundle schema v1

Day 26 defines the policy data contract and schema-level validation. Runtime
YAML/JSON loading, size limits, compile previews, and BPF map capacity checks
belong to Day 27 and are not implied by the presence of the default YAML file.

The canonical machine-readable shape is
`configs/policy.schema.json`. YAML uses the same keys after ordinary YAML to
JSON conversion. Go code uses `internal/policy`.

## Decision and action matrix

Combinations outside this table are rejected:

| `policy_decision` | Valid `requested_action` | Meaning |
| --- | --- | --- |
| `observe` | `audit`, `alert` | Record or alert without changing the operation. |
| `allow` | `audit` | Explicitly allow and record. |
| `deny` | `audit`, `alert`, `block`, `contain` | Deny intent; actual execution depends on the requested action and capability. |

Legacy `kill` is accepted only by the normalization path, becomes `contain`,
and emits `deprecated_action_kill`. New JSON output never emits `kill`.
`block` means a synchronous kernel hook rejected the operation. `contain`
means a separate post-event action and must not rewrite the original syscall
result.

## Scope precedence

Applicable policies are ordered deterministically:

1. more specific scope: `run` > `cgroup` > `labels` > `global`;
2. higher numeric `priority`;
3. lexically smaller stable policy ID.

An allow rule therefore cannot bypass a deny from a more specific scope merely
by choosing a larger priority. Resolution must retain every matched policy for
later explanation rather than exposing only the winner.

`cgroup_id` is a non-zero decimal string so JSON consumers do not lose 64-bit
precision. Each policy selects exactly one scope form and exactly one condition
kind.

## Conditions

- `file`: exact paths, prefixes, suffixes, or basenames plus one or more of
  `read`, `write`, and `execute`.
- `exec`: bounded executable names and/or argument fragments.
- `network`: an explicit `default_observe` or `default_deny`, IPv4/IPv6
  families, optional static CIDRs, and optional inclusive port ranges.

These fields describe policy intent. A valid schema does not prove a condition
can be enforced in the kernel. Tracepoint path strings and argv fragments are
audit/alert evidence; strict blocking requires a suitable LSM or cgroup hook.
