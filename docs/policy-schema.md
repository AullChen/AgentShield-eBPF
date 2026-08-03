# Policy bundle schema v1

The policy package defines the data contract, strict YAML/JSON loading, and a
bounded compile preview. The preview estimates map entries and identifies
conditions that require post-event user-space evaluation; it does not attach
eBPF programs or activate maps.

The canonical machine-readable shape is
`configs/policy.schema.json`. YAML uses the same keys. Go code uses
`internal/policy`; `LoadFile` accepts only `.json`, `.yaml`, and `.yml` files.

## Loader and resource limits

The loader rejects unknown keys, duplicate JSON keys, additional YAML
documents or JSON values, and omitted `enabled` or `priority` fields. It
normalizes deprecated `kill` before producing a compile preview.

The default limits are:

| Resource | Limit |
| --- | ---: |
| Input file | 1 MiB |
| Policies per bundle | 256 |
| UTF-8 bytes per string | 256 |
| Values per condition or label selector | 64 |
| Glob metacharacters per value | 4 |
| Estimated kernel map entries | 1024 |
| User-space match entries | 1024 |

Callers may supply different positive limits. A zero-valued limit selects the
documented default. Glob syntax is validated even though glob matching remains
a user-space capability.

## Compile preview

Each enabled policy receives one execution class:

| Class | Meaning |
| --- | --- |
| `kernel_eligible` | Every condition has an exact kernel-map representation. |
| `user_space_only` | Every condition needs post-event evaluation. |
| `mixed` | Exact candidates and user-space evidence are both present. |
| `disabled` | The policy emits no entries. |

Absolute exact file paths, exact executable names, CIDRs, port ranges, and
network-family defaults are kernel eligible. File prefixes, suffixes,
basenames, relative paths, glob patterns, and executable argument fragments
return stable reason codes explaining the required fallback. A `block` action
that depends on any user-space match is rejected instead of claiming a
synchronous denial that cannot be delivered. Audit, alert, and contain flows
may retain those rules for post-event handling.

## Atomic generation updates

Rule and profile maps use two logical banks. An update resets and fully writes
the inactive bank, reads every entry back, and compares it with the immutable
requested image before changing the active selector. A reset, write, readback,
verification, cancellation, or selector failure leaves the previous generation
active. The selector store must provide one atomic guarantee: when activation
returns an error, the visible generation has not changed.

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
