# Policy bundle schema v1

The canonical shape is [`configs/policy.schema.json`](../configs/policy.schema.json). `internal/policy` loads JSON or YAML, validates the bundle, compiles immutable matchers, and evaluates events against a named generation.

## Loading and limits

Pass a bundle through `--policy-file`. The loader accepts `.json`, `.yaml`, and `.yml`, requires explicit `enabled` and `priority` values, and rejects unknown fields, duplicate JSON keys, and extra documents.

| Resource | Default limit |
| --- | ---: |
| Input | 1 MiB |
| Policies | 256 |
| UTF-8 bytes per string | 256 |
| Values per condition/label selector | 64 |
| Glob metacharacters per value | 4 |
| Estimated kernel map entries | 1,024 |
| User-space match entries | 1,024 |

The compile preview reports `kernel_eligible`, `user_space_only`, `mixed`, or `disabled`, together with reason codes and resource estimates. Eligibility describes a representation; the action compiler determines which installed hook can enforce it.

## Match semantics

| Condition | Supported interpretation |
| --- | --- |
| File | Exact path, prefix, suffix, basename, and access-mode matching on observed path data |
| Exec | Executable and bounded-argument matching on execution attempts |
| Network | Family, protocol, destination CIDR/port matching and observe/default-deny intent |

File strings are labeled `user_path`; callers supplying resolved device/inode/mount evidence can label a match `file_identity`. Truncated paths can satisfy a complete prefix rule; exact, suffix, basename, and glob checks require complete input. File string rules support audit/alert.

Exec matching distinguishes empty arguments from missing capture and carries truncation information. Exec containment is requested through a `containment_hint` and authorized by the registered runtime coordinator. Syscall-entry evidence retains attempt semantics.

The running TCP hooks support a default-deny profile compiled from exact host addresses and exact ports. Matching tuples pass the hook; other scoped TCP destinations are rejected synchronously. Omitting `cidrs` allows any address in the declared families for the selected ports; omitting `ports` allows any port at the selected addresses. Omitting both produces an empty allowlist and denies all scoped TCP connections. General CIDRs and port ranges remain available to control-plane evaluation; synchronous block compilation accepts host prefixes and individual ports.

Enabling blocking requires exactly one applicable enabled network policy, including audit/observe policies in that count. Use the strict network profile as the selected network policy rather than combining it with the default outbound-observation rule. Core reconciles hook results with policy decisions using `enforced` and the effective mechanism. UDP/QUIC decision fixtures exercise matcher logic; capture extensions are on the [roadmap](roadmap.md).

## Actions and precedence

| Decision | Actions |
| --- | --- |
| `observe` | `audit`, `alert` |
| `allow` | `audit` |
| `deny` | `audit`, `alert`, `block`, `contain`, subject to hook and matcher capability |

`block` denotes synchronous hook rejection. `contain` requests a separate post-event cgroup action. `audit` and `alert` record policy evaluation. Legacy `kill` normalizes to `contain` with a deprecation reason code.

Applicable policies are ordered by scope specificity (`run` > `cgroup` > `labels` > `global`), descending priority, then lexical policy ID. Decisions preserve all matching rules and identify the final selection. Network decisions also retain `network_disposition` for an allowlist match.

`serve` supplies trusted registration context for Run, cgroup, and label scopes and installs one global TCP block profile at startup. `audit` supplies its registered cgroup ID and accepts policies supported by that context. Public cgroup IDs use decimal strings to preserve 64-bit precision.

## Generation contract

The policy package has a fault-tested A/B transaction contract: prepare the inactive bank, read it back, compare the requested image, then change the active selector. A failed preparation or activation retains the prior generation. Current runtime activation occurs at startup; persistent live-map transactions and hot reload are tracked in [development plans](roadmap.md).

```sh
make test-policy
```
