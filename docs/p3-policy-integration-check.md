# P3 policy integration check

Status date: 2026-08-07 (Day 32)

This check closes the first post-event policy path without claiming kernel
enforcement. `agentshield audit --policy-file <bundle.yaml>` strictly loads the
bundle before attaching hooks, evaluates each decoded file, exec, and network
event, and emits a correlated `policy_decision` JSON record immediately after
the raw kernel event.

## Resolution contract

Each event loads one immutable engine snapshot. Applicable policies are sorted
by scope specificity (`run`, `cgroup`, `labels`, `global`), descending priority,
and ascending stable policy ID. The output retains every rule hit in that order
and copies the first hit into `final`. A valid A/B activation must use a newer
revision and the inactive bank; validation completes before the pointer switch,
so failure preserves the old bundle. Concurrent tests reject mixed
generation/policy pairs.

The audit adapter handles `O_RDWR` as both read and write access while
deduplicating the same rule. `O_PATH` produces an explicit evaluation gap and
does not pretend that content was read. File, exec, and network records retain
their existing evidence confidence and enforcement fields.

## Reproducible checks

```sh
go test ./internal/policy ./internal/bpfmgr ./cmd/agentshield
go test ./...
```

On a supported Linux host with an accepted CO-RE object and trusted exact leaf
cgroup:

```sh
sudo ./agentshield audit \
  --bpf-object bpf/agentshield.bpf.o \
  --scope-cgroup /sys/fs/cgroup/agentshield-demo \
  --policy-file configs/default-policies.yaml
```

The automated gate covers stable file and exec hits, network evaluation,
multi-policy ordering, complete hit retention, the final decision, failed and
successful generation switches, and raw/derived log ordering. Real Linux
load/attach evidence is still required separately.

## Deliberate limits at this checkpoint

- Day 32 itself emitted post-event decisions only. Day 33 subsequently added
  the bounded synchronous network path documented in `network-enforcement.md`.
- The A/B evaluator snapshot is in process. A concrete eBPF rule/profile map
  store is still pending.
- The standalone audit command provides global and cgroup context only. Run and
  label scopes need the registration service to supply trusted metadata.
- Kernel network capture is TCP-only. UDP DNS/QUIC policy reasons remain
  control-plane behavior until capture and enforcement hooks are added.
