# Managed runtime

`agentshield serve` runs registration, checkpoint ingestion, policy evaluation, correlation, containment, SQLite storage, and read APIs in one process. This walkthrough uses the stopped-task fixture to exercise that complete lifecycle on a dedicated Linux 6.8 VM.

Optional `--workload-socket` and `--inspection-file` enable the
[offline container adapter](controlled-launch.md) and [local model/MCP
checks](local-inspection.md). The workload socket carries Run-authenticated
requests; approval routes stay on the owner-only management socket. Both paths
are covered by the [current Linux 6.8 validation](validation.md).

## Prepare the host

Use x86_64 Linux with cgroup v2, kernel BTF, Python 3.10+, and the [BPF build dependencies](bpf-build.md). Core needs BPF privileges, host cgroup namespace visibility, access to `clone3`, and permission to open cgroupfs descriptors. Run the following from the repository root in the disposable VM:

```sh
make bpf-object
CGO_ENABLED=1 make build
sudo install -d -m 700 /run/agentshield /var/lib/agentshield
sudo mkdir /sys/fs/cgroup/agentshield-core
sudo sh -c 'umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > /run/agentshield/read.token'
```

Keep the read token on the trusted side. The supervisor gives the workload a separate Run-scoped ingest token after registration.

## Start Core

Launch Core in its own leaf. The example test policy requests containment when the fixture attempts `/bin/sleep`:

```sh
sudo sh -c '
  echo $$ > /sys/fs/cgroup/agentshield-core/cgroup.procs
  umask 077
  exec ./bin/agentshield serve \
    --bpf-object bpf/agentshield.bpf.o \
    --cgroup-root /sys/fs/cgroup \
    --management-socket /run/agentshield/management.sock \
    --ingest-listen 127.0.0.1:8081 \
    --api-listen 127.0.0.1:8080 \
    --read-token-file /run/agentshield/read.token \
    --store /var/lib/agentshield/evidence.db \
    --policy-file configs/managed-test-policies.yaml \
    > /var/lib/agentshield/audit.jsonl
'
```

The management socket is restricted to its owner. The ingest listener accepts checkpoint writes; the read listener serves authenticated evidence, policies, diagnostics, and streaming. Core loads one policy bundle at startup. Use `configs/default-policies.yaml` for the audit/alert example or adapt `configs/strict-network-profile.yaml` to a controlled destination for TCP enforcement.

## Run the stopped-task fixture

In a second terminal:

```sh
sudo python3 scripts/check-managed-runtime.py \
  --isolated-vm \
  --management-socket /run/agentshield/management.sock \
  --ingest-url http://127.0.0.1:8081
```

The fixture prepares a stopped, unprivileged task in a new exact leaf, registers it through `sandbox/supervisor.py`, verifies the returned identity, and releases it with checkpoint credentials. Expected output includes a Run ID, exit code `-9`, and finished status. The supervisor verifies both task exit and an empty leaf before finishing.

Save the Run ID. Query its evidence using the owner-held read token:

```sh
sudo sh -c 'curl --fail --silent --show-error \
  -H "Authorization: Bearer $(cat /run/agentshield/read.token)" \
  http://127.0.0.1:8080/api/v1/evidence/REPLACE_WITH_RUN_ID'
```

Inspect four distinct sources: `agent_claim`, `kernel_fact`, `policy_decision`, and `containment_result`. The exec record describes an attempt; the containment result records the separate `cgroup_kill` outcome. Check `/api/v1/diagnostics` for actual hook attachment and pipeline/storage loss counters.

The [dashboard](../dashboard/README.md) uses the same read API. Its own login credential remains separate from the Core read token.

## Persistence and shutdown

Finish the fixture before sending Ctrl-C to Core. Shutdown stops listeners and monitoring, drains the runtime pipeline while scope maps are available, unregisters scopes, flushes the writer, and closes SQLite. Restart Core with the same database and query the saved Run ID to inspect the persisted evidence.

Managed queries return the newest bounded per-Run snapshot: at most 1,000 records and 4 MiB, with four concurrent snapshots. Checkpoint acceptance acknowledges the bounded pipeline handoff; SQLite persistence is asynchronous. Review queue and store diagnostics alongside each result. [Development plans](roadmap.md) cover active-task recovery, durable Run listing, and replay persistence.

Local inspection uses a separate synchronous SQLite append before returning a successful check or approval receipt. Its records remain queryable by saved Run ID after restart. Offline containers keep their network boundary when Core stops; a planned restart finishes existing workloads and prepares fresh socket mounts for subsequent containers.

After Core exits, its empty leaf can be removed with `sudo rmdir /sys/fs/cgroup/agentshield-core`. Retain the evidence directory as operator-owned data.

## Developer checks

```sh
make test-runtime
make test-lifecycle
make test-policy
make test-checkpoint
make test-sdk
make test-supervisor
```

Unit and integration tests use real HTTP handlers and SQLite together with synthetic kernel events and fake containment executors. The privileged fixture above exercises the kernel and task lifecycle. [Validation](validation.md) records both categories separately.
