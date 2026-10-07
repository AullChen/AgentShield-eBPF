# Controlled offline container launch

The Linux Docker adapter runs an application harness, agent, and ordinary stdio MCP children in one registered exact cgroup leaf. A trusted static init prepares the container, waits for registration, then starts the workload with a Run-bound local relay. The Linux 6.8/Docker workflow is covered by the [recorded integration results](validation.md).

## Operating boundary

| Control | Configuration |
| --- | --- |
| Network | Docker `--network=none`; local HTTP relay on `127.0.0.1:18181` |
| Identity | UID/GID 65532, all capabilities dropped, `no-new-privileges` |
| Filesystem | Read-only root and approved source; 16 MiB `/tmp` tmpfs and 1 MiB shared memory |
| Cgroup | Trusted exact leaf, held directory descriptor, read-only workload cgroupfs |
| Host channel | Individual workload Unix-socket bind mount |
| Image | Already installed immutable image ID/digest and trusted static init entrypoint |

The network namespace remains isolated when Core stops. The relay then reports service unavailability. This boundary also covers ordinary child processes within the container. Model/MCP requests use the [local inspection API](local-inspection.md), whose result is a check receipt.

## Prepare a dedicated host

Use rootful Docker on Linux with cgroup v2 and a root supervisor/Core in the host cgroup namespace. The supported adapter configuration uses Docker's regular identity mapping. Give a dedicated cgroup parent the `cpu`, `memory`, and `pids` controllers in `cgroup.subtree_control`; the launcher validates this operator-prepared hierarchy.

Prepare a root-owned approved project copy containing only the files needed by the workload. Keep regular files and directories writable only by the trusted operator, exclude credentials and special files, and hold the copy stable for the Run. Docker authority, the image, init binary, cgroup hierarchy, and source preparation belong to the trusted side.

The image must already contain the command/runtime. Its declared environment is restricted to PATH/LANG/TZ/TERM, and implicit image volumes are rejected. The launcher overrides the entrypoint and disables healthchecks and restarts. Preserve these settings throughout the task; Docker administration remains under operator control.

Build the trusted init and Core on the Linux host:

```sh
CGO_ENABLED=0 go build -o bin/sandbox-init ./cmd/sandbox-init
CGO_ENABLED=1 go build -o bin/agentshield ./cmd/agentshield
sudo install -d -o root -g root -m 0755 /opt/agentshield
sudo install -o root -g root -m 0755 bin/sandbox-init /opt/agentshield/sandbox-init
sudo install -d -m 0700 /run/agentshield-workload
```

The init and all ancestor directories must remain protected from untrusted replacement. Follow [managed runtime](managed-runtime.md) to build the BPF object and configure Core's own leaf, read credential, database, and management socket. Add:

```text
--workload-socket /run/agentshield-workload/gateway.sock
```

Add `--inspection-file` as described in [local inspection](local-inspection.md) to enable model/MCP checks. Start this workload with the default audit/alert policy unless a separately prepared runtime policy is required. A strict TCP profile must allow the relay's `127.0.0.1:18181` tuple.

The workload socket is mode `0666` inside a root-only `0700` directory, allowing the container's UID to use its individual file mount. Checkpoint and inspection requests still require an active Run token. Management and dashboard access remain on their separate interfaces.

## Launch

With the approved copy and controller-enabled parent prepared:

```sh
sudo python3 sandbox/container_launcher.py \
  --image 'sha256:REPLACE_WITH_INSTALLED_IMAGE_ID' \
  --project /srv/agentshield/approved-copy \
  --init /opt/agentshield/sandbox-init \
  --gateway /run/agentshield-workload/gateway.sock \
  --cgroup-parent /sys/fs/cgroup/agentshield-runs \
  --management-socket /run/agentshield/management.sock \
  --timeout 300 -- /usr/bin/python3 /workspace/harness.py
```

Use the same management socket path configured on Core. The workload receives a fresh environment with Run credentials, checkpoint and check endpoints, and a small set of approved process variables. Image pulls and dependency installation happen during trusted preparation.

| Resource | Launcher default | Recorded enforcement experiment |
| --- | --- | --- |
| Memory | 512 MiB | 128 MiB; an over-limit child triggered OOM kill |
| Swap | 0 | 0 |
| Processes/threads | 64 | Task-limit counter incremented |
| CPU | 50,000 µs per 100,000 µs period | 0.5 CPU; throttled-period counter incremented |
| Runtime | 300 seconds | Timeout ended the entire container |

The Python `ContainerTask` constructor accepts bounded memory, task, and CPU budgets. The CLI exposes timeout from 1 to 900 seconds, within the default 15-minute ingest-token lifetime. The experiment's 128 MiB setting is a test-specific override of the 512 MiB default.

## Registration and finish

1. The trusted init signals readiness and stops. The host supervisor verifies all its threads are stopped.
2. The adapter validates the read-only cgroupfs mount, moves the stopped init into its held leaf, and verifies identity and resource-limit readback.
3. Core registers the exact scope. The supervisor verifies the response against the held inode and stopped root process.
4. The supervisor sends the Run credential envelope and resumes init; only then does init start the application and local relay.
5. Docker exit state and `cgroup.events populated 0` establish complete workload exit. The supervisor finishes the Run, then cleans up the container and its empty leaf.

The held leaf is separate from Docker's runtime leaf. When the root PID disappears and the held leaf is empty, Core keeps the Run active awaiting trusted finish or expiry. The monitor continues checking child cgroups; remaining members, a migrated live root, or unreadable state cause inspection failure.

## Core shutdown and evidence

Complete workloads before planned Core shutdown. A stopped Core leaves Docker's offline boundary intact and makes the relay unavailable. Following a Core restart, prepare fresh containers so their single-file mounts reference the new socket inode.

The [validation record](validation.md) covers receiver-side zero application bytes, actual resource-limit events, relay body rejection, delayed finish, abnormal scope rejection, persistence, and cleanup. Platform extensions, editable work-copy export, and remote executor integration are described in [development plans](roadmap.md).

```sh
python3 -m unittest discover -s sandbox/tests -v
go test ./cmd/sandbox-init ./internal/scope ./internal/api
```
