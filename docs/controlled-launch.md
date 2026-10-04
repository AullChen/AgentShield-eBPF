# Controlled offline container launch

This opt-in Linux adapter places the **whole application** (harness, Agent, and
ordinary local stdio MCP children) in one registered exact leaf before the
harness executes. It is an initial single-container adapter, not a general
production platform integration. Linux/Docker acceptance is still required.

The network namespace uses `--network=none`: no external IPv4/IPv6, UDP, QUIC,
or DNS. The only intentional host channel is a single authenticated workload
Unix socket. A trusted static init exposes that socket to ordinary HTTP clients
on container loopback `127.0.0.1:18181`; it does not provide a CONNECT proxy.
The workload socket does not expose registration, finish, policies, or Dashboard
routes. With Core stopped the socket becomes unusable; arbitrary networking is
not restored. A Core restart requires newly prepared containers because existing
single-file mounts retain the old socket inode.

## Preconditions

- Dedicated rootful Linux Docker host, cgroup v2, root supervisor/Core, no user
  namespace remapping/rootless Docker. Native Windows/macOS is not supported.
- Root-owned, immutable locally installed image ID/digest. No implicit image
  volumes, non-whitelisted image environment, or healthchecks. Do not use images
  that contain credentials. The trusted init overrides the image entrypoint.
- A private root-owned approved project copy, not an entire home directory.
  Remove unapproved `.env`, keys, and configuration from the copy. Directories
  and regular files must not be group/world writable; special files are
  rejected. Submounts are excluded. Keep the copy unchanged during the Run.
- The trusted init binary and its ancestors must not be replaceable by an
  untrusted user. Do not use `/tmp` as the binary's deployment location.
- A dedicated cgroup parent with `cpu`, `memory`, and `pids` enabled in
  `cgroup.subtree_control`. Do not delegate it to the workload. The adapter
  refuses missing controllers instead of changing the host's controller tree.
- The operator must not `docker exec`, restart, move tasks, or add networks to
  the container. Docker authority remains outside the sandbox.

## Build and launch

Build on the Linux host (use the host architecture for the init):

```sh
CGO_ENABLED=0 go build -o bin/sandbox-init ./cmd/sandbox-init
go build -o bin/agentshield ./cmd/agentshield
sudo install -o root -g root -m 0755 bin/sandbox-init /opt/agentshield/sandbox-init
sudo install -d -m 0700 /run/agentshield-workload
```

Start the existing managed Core following [managed-runtime.md](managed-runtime.md),
with its usual policy/store/read-token flags and this additional flag:

```text
--workload-socket /run/agentshield-workload/gateway.sock
```

The socket file is mode 0666 **inside an owner-only 0700 directory**, allowing
only its individual bind mount to be used by UID 65532. Every checkpoint still
requires a signed active Run token. Never mount its parent or the management
socket into the container.

After preparing the approved copy and cgroup parent, launch:

```sh
sudo python3 sandbox/container_launcher.py \
  --image 'sha256:REPLACE_WITH_INSTALLED_IMAGE_ID' \
  --project /srv/agentshield/approved-copy \
  --init /opt/agentshield/sandbox-init \
  --gateway /run/agentshield-workload/gateway.sock \
  --cgroup-parent /sys/fs/cgroup/agentshield-runs \
  --management-socket /run/agentshield-management/management.sock \
  --timeout 300 -- /usr/bin/python3 /workspace/harness.py
```

The image must already contain the command/runtime. No image pull or dependency
download occurs during launch. Workload environment is freshly constructed:
fixed PATH/HOME/LANG plus Run/checkpoint/local-check capabilities; no host API
keys, proxy settings, Docker descriptors, or existing network connections.
Resource defaults are 512 MiB memory, no swap, 64 tasks, 0.5 CPU, 300 seconds.
The Python adapter constructor allows explicit bounded budgets; CLI timeout is
1–900 seconds, fitting the default 15-minute ingest-token lifetime.

## Lifecycle and boundaries

The trusted init signals readiness and stops; the host additionally stops it
from the ancestor PID namespace and verifies all threads. The adapter moves the
stopped init into a persistent, descriptor-held leaf, writes/readbacks resource
limits, then registers it. Only after registration matches the held inode and
stopped process identity does the supervisor send a launch envelope and resume
it. Descendants inherit this exact leaf. The container sees host cgroup namespace
for compatibility with the current resolver, but cgroupfs must be read-only,
UID non-root, all capabilities dropped, and no-new-privileges set. The adapter
reads the stopped task's mountinfo and rejects any writable/missing cgroup v2
mount before registration; it also rejects replaceable init-path ancestors.

The leaf is separate from Docker's auto-removed runtime leaf. Finish requires
Docker's trusted exit state **and** `cgroup.events populated 0` in the held leaf;
cleanup only removes this adapter's empty leaf. Failure invokes termination then
whole-leaf kill, never an Agent `run_finished` claim.

This first version mounts source read-only. Editing can use a task-created copy
under bounded `/tmp`, but this adapter does not export that copy or apply changes
to the original. High-privilege/shared MCP servers are not automatically covered;
they need their own isolation and integration. No cloud model or remote MCP
forwarding is provided by the local inspection feature.

## Checks

```sh
go test ./...
go vet ./...
python3 -m unittest discover -s sandbox/tests -v
```

These checks cannot establish cgroupfs mount permissions, Docker lifecycle,
whole-tree network isolation, or kernel enforcement. Run the dedicated-VM
acceptance procedure before deploying. Do not publish synthetic or unexecuted
checks as actual Linux evidence.
