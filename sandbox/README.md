# Sandbox and trusted supervisor

For controlled application execution, use [`container_launcher.py`](container_launcher.py)
with the static [`sandbox-init`](../cmd/sandbox-init/) binary. It prepares an offline
Docker workload, installs resource limits, binds an exact leaf, and releases the
application after trusted registration. Follow [controlled launch](../docs/controlled-launch.md)
and [local inspection](../docs/local-inspection.md). The recorded Linux 6.8 workflow
passed the [current integration checks](../docs/validation.md).

## Container audit demonstration

The container demonstration opens the repository fake credential, executes `/bin/echo`, and attempts IPv4/IPv6 loopback connections. Its Compose configuration uses UID 65532, a read-only root filesystem, dropped capabilities, and a read-only mount of `fixtures/demo-secrets/example-token`.

```sh
./scripts/accept-sandbox.sh
```

Run this on the dedicated Docker test VM. The script records image ID, fixture hash, and mount identity under owner-only `tmp/acceptance/sandbox/`. For the full host Core and dashboard workflow, follow the [demo guide](../docs/demo-guide.md).

## Trusted lifecycle

[`supervisor.py`](supervisor.py) coordinates a platform-provided `PreparedTask`:

1. Verify the task is prepared and stopped in its dedicated exact leaf.
2. Register it through the owner-only Unix management socket.
3. Check the response against the held leaf descriptor and confirm the root task remains stopped.
4. Pass the Run ID, ingest URL, and checkpoint token to the task, then release execution.
5. Finish the Run after root-task exit and `cgroup.events` reporting `populated 0`.

The supervisor owns management authority; the agent owns only its checkpoint credential. A reported `run_finished` is recorded as an agent claim. During cleanup, the supervisor attempts TERM and a bounded wait, then KILL and a bounded wait. Successful finish requires complete scope exit.

The `PreparedTask` interface keeps platform-specific cgroup/process preparation and waiting in the adapter. The management client validates the socket and Linux peer UID, bounds responses, rejects redirects, and redacts credentials.

`scripts/check-managed-runtime.py` supplies the stopped Linux containment fixture
used in the [managed walkthrough](../docs/managed-runtime.md). `ContainerTask` supplies
the rootful Docker adapter. In both flows, Core keeps an exited, empty scope active
until trusted finish; scope violations remain subject to monitoring. Additional
platform integrations are part of the [development plan](../docs/roadmap.md).

```sh
python -m unittest discover -s sandbox/tests -v
```
