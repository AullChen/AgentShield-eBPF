# Isolated Linux demo

The demo joins the host Core, a Compose-managed Dashboard, and an unprivileged
Sandbox. It is an acceptance harness for the standalone `agentshield audit`
path, not a production deployment.

> **Run only in a disposable, dedicated Ubuntu 24.04 VM.** The host Core runs
> as root to load eBPF. Raw owner-only evidence can contain bounded process,
> path, and argument metadata. Never point the demo at a workstation, shared
> server, production cgroup, or real credential.

## What the command does

`scripts/demo.sh` performs these steps in a fixed order:

1. verifies Linux, root, cgroup v2, kernel BTF, Docker Compose, and the required
   build tools;
2. confirms that the only secret fixture is the repository file
   `sandbox/fixtures/demo-secrets/example-token` and records its SHA-256;
3. builds the CO-RE object, Core binary, Dashboard image, and Sandbox image;
4. starts the Sandbox behind a file gate, discovers its host cgroup v2 path,
   and rejects a non-leaf or escaped path;
5. starts Core against that exact leaf and waits for the authenticated
   diagnostics API to report successful load and attachment;
6. verifies the authenticated Dashboard, releases the Sandbox, and requires
   `file_open`, `exec_attempt`, and `net_connect` kernel records;
7. stores logs, hashes, image IDs, and API snapshots below ignored
   `tmp/demo/`, with an owner-only umask.

The Sandbox runs as UID 65532 with a read-only root filesystem, no Linux
capabilities, `no-new-privileges`, and a read-only bind of the fake fixture.
The Dashboard runs read-only as an unprivileged user. No service in the Compose
file is privileged; only the host Core has root privileges.

## Interactive run

Install the prerequisites from [bpf-build.md](bpf-build.md), make sure ports
`127.0.0.1:8080` and `127.0.0.1:3000` are unused, then run from the repository
root:

```sh
sudo ./scripts/demo.sh --isolated-vm
```

After all checks pass, the command prints a one-time Dashboard password. Open
`http://127.0.0.1:3000`, use username `agentshield`, and keep the command
running while inspecting Overview, Live Trace, Policies, History, and
Diagnostics. Press Ctrl-C to stop Core and remove the demo containers.

For a non-interactive gate that captures snapshots and cleans up immediately:

```sh
sudo ./scripts/demo.sh --isolated-vm --non-interactive
```

The mandatory `--isolated-vm` acknowledgement can instead be supplied as
`AGENTSHIELD_DEMO_ISOLATED_VM=1` for a dedicated CI runner. Do not set it on a
general-purpose host.

## Evidence and interpretation

A passing `summary.sanitized.md` proves only the checks named in that file:
exact-scope attachment, all configured hooks ready, fake-fixture protection,
three event classes, and an authenticated Dashboard request. Review the raw
JSON Lines before publishing even the sanitized summary. Do not commit the
evidence directory or either generated authentication token.

The demo does **not** prove a production supervisor adapter, checkpoint/store/
correlator fan-in, durable Dashboard history, policy CRUD, fallback containment
dispatch, or synchronous network-block behavior. The Sandbox shell exists
before attachment but remains behind a benign file gate; this avoids executing
the attack before hooks are ready, while not claiming the stronger stopped-task
contract required by `sandbox/supervisor.py`.

See [troubleshooting.md](troubleshooting.md) when a preflight, build, attach,
event, or Dashboard check fails. See [support-matrix.md](support-matrix.md) for
the exact supported and pending boundaries.
