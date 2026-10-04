# Container audit demonstration

This walkthrough combines a privileged host Core with a Compose-managed desktop dashboard and an unprivileged sandbox. It exercises `agentshield audit` with exact-leaf file, exec, and TCP observation. For checkpoint correlation and task containment, use the [managed runtime](managed-runtime.md).

## Run

Use a disposable, dedicated Ubuntu VM with Docker Compose v2 and the [BPF toolchain](bpf-build.md). The workload opens a repository-owned fake credential, executes `/bin/echo`, and attempts IPv4/IPv6 loopback connections.

```sh
sudo ./scripts/demo.sh --isolated-vm
```

The script builds the object and images, starts the sandbox behind a file gate, verifies its exact cgroup leaf, and starts Core. Once all hooks are attached, it checks dashboard authentication and releases the workload. It then requires all three kernel event classes.

Open `http://127.0.0.1:3000`, use username `agentshield`, and enter the generated dashboard password printed by the script. Explore Overview, Live Trace, History, Policies, and Diagnostics. Ctrl-C stops Core and removes the demonstration containers.

For an automated run with immediate cleanup:

```sh
sudo ./scripts/demo.sh --isolated-vm --non-interactive
```

## Isolation and evidence

The sandbox runs as UID 65532 with a read-only root filesystem, dropped capabilities, and `no-new-privileges`. Its credential fixture is the read-only repository file `sandbox/fixtures/demo-secrets/example-token`. The dashboard runs as an unprivileged container; the host Core owns BPF privileges.

Owner-only artifacts under `tmp/demo/` include object hashes, image IDs, raw events, diagnostics, API snapshots, and a sanitized summary. Treat raw path and argv fragments as sensitive. Review material before publishing it.

The result describes exact-scope attachment, the three captured event classes, fixture isolation, and dashboard access. [Troubleshooting](troubleshooting.md) follows the build, attach, trigger, and display sequence.
