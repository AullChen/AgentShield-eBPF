# Troubleshooting

Start with the first failing command and preserve its owner-only evidence
directory. A later symptom is often a consequence of an earlier failed build
or attachment.

## Demo preflight

| Message or symptom | Meaning | Corrective action |
| --- | --- | --- |
| `refusing to load eBPF without the --isolated-vm acknowledgement` | The destructive boundary was not acknowledged. | Move to a disposable, dedicated VM, then pass `--isolated-vm`. Do not bypass it on a workstation. |
| `the end-to-end demo requires Linux` | The current OS cannot load this eBPF path. | Use supported Ubuntu Linux. Cross-platform unit and Dashboard fixture checks remain available. |
| `run the demo as root` | Core cannot perform the required privileged load/attach. | Run the complete command with `sudo`; do not grant privileges to the Sandbox container. |
| `cgroup v2 is not mounted` | Unified cgroup scope identity is unavailable at the expected root. | Enable unified cgroup v2 and reboot the disposable VM. Do not substitute PID-only filtering. |
| `kernel BTF is not readable` | CO-RE cannot be built against the target kernel provenance. | Install the distribution kernel BTF package or use a supported kernel that exposes `/sys/kernel/btf/vmlinux`. |
| `required loopback endpoint is already in use` | Port 8080 or 3000 belongs to another process. | Identify that process and stop it explicitly. The script never kills an unknown listener. |
| existing demo container/project | A previous run was not fully cleaned up. | Inspect exact resources with `docker ps -a --filter label=com.docker.compose.project=agentshield-demo` and `docker ps -a --filter name=agentshield-demo-agent`; remove them only after confirming ownership. |

On failure the demo writes `failure-diagnostics.txt`, `compose-ps.txt`, Core
logs when available, and Sandbox logs when the container started. The script
then terminates only the Core process and containers that it created.

## BPF build and attachment

- `required command not found: clang-18`, `llvm-strip-18`, or `bpftool`:
  install the Ubuntu 24.04 packages listed in [bpf-build.md](bpf-build.md).
- `unsupported clang toolchain`: use clang/LLVM 18.x. A successful C syntax
  check with another compiler is not a CO-RE object build.
- verifier or attachment failure: read `bpf-build.txt` and `core-log.txt` in
  the evidence directory. Record the kernel, BTF hash, object hash, exact
  verifier output, then use `scripts/accept-file-exec.sh` only to isolate the
  file/exec path. That narrower pass is not a P1/network pass.
- `Core exited before the BPF hooks became ready`: use the Core log, not the
  static `diagnose` result, as the authoritative load/attach outcome. The
  diagnostics command deliberately leaves BPF permission `unknown` without an
  actual load.
- non-leaf cgroup rejection: inspect Docker's cgroup driver and the directory
  beneath the reported path. AgentShield intentionally refuses subtree scope;
  do not weaken the resolver to make the demo pass.

## Missing events

The non-interactive demo requires all three event classes. Inspect
`sandbox-output.txt` first:

- missing `trusted_start_gate=released` means Core never released the workload;
- a fixture hash or read-only error means the bind is not the repository-owned
  immutable fixture;
- actions are present but a kernel class is absent means capture, filtering,
  or hook behavior failed. Preserve `core-output.jsonl`, `core-log.txt`,
  `diagnostics.json`, the object manifest, and image IDs.

An IPv4/IPv6 connection may be refused by the target and still produce a
`net_connect` attempt. File and exec records are also syscall-entry attempts;
none of these records proves successful completion.

## Dashboard

- HTTP 401 is expected without Basic authentication. Use username
  `agentshield` and the password printed by the running demo.
- HTTP 503 from the Dashboard means its authentication or control-plane
  configuration is missing or invalid. Inspect `dashboard-start.txt` and
  `docker compose ... logs dashboard` without publishing environment values.
- Overview unavailable while Diagnostics is reachable usually means an API
  validation or Run-state issue; preserve both authenticated responses.
- Live Trace repeatedly reconnecting can mean Core stopped, the one-time ticket
  failed, or the bounded replay cursor expired. A resync clears stale rows by
  design; it is not durable history.
- Plain HTTP/WebSocket is accepted only on loopback. Use an authenticated TLS
  reverse proxy for any remote exposure; do not change the validation to accept
  cleartext non-loopback endpoints.

## Safe cleanup

The normal Ctrl-C path removes the demo containers and stops the Core. If the
host crashed, first inspect resources, then use the exact project and container
names:

```sh
docker ps -a --filter label=com.docker.compose.project=agentshield-demo
docker ps -a --filter name=agentshield-demo-agent
```

Do not use broad `docker system prune`, recursive cgroup deletion, or process
name matching. Generated evidence is under `tmp/demo/`; delete it only after
review because it may be the only diagnostic record.
