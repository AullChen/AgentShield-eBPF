# Troubleshooting

Start with the earliest failing stage and retain its owner-only logs and object manifest.

| Symptom | Check |
| --- | --- |
| BPF build fails | Clang/LLVM 18, libbpf headers, bpftool, readable kernel BTF, and the architecture recorded by the build script |
| Verifier rejects a program | Full verifier log, object hash, kernel version, and IPv6 context-load disassembly; run the relevant acceptance script |
| Hooks fail to attach | Core privileges, cgroup v2 mount, target path, and actual load/attach status from the running Core |
| Registration fails | Exact-leaf state, host cgroup namespace, root PID membership, `clone3` access, and Core's own cgroup placement |
| Events are missing | Registered scope identity, task membership, successful hook attachment, and ring/pipeline loss counters |
| Containment is absent | Active Run identity, matching exec rule, final decision, executor result, and scope permissions |
| Dashboard returns 401 | Basic username `agentshield` and the separate dashboard password |
| Dashboard returns 503 | Dashboard token length, API URL, server-side read credential, and Core availability |
| Live Trace reconnects | Ticket creation, configured WebSocket URL, Core availability, and whether the cursor is within the live recovery window |
| Old evidence is needed | Query the saved Run ID against the managed Core using the same SQLite database |

`agentshield diagnose` reports static environment checks. Required checks that are failed or unknown produce exit status 1; the actual running Core's diagnostics report load and attachment results. Use that runtime result to assess hook readiness.

An allowlisted TCP attempt can return `ECONNREFUSED` when its destination has no listener. A synchronously rejected tuple returns `EPERM` in the recorded tests. File and exec tracepoints observe syscall entry; use the corresponding event semantics when reading the timeline.

For the Compose demo, inspect `sandbox-output.txt`, `core-output.jsonl`, `core-log.txt`, and `diagnostics.json` in its evidence directory. Confirm that `trusted_start_gate=released` preceded the fixture actions.

The normal shutdown path cleans up the resources created by the demo. After a host interruption, identify its exact resources before removing them:

```sh
docker ps -a --filter label=com.docker.compose.project=agentshield-demo
docker ps -a --filter name=agentshield-demo-agent
```

Use empty-directory removal for known cgroup leaves and retain runtime artifacts for diagnosis. [Development plans](roadmap.md) track compatibility, dependency, recovery, and layout follow-up work.
