# Exact-leaf cgroup scope acceptance

The MVP supports only one exact cgroup v2 leaf per registration. Subtree mode,
duplicate IDs, and parent/child overlaps are rejected. The cgroup directory
file descriptor remains open while the binding is active.

Automated source and Go tests verify:

- every BPF event path performs the scope-map lookup before ring-buffer reserve;
- map misses are not treated as captured host cgroups;
- every captured event carries one consistent non-zero cgroup/instance/cookie tuple;
- registration rejects duplicate and overlapping bindings;
- registration rejects Core's own cgroup, its ancestors, non-leaf targets, and
  PID/subtree scope selection;
- a new child cgroup and root-PID migration produce `scope_violation`;
- an inspection error fails the run closed with `inspection_failed`;
- a violation changes the associated Agent Run status to `failed`.
- sequential reuse of the same cgroup path and ID receives a new scope cookie,
  while delayed events keep their original Run attribution.

On a supported isolated Ubuntu 24.04 Linux host, run:

```sh
make bpf-object
sudo ./scripts/accept-p1.sh bpf/agentshield.bpf.o bpf/agentshield.bpf.manifest.json
```

The gate moves only its fixture subprocess into the registered leaf. It then
performs unique host file/exec actions and host IPv4/IPv6 attempts on port
18081, and fails if any of those host markers appear. Scoped file, exec, IPv4,
and IPv6 events must all pass and share one binary scope identity.

This Windows development snapshot cannot load or attach eBPF and has no running
Docker daemon. Therefore the tracked status is **source/automated gates pass;
isolated-Linux kernel and combined Docker evidence pending**. Do not rewrite
that status as a runtime pass until the commands above and
`./scripts/accept-sandbox.sh` produce owner-only evidence.
