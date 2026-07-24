# scripts

Developer, environment-check, and demo helper scripts live here.

Current files:

- `build-bpf.sh`: builds a real CO-RE ELF object on the supported Ubuntu
  toolchain and records object/BTF hashes and a parsed spec manifest.
- `accept-file-exec.sh`: performs the Day 14 kernel load, verifier, tracepoint
  attach, attempt semantics, empty-argv, truncation, and ABI acceptance gate.
- `accept-p1.sh`: performs the Day 17 single-run file/exec/connect pre-M1 gate
  plus the Day 22 exact-scope positive/host-negative gate, and produces
  owner-only evidence plus a sanitized coverage matrix.
- `accept-sandbox.sh`: builds the minimal demo Agent, verifies its repository
  fixture origin/read-only mount metadata, and triggers all three event classes.
- `test-audit.sh`: triggers one file-open action and one process execution for
  the Linux audit loop.
- `test-network.sh`: triggers TCP IPv4 and IPv6 connection attempts from the
  caller's current cgroup; connection refusal is an acceptable fixture result.

The trigger scripts only produce syscalls; they do not build or load BPF.
Run them from the exact cgroup registered by the trusted audit supervisor.
