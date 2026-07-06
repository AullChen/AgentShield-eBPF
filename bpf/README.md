# bpf

eBPF programs, BPF map declarations, and shared event structure headers will live here.

Current files:

- `agentshield.bpf.c`
- `events.h`
- `maps.h`

`agentshield.bpf.c` is prepared for Linux CO-RE builds with `vmlinux.h` and
libbpf headers. During early repository initialization it can also be syntax
checked without a Linux BPF sysroot:

```sh
clang -DAGENTSHIELD_BPF_SYNTAX_CHECK -fsyntax-only bpf/agentshield.bpf.c
```

Current probe coverage:

- `tracepoint/syscalls/sys_enter_openat` emits `AGENTSHIELD_EVENT_FILE_OPEN`
  events with pid, uid, comm, filename, and open flags. Day 8 intentionally
  does not filter by cgroup or PID; scope filtering is scheduled later.
