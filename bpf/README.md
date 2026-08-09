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

> Scope filtering is not active yet. These probes observe matching syscalls from
> the entire host and capture raw bounded path/argv fragments. Use them only in
> an isolated VM or dedicated test host.

- `tracepoint/syscalls/sys_enter_openat` emits `AGENTSHIELD_EVENT_FILE_OPEN`
  events with pid, uid, comm, filename, and open flags. Day 8 intentionally
  does not filter by cgroup or PID; scope filtering is scheduled later.
- `tracepoint/syscalls/sys_enter_execve` emits `AGENTSHIELD_EVENT_EXEC_ATTEMPT`
  events with pid, ppid, uid, comm, executable, and up to four arguments.
  Executable and argument truncation is reported through the event flags. Wire
  schema v2 carries an explicit captured-argument count so legal empty arguments
  do not hide later arguments; legacy wire v1 objects are rejected.
- `cgroup/connect4` and `cgroup/connect6` emit TCP destination address/port
  records when the loader is given an explicit cgroup v2 path. They have no
  host-wide fallback. Without a block profile they allow; with the supported
  exact-tuple default-deny profile they synchronously reject non-allowlisted
  connects and report the block result.

Both probes run at syscall entry, so `action_result` is `NONE`. They do not
prove that the file open or process execution succeeded.

Run `make bpf-object` on a supported Ubuntu host to generate the ignored
`agentshield.bpf.o` and its JSON build manifest. See `docs/bpf-build.md` for
toolchain/BTF provenance and the boundary between ELF parsing and kernel
load/attach acceptance.
