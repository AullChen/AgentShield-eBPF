# BPF programs

`agentshield.bpf.c` implements scoped `openat`, `execve`, `connect4`, and `connect6` hooks. `events.h` defines the shared event ABI; `maps.h` defines scope, TCP enforcement, event transport, and loss-accounting maps.

Every capture begins with an exact cgroup scope lookup. File and exec events describe syscall-entry attempts with bounded path/argv fields and truncation flags. The TCP hooks also enforce the configured exact-tuple default-deny profile.

IPv6 destination reads use four explicit volatile 32-bit field accesses. Keep these accesses tied to the original context pointer so both verifier access rules and CO-RE relocations remain valid. A loop or bulk context copy can change the generated instruction shape.

```sh
make generate
make verify-generated
make bpf-object
make verify-bpf-object
sudo make accept-audit
sudo make accept-network-block
```

See [BPF build](../docs/bpf-build.md) for the toolchain and [validation](../docs/validation.md) for recorded load/attach results.
