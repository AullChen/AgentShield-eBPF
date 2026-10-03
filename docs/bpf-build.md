# Reproducible CO-RE Object Build

Day 13 adds a real Linux BPF ELF build. It proves that clang can compile the
CO-RE source and that `github.com/cilium/ebpf` can parse the resulting ELF and
collection spec. It does **not** prove that a kernel verifier accepted the
program or that any hook was attached; those are separate runtime gates.

## Supported build baseline

- Ubuntu 24.04 on little-endian `amd64` or `arm64`.
- clang/llvm 18.x; other major versions are rejected to avoid silently changing
  the object toolchain.
- `bpftool` and `/sys/kernel/btf/vmlinux` from the target Linux host.
- Go 1.25.12+, Go 1.26.5+, or a newer supported release for the object
  inspector.

Install the Ubuntu packages once:

```sh
sudo apt-get update
sudo apt-get install -y bpftool clang-18 llvm-18 libbpf-dev gcc make
```

Then build and inspect the object with one repository command:

```sh
make bpf-object
```

The command writes ignored local artifacts:

- `bpf/agentshield.bpf.o`: the loadable little-endian BPF ELF object.
- `bpf/agentshield.bpf.manifest.json`: the object SHA-256, object size,
  program/map spec, build architecture, exact clang/LLVM, GCC, and bpftool
  versions, and the SHA-256 of the source kernel BTF.

The build creates `vmlinux.h` from `/sys/kernel/btf/vmlinux` in a temporary
directory. Override only for controlled compatibility testing:

```sh
AGENTSHIELD_VMLINUX_BTF=/path/to/pinned/vmlinux.btf make bpf-object
```

Retain the BTF blob or its independently retrievable package together with the
manifest when a byte-for-byte rebuild is required. A matching object hash is
expected only when source, clang/llvm patch release, bpftool output, BTF input,
and architecture all match.

To re-check an existing object and prove that it still matches its manifest,
without loading it into the kernel:

```sh
make verify-bpf-object
```

Kernel acceptance still requires `ebpf.NewCollection` (verifier/map creation)
and successful link attachment on an isolated supported Linux host.

## IPv6 context-load regression

`agentshield_copy_destination` deliberately reads `user_ip6[0]` through
`user_ip6[3]` separately. Volatile 32-bit reads alone are insufficient: an
unrolled array loop can still generate pointer arithmetic on `PTR_TO_CTX`,
followed by a load from that modified pointer. The verifier rejects it before
checking the context field; see the
[Linux verifier context-access checks](https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/verifier.c).
Keep constant **field indices**, not hard-coded byte offsets from `ctx`, so
each access retains CO-RE relocation. Both the allow-map key and event payload
use this helper.

After changing it, run on the isolated supported Linux host:

```sh
go generate ./internal/bpfmgr
make verify-generated
make bpf-object
make verify-bpf-object
CGO_ENABLED=1 make build
llvm-objdump-18 --disassemble bpf/agentshield.bpf.o
sudo make accept-p1
sudo make accept-network-block
```

Inspect both network programs for word-sized loads from the original context
base with instruction-local constant offsets. Retain the manifest, hashes,
toolchain/kernel identity, and actual load/attach logs. The real-kernel gates
must not skip connect6 or substitute a reduced collection just because a
workload uses IPv4. A connect6 verifier failure prevents scoped `audit` and
managed `serve` from loading their collection.

Finally regress the original [managed runtime](managed-runtime.md), including
four-hook startup, registration, checkpoint, stored evidence, and containment
outcome. Do not label these runtime checks PASS from source tests or an
object parse alone.
