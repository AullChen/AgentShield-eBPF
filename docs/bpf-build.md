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
