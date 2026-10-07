# CO-RE object build

The build compiles a BPF ELF object and records the compiler, kernel BTF, program/map specifications, and hashes in a manifest. Kernel loading and hook attachment are checked by the Linux acceptance scripts.

## Toolchain

Use a dedicated Linux environment with cgroup v2 and readable `/sys/kernel/btf/vmlinux`. The build script selects little-endian x86_64 or ARM64 and requires Clang/LLVM 18.x. The recorded runtime matrix uses x86_64, Debian Clang 18.1.8 and Ubuntu Clang 18.1.3.

On Ubuntu, install the native build dependencies alongside Go 1.25+:

```sh
sudo apt-get update
sudo apt-get install -y bpftool clang-18 llvm-18 libbpf-dev libsqlite3-dev gcc make
make bpf-object
make verify-bpf-object
CGO_ENABLED=1 make build
```

The outputs are `bpf/agentshield.bpf.o` and `bpf/agentshield.bpf.manifest.json`. Both are local build artifacts. Unix SQLite support uses cgo and system `libsqlite3`.

The script generates `vmlinux.h` from the kernel BTF in a temporary directory. For compatibility experiments, set `AGENTSHIELD_VMLINUX_BTF` to a pinned BTF file. A byte-for-byte rebuild requires matching source, compiler patch release, bpftool output, architecture, and BTF input.

## IPv6 context reads

`agentshield_copy_destination` reads `user_ip6[0]` through `user_ip6[3]` explicitly. Each volatile 32-bit field access retains its CO-RE relocation. An unrolled loop may produce arithmetic on `PTR_TO_CTX` followed by a dereference of the modified pointer, which the verifier rejects.

Both the network allow-map key and event payload use the helper. After changing it, inspect disassembly for word-sized loads from the original context base and exercise addresses with all four words nonzero:

```sh
make generate
make verify-generated
make bpf-object
make verify-bpf-object
llvm-objdump-18 --disassemble bpf/agentshield.bpf.o
sudo make accept-audit
sudo make accept-network-block
```

The acceptance path loads the full collection and attaches all four hooks. Follow it with the [managed fixture](managed-runtime.md) to check registration, checkpoint ingestion, evidence, and containment together.

## Source-only checks

```sh
make verify-generated
make check-bpf-syntax CLANG=clang
make check-linux-bpfmgr
```

The checked-in Go binding embeds BPF source text and hashes. `make generate` refreshes that binding; `make bpf-object` produces the loadable ELF.
