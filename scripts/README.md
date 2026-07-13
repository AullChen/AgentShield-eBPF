# scripts

Developer, environment-check, and demo helper scripts live here.

Current files:

- `build-bpf.sh`: builds a real CO-RE ELF object on the supported Ubuntu
  toolchain and records object/BTF hashes and a parsed spec manifest.
- `test-audit.sh`: triggers one file-open action and one process execution for
  the Linux audit loop.

The trigger script only produces syscalls; it does not build or load BPF. The current
audit loop is host-wide and should only be run in an isolated VM/test host.
