# Build and verification scripts

| Script | Purpose |
| --- | --- |
| `build-bpf.sh` | CO-RE compilation and object/BTF/toolchain manifest |
| `accept-file-exec.sh` | Linux file/exec capture, empty argv, truncation, and ABI checks |
| `accept-audit.sh` | Full collection load/attach, file/exec/TCP capture, and scope filtering |
| `accept-lifecycle.sh` | Registration lifecycle, scoped audit, and sandbox checks |
| `accept-network-block.sh` | IPv4/IPv6 exact tuples, alternate ports, and synchronous rejection |
| `accept-sandbox.sh` | Container hardening, fake fixture identity, and workload triggers |
| `check-managed-runtime.py` | Stopped-task supervisor, checkpoint, and real containment fixture |
| `check-dashboard.mjs` | Authenticated browser navigation, evidence, streaming, and layout assertions |
| `demo.sh` | Host Core with Compose dashboard and gated sandbox |
| `release-check.sh` | Module integrity, source checks, vulnerability scans, builds, and container demo |
| `test-audit.sh`, `test-network.sh` | Syscall triggers executed inside a registered leaf |

The Makefile exposes named targets for these checks. Linux acceptance commands run on a dedicated VM; owner-only artifacts are written beneath ignored `tmp/`. See [validation](../docs/validation.md) for commands and experiment provenance.
