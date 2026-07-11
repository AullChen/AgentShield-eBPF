# P0 Integration Check

Date: 2026-07-03  
Scope: Day 1 through Day 6 project initialization.

> This is a historical P0 snapshot, not the current capability report. Later
> commits added a Linux audit loader and file/exec probes; the root README and
> development plan describe the current Day 12 source baseline and remaining
> real CO-RE/Linux acceptance gate.

## Purpose

This note records the first weekly integration pass. The goal is to make the repository easy to verify before P1 eBPF audit work begins.

## Command Matrix

| Area | Command | Expected result |
| --- | --- | --- |
| BPF source binding | `make generate` | Regenerates `internal/bpfmgr/generated/bpf_sources.go`. |
| BPF syntax check | `make check-bpf-syntax` | Runs the local clang syntax-only check for `bpf/agentshield.bpf.c`. |
| Go tests | `make test` | Runs all Go package tests. |
| Go build | `make build` | Builds the control-plane binary into `bin/`. |
| CLI version | `go run ./cmd/agentshield version` | Prints the current dev version string. |
| CLI health | `go run ./cmd/agentshield health` | Prints a JSON health response. |
| CLI diagnostics | `go run ./cmd/agentshield diagnose` | Prints an environment capability report. On non-Linux hosts, exits with status 1 because kernel features are unavailable. |
| Dashboard install | `cd dashboard && npm install` | Installs pinned Next.js dependencies from `package-lock.json`. |
| Dashboard typecheck | `cd dashboard && npm run typecheck` | Runs TypeScript checking. |
| Dashboard build | `cd dashboard && npm run build` | Builds all App Router pages. |

## Environment Notes

- Go control-plane checks run on Windows for the current skeleton.
- Kernel feature development still requires Linux with kernel 5.15 or newer, BTF, cgroup v2, and permission to load eBPF programs.
- The current BPF syntax check is a local bootstrap check using `AGENTSHIELD_BPF_SYNTAX_CHECK`; it is not a replacement for a real Linux CO-RE build.
- Dashboard build artifacts under `dashboard/.next/`, dependencies under `dashboard/node_modules/`, TypeScript build metadata, and Go binaries under `bin/` are intentionally ignored by Git.

## Current Limitations

- The Go control plane does not load eBPF programs yet.
- The Dashboard uses mock data until the WebSocket API exists.
- The diagnostics command intentionally reports failure on Windows because AgentShield kernel features require Linux.
- The generated BPF source binding embeds source text only; object compilation and real loader integration are scheduled later.

## P0 Result

P0 is ready for P1 when these checks pass:

```sh
make generate
make check-bpf-syntax
make test
make build
cd dashboard
npm run typecheck
npm run build
```
