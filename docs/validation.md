# Validation

The recorded experiment targets commit `ebcfa7e54dc12be21822d477a079a8655bd50a51` on 2026-10-04. The [machine-readable summary](validation/2026-10-04.json) includes environment versions, object hashes, source-record hashes, and all managed-run outcomes.

## Environment and results

Kernel experiments ran on x86_64 in QEMU TCG with real guest kernels and a minimal initramfs. Objects built with Debian Clang 18.1.8 and Ubuntu Clang 18.1.3 were each loaded on Linux `6.8.0-146-generic` and `7.0.0-38-generic`.

| Experiment | Result |
| --- | --- |
| Full BPF collection | All four programs loaded and attached in each of the four compiler/kernel combinations |
| File and exec capture | Marker paths, empty arguments, and truncation checks passed in each combination |
| TCP capture | IPv4, IPv6 loopback, and an IPv6 address with four nonzero words decoded correctly |
| TCP enforcement | Exact address/port allowlist matched; wrong-address and wrong-port attempts returned `EPERM` |
| Scope filtering | Registered-leaf activity captured; outside-scope activity excluded |
| Managed Core on Linux 6.8 | Both compiler builds passed 24 runtime and 2 restart checks |
| Software suite | 395 passing Go test/subtest results with race detection; 67.4% statement coverage; SDK 12 and supervisor 16 tests passed |
| Build checks | Go vet, module verification, generated bindings, Core builds, dashboard typecheck/build, and shell syntax passed |

The allowlist experiments used destinations without TCP listeners. `ECONNREFUSED` established passage through the policy hook; rejected tuples returned `EPERM`. File and exec records retain syscall-entry attempt semantics.

The Linux 6.8 managed checks exercised trusted registration replay/conflict handling, Core self-protection, eight checkpoint types, token revocation, actual `cgroup.kill`, four-source evidence, WebSocket delivery, redaction, diagnostics, and persistence. Successful containment produced SIGKILL/-9 and an empty task leaf. Reopened SQLite databases returned saved Run evidence and `integrity_check=ok`.

Linux 7.0 investigation, dependency remediation, narrow-screen layout, and extended coverage are recorded in [development plans](roadmap.md). The JSON summary preserves both the initial 7.0 managed outcome and its unchanged rerun. Linux 6.8 remains the demonstrated operating baseline.

## Evidence provenance

The public summary is derived from the retained test results, environment record, suite exit codes, and screenshot metadata. Their SHA-256 hashes identify the source records. The supplied evidence bundle passed verification for 140 files during repository preparation.

The [dashboard screenshot](assets/containment-desktop.png) is an unchanged production UI capture rendering API snapshots from a fresh Linux 6.8 run. The browser connected to a local HTTP replay service. The image shows the exec attempt, matched checkpoint context, policy decision, and distinct containment result. Its capture time and hash are included in the JSON summary.

These measurements characterize functional checks and software coverage. The guest environment, compiler versions, and tested commit define their scope. The [research evaluation plan](roadmap.md#research-evaluation) sets out throughput, latency, overhead, and correlation-quality experiments.

## Reproduce source checks

```sh
go test -race ./...
go vet ./...
go mod verify
make verify-generated
make test-lifecycle
make test-policy
make test-runtime
make test-sdk
make test-supervisor
npm --prefix dashboard ci
npm --prefix dashboard run typecheck
npm --prefix dashboard run build
```

Use a race-enabled Go toolchain and native C compiler for `-race`. See the [dashboard guide](../dashboard/README.md) for the synthetic browser fixture.

## Reproduce Linux checks

On the dedicated VM described in [BPF build](bpf-build.md):

```sh
make bpf-object
make verify-bpf-object
CGO_ENABLED=1 make build
sudo make accept-audit
sudo make accept-lifecycle
sudo make accept-network-block
```

Then follow the [managed runtime walkthrough](managed-runtime.md), save its Run ID, inspect its evidence and diagnostics, and repeat the evidence query after a clean Core restart. The repository scripts provide the component and stopped-task fixtures. Reconstructing the exact recorded matrix additionally requires the archived guest kernels, BTF, initramfs, and external test driver.

Keep raw logs owner-only and retain the tested revision, environment, object manifest, commands, and outcomes together. Each verification result should identify whether it covers source behavior, synthetic UI data, or a real kernel path.
