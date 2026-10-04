# Contributing

Keep changes focused on a reproducible behavior. Describe the observed result, the proposed change, and the checks used to validate it. Include a regression test for a behavior change and update the relevant operating guide when commands or API contracts change.

## Development checks

```sh
go test ./...
go vet ./...
python -m unittest discover -s sdk/python/tests -v
python -m unittest discover -s sandbox/tests -v
npm --prefix dashboard ci
npm --prefix dashboard run typecheck
npm --prefix dashboard run build
```

Use `gofmt` for Go changes. Keep generated BPF source bindings synchronized with `make generate` and check them with `make verify-generated`. Kernel changes also require the relevant [Linux acceptance checks](docs/validation.md) on a dedicated VM. Record kernel, architecture, compiler, object hash, and each executed check with the result.

Go tests live beside their packages; Python tests live under `sdk/python/tests` and `sandbox/tests`; browser and Linux acceptance scripts live under `scripts/`. Name fixtures and checks after their behavior.

## Design invariants

- Derive scope and lifecycle authority from trusted registration.
- Keep capture-time identity intact through delayed event processing.
- Preserve the distinction between an observed attempt, a synchronous block, and post-event containment.
- Redact evidence before persistence or broadcast, and surface queue/storage loss in diagnostics.
- Keep privileged operations inside the documented dedicated-VM workflow.
- Preserve the offline container boundary independently of Core availability.
- Bind local approval to Run, route, exact request bytes, expiry, and one consumption; apply content/tool rules before approval.
- Label local inspection receipts separately from kernel enforcement and backend execution.

Store raw runtime artifacts in ignored local directories. Publish reviewed summaries and scrubbed fixtures that preserve the information needed to reproduce a result. Security-sensitive reports follow [SECURITY.md](SECURITY.md).
