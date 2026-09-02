# tests

Project tests are grouped by purpose:

- `integration`
- `security`
- `perf`

Go tests remain beside their packages, Python tests live under
`sdk/python/tests` and `sandbox/tests`, browser acceptance is implemented by
`scripts/check-dashboard.mjs`, and privileged Linux harnesses live under
`scripts/`. The directories above reserve shared fixtures for future suites.

Aggregate entry points:

- `make check`: cross-platform source, unit, BPF syntax, and Linux cross-build;
- `make test-p3`: policy and containment semantics with fake executors;
- `make accept-p2`: supported-Linux exact-scope lifecycle and Sandbox gates;
- `make accept-network-block`: privileged synchronous network block gate;
- `sudo make release-check`: complete automated clean-host gate, only on a
  disposable supported VM.

Passing a deterministic or cross-compiled gate is not kernel runtime evidence.
Raw acceptance artifacts remain ignored and owner-only under `tmp/`.
