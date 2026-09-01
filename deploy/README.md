# deploy

`compose.demo.yaml` builds and runs the loopback Dashboard plus the
unprivileged, gated Sandbox. The privileged eBPF Core deliberately remains a
host process controlled by `scripts/demo.sh`; there is no privileged Core
container or production deployment in this directory.

Do not invoke the Compose file directly. The script generates separate random
Dashboard/read tokens, verifies the fixed fake-secret fixture, discovers and
validates the Sandbox exact-leaf cgroup, waits for real hook attachment, and
then releases the workload. See `docs/demo-guide.md`.
