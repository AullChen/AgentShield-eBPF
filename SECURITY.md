# Security

AgentShield's operating model is a dedicated Linux host or VM with a trusted supervisor, a privileged Core process, and controlled agent workloads. The demonstrated runtime baseline is described in [validation](docs/validation.md).

## Deployment boundary

Core and the supervisor control the cgroup hierarchy and management socket. Workloads receive a Run-scoped checkpoint credential. Keep the management directory owner-only (`0700`), its socket owner-only (`0600`), and evidence/token files accessible only to the operator. Use loopback listeners for local access and authenticated TLS termination for a remote interface.

The demo uses a repository-owned fake credential and disposable workloads. Raw audit output can contain path and argument fragments; treat it as sensitive operator data. The dashboard and SQLite projections apply bounded redaction.

The [controlled launcher](docs/controlled-launch.md) trusts the rootful Docker
engine, immutable image, static init, approved project copy, and cgroup parent.
It combines `network=none`, a non-root workload, dropped capabilities, read-only
mounts, and resource budgets. The only mounted service channel is the workload
socket, in its separate owner-only host directory. The supervisor retains
control of Docker and cgroup changes throughout the Run.

[Local inspection](docs/local-inspection.md) returns request-check receipts.
Its trusted approvals bind Run, route, exact raw-body digest, expiry, and single
use, with content/tool rules checked on every attempt. Sensitive values and tool
snapshots stay on the host. Treat digests as request identifiers and retain the
documented authentication around their evidence; raw request bodies and tokens
are excluded from stored inspection records. External execution and backend
filesystem isolation are separate integration responsibilities.

## Reporting

Report vulnerabilities privately through the repository host's security reporting feature when enabled, or through a maintainer's published contact. A report should include the affected commit, environment, trust boundary, minimal reproduction, and observed impact. Use synthetic credentials and a dedicated test VM when preparing evidence. Reserve public issues for reports with disclosure already agreed with the maintainer.

Dependency remediation and extended runtime evaluation are tracked in [development plans](docs/roadmap.md).
