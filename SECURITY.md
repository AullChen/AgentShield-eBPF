# Security

AgentShield's operating model is a dedicated Linux host or VM with a trusted supervisor, a privileged Core process, and controlled agent workloads. The demonstrated runtime baseline is described in [validation](docs/validation.md).

## Deployment boundary

Core and the supervisor control the cgroup hierarchy and management socket. Workloads receive a Run-scoped checkpoint credential. Keep the management directory owner-only (`0700`), its socket owner-only (`0600`), and evidence/token files accessible only to the operator. Use loopback listeners for local access and authenticated TLS termination for a remote interface.

The demo uses a repository-owned fake credential and disposable workloads. Raw audit output can contain path and argument fragments; treat it as sensitive operator data. The dashboard and SQLite projections apply bounded redaction.

## Reporting

Report vulnerabilities privately through the repository host's security reporting feature when enabled, or through a maintainer's published contact. A report should include the affected commit, environment, trust boundary, minimal reproduction, and observed impact. Use synthetic credentials and a dedicated test VM when preparing evidence. Reserve public issues for reports with disclosure already agreed with the maintainer.

Dependency remediation and extended runtime evaluation are tracked in [development plans](docs/roadmap.md).
