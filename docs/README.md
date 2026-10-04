# Documentation

Start with the [architecture](architecture.md), then run the [managed fixture](managed-runtime.md) or [container audit demo](demo-guide.md).

| Guide | Contents |
| --- | --- |
| [Architecture](architecture.md) | Trust boundaries, kernel hooks, identities, queues, and evidence flow |
| [Managed runtime](managed-runtime.md) | Build, start Core, register a stopped workload, and inspect containment |
| [BPF build](bpf-build.md) | CO-RE toolchain, object manifests, and IPv6 context accesses |
| [Validation](validation.md) | Recorded results, provenance, and reproducible checks |
| [Registration API](agent-registration.md) | Trusted Run creation, credentials, finish, and delayed events |
| [Checkpoint API](checkpoint-ingest.md) | Agent claims, replay, limits, and receipt clocks |
| [Policy schema](policy-schema.md) | Match conditions, precedence, and action semantics |
| [Containment](containment.md) | Descriptor-relative execution and scope revalidation |
| [Correlation](correlation.md) | Run attribution and scored checkpoint matching |
| [Event store](event-store.md) | SQLite, redaction, retention, and failure isolation |
| [Realtime stream](realtime-stream.md) | Authentication, filters, cursors, and bounded recovery |
| [Dashboard](../dashboard/README.md) | Configuration and browser fixture |
| [Demo](demo-guide.md) | Host Core with Compose dashboard and sandbox |
| [Troubleshooting](troubleshooting.md) | Environment, attachment, evidence, and authentication checks |
| [Development plans](roadmap.md) | Durability, compatibility, security maintenance, and evaluation |
