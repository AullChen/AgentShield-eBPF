# Configuration

Pass a policy bundle to `agentshield serve --policy-file PATH` or `agentshield audit --policy-file PATH`. The strict loader accepts JSON and YAML, validates fields and resource limits, and compiles matchers before processing events.

| File | Use |
| --- | --- |
| `default-policies.yaml` | Audit and alert examples |
| `managed-test-policies.yaml` | Exec containment for the stopped `/bin/sleep` fixture |
| `strict-network-profile.yaml` | A single exact proxy address/port with TCP default deny; replace its TEST-NET address for a controlled experiment |
| `policy.schema.json` | Policy bundle schema v1 |

Core configuration uses CLI flags. Policies load at startup; `serve` binds its compiled global TCP enforcement profile to registered leaves. [Policy schema](../docs/policy-schema.md) explains the supported match/action combinations, and [development plans](../docs/roadmap.md) describe policy management extensions.

Local inspection uses a separate owner-only JSON configuration supplied through
`serve --inspection-file PATH`. It defines model/MCP routes, sensitive-value
files, trusted tool-definition digests, per-Run attempts, and checker-wide
concurrency. See [local inspection](../docs/local-inspection.md) for the schema
examples and single-use approval flow. Runtime policies evaluate events;
inspection configuration governs request checks.
