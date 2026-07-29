# configs

Runtime and policy configuration files live here.

`agentshield.example.yaml` is illustrative only. The current CLI rejects
`--config`/`AGENTSHIELD_CONFIG` until YAML loading is implemented, so a path is
never silently accepted and ignored.

`policy.schema.json` defines policy bundle schema v1 for JSON and
YAML-converted data. `default-policies.yaml` is the Day 26 default audit/alert
draft. The policy package validates the equivalent Go model, but the CLI does
not load either file until the planned Day 27 loader is implemented.
