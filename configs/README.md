# configs

Default runtime and policy configuration files will live here.

Planned files:

- `agentshield.yaml`
- `default-policies.yaml`

`agentshield.example.yaml` is illustrative only. The current CLI rejects
`--config`/`AGENTSHIELD_CONFIG` until YAML loading is implemented, so a path is
never silently accepted and ignored.
