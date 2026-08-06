# configs

Runtime and policy configuration files live here.

`agentshield.example.yaml` is illustrative only. The current CLI rejects
`--config`/`AGENTSHIELD_CONFIG` until YAML loading is implemented, so a path is
never silently accepted and ignored.

`policy.schema.json` defines policy bundle schema v1 for JSON and
YAML-converted data. `default-policies.yaml` is the default audit/alert bundle.
`internal/policy` loads `.json`, `.yaml`, and `.yml` files with strict field,
size, and capacity checks and returns a kernel/user-space compile preview. The
current CLI configuration path does not yet select or activate a policy file.

`strict-network-profile.yaml` demonstrates default-deny intent with a single
fixed proxy tuple. Its TEST-NET address is documentation-only and must be
replaced before use. Loading or matching the profile does not activate kernel
enforcement.
