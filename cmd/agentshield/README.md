# Core CLI

| Command | Purpose |
| --- | --- |
| `serve` | Registered runtime: checkpoints, policy coordination, containment, SQLite evidence, and read APIs |
| `audit` | Exact-leaf kernel capture and policy reporting as JSON Lines |
| `diagnose` | Environment capability report |
| `health` | Basic process health response |
| `version` | Build version |

Use `go run ./cmd/agentshield <command> --help` to inspect flags. Runtime configuration uses command-line flags and the supported environment values; policy bundles use `--policy-file`.

Follow the [managed walkthrough](../../docs/managed-runtime.md) for `serve` and the [container demo](../../docs/demo-guide.md) for `audit`. Keep raw event output owner-only because path and argument fragments may contain sensitive data.
