# Dashboard

The Next.js interface displays active Runs, live events, source-aware evidence, loaded policies, and runtime diagnostics. Use Node.js 22 or 24 and npm 10+.

## Connect to Core

Set these server-side values in the terminal that starts the dashboard:

```sh
export AGENTSHIELD_API_URL=http://127.0.0.1:8080
export AGENTSHIELD_READ_TOKEN=REPLACE_WITH_CORE_READ_TOKEN
export AGENTSHIELD_DASHBOARD_TOKEN=REPLACE_WITH_SEPARATE_RANDOM_TOKEN
npm --prefix dashboard ci
npm --prefix dashboard run build
npm --prefix dashboard run start
```

Log in with the Basic-auth username `agentshield` and the dashboard token as password. The dashboard token must be 24–512 bytes and distinct from the Core read token. Keep the Core credential server-side. Production start binds to loopback; remote access uses authenticated TLS termination.

Live Trace obtains a single-use ticket through a same-origin route. Set `AGENTSHIELD_STREAM_URL` when the browser-visible WebSocket URL differs from the API URL; remote URLs use `wss://`.

| Page | Data |
| --- | --- |
| Overview | Current Run registry and counters |
| Live Trace | Filtered WebSocket events with bounded cursor recovery |
| Evidence | Four-source snapshot, including local inspection decisions; managed Core reads SQLite |
| History | Links from the current Run catalog to evidence |
| Policies | Loaded bundle, generation, enabled state, and view refresh |
| Diagnostics | Environment checks, actual load/attach status, queues, and losses |

Managed evidence can be opened by a saved Run ID after Core restarts. Standalone audit provides evidence from its live recovery window. Durable Run listing and cursor work are described in [development plans](../docs/roadmap.md).

Local request checks appear as `local_inspection` policy decisions with action
`check`, mechanism `local_preflight_only`, and `enforced=false`. Read their
approval/check/rejection reasons as preflight results alongside the separate
kernel and containment records. The [current validation](../docs/validation.md)
includes live screenshots from the running guest Core.

## Synthetic browser fixture

The cross-platform fixture replays the [sample timeline](../docs/examples/evidence-timeline.json) through production read handlers. Its diagnostics identify synthetic data and leave kernel attachment status unknown.

In terminal one, from the repository root:

```sh
export AGENTSHIELD_READ_TOKEN=dashboard-fixture-token-123456789
go run ./cmd/dashboardcheck --listen 127.0.0.1:18080
```

In terminal two:

```sh
export AGENTSHIELD_READ_TOKEN=dashboard-fixture-token-123456789
export AGENTSHIELD_DASHBOARD_TOKEN=dashboard-browser-token-123456789
export AGENTSHIELD_API_URL=http://127.0.0.1:18080
export AGENTSHIELD_STREAM_URL=ws://127.0.0.1:18080/api/v1/stream
npm --prefix dashboard run build
npm --prefix dashboard run start -- --port 3000
```

In a third terminal with Playwright/Chromium available to Node.js:

```sh
export AGENTSHIELD_DASHBOARD_TOKEN=dashboard-browser-token-123456789
node scripts/check-dashboard.mjs http://127.0.0.1:3000
```

On PowerShell, set variables with `$env:NAME = 'value'`. The script checks navigation, six evidence rows, attempt/block/containment semantics, streaming, and synthetic narrow-screen layouts. Screenshots go to `tmp/dashboard-check/`. Use the [recorded runtime evidence](../docs/validation.md) for the real-kernel experiment.

## Source checks

```sh
npm --prefix dashboard run typecheck
npm --prefix dashboard run build
```

Next.js generates `next-env.d.ts` during type generation and builds. Keep that file as a local build artifact.
