# P5 dashboard integration acceptance

Day 47 closes the P5 dashboard slice with one navigable flow:

1. Overview lists a Run and links to its evidence.
2. Evidence detail keeps Agent claim, kernel fact, attribution/correlation,
   policy decision, and block/containment evidence in separate columns.
3. Live Trace receives authenticated replay records through a single-use
   stream ticket and supports the audit filter.
4. Policies shows the validated default bundle and enabled state without a
   mutation endpoint.
5. Diagnostics reports the host environment while leaving actual BPF
   load/attach `unknown` in the non-privileged fixture.

## Deterministic browser gate

`cmd/dashboardcheck` is an explicit acceptance fixture. It replays the tracked
P4 sample and default policies through the production read handlers and stream
hub, but it never loads eBPF and never marks hooks ready. Its Overview and
diagnostic records state that it is a fixture and not kernel proof.

With Playwright available to Node.js, build once and start the fixture and
dashboard in separate terminals from the repository root:

```powershell
$env:AGENTSHIELD_READ_TOKEN = 'dashboard-fixture-token-123456789'
go run ./cmd/dashboardcheck --listen 127.0.0.1:18080
```

```powershell
$env:AGENTSHIELD_READ_TOKEN = 'dashboard-fixture-token-123456789'
$env:AGENTSHIELD_DASHBOARD_TOKEN = 'dashboard-browser-token-123456789'
$env:AGENTSHIELD_API_URL = 'http://127.0.0.1:18080'
$env:AGENTSHIELD_STREAM_URL = 'ws://127.0.0.1:18080/api/v1/stream'
npm --prefix dashboard run build
npm --prefix dashboard run start -- --port 3000
```

```powershell
node scripts/check-dashboard.mjs http://127.0.0.1:3000
```

Manual browser access uses the Basic-auth username `agentshield` and the
dashboard token as its password. The token is deliberately separate from the
control-plane read token, which remains server-only.

The browser gate checks all five pages, the six-row evidence chain, explicit
attempt-versus-outcome wording, WebSocket delivery, and a 390 px layout without
horizontal overflow. Screenshots are written under ignored `tmp/p5-dashboard/`.

This cross-platform gate complements rather than replaces the privileged Linux
acceptance procedures in `file-exec-acceptance.md`, `p2-acceptance.md`, and
`p3-policy-integration-check.md`.
