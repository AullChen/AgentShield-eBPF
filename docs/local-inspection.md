# Local model-request and MCP preflight checks

This feature implements the requested **local-only** alternative. It never
forwards a model request, connects to an MCP backend, or executes a tool. There
is no provider SDK, upstream URL, provider credential, HTTPS CONNECT handling,
or cloud-model `base_url` compatibility. Do not point a model SDK's `base_url`
at this endpoint: its response is an inspection receipt, not a model response.

A trusted integration must separately arrange checking before execution. An
uncontrolled client can ignore a local check; the checker alone cannot stop its
upload or tool execution. The [offline container adapter](controlled-launch.md)
separately prevents external networking and host-source writes. Its ordinary
stdio MCP children share the controlled leaf but are not automatically routed
through protocol authorization. High-privilege/shared MCP integration is deferred.

## Enable

The managed Core accepts:

```text
--workload-socket /run/agentshield-workload/gateway.sock
--inspection-file /run/agentshield-inspection/config.json
```

Configuration, sensitive-value files, and MCP definition snapshots must be
regular owner-only files (0600), within owner-only canonical directories (0700),
owned by Core's effective UID. Do not mount them into the workload. Definitions
are read again for each MCP check; sensitive values are loaded at Core startup.
Changing sensitive values or policy requires a controlled Core restart.

Example model-only configuration:

```json
{
  "routes": [{"id": "model", "kind": "model"}],
  "sensitive_files": ["/run/agentshield-inspection/synthetic-sensitive.txt"],
  "requests_per_run": 100,
  "concurrency": 4
}
```

Each sensitive file contains **one exact value, including any newline bytes**.
It can contain an entire sensitive file, but this does not detect arbitrary
fragments, transformations, base64, encryption, or every secret format. Built-in
checks cover private-key markers, selected credential assignments/fields and
AWS access-key-shaped values. Checks inspect decoded JSON strings, including
escaped Unicode, independently of storage redaction.

## Request and approval

Workloads make authenticated local requests:

```text
POST /gateway/v1/check/{route_id}
Authorization: Bearer <active Run ingest token>
Content-Type: application/json
```

The trusted container relay supplies its own Run token and strips caller
credentials. The body is collected completely, limited to 256 KiB, validated
as a JSON object, and checked before a result is returned. Duplicate names,
invalid UTF-8, nesting deeper than 32, trailing values, compressed bodies,
Origin-bearing requests and session headers are rejected. Unknown routes cannot
select a destination. GET, CONNECT, attachments, SSE and MCP sessions are not
supported. The checker contains no upstream transport.

An otherwise acceptable body initially returns HTTP 403 with
`reason=approval_required` and its **raw-byte** SHA-256. A trusted operator must
review the exact saved body, its files/fragments and (for MCP) tool/arguments,
then create approval on the separate owner-only management socket:

```text
POST /api/v1/inspection/approvals
{
  "run_id": "0123456789abcdef0123456789abcdef",
  "route_id": "model",
  "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
  "expires_at": "REPLACE_WITH_RFC3339_TIME_WITHIN_FIVE_MINUTES"
}
```

This route is absent from the workload, checkpoint TCP and Dashboard listeners.
Approvals are bound to active Run, route, full body digest, expiry and one use;
even whitespace or JSON-RPC ID changes require another approval. There are at
most 1024 pending approvals. Secrets, changed tool definitions and out-of-range
arguments remain hard-denied even if approved. Approval permits a local check,
**not external forwarding or tool execution**.

The successful response explicitly says:

```json
{"mode":"local_only","checked":true,"reason":"checked","sha256":"...","forwarded":false,"executed":false}
```

The checker enforces per-Run authenticated-check attempt counts (including
denials) and bounded concurrent checks. The first budget exhaustion is recorded;
subsequent exhausted attempts are rejected without flooding audit storage.
These are not model token/cost budgets or tool-execution concurrency limits.
Approved attempts consume their approval even if evidence storage fails.
Approval/check/denial evidence is synchronously appended to the existing SQLite
store before success, then published to the existing stream. Records contain
only trusted Run identity, route, digest and fixed reasons; no body, arguments,
secret values or ingest tokens. Evidence uses `local_preflight_only` and
`enforced=false`, never a kernel-block or tool-executed claim.

## MCP local policy

Only a single JSON-RPC `tools/call` **body** is checked. This is not a complete
Streamable HTTP MCP server or stdio proxy: initialization, tools/list, resources,
prompts, notifications, batching and sessions are outside this local checker.
The smallest integration leaves transport/execution separate for later work.

An MCP route adds this policy (example pin is deliberately a placeholder):

```json
{
  "id": "files", "kind": "mcp",
  "mcp": {
    "server_name": "local-files", "version": "1",
    "definition_file": "/run/agentshield-inspection/tools.json",
    "definition_sha256": "REPLACE_WITH_SHA256_OF_EXACT_DEFINITION_FILE",
    "tools": [{
      "name": "read_file", "required": ["path"],
      "arguments": {"path": {"path_prefix": "/workspace"}}
    }]
  }
}
```

The trusted definition snapshot uses:

```json
{
  "server_name":"local-files", "version":"1",
  "tools":[{
    "name":"read_file", "description":"Read an approved file",
    "inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}
  }]
}
```

The full snapshot's exact-byte hash pins identity/version, descriptions and input
schemas, including formatting changes. Updates fail closed until the operator
reviews the snapshot and replaces the configured pin at restart. The snapshot
must come from a trusted operator/backend exporter; Agent-supplied definitions
are not authoritative, and this feature cannot detect an unreported backend
definition change. It does not call a live backend to fetch definitions.

Unlisted tools/argument keys, missing required arguments and non-string arguments
are denied. A rule uses either an absolute clean `path_prefix` (not `/`) or an
exact `allowed_values` list for a domain/repository/resource identifier. Paths
cannot contain `..`, backslashes, or escape by similar prefix; **symlink and
backend filesystem resolution still require the backend's own isolation**.
This is not a general JSON Schema validator. Tool annotations such as
`readOnlyHint` and SDK `tool_planned` never grant permission. High-risk tools
are absent unless explicitly configured and every call still needs approval.

The body shape follows the official [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
The transport limitations intentionally avoid advertising support for features
defined in [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

## Example client

Use the exact saved bytes for both operator review and retry. Do not serialize
them differently after approval:

```python
import http.client, os
body = b'{"question":"approved synthetic source fragment"}'
connection = http.client.HTTPConnection("127.0.0.1", 18181, timeout=5)
connection.request("POST", "/gateway/v1/check/model", body, {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + os.environ["AGENTSHIELD_INGEST_TOKEN"],
})
response = connection.getresponse()
print(response.status, response.read(4096).decode())
connection.close()
```

If the global eBPF TCP policy is strict, explicitly allow `127.0.0.1:18181` for
this in-container relay. Do not disable the independent `--network=none`
boundary. That loopback allow rule does not create an external route.

Run `go test ./internal/inspection ./internal/api ./cmd/agentshield` and the
dedicated-VM procedures before operational use. Normal cloud-model interaction,
trusted backend execution, writable work-copy export, Landlock/AppArmor, model
cost/output budgets and new BPF hooks remain separate follow-up work.
