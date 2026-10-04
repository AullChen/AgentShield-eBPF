# Local model-request and MCP inspection

The checker validates a complete request body against local content rules, a configured route, and a trusted single-use approval. It returns an inspection receipt and stores a minimal decision record. The [offline container](controlled-launch.md) supplies the network boundary; an integration controls the separate execution step.

Model routes check JSON structure and sensitive content. MCP routes additionally check a `tools/call` body against pinned tool definitions and argument rules. The receipt describes local preflight, with `forwarded=false` and `executed=false`.

## Enable

Add these flags to managed Core:

```text
--workload-socket /run/agentshield-workload/gateway.sock
--inspection-file /run/agentshield-inspection/config.json
```

Configuration, sensitive-value files, and MCP snapshots belong to Core's effective UID. Use canonical owner-only directories (`0700`) and regular owner-only files (`0600`) on the trusted host. Keep these inputs outside workload mounts. Sensitive values and configuration load at startup; MCP definition bytes are read and checked against the configured digest on each request.

Example model-only configuration:

```json
{
  "routes": [{"id": "model", "kind": "model"}],
  "sensitive_files": ["/run/agentshield-inspection/synthetic-sensitive.txt"],
  "requests_per_run": 100,
  "concurrency": 4
}
```

Each sensitive file contains one exact value, including any newline bytes, between 8 bytes and 256 KiB. The checker searches decoded JSON strings, so escaped Unicode is checked after decoding. Built-in rules also recognize private-key markers, selected credential fields/assignments, and AWS access-key-shaped values. Extended detection is covered in [development plans](roadmap.md#inspection-and-executor-integration).

## Request contract

```text
POST /gateway/v1/check/{route_id}
Authorization: Bearer <active Run ingest token>
Content-Type: application/json
```

The trusted init's relay collects up to 256 KiB before handing the body to Core. It replaces caller credentials with its own Run token and sends requests through the individually mounted workload socket. Oversized or incomplete bodies receive HTTP 413 at the relay; the recorded oversized request added zero inspection records to Core.

Core accepts one valid UTF-8 JSON object with unique keys, nesting at most 32, and a complete body. Compression, extra JSON values, query parameters, Origin/session headers, and unsupported routes are rejected. This bounded POST interface is the local request format.

| Result | HTTP status | Meaning |
| --- | --- | --- |
| `approval_required` | 403 | Body passes content/tool checks and needs an exact approval |
| `sensitive_data` or tool-rule rejection | 403 | Content or policy rule rejects the body |
| `invalid_json` | 400 | JSON contract failed |
| `body_limit` | 413 | Core body bound exceeded; relay has its own preceding bound |
| `request_budget` / busy | 429 | Run attempt budget or checker-wide concurrency limit reached |
| `checked` | 200 | Rules and approval passed; minimal evidence was stored |

## Trusted single-use approval

Review the saved raw body and its intended route. Approve its SHA-256 through the owner-only management socket:

```text
POST /api/v1/inspection/approvals
{
  "run_id": "0123456789abcdef0123456789abcdef",
  "route_id": "model",
  "sha256": "REPLACE_WITH_64_LOWERCASE_HEX_CHARACTERS",
  "expires_at": "REPLACE_WITH_RFC3339_TIME_WITHIN_FIVE_MINUTES"
}
```

The approval binds active Run, route, complete raw-body digest, and expiry. Retrying uses the same saved bytes, including whitespace and JSON-RPC ID. Consumption is synchronized, so concurrent requests can use an approval once. The pending approval store is capped at 1,024 entries.

Sensitive-content and MCP rules run before approval consumption. An approval grants eligibility for a local check while those rules continue to apply. A successful response has this form:

```json
{"mode":"local_only","checked":true,"reason":"checked","sha256":"...","forwarded":false,"executed":false}
```

Management approvals use a separate interface from workload checks, checkpoint TCP ingestion, and dashboard reads. An approved attempt consumes its approval even if evidence storage subsequently fails.

## MCP policy and definition pinning

Configure an MCP route with a trusted tool snapshot:

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

The route's `mcp` object refers to a snapshot shaped as:

```json
{
  "server_name":"local-files", "version":"1",
  "tools":[{
    "name":"read_file", "description":"Read an approved file",
    "inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}
  }]
}
```

Pin the SHA-256 of the exact snapshot bytes. That digest covers identity, version, descriptions, schemas, and formatting. A change requires operator review and an updated startup pin. Obtain snapshots from a trusted operator or backend exporter.

The checker accepts the configured tool names, required string arguments, and listed argument keys. Each argument rule supplies either a clean absolute `path_prefix` other than `/`, or exact `allowed_values`. Path checks reject traversal, backslashes, and similar-prefix escapes. These are lexical request rules; filesystem resolution and symlink controls belong to the executor's isolation boundary. The snapshot pins definitions, while the explicit route rules define the implemented argument checks.

## Budgets and evidence

`requests_per_run` limits authenticated check attempts for each Run, including body/rule denials that reach that stage. `concurrency` limits simultaneous checks across the checker. The first exhausted-budget response records the condition; further exhausted attempts are rejected without repeating that evidence. These are request-processing budgets, separate from model token/cost or tool-execution accounting.

Approvals, checks, and denials are appended synchronously to SQLite before a successful result is returned, then published to the realtime stream. Storage failure prevents a successful check receipt. The record keeps trusted Run identity, route, digest, fixed reason, and clocks; request bodies and credentials stay outside the evidence record.

Evidence uses type `local_inspection`, source `policy_decision`, requested action `check`, mechanism `local_preflight_only`, and `enforced=false`. The dashboard displays these alongside kernel and containment records. The recorded restart experiment preserved all 49 local inspection records and their IDs.

## Example client

Inside the controlled container, submit the exact saved bytes to its relay:

```python
import http.client

body = b'{"question":"approved synthetic source fragment"}'
connection = http.client.HTTPConnection("127.0.0.1", 18181, timeout=5)
connection.request("POST", "/gateway/v1/check/model", body, {
    "Content-Type": "application/json",
})
response = connection.getresponse()
print(response.status, response.read(4096).decode())
connection.close()
```

The relay supplies the Run credential. First obtain the digest from the approval-required receipt, have the trusted operator review and approve the saved bytes, then submit those same bytes again. A direct trusted-host call to the workload socket supplies its Run Bearer token explicitly.

Use [validation](validation.md) for the real-container results and [development plans](roadmap.md#inspection-and-executor-integration) for remote model execution, MCP protocol integration, and broader content detection.

```sh
go test ./internal/inspection ./internal/api ./cmd/sandbox-init ./cmd/agentshield
```
