# Dashboard policy catalog

`GET /api/v1/policies` returns a read-only snapshot of the policy bundle
loaded by the running `agentshield audit` process. The endpoint requires the
same 24–512 byte bearer read token as the other dashboard APIs and exposes no
write method.

The response includes the active generation revision and bank plus each
policy's ID, enabled flag, scope, condition class, decision, requested action,
severity, and priority. When audit starts without `--policy-file`, the API
returns `configured: false` and an empty JSON array; it does not invent default
state.

The dashboard's **Refresh view** button performs a Next.js server refresh and
re-reads `GET /api/v1/policies`. It never sends a reload or mutation request,
so possession of the read-only credential cannot alter enforcement state.
