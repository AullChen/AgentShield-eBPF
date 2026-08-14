# AgentShield Python ingest SDK

This zero-runtime-dependency package reports semantic checkpoints for one
already registered Agent Run. It is context, not a security boundary: kernel
events and trusted supervisor lifecycle facts remain authoritative.

`IngestClient` is fixed to the base URL, `run_id`, and short-lived ingest token
provided at construction. Its only network operation is:

```text
POST /ingest/v1/runs/{run_id}/checkpoints
Authorization: Bearer <ingest token>
```

It has no registration, finish, policy, event-query, or other management
method. The Agent process must not receive the owner-only management socket or
management credential.

## Use

Python 3.10 or newer is required.

```python
from agentshield import IngestClient

ingest = IngestClient(
    "http://127.0.0.1:8081",
    run_id="8bbbc043619641aba8007a9f255b2665",
    token=run_scoped_token,
    timeout=3,
)

receipt = ingest.checkpoint(
    "tool_started",
    phase="execute",
    tool_name="python",
    summary="Running the redacted analysis step",
    labels={"risk": "reviewed"},
)
```

The client creates a positive decimal-string sequence, a stable idempotency
key, and an untrusted client timestamp. Calls are serialized, so concurrent
threads cannot deliver later sequences before earlier ones. `429` and `503`
responses are retried at most `max_retries` times, reusing the exact body,
sequence, idempotency key, and Authorization value. Redirects are returned as
errors and are never followed, preventing a redirect target from receiving the
Run token. Plain HTTP is accepted only for loopback addresses or `localhost`;
non-loopback endpoints must use HTTPS.

A timeout, connection failure, malformed success response, or oversized
response leaves the delivery outcome ambiguous. The client retains the exact
serialized checkpoint and blocks new checkpoints until it is resolved:

```python
from agentshield import IngestProtocolError, IngestTransportError

try:
    ingest.checkpoint("tool_finished", summary="Completed without raw output")
except (IngestProtocolError, IngestTransportError):
    receipt = ingest.retry_pending()
```

`retry_pending()` reuses the same sequence, idempotency key, timestamp, and
body, so a server that already accepted the first attempt can return its stable
replay result. If that retry receives a definite HTTP error, the client keeps
the ambiguous checkpoint pending; reconcile the Run before creating another
client or advancing its sequence.

## Privacy and failure behavior

Send only short, redacted semantic summaries. Do not put full prompts, model
outputs, private chain-of-thought, tokens, secrets, or complete file contents in
`summary`, `labels`, or `metadata`.

The client does not log. Its representation redacts the token, and its
exceptions never include the Authorization value, request body, response body,
or underlying transport exception. Successful responses are limited to 128 KiB
and checked for the fixed Run, sequence, idempotency key, source, and decimal
server clocks before they are returned.

The Agent may report `run_finished`, but that is still an `agent_claim`; it does
not finish the Run or clean its cgroup scope. A trusted supervisor must first
observe actual task/container exit, then invoke the separate management finish
operation.

## Verify

```sh
python -m unittest discover -s tests -v
```
