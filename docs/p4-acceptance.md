# P4 source acceptance

Day 40 closes the source-level P4 evidence contract. The tracked sample is
[`examples/p4-evidence-timeline.json`](examples/p4-evidence-timeline.json).

Every timeline item has an explicit source and decimal-string sequence and
server clocks. Agent checkpoints are `agent_claim`; observed syscall attempts
are `kernel_fact`; matcher output is `policy_decision`; and fallback execution
is a separate `containment_result`.

The exec example deliberately records the original operation as
`action_result=none`: the entry tracepoint observed an attempt but did not prove
success. Its later cgroup containment is recorded independently as `killed`.
The network example is different: `cgroup/connect4` synchronously returned a
deny and therefore records `action_result=blocked` and an enforced block
decision. These meanings must not be collapsed in storage, APIs, or the UI.
The schema enforces a mutually exclusive source-field matrix: Agent claims
cannot carry attribution, correlation, or authoritative results; those fields
are accepted only on the server-derived source that owns them.

Attribution states their `{instance_id,scope_cookie}` basis. Correlation embeds
the selected checkpoint, confidence, authoritative server-monotonic clock, and
all score factors. Confidence describes association strength, not truth or
causality.

Reproduce and verify the source sample with:

```sh
go run ./cmd/evidencecheck
go test ./internal/evidence -run '^TestP4Acceptance$' -count=1
```

The test reconstructs the sample and compares its semantic JSON with the
tracked artifact. This gate uses deterministic fixtures; production reader,
checkpoint-store, and containment-store wiring remains pending and is not
presented as live P4 runtime evidence.
