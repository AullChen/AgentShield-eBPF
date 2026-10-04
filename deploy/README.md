# Demo deployment

`compose.demo.yaml` runs the loopback dashboard and gated, unprivileged sandbox. The host Core is managed by `scripts/demo.sh`.

Start the deployment through the [demo script](../docs/demo-guide.md). It generates separate credentials, validates the fake-secret mount and sandbox cgroup, waits for hook attachment, and releases the workload in that order.
