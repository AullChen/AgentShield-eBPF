# Sandbox

The minimal demo Agent deliberately performs four auditable actions:

- opens the repository-owned fake fixture at `/demo-secrets/example-token`;
- executes `/bin/echo`;
- attempts TCP connections to IPv4 and IPv6 loopback.

No host credential or real secret may be mounted. `compose.yaml` fixes the only
bind source to `fixtures/demo-secrets/example-token`, mounts it read-only, runs
as an unprivileged user, drops all capabilities, and uses a read-only root
filesystem.

Run the reproducible Linux acceptance:

```sh
./scripts/accept-sandbox.sh
```

The command records the repository fixture's host path and SHA-256, then records
the container mount namespace, mount ID/options, and device/inode without
printing the fixture content. Raw evidence is owner-only under
`tmp/acceptance/day20/` and must not be committed.
