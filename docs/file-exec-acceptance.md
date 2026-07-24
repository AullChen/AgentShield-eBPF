# Day 14 File and Exec Runtime Acceptance

Status in this repository snapshot: **automated gate implemented; supported
Linux execution evidence not available from the Windows development host**.
This status must not be rewritten as a kernel load/attach pass until the script
below succeeds on an isolated supported Linux host.

## Gate

After `make bpf-object`, run as root only on an isolated VM or dedicated test
host:

```sh
sudo ./scripts/accept-file-exec.sh
```

The command fails unless all of these conditions hold:

1. `ebpf.NewCollection` creates maps and passes the kernel verifier.
2. Both `sys_enter_openat` and `sys_enter_execve` links attach.
3. A marker file produces `file_open` with `action_result=none`.
4. `/bin/echo` produces `exec_attempt` with `action_result=none`.
5. A legal empty argument is preserved before a marker argument.
6. A long argument produces `truncated=true`.
7. The C/Go wire-v3 size/offset, scope identity, and exec decode tests pass.
8. The supplied object hash and parsed program/map specifications match the
   supplied build manifest.

Each invocation atomically creates a distinct owner-only evidence directory,
including for concurrent runs. The directory contains the environment,
object/manifest hashes, object/manifest verification output, ABI test output,
runtime log, raw JSON Lines, and a sanitized summary.
Only the sanitized summary is suitable for review. Raw output is intentionally
under ignored `tmp/` because scoped paths and argv values may still be sensitive.

`LoadCollectionSpec` or `make verify-bpf-object` alone does not satisfy this
gate. If verifier or attachment fails, preserve `runtime.log`, record the exact
kernel/toolchain/object hash, and leave the status failed.
