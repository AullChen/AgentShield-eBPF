# File and Exec Audit Notes

The unified Linux audit loop attaches both syscall-entry tracepoints and emits
their events through the same ring buffer as JSON schema v2 Lines carrying
Kernel Event wire schema v2 records.

> **Safety warning:** scope filtering is not implemented yet. The probes observe
> matching syscalls from the entire host, and the JSON output contains raw bounded
> path/argv fragments that may include credentials. Use this command only in an
> isolated VM or dedicated test host.

## Trigger Check

Start the audit loop with a compiled CO-RE object:

```sh
sudo ./bin/agentshield audit --bpf-object ./bpf/agentshield.bpf.o
```

In another terminal, run:

```sh
./scripts/test-audit.sh
```

The output should contain at least one `file_open` event and one `exec_attempt`
event. The script only triggers the events; it does not build or load eBPF.

For the actual Day 14 verifier/load/attach and edge-case gate, use
`scripts/accept-file-exec.sh` as documented in
`docs/file-exec-acceptance.md`; visually observing two lines is not sufficient.

Both are attempt events. Their `action_result` is `none`; a syscall-entry
tracepoint cannot establish that the operation was allowed, succeeded, or read
any data. `timestamp_ns` is a monotonic kernel timestamp rather than Unix epoch
time. JSON schema v2 encodes `timestamp_ns` and `cgroup_id` as decimal strings
to preserve all 64-bit values in JavaScript clients. The separate
`wire_schema_version` field identifies the BPF record ABI (currently v2).
Invalid UTF-8 in `comm`, `data`, or an argv slot is Base64-encoded, with that
field listed as `base64` in the `raw_encoding` object; it is never silently
replaced with the Unicode replacement character.

## Tracepoint Field Differences

| Field | `sys_enter_openat` | `sys_enter_execve` |
| --- | --- | --- |
| Primary data | `args[1]` filename | `args[0]` executable filename |
| Extra data | `args[2]` open flags | `args[1]` argv pointer array |
| `data` JSON field | Up to 255 bytes of filename | Up to 127 bytes of executable filename |
| `argv` JSON field | Omitted | Up to four arguments, 31 bytes each |

Important semantics:

- An `openat` filename may be relative to its directory file descriptor. The
  current event does not resolve it to an absolute path.
- The `execve` filename is the user-supplied syscall value. It may also be
  relative and is not guaranteed to be the final resolved executable path.
- `comm` is captured at syscall entry, before a successful exec changes the
  task name.
- `ppid` is read from the current task through CO-RE, because it is not a
  syscall tracepoint argument.
- Long executable names, arguments, or argument lists set `truncated=true`.
- These are attempt events. A syscall-entry tracepoint does not prove that the
  file open or process execution succeeded.
- Up to four arguments are captured. The wire record carries the captured slot
  count so a legal empty-string argument does not hide later arguments.
- An isolated malformed v2 ring-buffer record is skipped; at most the first
  three malformed records are logged. Three consecutive malformed records stop
  the audit loop to expose a likely object/decoder mismatch. Any legacy or
  future wire schema stops immediately rather than being silently
  misinterpreted.
