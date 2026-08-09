#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
object_path="${1:-$repo_root/bpf/agentshield.bpf.o}"
binary_path="$repo_root/bin/agentshield"
policy_path="$repo_root/configs/strict-network-profile.yaml"
cgroup_path="/sys/fs/cgroup/agentshield-day33-$$"
evidence_dir="$(mktemp -d)"
audit_pid=""

cleanup() {
  if [[ -n "$audit_pid" ]]; then
    kill -TERM "$audit_pid" 2>/dev/null || true
    wait "$audit_pid" 2>/dev/null || true
  fi
  rmdir "$cgroup_path" 2>/dev/null || true
  rm -rf "$evidence_dir"
}
trap cleanup EXIT

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "network block acceptance requires root" >&2
  exit 2
fi
if [[ ! -f "$object_path" || ! -x "$binary_path" ]]; then
  echo "missing BPF object or agentshield binary; run make bpf-object build" >&2
  exit 2
fi

mkdir "$cgroup_path"
"$binary_path" audit \
  --bpf-object "$object_path" \
  --scope-cgroup "$cgroup_path" \
  --policy-file "$policy_path" \
  >"$evidence_dir/events.jsonl" 2>"$evidence_dir/audit.log" &
audit_pid=$!

for _ in {1..100}; do
  if grep -q 'kernel audit hooks attached' "$evidence_dir/audit.log"; then
    break
  fi
  if ! kill -0 "$audit_pid" 2>/dev/null; then
    cat "$evidence_dir/audit.log" >&2
    exit 1
  fi
  sleep 0.05
done
if ! grep -q 'kernel audit hooks attached' "$evidence_dir/audit.log"; then
  echo "audit did not become ready" >&2
  exit 1
fi

CGROUP_PATH="$cgroup_path" bash -c '
  echo $$ >"$CGROUP_PATH/cgroup.procs"
  python3 - <<"PY"
import errno
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect(("127.0.0.1", 9))
except OSError as error:
    if error.errno not in (errno.EPERM, errno.EACCES):
        raise SystemExit(f"connect was not blocked by cgroup hook: {error}")
else:
    raise SystemExit("connect unexpectedly succeeded")
finally:
    sock.close()
PY
'

for _ in {1..100}; do
  if grep -q '"action_result_name":"blocked"' "$evidence_dir/events.jsonl"; then
    break
  fi
  sleep 0.05
done

EVIDENCE_PATH="$evidence_dir/events.jsonl" python3 - <<'PY'
import json
import os

records = []
with open(os.environ["EVIDENCE_PATH"], encoding="utf-8") as stream:
    for line in stream:
        records.append(json.loads(line))

blocked = next((record for record in records
                if record.get("event_type_name") == "net_connect"
                and record.get("action_name") == "block"
                and record.get("action_result_name") == "blocked"), None)
if blocked is None:
    raise SystemExit("blocked kernel network event was not emitted")

decision = next((record for record in records
                 if record.get("record_type") == "policy_decision"
                 and record.get("kernel_monotonic_ns") == blocked.get("kernel_monotonic_ns")), None)
if decision is None or not decision.get("final", {}).get("enforced"):
    raise SystemExit("enforced policy decision was not correlated with blocked event")
print("network block acceptance passed")
PY
