#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo "Day 14 acceptance requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run Day 14 acceptance as root on an isolated test host" >&2
  exit 1
fi

object_path=${1:-bpf/agentshield.bpf.o}
manifest_path=${2:-bpf/agentshield.bpf.manifest.json}
evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-tmp/acceptance/day14}

for path in "$object_path" "$manifest_path"; do
  if [ ! -r "$path" ]; then
    echo "required artifact is not readable: $path" >&2
    exit 1
  fi
done

umask 077
run_id=$(date -u +%Y%m%dT%H%M%SZ)
evidence_dir="$evidence_root/$run_id"
mkdir -p "$evidence_dir"

binary="$evidence_dir/agentshield"
events_log="$evidence_dir/events.raw.jsonl"
runtime_log="$evidence_dir/runtime.log"
summary="$evidence_dir/summary.sanitized.json"
file_marker="agentshield-day14-file-$run_id"
exec_marker="agentshield-day14-exec-$run_id"
fixture="$evidence_dir/$file_marker"
audit_pid=

cleanup() {
  if [ -n "${audit_pid:-}" ] && kill -0 "$audit_pid" 2>/dev/null; then
    kill -INT "$audit_pid" 2>/dev/null || true
    wait "$audit_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

{
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -srvm)"
  echo "architecture=$(uname -m)"
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "distribution=${NAME:-unknown} ${VERSION_ID:-unknown}"
  fi
  echo "cgroup_filesystem=$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo unknown)"
  echo "btf_vmlinux_readable=$([ -r /sys/kernel/btf/vmlinux ] && echo true || echo false)"
  sha256sum "$object_path" "$manifest_path"
} >"$evidence_dir/environment.txt"

cp "$manifest_path" "$evidence_dir/object.manifest.json"
go run ./cmd/bpfcheck \
  --object "$object_path" \
  --verify-manifest "$manifest_path" >"$evidence_dir/object-verification.json"
go test ./internal/events -run 'TestKernelEventV2WireSize|TestDecodeKernelExecEventV2' -count=1 >"$evidence_dir/abi-test.txt"
go build -trimpath -buildvcs=false -o "$binary" ./cmd/agentshield

"$binary" audit --bpf-object "$object_path" >"$events_log" 2>"$runtime_log" &
audit_pid=$!

ready=false
for _ in $(seq 1 100); do
  if grep -q 'kernel audit hooks attached' "$runtime_log"; then
    ready=true
    break
  fi
  if ! kill -0 "$audit_pid" 2>/dev/null; then
    wait "$audit_pid" || true
    echo "audit process exited before hooks attached; see $runtime_log" >&2
    exit 1
  fi
  sleep 0.1
done
if [ "$ready" != true ]; then
  echo "timed out waiting for kernel load and tracepoint attachment" >&2
  exit 1
fi

printf 'AgentShield Day 14 fixture\n' >"$fixture"
cat -- "$fixture" >/dev/null
long_arg=$(printf 'x%.0s' $(seq 1 96))
/bin/echo "" "$exec_marker" "$long_arg" >/dev/null
sleep 1

kill -INT "$audit_pid"
wait "$audit_pid"
audit_pid=

go run ./cmd/auditcheck \
  --input "$events_log" \
  --file-marker "$file_marker" \
  --exec-marker "$exec_marker" >"$summary"

echo "Day 14 acceptance passed. Sanitized summary: $summary"
echo "Raw host-wide events remain owner-only under $evidence_dir and must not be committed."
