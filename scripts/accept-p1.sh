#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo "Day 17 P1 acceptance requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run P1 acceptance as root on an isolated test host" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) echo "unsupported architecture: $(uname -m); expected x86_64 or aarch64" >&2; exit 1 ;;
esac
if [ ! -r /etc/os-release ]; then
  echo "cannot verify the supported Ubuntu 24.04 baseline" >&2
  exit 1
fi
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
  echo "unsupported distribution: ${ID:-unknown} ${VERSION_ID:-unknown}; expected Ubuntu 24.04" >&2
  exit 1
fi
kernel_version=$(uname -r | cut -d- -f1)
if [ "$(printf '%s\n' 5.15 "$kernel_version" | sort -V | head -n 1)" != 5.15 ]; then
  echo "unsupported kernel: $kernel_version; expected 5.15 or newer" >&2
  exit 1
fi
if [ ! -r /sys/kernel/btf/vmlinux ]; then
  echo "kernel BTF is required at /sys/kernel/btf/vmlinux" >&2
  exit 1
fi
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" != cgroup2fs ]; then
  echo "cgroup v2 is required at /sys/fs/cgroup" >&2
  exit 1
fi

object_path=${1:-bpf/agentshield.bpf.o}
manifest_path=${2:-bpf/agentshield.bpf.manifest.json}
evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-tmp/acceptance/day17}

for path in "$object_path" "$manifest_path"; do
  if [ ! -r "$path" ]; then
    echo "required artifact is not readable: $path" >&2
    exit 1
  fi
done

umask 077
mkdir -p "$evidence_root"
evidence_dir=$(mktemp -d "$evidence_root/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
run_id=${evidence_dir##*/}
cgroup_path="/sys/fs/cgroup/agentshield-p1-$run_id"
mkdir "$cgroup_path"

binary="$evidence_dir/agentshield"
events_log="$evidence_dir/events.raw.jsonl"
runtime_log="$evidence_dir/runtime.log"
summary="$evidence_dir/summary.sanitized.json"
strict_error="$evidence_dir/network-check.txt"
coverage="$evidence_dir/coverage-matrix.sanitized.md"
file_marker="agentshield-day17-file-$run_id"
exec_marker="agentshield-day17-exec-$run_id"
fixture="$evidence_dir/$file_marker"
audit_pid=

cleanup() {
  if [ -n "${audit_pid:-}" ] && kill -0 "$audit_pid" 2>/dev/null; then
    kill -INT "$audit_pid" 2>/dev/null || true
    wait "$audit_pid" 2>/dev/null || true
  fi
  rmdir "$cgroup_path" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

{
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kernel=$(uname -srvm)"
  echo "architecture=$(uname -m)"
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "distribution=${NAME:-unknown} ${VERSION_ID:-unknown}"
  fi
  echo "cgroup_filesystem=$(stat -fc %T /sys/fs/cgroup)"
  echo "btf_vmlinux_readable=$([ -r /sys/kernel/btf/vmlinux ] && echo true || echo false)"
  sha256sum "$object_path" "$manifest_path"
  if [ -r "/boot/config-$(uname -r)" ]; then
    grep -E '^CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|CGROUP_BPF|DEBUG_INFO_BTF)=' "/boot/config-$(uname -r)" || true
  fi
} >"$evidence_dir/environment.txt"

cat >"$evidence_dir/reproduction-commands.txt" <<EOF
make bpf-object
sudo ./scripts/accept-p1.sh $object_path $manifest_path
./scripts/test-network.sh http://127.0.0.1:18080/agentshield-day17-ipv4 http://[::1]:18080/agentshield-day17-ipv6
EOF

cp "$manifest_path" "$evidence_dir/object.manifest.json"
go run ./cmd/bpfcheck --object "$object_path" --verify-manifest "$manifest_path" >"$evidence_dir/object-verification.json"
go test ./internal/events ./internal/bpfmgr -count=1 >"$evidence_dir/go-tests.txt"
go build -trimpath -buildvcs=false -o "$binary" ./cmd/agentshield

start_audit() {
  : >"$events_log"
  : >"$runtime_log"
  "$binary" audit --bpf-object "$object_path" "$@" >"$events_log" 2>"$runtime_log" &
  audit_pid=$!
}

wait_for_ready() {
  for _ in $(seq 1 100); do
    if grep -q 'kernel audit hooks attached' "$runtime_log"; then
      return 0
    fi
    if ! kill -0 "$audit_pid" 2>/dev/null; then
      wait "$audit_pid" || true
      audit_pid=
      return 1
    fi
    sleep 0.1
  done
  kill -INT "$audit_pid" 2>/dev/null || true
  wait "$audit_pid" 2>/dev/null || true
  audit_pid=
  return 1
}

network_attach_status=PASS
start_audit --cgroup "$cgroup_path"
if ! wait_for_ready; then
  network_attach_status=ROADMAP
  mv "$runtime_log" "$evidence_dir/network-attach.log"
  mv "$events_log" "$evidence_dir/network-attach-events.raw.jsonl"
  start_audit
  if ! wait_for_ready; then
    echo "file/exec kernel load or tracepoint attachment failed; see $runtime_log" >&2
    exit 1
  fi
fi

printf 'AgentShield P1 fixture\n' >"$fixture"
(
  echo "$BASHPID" >"$cgroup_path/cgroup.procs"
  cat -- "$fixture" >/dev/null
  long_arg=$(printf 'x%.0s' $(seq 1 96))
  /bin/echo "" "$exec_marker" "$long_arg" >/dev/null
  ./scripts/test-network.sh \
    http://127.0.0.1:18080/agentshield-day17-ipv4 \
    'http://[::1]:18080/agentshield-day17-ipv6'
)
sleep 1

kill -TERM "$audit_pid"
wait "$audit_pid"
audit_pid=

ipv4_status=$network_attach_status
if [ "$network_attach_status" != PASS ]; then
  echo "connect4/connect6 verifier or attachment failed; see network-attach.log" >"$strict_error"
fi
if [ "$ipv4_status" = PASS ] && ! go run ./cmd/auditcheck \
  --input "$events_log" \
  --file-marker "$file_marker" \
  --exec-marker "$exec_marker" \
  --ipv4-destination 127.0.0.1:18080 \
  --require-receipt-clocks >/dev/null 2>"$strict_error"; then
  ipv4_status=ROADMAP
fi
ipv6_status=$network_attach_status
if [ "$ipv6_status" = PASS ] && ! go run ./cmd/auditcheck \
  --input "$events_log" \
  --file-marker "$file_marker" \
  --exec-marker "$exec_marker" \
  --ipv6-destination '[::1]:18080' \
  --require-receipt-clocks >/dev/null 2>>"$strict_error"; then
  ipv6_status=ROADMAP
fi

stable_types=2
if [ "$ipv4_status" = PASS ] && [ "$ipv6_status" = PASS ]; then
  stable_types=3
  go run ./cmd/auditcheck \
    --input "$events_log" \
    --file-marker "$file_marker" \
    --exec-marker "$exec_marker" \
    --ipv4-destination 127.0.0.1:18080 \
    --ipv6-destination '[::1]:18080' \
    --require-receipt-clocks >"$summary"
else
  go run ./cmd/auditcheck \
    --input "$events_log" \
    --file-marker "$file_marker" \
    --exec-marker "$exec_marker" \
    --require-receipt-clocks >"$summary"
fi

cat >"$coverage" <<EOF
# P1 pre-M1 coverage ($run_id)

| Event path | Status | Evidence |
| --- | --- | --- |
| file/openat attempt | PASS | summary.sanitized.json |
| exec/execve attempt | PASS | summary.sanitized.json |
| TCP IPv4 connect4 | $ipv4_status | summary.sanitized.json / network-check.txt |
| TCP IPv6 connect6 | $ipv6_status | summary.sanitized.json / network-check.txt |
| openat2 | ROADMAP | not instrumented |
| execveat | ROADMAP | not instrumented |
| UDP and AF_UNIX | ROADMAP | not instrumented |

Stable event classes: $stable_types/3. P1 pre-M1 requires file + exec (2/3); network counts as stable only when both IPv4 and IPv6 pass. Final MVP requires 3/3.
Object, environment, reproduction commands, ABI, and runtime evidence are stored in this owner-only directory.
EOF

echo "P1 pre-M1 acceptance passed with $stable_types/3 stable event classes."
echo "Sanitized coverage: $coverage"
echo "Raw host-wide file/exec events remain owner-only and must not be committed."
