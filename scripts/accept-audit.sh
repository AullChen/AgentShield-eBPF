#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo "Audit acceptance requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run audit acceptance as root on an isolated test host" >&2
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
evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-tmp/acceptance/audit}

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
cgroup_path="/sys/fs/cgroup/agentshield-audit-$run_id"
mkdir "$cgroup_path"

binary="$evidence_dir/agentshield"
events_log="$evidence_dir/events.raw.jsonl"
runtime_log="$evidence_dir/runtime.log"
summary="$evidence_dir/summary.sanitized.json"
strict_error="$evidence_dir/network-check.txt"
coverage="$evidence_dir/coverage-matrix.sanitized.md"
file_marker="agentshield-audit-file-$run_id"
exec_marker="agentshield-audit-exec-$run_id"
fixture="$evidence_dir/$file_marker"
host_marker="agentshield-host-negative-$run_id"
host_fixture="$evidence_dir/$host_marker"
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
sudo ./scripts/accept-audit.sh $object_path $manifest_path
./scripts/test-network.sh http://127.0.0.1:18080/agentshield-audit-ipv4 http://[::1]:18080/agentshield-audit-ipv6
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

start_audit --scope-cgroup "$cgroup_path"
if ! wait_for_ready; then
  echo "exact-scope kernel load or attachment failed; see $runtime_log" >&2
  exit 1
fi

printf 'AgentShield audit fixture\n' >"$fixture"
(
  echo "$BASHPID" >"$cgroup_path/cgroup.procs"
  cat -- "$fixture" >/dev/null
  long_arg=$(printf 'x%.0s' $(seq 1 96))
  /bin/echo "" "$exec_marker" "$long_arg" >/dev/null
  ./scripts/test-network.sh \
    http://127.0.0.1:18080/agentshield-audit-ipv4 \
    'http://[::1]:18080/agentshield-audit-ipv6'
)
printf 'AgentShield host negative fixture\n' >"$host_fixture"
cat -- "$host_fixture" >/dev/null
/bin/echo "$host_marker" >/dev/null
./scripts/test-network.sh \
  http://127.0.0.1:18081/agentshield-host-negative \
  'http://[::1]:18081/agentshield-host-negative'
sleep 1

kill -TERM "$audit_pid"
wait "$audit_pid"
audit_pid=

if grep -F "$host_marker" "$events_log" >/dev/null; then
  echo "unregistered host file/exec activity leaked into exact-scope events" >&2
  exit 1
fi
if grep -E '"dst_port":18081([,}])' "$events_log" >/dev/null; then
  echo "unregistered host network activity leaked into exact-scope events" >&2
  exit 1
fi

if ! go run ./cmd/auditcheck \
  --input "$events_log" \
  --file-marker "$file_marker" \
  --exec-marker "$exec_marker" \
  --ipv4-destination 127.0.0.1:18080 \
  --require-receipt-clocks \
  --require-scope-identity >/dev/null 2>"$strict_error"; then
  echo "IPv4 exact-scope acceptance failed; see $strict_error" >&2
  exit 1
fi
if ! go run ./cmd/auditcheck \
  --input "$events_log" \
  --file-marker "$file_marker" \
  --exec-marker "$exec_marker" \
  --ipv6-destination '[::1]:18080' \
  --require-receipt-clocks \
  --require-scope-identity >/dev/null 2>>"$strict_error"; then
  echo "IPv6 exact-scope acceptance failed; see $strict_error" >&2
  exit 1
fi

go run ./cmd/auditcheck \
  --input "$events_log" \
  --file-marker "$file_marker" \
  --exec-marker "$exec_marker" \
  --ipv4-destination 127.0.0.1:18080 \
  --ipv6-destination '[::1]:18080' \
  --require-receipt-clocks \
  --require-scope-identity >"$summary"

cat >"$coverage" <<EOF
# Audit coverage ($run_id)

| Event path | Status | Evidence |
| --- | --- | --- |
| file/openat attempt | PASS | summary.sanitized.json |
| exec/execve attempt | PASS | summary.sanitized.json |
| TCP IPv4 connect4 | PASS | summary.sanitized.json / network-check.txt |
| TCP IPv6 connect6 | PASS | summary.sanitized.json / network-check.txt |
| openat2 | ROADMAP | not instrumented |
| execveat | ROADMAP | not instrumented |
| UDP and AF_UNIX | ROADMAP | not instrumented |

Stable event classes: 3/3. The combined gate fails on any required file, exec, IPv4, or IPv6 verifier/attach/capture error.
Object, environment, reproduction commands, ABI, and runtime evidence are stored in this owner-only directory.
EOF

echo "Audit acceptance passed with 3/3 stable event classes."
echo "Sanitized coverage: $coverage"
echo "Raw exact-scope events remain owner-only and must not be committed."
