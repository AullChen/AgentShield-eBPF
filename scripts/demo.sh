#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/demo.sh --isolated-vm [--non-interactive]

Runs the host eBPF Core plus Compose-managed Dashboard and unprivileged Sandbox.
Use only in a disposable, dedicated Linux VM. Raw evidence is written owner-only
under tmp/demo/ and may contain bounded process/path metadata.

Options:
  --isolated-vm      Required acknowledgement of the dedicated-VM boundary.
  --non-interactive  Verify the three kernel event classes, capture snapshots,
                     then stop all demo processes instead of waiting for Ctrl-C.
EOF
}

acknowledged=0
non_interactive=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --isolated-vm) acknowledged=1 ;;
    --non-interactive) non_interactive=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$acknowledged" -ne 1 ] && [ "${AGENTSHIELD_DEMO_ISOLATED_VM:-0}" != "1" ]; then
  echo "refusing to load eBPF without the --isolated-vm acknowledgement" >&2
  usage >&2
  exit 2
fi
if [ "$(uname -s)" != "Linux" ]; then
  echo "the end-to-end demo requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run the demo as root: sudo ./scripts/demo.sh --isolated-vm" >&2
  exit 1
fi

for command in awk cut curl docker find git go grep head make openssl readlink seq sha256sum sort stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 1
  fi
done
if [ ! -r /etc/os-release ]; then
  echo "cannot verify the supported Ubuntu 24.04 baseline" >&2
  exit 1
fi
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
  echo "unsupported distribution: ${ID:-unknown} ${VERSION_ID:-unknown}; expected Ubuntu 24.04" >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) echo "unsupported architecture: $(uname -m); expected x86_64 or aarch64" >&2; exit 1 ;;
esac
kernel_version=$(uname -r | cut -d- -f1)
if [ "$(printf '%s\n' 5.15 "$kernel_version" | sort -V | head -n 1)" != 5.15 ]; then
  echo "unsupported kernel: $kernel_version; expected 5.15 or newer" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required" >&2
  exit 1
fi
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" != cgroup2fs ]; then
  echo "cgroup v2 is not mounted at /sys/fs/cgroup" >&2
  exit 1
fi
if [ ! -r /sys/kernel/btf/vmlinux ]; then
  echo "kernel BTF is not readable at /sys/kernel/btf/vmlinux" >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=$repo_root
compose_file="$repo_root/deploy/compose.demo.yaml"
fixture="$repo_root/sandbox/fixtures/demo-secrets/example-token"
fixture_source=$(readlink -f "$fixture")
if [ "$fixture_source" != "$fixture" ]; then
  echo "demo fixture must be the repository-owned regular file: $fixture" >&2
  exit 1
fi
if [ ! -f "$fixture_source" ]; then
  echo "repository demo fixture is missing" >&2
  exit 1
fi

project=agentshield-demo
container_name=agentshield-demo-agent
if docker container inspect "$container_name" >/dev/null 2>&1; then
  echo "container $container_name already exists; inspect and remove it manually" >&2
  exit 1
fi
if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]; then
  echo "Compose project $project is already running; stop it before starting a new demo" >&2
  exit 1
fi
for url in http://127.0.0.1:8080/ http://127.0.0.1:3000/; do
  if curl --silent --max-time 1 --output /dev/null "$url"; then
    echo "required loopback endpoint is already in use: $url" >&2
    exit 1
  fi
done

evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-"$repo_root/tmp/demo"}
umask 077
mkdir -p "$evidence_root"
evidence_dir=$(mktemp -d "$evidence_root/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
core_pid=
container_started=0
compose_started=0

collect_failure() {
  status=$1
  line=$2
  set +e
  {
    echo "exit_status=$status"
    echo "failed_line=$line"
    echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    uname -a
  } >"$evidence_dir/failure-diagnostics.txt"
  docker compose --project-name "$project" -f "$compose_file" ps --all \
    >"$evidence_dir/compose-ps.txt" 2>&1
  if [ "$container_started" -eq 1 ]; then
    docker logs "$container_name" >"$evidence_dir/sandbox-output.txt" 2>&1
  fi
  echo "Demo failed at line $line (status $status). Diagnostics: $evidence_dir" >&2
}

cleanup() {
  set +e
  if [ -n "$core_pid" ] && kill -0 "$core_pid" 2>/dev/null; then
    kill -TERM "$core_pid" 2>/dev/null
    wait "$core_pid" 2>/dev/null
  fi
  if [ "$container_started" -eq 1 ]; then
    docker rm --force "$container_name" >/dev/null 2>&1
  fi
  if [ "$compose_started" -eq 1 ]; then
    docker compose --project-name "$project" -f "$compose_file" down --remove-orphans >/dev/null 2>&1
  fi
}

on_exit() {
  status=$?
  line=${BASH_LINENO[0]:-unknown}
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ]; then
    collect_failure "$status" "$line"
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT INT TERM

fixture_hash=$(sha256sum "$fixture_source" | awk '{print $1}')
read_token=$(openssl rand -hex 32)
dashboard_token=$(openssl rand -hex 32)
read_token_file="$evidence_dir/read-token"
printf '%s\n' "$read_token" >"$read_token_file"
chmod 0600 "$read_token_file"

{
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "fixture_source=$fixture_source"
  echo "fixture_sha256=$fixture_hash"
  echo "kernel=$(uname -r)"
  echo "architecture=$(uname -m)"
  go version
  docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
  docker compose version
} >"$evidence_dir/environment.txt"

echo "[1/6] Building the CO-RE object and Core binary..."
make bpf-object >"$evidence_dir/bpf-build.txt" 2>&1
go build -o "$evidence_dir/agentshield" ./cmd/agentshield \
  >"$evidence_dir/go-build.txt" 2>&1
sha256sum bpf/agentshield.bpf.o bpf/agentshield.bpf.manifest.json \
  "$evidence_dir/agentshield" >"$evidence_dir/artifact-sha256.txt"

export AGENTSHIELD_FIXTURE_SHA256=$fixture_hash
export AGENTSHIELD_READ_TOKEN=$read_token
export AGENTSHIELD_DASHBOARD_TOKEN=$dashboard_token
echo "[2/6] Building the Dashboard and Sandbox images..."
docker compose --project-name "$project" -f "$compose_file" build --pull \
  >"$evidence_dir/compose-build.txt" 2>&1
docker image inspect --format '{{.RepoTags}} {{.Id}}' \
  agentshield-dashboard-demo:local agentshield-sandbox-demo:local \
  >"$evidence_dir/image-identities.txt"

echo "[3/6] Starting the Dashboard and gated Sandbox..."
compose_started=1
docker compose --project-name "$project" -f "$compose_file" up -d dashboard \
  >"$evidence_dir/dashboard-start.txt" 2>&1
container_started=1
docker compose --project-name "$project" -f "$compose_file" run -d \
  --name "$container_name" --no-deps agent >"$evidence_dir/sandbox-start.txt"
container_pid=$(docker inspect --format '{{.State.Pid}}' "$container_name")
case "$container_pid" in
  ''|*[!0-9]*|0) echo "could not determine the sandbox host PID" >&2; exit 1 ;;
esac
cgroup_relative=$(awk -F: '$1 == "0" { print $3; found = 1 } END { if (!found) exit 1 }' "/proc/$container_pid/cgroup")
scope_cgroup=$(readlink -f "/sys/fs/cgroup/${cgroup_relative#/}")
case "$scope_cgroup" in
  /sys/fs/cgroup/*) ;;
  *) echo "sandbox cgroup escaped the trusted cgroup v2 root" >&2; exit 1 ;;
esac
if find "$scope_cgroup" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  echo "Docker placed the sandbox in a non-leaf cgroup: $scope_cgroup" >&2
  exit 1
fi
printf 'sandbox_container=%s\nsandbox_pid=%s\nscope_cgroup=%s\n' \
  "$container_name" "$container_pid" "$scope_cgroup" >>"$evidence_dir/environment.txt"

run_id="demo-$(date -u +%Y%m%dT%H%M%SZ)"
echo "[4/6] Loading eBPF and attaching the exact sandbox leaf..."
"$evidence_dir/agentshield" audit \
  --bpf-object "$repo_root/bpf/agentshield.bpf.o" \
  --scope-cgroup "$scope_cgroup" \
  --policy-file "$repo_root/configs/default-policies.yaml" \
  --api-listen 127.0.0.1:8080 \
  --read-token-file "$read_token_file" \
  --run-id "$run_id" \
  >"$evidence_dir/core-output.jsonl" 2>"$evidence_dir/core-log.txt" &
core_pid=$!

hooks_ready=0
for _ in $(seq 1 40); do
  if ! kill -0 "$core_pid" 2>/dev/null; then
    echo "Core exited before the BPF hooks became ready" >&2
    exit 1
  fi
  if curl --fail --silent --max-time 2 \
    --header "Authorization: Bearer $read_token" \
    http://127.0.0.1:8080/api/v1/diagnostics \
    >"$evidence_dir/diagnostics.json" && \
    grep -F '"load_attach":{"status":"available"' "$evidence_dir/diagnostics.json" >/dev/null; then
    hooks_ready=1
    break
  fi
  sleep 0.25
done
if [ "$hooks_ready" -ne 1 ]; then
  echo "Core did not report successful BPF load/attach within 10 seconds" >&2
  exit 1
fi
if ! curl --fail --silent --max-time 10 \
  --user "agentshield:$dashboard_token" \
  http://127.0.0.1:3000/ >"$evidence_dir/dashboard-overview.html"; then
  echo "Dashboard did not become ready" >&2
  exit 1
fi

echo "[5/6] Releasing the fake-secret attack after the hooks are ready..."
docker exec "$container_name" /bin/sh -c 'umask 077; : > /tmp/agentshield-start'
for _ in $(seq 1 40); do
  running=$(docker inspect --format '{{.State.Running}}' "$container_name")
  [ "$running" = "false" ] && break
  sleep 0.25
done
if [ "$(docker inspect --format '{{.State.Running}}' "$container_name")" != "false" ]; then
  echo "sandbox did not exit within 10 seconds" >&2
  exit 1
fi
sandbox_status=$(docker inspect --format '{{.State.ExitCode}}' "$container_name")
docker logs "$container_name" >"$evidence_dir/sandbox-output.txt" 2>&1
if [ "$sandbox_status" -ne 0 ]; then
  echo "sandbox exited with status $sandbox_status" >&2
  exit 1
fi

events_ready=0
for _ in $(seq 1 40); do
  if grep -F '"event_type_name":"file_open"' "$evidence_dir/core-output.jsonl" >/dev/null && \
     grep -F '"event_type_name":"exec_attempt"' "$evidence_dir/core-output.jsonl" >/dev/null && \
     grep -F '"event_type_name":"net_connect"' "$evidence_dir/core-output.jsonl" >/dev/null; then
    events_ready=1
    break
  fi
  sleep 0.25
done
if [ "$events_ready" -ne 1 ]; then
  echo "did not observe all three kernel event classes within 10 seconds" >&2
  exit 1
fi
grep -F '"wire_schema_version":3' "$evidence_dir/core-output.jsonl" \
  >"$evidence_dir/core-events.raw.jsonl"
go run ./cmd/auditcheck \
  --input "$evidence_dir/core-events.raw.jsonl" \
  --file-marker /demo-secrets/example-token \
  --exec-marker agentshield-sandbox-command \
  --ipv4-destination 127.0.0.1:18080 \
  --ipv6-destination '[::1]:18080' \
  --require-receipt-clocks \
  --require-scope-identity >"$evidence_dir/audit-summary.sanitized.json"
grep -Fx 'AGENTSHIELD_EVIDENCE trusted_start_gate=released' "$evidence_dir/sandbox-output.txt" >/dev/null
grep -Fx "AGENTSHIELD_EVIDENCE fixture_sha256=$fixture_hash" "$evidence_dir/sandbox-output.txt" >/dev/null
grep -Fx 'AGENTSHIELD_ACTION file_open=/demo-secrets/example-token' "$evidence_dir/sandbox-output.txt" >/dev/null
grep -Fx 'AGENTSHIELD_ACTION exec=/bin/echo' "$evidence_dir/sandbox-output.txt" >/dev/null

echo "[6/6] Capturing authenticated API snapshots..."
curl --fail --silent --max-time 2 --header "Authorization: Bearer $read_token" \
  http://127.0.0.1:8080/api/v1/overview >"$evidence_dir/overview.json"
curl --fail --silent --max-time 2 --header "Authorization: Bearer $read_token" \
  http://127.0.0.1:8080/api/v1/policies >"$evidence_dir/policies.json"

cat >"$evidence_dir/summary.sanitized.md" <<EOF
# AgentShield isolated demo

- Captured at (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Repository commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)
- Exact sandbox leaf registration: PASS
- BPF load and all configured hook attachment: PASS
- Repository-owned read-only fake secret gate: PASS
- Kernel file_open, exec_attempt, and net_connect event classes: PASS
- Authenticated Dashboard overview request: PASS

This result covers the standalone audit demo only. It does not prove production
supervisor, checkpoint/store/correlator fan-in, durable history, policy CRUD,
fallback containment dispatch, or network block runtime behavior.
EOF

echo
echo "Demo checks passed. Owner-only evidence: $evidence_dir"
if [ "$non_interactive" -eq 1 ]; then
  exit 0
fi
echo "Dashboard: http://127.0.0.1:3000"
echo "Username: agentshield"
echo "Password: $dashboard_token"
echo "The sandbox attack is complete; the bounded in-memory trace remains visible."
echo "Press Ctrl-C to stop Core and remove the demo containers."
wait "$core_pid"
