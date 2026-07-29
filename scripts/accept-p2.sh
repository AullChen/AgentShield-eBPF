#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo "P2 runtime acceptance requires Linux" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "run P2 acceptance as root on an isolated test host" >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"

object_path=${1:-bpf/agentshield.bpf.o}
manifest_path=${2:-bpf/agentshield.bpf.manifest.json}
evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-"$repo_root/tmp/acceptance/day25"}

umask 077
mkdir -p "$evidence_root"
evidence_dir=$(mktemp -d "$evidence_root/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")

go test ./internal/api -run '^TestP2LifecycleAcceptance$' -count=1 \
  >"$evidence_dir/lifecycle-test.txt"

AGENTSHIELD_EVIDENCE_DIR="$evidence_dir/kernel-scope" \
  ./scripts/accept-p1.sh "$object_path" "$manifest_path" \
  >"$evidence_dir/kernel-scope.txt"

AGENTSHIELD_EVIDENCE_DIR="$evidence_dir/sandbox" \
  ./scripts/accept-sandbox.sh \
  >"$evidence_dir/sandbox.txt"

cat >"$evidence_dir/summary.sanitized.md" <<EOF
# P2 cgroup lifecycle acceptance

- Captured at (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Hermetic register/capture/finish/TTL/reuse/host-negative lifecycle: PASS
- Exact-leaf kernel capture and host-negative runtime gate: PASS
- Repository-owned read-only sandbox fixture gate: PASS

Raw kernel and sandbox evidence remains in this owner-only ignored directory.
EOF

echo "P2 acceptance passed. Evidence: $evidence_dir"
