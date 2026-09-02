#!/usr/bin/env bash
set -Eeuo pipefail

if [ "${1:-}" != "--isolated-vm" ] || [ "$#" -ne 1 ]; then
  echo "usage: sudo ./scripts/release-check.sh --isolated-vm" >&2
  exit 2
fi
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ]; then
  echo "release acceptance requires root on a disposable, dedicated Linux VM" >&2
  exit 1
fi
if [ ! -r /etc/os-release ]; then
  echo "cannot verify the supported Ubuntu 24.04 baseline" >&2
  exit 1
fi
. /etc/os-release
if [ "${ID:-}" != ubuntu ] || [ "${VERSION_ID:-}" != 24.04 ]; then
  echo "unsupported distribution: ${ID:-unknown} ${VERSION_ID:-unknown}; expected Ubuntu 24.04" >&2
  exit 1
fi
for command in cut docker find git go govulncheck make node npm python3 sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required release command not found: $command" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required" >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0=$repo_root
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "release acceptance requires a clean tracked and untracked working tree" >&2
  exit 1
fi

go_version=$(go env GOVERSION)
if [[ ! "$go_version" =~ ^go([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "a stable three-component Go release is required; found $go_version" >&2
  exit 1
fi
go_major=${BASH_REMATCH[1]}
go_minor=${BASH_REMATCH[2]}
go_patch=${BASH_REMATCH[3]}
case "$go_major.$go_minor" in
  1.25) [ "${go_patch:-0}" -ge 12 ] || { echo "Go 1.25.12 or newer patch is required" >&2; exit 1; } ;;
  1.26) [ "${go_patch:-0}" -ge 5 ] || { echo "Go 1.26.5 or newer patch is required" >&2; exit 1; } ;;
  1.*) [ "$go_minor" -gt 26 ] || { echo "unsupported Go version: $go_version" >&2; exit 1; } ;;
  *) echo "unsupported Go version: $go_version" >&2; exit 1 ;;
esac
node_version=$(node --version)
if [[ ! "$node_version" =~ ^v([0-9]+)\. ]]; then
  echo "could not parse Node.js version: $node_version" >&2
  exit 1
fi
node_major=${BASH_REMATCH[1]}
if [ "$node_major" -ne 22 ] && [ "$node_major" -ne 24 ]; then
  echo "Node.js 22 or 24 is required; found $(node --version)" >&2
  exit 1
fi
npm_major=$(npm --version | cut -d. -f1)
if [ "$npm_major" -lt 10 ]; then
  echo "npm 10 or newer is required" >&2
  exit 1
fi

evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-"$repo_root/tmp/release"}
umask 077
mkdir -p "$evidence_root"
evidence_dir=$(mktemp -d "$evidence_root/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")

run_check() {
  name=$1
  shift
  echo "Running $name..."
  "$@" >"$evidence_dir/$name.txt" 2>&1
}

{
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit=$(git rev-parse HEAD)"
  echo "branch=$(git branch --show-current)"
  uname -a
  go version
  govulncheck -version
  node --version
  npm --version
  python3 --version
  docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
  docker compose version
} >"$evidence_dir/toolchain.txt"
git archive --format=tar HEAD | sha256sum >"$evidence_dir/source-archive-sha256.txt"

run_check go-mod-verify go mod verify
run_check go-vulnerability-scan govulncheck ./...
run_check aggregate-source-check make check
run_check go-vet go vet ./...
run_check p2-source-gate make test-p2
run_check p3-source-gate make test-p3
run_check checkpoint-source-gate make test-checkpoint
run_check stream-source-gate make test-stream
run_check python-sdk-tests python3 -m unittest discover -s sdk/python/tests -v
run_check supervisor-tests python3 -m unittest discover -s sandbox/tests -v
run_check dashboard-install npm --prefix dashboard ci
run_check dashboard-typecheck npm --prefix dashboard run typecheck
run_check dashboard-build npm --prefix dashboard run build
run_check dashboard-dependency-audit npm --prefix dashboard audit --audit-level=high --registry=https://registry.npmjs.org

echo "Running the privileged three-event demo gate..."
AGENTSHIELD_EVIDENCE_DIR="$evidence_dir/demo" \
  ./scripts/demo.sh --isolated-vm --non-interactive \
  >"$evidence_dir/demo-command.txt" 2>&1

demo_summary=$(find "$evidence_dir/demo" -name summary.sanitized.md -type f -print -quit)
if [ -z "$demo_summary" ]; then
  echo "demo completed without a sanitized summary" >&2
  exit 1
fi
cp "$demo_summary" "$evidence_dir/demo-summary.sanitized.md"
run_check clean-tracked-tree git diff --exit-code

cat >"$evidence_dir/release-check.sanitized.md" <<EOF
# AgentShield release check

- Captured at (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Commit: $(git rev-parse HEAD)
- Clean working tree before checks: PASS
- Go module integrity and reachable-vulnerability scan: PASS
- Go, BPF syntax/cross-build, Python, and supervisor source gates: PASS
- Dashboard clean install, typecheck, build, and high-severity audit gate: PASS
- Supported-Linux CO-RE build/load and isolated three-event demo: PASS

This command does not select a repository license, review raw evidence, or
capture/review human-facing Dashboard screenshots. Those manual release gates
remain required before a public release claim.
EOF

echo "Automated release checks passed. Review all owner-only evidence: $evidence_dir"
echo "Manual license, raw-evidence, and screenshot review are still required."
