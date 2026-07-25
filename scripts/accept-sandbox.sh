#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo "sandbox acceptance requires Linux" >&2
  exit 1
fi
for command in docker sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required" >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
compose_file="$repo_root/sandbox/compose.yaml"
fixture="$repo_root/sandbox/fixtures/demo-secrets/example-token"
evidence_root=${AGENTSHIELD_EVIDENCE_DIR:-"$repo_root/tmp/acceptance/day20"}

fixture_source=$(readlink -f "$fixture")
case "$fixture_source" in
  "$repo_root"/sandbox/fixtures/demo-secrets/example-token) ;;
  *)
    echo "fixture source escaped the repository-owned demo fixture path" >&2
    exit 1
    ;;
esac
fixture_hash=$(sha256sum "$fixture_source" | awk '{print $1}')

umask 077
mkdir -p "$evidence_root"
evidence_dir=$(mktemp -d "$evidence_root/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
output="$evidence_dir/sandbox-output.txt"
metadata="$evidence_dir/host-fixture.txt"

{
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "fixture_source=$fixture_source"
  echo "fixture_sha256=$fixture_hash"
  stat -c 'fixture_device_inode=%d:%i' "$fixture_source"
} >"$metadata"

export AGENTSHIELD_FIXTURE_SHA256=$fixture_hash
docker compose -f "$compose_file" build --pull
image_ref=$(docker compose -f "$compose_file" config --images)
image_id=$(docker image inspect --format '{{.Id}}' "$image_ref")
if [ -z "$image_id" ]; then
  echo "could not determine the built sandbox image ID" >&2
  exit 1
fi
{
  echo "sandbox_image_ref=$image_ref"
  echo "sandbox_image_id=$image_id"
} >>"$metadata"
docker compose -f "$compose_file" run --rm --no-deps -T agent >"$output"

grep -Fx "AGENTSHIELD_EVIDENCE fixture_origin=repository_read_only_bind" "$output" >/dev/null
grep -Fx "AGENTSHIELD_EVIDENCE fixture_sha256=$fixture_hash" "$output" >/dev/null
grep -F "AGENTSHIELD_EVIDENCE mount_namespace=mnt:[" "$output" >/dev/null
grep -F "AGENTSHIELD_EVIDENCE mount_record=" "$output" >/dev/null
grep -F "AGENTSHIELD_EVIDENCE fixture_device_inode=" "$output" >/dev/null
grep -Fx "AGENTSHIELD_ACTION file_open=/demo-secrets/example-token" "$output" >/dev/null
grep -Fx "AGENTSHIELD_ACTION exec=/bin/echo" "$output" >/dev/null
grep -Fx "AGENTSHIELD_ACTION network_ipv4=127.0.0.1:18080" "$output" >/dev/null
grep -Fx "AGENTSHIELD_ACTION network_ipv6=[::1]:18080" "$output" >/dev/null

echo "Day 20 sandbox acceptance passed. Evidence: $evidence_dir"
