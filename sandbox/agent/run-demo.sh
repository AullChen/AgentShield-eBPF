#!/bin/sh
set -eu

fixture=/demo-secrets/example-token
expected_hash=${EXPECTED_FIXTURE_SHA256:-}

if [ ! -f "$fixture" ] || [ ! -r "$fixture" ]; then
  echo "fixture is not a readable regular file: $fixture" >&2
  exit 1
fi
actual_hash=$(sha256sum "$fixture" | awk '{print $1}')
if [ -z "$expected_hash" ] || [ "$actual_hash" != "$expected_hash" ]; then
  echo "fixture hash does not match the repository-provided value" >&2
  exit 1
fi
if (printf 'write-probe' >>"$fixture") 2>/dev/null; then
  echo "fixture bind mount is writable" >&2
  exit 1
fi

mount_record=$(
  awk '$5 == "/demo-secrets/example-token" {
    print $1 "|" $3 "|" $5 "|" $6
    found = 1
  } END {
    if (!found) exit 1
  }' /proc/self/mountinfo
)
case "$mount_record" in
  *"|ro,"*|*"|ro") ;;
  *)
    echo "fixture mount metadata does not report read-only options" >&2
    exit 1
    ;;
esac

mount_namespace=$(readlink /proc/self/ns/mnt)
fixture_identity=$(stat -c '%d:%i' "$fixture")

echo "AGENTSHIELD_EVIDENCE fixture_origin=repository_read_only_bind"
echo "AGENTSHIELD_EVIDENCE fixture_sha256=$actual_hash"
echo "AGENTSHIELD_EVIDENCE mount_namespace=$mount_namespace"
echo "AGENTSHIELD_EVIDENCE mount_record=$mount_record"
echo "AGENTSHIELD_EVIDENCE fixture_device_inode=$fixture_identity"

cat -- "$fixture" >/dev/null
echo "AGENTSHIELD_ACTION file_open=/demo-secrets/example-token"

/bin/echo "agentshield-sandbox-command" >/dev/null
echo "AGENTSHIELD_ACTION exec=/bin/echo"

curl --noproxy '*' --connect-timeout 1 --max-time 2 --silent --output /dev/null \
  http://127.0.0.1:18080/agentshield-sandbox-ipv4 || true
echo "AGENTSHIELD_ACTION network_ipv4=127.0.0.1:18080"

curl --noproxy '*' --connect-timeout 1 --max-time 2 --silent --output /dev/null \
  'http://[::1]:18080/agentshield-sandbox-ipv6' || true
echo "AGENTSHIELD_ACTION network_ipv6=[::1]:18080"
