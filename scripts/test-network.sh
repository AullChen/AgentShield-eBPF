#!/usr/bin/env sh
set -eu

ipv4_url=${1:-http://127.0.0.1:18080/agentshield-day15-ipv4}
ipv6_url=${2:-http://[::1]:18080/agentshield-day15-ipv6}

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

curl --noproxy '*' --connect-timeout 1 --max-time 2 --silent --output /dev/null "$ipv4_url" || true
curl --noproxy '*' --connect-timeout 1 --max-time 2 --silent --output /dev/null "$ipv6_url" || true

echo "Triggered TCP IPv4 and IPv6 connect attempts. Connection failure is acceptable for an audit-attempt fixture."
