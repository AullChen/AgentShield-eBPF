#!/usr/bin/env sh
set -eu

target=${1:-/etc/hosts}

cat "$target" >/dev/null
/bin/echo "AgentShield exec audit probe" >/dev/null

echo "Triggered file_open for $target and exec_attempt for /bin/echo."
