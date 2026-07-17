#!/usr/bin/env bash
set -euo pipefail

object_path=${1:-bpf/agentshield.bpf.o}
manifest_path=${2:-bpf/agentshield.bpf.manifest.json}
btf_path=${AGENTSHIELD_VMLINUX_BTF:-/sys/kernel/btf/vmlinux}
clang_bin=${CLANG:-clang-18}
strip_bin=${LLVM_STRIP:-llvm-strip-18}
bpftool_bin=${BPFTOOL:-bpftool}

case "$(uname -m)" in
  x86_64) target_arch=x86 ;;
  aarch64|arm64) target_arch=arm64 ;;
  *) echo "unsupported build architecture: $(uname -m); expected x86_64 or arm64" >&2; exit 1 ;;
esac

for command in "$clang_bin" "$strip_bin" "$bpftool_bin" gcc go sha256sum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 1
  fi
done

clang_version=$($clang_bin --version | head -n 1)
case "$clang_version" in
  *"clang version 18."*|*"Ubuntu clang version 18."*) ;;
  *) echo "unsupported clang toolchain: $clang_version; AgentShield requires clang 18.x" >&2; exit 1 ;;
esac
gcc_version=$(gcc --version | head -n 1)

if [ ! -r "$btf_path" ]; then
  echo "kernel BTF is not readable: $btf_path" >&2
  exit 1
fi

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/agentshield-bpf.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT

"$bpftool_bin" btf dump file "$btf_path" format c >"$build_dir/vmlinux.h"

multiarch_include=/usr/include/$(gcc -dumpmachine 2>/dev/null || true)
include_args=(-I"$build_dir" -I./bpf -I/usr/include)
if [ -d "$multiarch_include" ]; then
  include_args+=("-I$multiarch_include")
fi

mkdir -p "$(dirname "$object_path")" "$(dirname "$manifest_path")"
"$clang_bin" \
  -target bpfel \
  -D"__TARGET_ARCH_${target_arch}" \
  -O2 -g -Wall -Werror \
  "${include_args[@]}" \
  -c bpf/agentshield.bpf.c \
  -o "$object_path"
"$strip_bin" -g "$object_path"

btf_sha256=$(sha256sum "$btf_path" | awk '{print $1}')
bpftool_version=$($bpftool_bin version | head -n 1)
strip_version=$($strip_bin --version | head -n 1)

go run ./cmd/bpfcheck \
  --object "$object_path" \
  --manifest "$manifest_path" \
  --metadata "arch=$(uname -m)" \
  --metadata "btf_path=$btf_path" \
  --metadata "btf_sha256=$btf_sha256" \
  --metadata "clang=$clang_version" \
  --metadata "gcc=$gcc_version" \
  --metadata "llvm_strip=$strip_version" \
  --metadata "bpftool=$bpftool_version"
