#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <version> <target> <binary-path> <dist-dir>" >&2
  exit 1
fi

version="$1"
target="$2"
binary_path="$3"
dist_dir="$4"

if [ -z "$version" ] || [ -z "$target" ]; then
  echo "version and target must be non-empty" >&2
  exit 1
fi

if [ ! -f "$binary_path" ]; then
  echo "binary not found at $binary_path" >&2
  exit 1
fi

archive_root="keyclaw-v${version}-${target}"
archive_name="keyclaw-v${version}-${target}.tar.gz"
stage_dir="${dist_dir}/${archive_root}"
archive_path="${dist_dir}/${archive_name}"

rm -rf "$stage_dir" "$archive_path"
mkdir -p "$stage_dir"

install -m 755 "$binary_path" "${stage_dir}/keyclaw"
cp README.md "${stage_dir}/README.md"
cp LICENSE "${stage_dir}/LICENSE"
cp SECURITY.md "${stage_dir}/SECURITY.md"

tar -C "$dist_dir" -czf "$archive_path" "$archive_root"

echo "$archive_path"
