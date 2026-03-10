#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <version> <dist-dir>" >&2
  exit 1
fi

version="$1"
dist_dir="$2"
targets=(
  "x86_64-unknown-linux-gnu"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

archives=()
for target in "${targets[@]}"; do
  archive_root="keyclaw-v${version}-${target}"
  archive_path="${dist_dir}/${archive_root}.tar.gz"
  if [ ! -f "$archive_path" ]; then
    echo "missing release archive $archive_path" >&2
    exit 1
  fi

  listing="$(tar -tzf "$archive_path")"
  for entry in \
    "${archive_root}/" \
    "${archive_root}/keyclaw" \
    "${archive_root}/README.md" \
    "${archive_root}/LICENSE" \
    "${archive_root}/SECURITY.md"
  do
    if ! grep -Fqx "$entry" <<<"$listing"; then
      echo "archive $archive_path is missing $entry" >&2
      exit 1
    fi
  done

  archives+=("$(basename "$archive_path")")
done

checksum_file="${dist_dir}/SHA256SUMS"
if [ ! -f "$checksum_file" ]; then
  echo "missing checksum file $checksum_file" >&2
  exit 1
fi

line_count="$(wc -l < "$checksum_file" | tr -d ' ')"
if [ "$line_count" -ne "${#archives[@]}" ]; then
  echo "expected ${#archives[@]} checksum entries, found $line_count" >&2
  exit 1
fi

for archive_name in "${archives[@]}"; do
  if ! grep -Eq "^[0-9a-f]{64}  ${archive_name}$" "$checksum_file"; then
    echo "checksum entry missing or malformed for $archive_name" >&2
    exit 1
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$dist_dir" && sha256sum -c SHA256SUMS)
  exit 0
fi

if command -v shasum >/dev/null 2>&1; then
  while read -r expected checksum_name; do
    actual="$(shasum -a 256 "${dist_dir}/${checksum_name}" | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
      echo "checksum mismatch for ${checksum_name}" >&2
      exit 1
    fi
  done < "$checksum_file"
  exit 0
fi

echo "need sha256sum or shasum to verify SHA256SUMS" >&2
exit 1
