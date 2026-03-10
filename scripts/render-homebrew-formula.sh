#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 <version> <dist-dir> [output-path]" >&2
  exit 1
fi

version="$1"
dist_dir="$2"
output_path="${3:-/dev/stdout}"
checksum_file="${dist_dir}/SHA256SUMS"

if [ -z "$version" ]; then
  echo "version must be non-empty" >&2
  exit 1
fi

if [ ! -f "$checksum_file" ]; then
  echo "missing checksum file $checksum_file" >&2
  exit 1
fi

checksum_for() {
  local archive_name="$1"
  local checksum
  checksum="$(awk -v archive="$archive_name" '$2 == archive { print $1 }' "$checksum_file")"
  if [ -z "$checksum" ]; then
    echo "missing checksum entry for $archive_name" >&2
    exit 1
  fi
  printf '%s\n' "$checksum"
}

linux_archive="keyclaw-v${version}-x86_64-unknown-linux-gnu.tar.gz"
macos_intel_archive="keyclaw-v${version}-x86_64-apple-darwin.tar.gz"
macos_arm_archive="keyclaw-v${version}-aarch64-apple-darwin.tar.gz"

linux_sha="$(checksum_for "$linux_archive")"
macos_intel_sha="$(checksum_for "$macos_intel_archive")"
macos_arm_sha="$(checksum_for "$macos_arm_archive")"

mkdir -p "$(dirname "$output_path")"

cat >"$output_path" <<EOF
class Keyclaw < Formula
  desc "Local MITM proxy that keeps secrets out of LLM traffic"
  homepage "https://github.com/GuthL/KeyClaw"
  version "${version}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/GuthL/KeyClaw/releases/download/v${version}/${macos_arm_archive}"
      sha256 "${macos_arm_sha}"
    else
      url "https://github.com/GuthL/KeyClaw/releases/download/v${version}/${macos_intel_archive}"
      sha256 "${macos_intel_sha}"
    end
  end

  on_linux do
    url "https://github.com/GuthL/KeyClaw/releases/download/v${version}/${linux_archive}"
    sha256 "${linux_sha}"
  end

  def install
    bin.install "keyclaw"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/keyclaw --version")
  end
end
EOF
