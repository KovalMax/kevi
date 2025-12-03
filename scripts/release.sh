#!/usr/bin/env bash
set -euo pipefail

# Simple reproducible build helper for local releases.
# Produces stripped binaries and SHA256 checksums for the current host.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Building kevi (release, locked)…"
RUSTFLAGS="-C strip=symbols" cargo build --release --locked

BIN=target/release/kevi
OUT_DIR=dist
mkdir -p "$OUT_DIR"

case "$(uname -s)" in
  Linux)
    ARCHIVE="$OUT_DIR/kevi-linux-$(uname -m).tar.gz"
    tar -czf "$ARCHIVE" -C target/release kevi
    ;;
  Darwin)
    ARCHIVE="$OUT_DIR/kevi-macos-$(uname -m).tar.gz"
    tar -czf "$ARCHIVE" -C target/release kevi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "Windows not supported by this script; use CI release workflow"
    exit 1
    ;;
  *)
    echo "Unknown OS; aborting"
    exit 1
    ;;
esac

echo "Computing checksums…"
pushd "$OUT_DIR" >/dev/null
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$(basename "$ARCHIVE")" > SHA256SUMS.txt
else
  sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS.txt
fi
popd >/dev/null

echo "Done. Artifacts in $OUT_DIR/"
