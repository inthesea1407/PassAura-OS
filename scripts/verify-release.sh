#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

cd "$RELEASE_DIR"

SUM_FILE="SHA256SUMS"

EXPECTED_FILES=(
  "pos-gate-linux-x86_64"
  "pos-cli-linux-x86_64"
  "pos-gate-windows-x86_64.exe"
  "pos-cli-windows-x86_64.exe"
)

if [[ ! -f "$SUM_FILE" ]]; then
  echo "ERROR: Missing $SUM_FILE" >&2
  exit 1
fi

for file in "${EXPECTED_FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: Missing release file: $file" >&2
    exit 1
  fi

  if ! grep -Eq "^[[:xdigit:]]{64}[[:space:]]+[* ]?${file}$" "$SUM_FILE"; then
    echo "ERROR: Missing or invalid checksum entry: $file" >&2
    exit 1
  fi
done

echo "Verifying release checksums..."

sha256sum --check "$SUM_FILE"

echo "SUCCESS: Release checksum verification passed."
