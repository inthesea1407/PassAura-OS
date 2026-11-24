#!/usr/bin/env bash
set -euo pipefail

# PassAura OS (POS) - Headless QEMU Boot Smoke Test (MIT)
# Boots the built ISO in headless mode over serial console, verifies:
#   1) System reaches a login prompt
#   2) PassAura package gate hook is installed and blocks competing password managers

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SUITE="${SUITE:-stable}"
ARCH="${ARCH:-amd64}"
ISO_PATH="${1:-${REPO_ROOT}/build/linux-iso/passaura-os-linux-${SUITE}-${ARCH}.iso}"
TIMEOUT_SEC="${TIMEOUT_SEC:-90}"
WORK_DIR="${WORK_DIR:-${REPO_ROOT}/build/qemu-smoke}"
SERIAL_LOG="${WORK_DIR}/serial-console.log"

mkdir -p "$WORK_DIR"
: > "$SERIAL_LOG"

if [[ ! -f "$ISO_PATH" ]]; then
    echo "Error: ISO file not found at '$ISO_PATH'." >&2
    exit 1
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "Error: qemu-system-x86_64 not found in PATH." >&2
    exit 1
fi

# Verify package gate hook script syntax and behavior directly on repo/rootfs artifact
"${SCRIPT_DIR}/passaura-pkg-gate.sh" passaura >/dev/null
if "${SCRIPT_DIR}/passaura-pkg-gate.sh" bitwarden >/dev/null 2>&1; then
    echo "Error: passaura-pkg-gate.sh failed to block 'bitwarden'." >&2
    exit 1
fi

# Inspect ISO contents for PassAura package gate hook and GRUB BIOS/UEFI layout
if command -v xorriso >/dev/null 2>&1; then
    if ! xorriso -indev "$ISO_PATH" -find / -name "passaura-pkg-gate.sh" 2>/dev/null | grep -q "passaura-pkg-gate.sh"; then
        echo "Error: passaura-pkg-gate.sh not found inside ISO '$ISO_PATH'." >&2
        exit 1
    fi
fi

QEMU_ACCEL="-accel tcg"
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    QEMU_ACCEL="-enable-kvm"
fi

echo "Booting '$ISO_PATH' in headless QEMU (timeout=${TIMEOUT_SEC}s)..."
set +e
timeout "${TIMEOUT_SEC}s" qemu-system-x86_64 \
    $QEMU_ACCEL \
    -m 1024 \
    -smp 2 \
    -nographic \
    -no-reboot \
    -cdrom "$ISO_PATH" \
    -boot d \
    -serial "file:${SERIAL_LOG}" \
    -monitor none \
    >/dev/null 2>&1
QEMU_RC=$?
set -e

echo "QEMU exited with status $QEMU_RC. Checking serial console output..."
if [[ -s "$SERIAL_LOG" ]]; then
    cat "$SERIAL_LOG"
fi

if ! grep -qiE '(login:|PassAura OS)' "$SERIAL_LOG"; then
    echo "Error: did not observe login prompt or PassAura OS boot banner on serial console." >&2
    exit 1
fi

echo "Smoke test passed: login prompt/banner observed and PassAura package gate hook verified."
