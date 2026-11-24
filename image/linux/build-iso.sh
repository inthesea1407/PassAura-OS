#!/usr/bin/env bash
set -euo pipefail

# PassAura OS (POS) - Debian Stable Live/Installable ISO Builder (MIT)
# Uses free tools only: mmdebstrap, squashfs-tools, xorriso, grub (BIOS + UEFI).
# Requires no secrets.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SUITE="${SUITE:-stable}"
ARCH="${ARCH:-amd64}"
MIRROR="${MIRROR:-http://deb.debian.org/debian}"
WORK_DIR="${WORK_DIR:-${REPO_ROOT}/build/linux-iso}"
OUT_ISO="${OUT_ISO:-${WORK_DIR}/passaura-os-linux-${SUITE}-${ARCH}.iso}"

ROOTFS_DIR="${WORK_DIR}/rootfs"
ISO_ROOT="${WORK_DIR}/iso-staging"
LIVE_DIR="${ISO_ROOT}/live"
BOOT_GRUB_DIR="${ISO_ROOT}/boot/grub"

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found in PATH." >&2
        exit 1
    fi
}

require_cmd mmdebstrap
require_cmd mksquashfs
require_cmd xorriso
require_cmd grub-mkrescue

rm -rf "$ROOTFS_DIR" "$ISO_ROOT"
mkdir -p "$ROOTFS_DIR" "$LIVE_DIR" "$BOOT_GRUB_DIR" "$(dirname "$OUT_ISO")"

echo "[1/5] Bootstrapping Debian ($SUITE/$ARCH) rootfs via mmdebstrap..."
mmdebstrap \
    --arch="$ARCH" \
    --variant=minbase \
    --include=ca-certificates,systemd,systemd-sysv,udev,dbus,iproute2,bash,coreutils,util-linux,passwd,procps,curl,gnupg \
    "$SUITE" \
    "$ROOTFS_DIR" \
    "$MIRROR"

echo "[2/5] Installing PassAura OS Linux identity, serial console, and package gate hook..."
printf 'passaura-pos-linux\n' > "${ROOTFS_DIR}/etc/hostname"
cat > "${ROOTFS_DIR}/etc/hosts" <<'EOF'
127.0.0.1 localhost passaura-pos-linux
::1       localhost ip6-localhost ip6-loopback
EOF

install -d -m 0755 "${ROOTFS_DIR}/usr/local/bin"
install -m 0755 "${SCRIPT_DIR}/passaura-pkg-gate.sh" "${ROOTFS_DIR}/usr/local/bin/passaura-pkg-gate.sh"

install -d -m 0755 "${ROOTFS_DIR}/etc/apt/apt.conf.d"
cat > "${ROOTFS_DIR}/etc/apt/apt.conf.d/99passaura-pkg-gate" <<'EOF'
DPkg::Pre-Invoke { "/usr/local/bin/passaura-pkg-gate.sh"; };
EOF

install -d -m 0755 "${ROOTFS_DIR}/etc/passaura"
cat > "${ROOTFS_DIR}/etc/passaura/pos-linux.conf" <<'EOF'
POS_EDITION=linux-live-installable
POS_PASSWORD_MANAGER_SOLE=passaura
POS_INVITE_MODE=free-invite
EOF

# Ensure serial getty is enabled for headless QEMU console inspection
install -d -m 0755 "${ROOTFS_DIR}/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "${ROOTFS_DIR}/etc/systemd/system/serial-getty@ttyS0.service.d/autologin-hint.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --keep-baud 115200,38400,9600 %I $TERM
EOF

# Ensure a standard login prompt is reachable on ttyS0 even in minimal init/container smoke boots
cat > "${ROOTFS_DIR}/usr/local/bin/pos-init-ttyS0.sh" <<'EOF'
#!/usr/bin/env bash
exec /sbin/agetty --noclear 115200 ttyS0 vt102
EOF
chmod 0755 "${ROOTFS_DIR}/usr/local/bin/pos-init-ttyS0.sh"

echo "[3/5] Packing rootfs into SquashFS image..."
mksquashfs "$ROOTFS_DIR" "${LIVE_DIR}/filesystem.squashfs" \
    -comp xz \
    -noappend \
    -e boot/vmlinuz* boot/initrd.img*

VMLINUZ="$(find "${ROOTFS_DIR}/boot" -maxdepth 1 -name 'vmlinuz-*' | sort -V | tail -n 1)"
INITRD="$(find "${ROOTFS_DIR}/boot" -maxdepth 1 -name 'initrd.img-*' | sort -V | tail -n 1)"

if [[ -n "$VMLINUZ" && -f "$VMLINUZ" ]]; then
    cp "$VMLINUZ" "${LIVE_DIR}/vmlinuz"
fi
if [[ -n "$INITRD" && -f "$INITRD" ]]; then
    cp "$INITRD" "${LIVE_DIR}/initrd.img"
fi

echo "[4/5] Writing GRUB configuration for BIOS + UEFI boot..."
cat > "${BOOT_GRUB_DIR}/grub.cfg" <<'EOF'
set default=0
set timeout=2

serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

menuentry "PassAura OS (POS) Linux Live/Installer (Serial ttyS0)" {
    linux /live/vmlinuz console=ttyS0,115200n8 console=tty0 ro quiet
    initrd /live/initrd.img
}

menuentry "PassAura OS (POS) Linux Direct Shell/Login Test" {
    linux /live/vmlinuz console=ttyS0,115200n8 init=/usr/local/bin/pos-init-ttyS0.sh
    initrd /live/initrd.img
}
EOF

echo "[5/5] Generating hybrid BIOS + UEFI ISO with grub-mkrescue / xorriso..."
grub-mkrescue \
    -o "$OUT_ISO" \
    "$ISO_ROOT" \
    -- -volid "PASSAURA_POS_LINUX"

echo "Built ISO successfully: $OUT_ISO"
