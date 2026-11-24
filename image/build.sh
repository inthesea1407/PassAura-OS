#!/usr/bin/env bash
set -euo pipefail

# Reproducible minimal Debian (stable) rootfs builder for PassAura OS (POS).
# Zero budget, free tools only, no privileged hardware required.
# Supports mmdebstrap (preferred) with fallback to debootstrap.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="${DEBIAN_SUITE:-bookworm}"
ARCH="${DEBIAN_ARCH:-amd64}"
MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"
ROOTFS_DIR="${ROOTFS_DIR:-${REPO_ROOT}/out/rootfs}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1735689600}"
export SOURCE_DATE_EPOCH
export LC_ALL=C
export LANG=C

BASE_PACKAGES="ca-certificates,systemd,systemd-sysv,dbus,apparmor,apparmor-utils,procps,kmod,jq"

log() {
  printf '[passaura-build] %s\n' "$*"
}

rm -rf "${ROOTFS_DIR}"
mkdir -p "$(dirname "${ROOTFS_DIR}")" "${ROOTFS_DIR}"

if command -v mmdebstrap >/dev/null 2>&1; then
  log "Building ${SUITE} (${ARCH}) rootfs with mmdebstrap..."
  mmdebstrap \
    --variant=minbase \
    --architectures="${ARCH}" \
    --include="${BASE_PACKAGES}" \
    --skip=check/empty \
    "${SUITE}" \
    "${ROOTFS_DIR}" \
    "${MIRROR}"
elif command -v debootstrap >/dev/null 2>&1; then
  log "Building ${SUITE} (${ARCH}) rootfs with debootstrap..."
  debootstrap \
    --variant=minbase \
    --arch="${ARCH}" \
    --include="${BASE_PACKAGES}" \
    "${SUITE}" \
    "${ROOTFS_DIR}" \
    "${MIRROR}"
else
  echo "ERROR: Neither mmdebstrap nor debootstrap is installed." >&2
  exit 1
fi

log "Installing PassAura apt gate hook and configuration..."
install -d -m 0755 "${ROOTFS_DIR}/usr/local/bin" "${ROOTFS_DIR}/etc/apt/apt.conf.d" "${ROOTFS_DIR}/var/lib/passaura" "${ROOTFS_DIR}/etc/passaura"
install -d -m 0755 "${ROOTFS_DIR}/usr/local/lib/pos"
install -m 0755 "${REPO_ROOT}/enforcement/apt-hook.sh" "${ROOTFS_DIR}/usr/local/lib/pos/apt-hook.sh"
# pos-gate binary is required: the hook fails closed without it. Build with: cargo build --release -p pos-gate
POS_GATE_BIN="${POS_GATE_BIN:-${REPO_ROOT}/target/release/pos-gate}"
if [ ! -x "${POS_GATE_BIN}" ]; then echo "ERROR: pos-gate binary not found at ${POS_GATE_BIN}" >&2; exit 1; fi
install -m 0755 "${POS_GATE_BIN}" "${ROOTFS_DIR}/usr/local/bin/pos-gate"

cat > "${ROOTFS_DIR}/etc/apt/apt.conf.d/99passaura-gate" <<'EOF'
DPkg::Pre-Install-Pkgs { "/usr/local/lib/pos/apt-hook.sh"; };
DPkg::Pre-Install-Pkgs::Version "3";
APT::Keep-Downloaded-Packages "false";
EOF
chmod 0644 "${ROOTFS_DIR}/etc/apt/apt.conf.d/99passaura-gate"

log "Applying sysctl hardening and kernel module blocklist..."
install -d -m 0755 "${ROOTFS_DIR}/etc/sysctl.d" "${ROOTFS_DIR}/etc/modprobe.d" "${ROOTFS_DIR}/etc/passaura"

if [ -f "${REPO_ROOT}/profiles/linux-kernel-hardening.txt" ]; then
  install -m 0644 "${REPO_ROOT}/profiles/linux-kernel-hardening.txt" "${ROOTFS_DIR}/etc/passaura/linux-kernel-hardening.txt"
fi

cat > "${ROOTFS_DIR}/etc/sysctl.d/99-passaura-hardening.conf" <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.suid_dumpable = 0
EOF
chmod 0644 "${ROOTFS_DIR}/etc/sysctl.d/99-passaura-hardening.conf"

cat > "${ROOTFS_DIR}/etc/modprobe.d/passaura-blocklist.conf" <<'EOF'
install usb-storage /bin/false
install firewire-ohci /bin/false
install thunderbolt /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
chmod 0644 "${ROOTFS_DIR}/etc/modprobe.d/passaura-blocklist.conf"

log "Configuring AppArmor profile for pos-register and pos-gate..."
install -d -m 0755 "${ROOTFS_DIR}/etc/apparmor.d"
cat > "${ROOTFS_DIR}/etc/apparmor.d/usr.local.bin.pos-register" <<'EOF'
#include <tunables/global>

/usr/local/bin/pos-register flags=(attach_disconnected) {
  #include <abstractions/base>

  /etc/passaura/ r,
  /etc/passaura/invite.code r,
  /run/passaura/ r,
  /run/passaura/invite.code r,
  /var/lib/passaura/ rw,
  /var/lib/passaura/** rwk,
  /usr/local/bin/pos-register mr,
}
EOF
chmod 0644 "${ROOTFS_DIR}/etc/apparmor.d/usr.local.bin.pos-register"

log "Disabling unneeded services via systemd symlinks..."
UNNEEDED_SERVICES="bluetooth.service cups.service cups-browsed.service avahi-daemon.service rpcbind.service exim4.service ModemManager.service"
install -d -m 0755 "${ROOTFS_DIR}/etc/systemd/system"
for svc in ${UNNEEDED_SERVICES}; do
  ln -sf /dev/null "${ROOTFS_DIR}/etc/systemd/system/${svc}"
done

log "Installing browser policies from policies/browser..."
install -d -m 0755 \
  "${ROOTFS_DIR}/etc/chromium/policies/managed" \
  "${ROOTFS_DIR}/etc/opt/chrome/policies/managed" \
  "${ROOTFS_DIR}/etc/firefox/policies"

if [ -d "${REPO_ROOT}/policies/browser" ]; then
  shopt -s nullglob
  for pol in "${REPO_ROOT}/policies/browser"/chrome-*.json; do
    base_name="$(basename "${pol}")"
    install -m 0644 "${pol}" "${ROOTFS_DIR}/etc/chromium/policies/managed/${base_name}"
    install -m 0644 "${pol}" "${ROOTFS_DIR}/etc/opt/chrome/policies/managed/${base_name}"
  done
  if [ -f "${REPO_ROOT}/policies/browser/firefox-policies.json" ]; then
    install -m 0644 "${REPO_ROOT}/policies/browser/firefox-policies.json" "${ROOTFS_DIR}/etc/firefox/policies/policies.json"
  fi
  shopt -u nullglob
fi

log "Installing first-boot registration unit and pos-register stub..."
install -m 0755 "${REPO_ROOT}/image/bin/pos-register" "${ROOTFS_DIR}/usr/local/bin/pos-register"
install -m 0644 "${REPO_ROOT}/image/systemd/passaura-firstboot.service" "${ROOTFS_DIR}/etc/systemd/system/passaura-firstboot.service"

install -d -m 0755 "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/passaura-firstboot.service \
  "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/passaura-firstboot.service"

log "Normalizing timestamps and cleaning apt caches..."
rm -rf "${ROOTFS_DIR}/var/cache/apt/archives/"*.deb "${ROOTFS_DIR}/var/lib/apt/lists/"*
find "${ROOTFS_DIR}" -newermt "@${SOURCE_DATE_EPOCH}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

log "Done: ${ROOTFS_DIR}"

