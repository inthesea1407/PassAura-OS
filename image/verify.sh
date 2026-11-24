#!/usr/bin/env bash
set -euo pipefail

# Verifies a built PassAura OS Debian rootfs against hardening rules.
# Safe to run on non-privileged CI runners (no hardware or live boot required).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOTFS_DIR="${1:-${REPO_ROOT}/out/rootfs}"
PROFILE_FILE="${REPO_ROOT}/profiles/linux-kernel-hardening.txt"
FAILURES=0

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }

if [ ! -d "${ROOTFS_DIR}" ]; then
  fail "Rootfs directory missing: ${ROOTFS_DIR}"
  exit 1
fi

# 1. Apt gate hook & config
if [ -f "${ROOTFS_DIR}/etc/apt/apt.conf.d/99passaura-gate" ] && grep -q "Pre-Install-Pkgs" "${ROOTFS_DIR}/etc/apt/apt.conf.d/99passaura-gate"; then
  pass "APT pre-invoke gate configuration present"
else
  fail "Missing or invalid /etc/apt/apt.conf.d/99passaura-gate"
fi

if [ -x "${ROOTFS_DIR}/usr/local/lib/pos/apt-hook.sh" ]; then
  pass "APT hook script is executable"
else
  fail "APT hook script missing or not executable"
fi

if [ -x "${ROOTFS_DIR}/usr/local/bin/pos-gate" ]; then pass "pos-gate binary installed"; else fail "pos-gate binary missing"; fi

# 2. Sysctl hardening
SYSCTL_CONF="${ROOTFS_DIR}/etc/sysctl.d/99-passaura-hardening.conf"
if [ -f "${SYSCTL_CONF}" ]; then
  for req_key in "kernel.kptr_restrict" "kernel.dmesg_restrict" "kernel.unprivileged_bpf_disabled" "net.ipv4.tcp_syncookies" "fs.protected_symlinks"; do
    if grep -qE "^${req_key}[[:space:]]*=" "${SYSCTL_CONF}"; then
      pass "Sysctl key configured: ${req_key}"
    else
      fail "Missing sysctl key in 99-passaura-hardening.conf: ${req_key}"
    fi
  done
else
  fail "Missing /etc/sysctl.d/99-passaura-hardening.conf"
fi

# 3. Module blocklist
MODLIST_CONF="${ROOTFS_DIR}/etc/modprobe.d/passaura-blocklist.conf"
if [ -f "${MODLIST_CONF}" ]; then
  for mod in "usb-storage" "dccp" "sctp"; do
    if grep -qE "^install[[:space:]]+${mod}[[:space:]]+/bin/false" "${MODLIST_CONF}"; then
      pass "Kernel module blocked: ${mod}"
    else
      fail "Expected module blocklist entry for ${mod}"
    fi
  done
else
  fail "Missing /etc/modprobe.d/passaura-blocklist.conf"
fi

# 4. AppArmor MAC profile
if [ -f "${ROOTFS_DIR}/etc/apparmor.d/usr.local.bin.pos-register" ]; then
  pass "AppArmor profile present for pos-register"
else
  fail "Missing AppArmor profile /etc/apparmor.d/usr.local.bin.pos-register"
fi

# 5. Unneeded services masked
for svc in "bluetooth.service" "cups.service" "avahi-daemon.service"; do
  target="$(readlink "${ROOTFS_DIR}/etc/systemd/system/${svc}" 2>/dev/null || true)"
  if [ "${target}" = "/dev/null" ]; then
    pass "Service masked: ${svc}"
  else
    fail "Service not masked (${svc} -> ${target})"
  fi
done

# 6. Browser policies installed from policies/browser/*.json
if [ -d "${REPO_ROOT}/policies/browser" ]; then
  policy_count=0
  for src_pol in "${REPO_ROOT}/policies/browser"/chrome-*.json; do
    [ -e "${src_pol}" ] || continue
    policy_count=$((policy_count + 1))
    bname="$(basename "${src_pol}")"
    if [ -f "${ROOTFS_DIR}/etc/chromium/policies/managed/${bname}" ]; then
      pass "Chromium policy installed: ${bname}"
    else
      fail "Missing Chromium policy in rootfs: ${bname}"
    fi
  done
  if [ "${policy_count}" -eq 0 ]; then
    fail "No *.json policies found in policies/browser"
  fi
fi

# 7. Systemd first-boot unit and pos-register stub
if [ -x "${ROOTFS_DIR}/usr/local/bin/pos-register" ]; then
  pass "pos-register stub is executable"
else
  fail "pos-register stub missing or not executable"
fi

if [ -f "${ROOTFS_DIR}/etc/systemd/system/passaura-firstboot.service" ] && [ -L "${ROOTFS_DIR}/etc/systemd/system/multi-user.target.wants/passaura-firstboot.service" ]; then
  pass "passaura-firstboot.service installed and enabled"
else
  fail "passaura-firstboot.service missing or not linked under multi-user.target.wants"
fi

# 8. Cross-check against kernel hardening profile if present
if [ -f "${PROFILE_FILE}" ]; then
  while IFS= read -r line; do
    clean_line="$(echo "${line}" | sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')"
    [ -z "${clean_line}" ] && continue
    case "${clean_line}" in
      CONFIG_*)
        pass "Kernel profile option noted: ${clean_line}"
        ;;
      *=*)
        key="${clean_line%%=*}"
        if [ -f "${SYSCTL_CONF}" ] && grep -qE "^${key}[[:space:]]*=" "${SYSCTL_CONF}"; then
          pass "Profile setting present in sysctl: ${key}"
        fi
        ;;
    esac
  done < "${PROFILE_FILE}"
fi

if [ "${FAILURES}" -gt 0 ]; then
  echo "Verification failed with ${FAILURES} issue(s)." >&2
  exit 1
fi

echo "All rootfs verification checks passed."

