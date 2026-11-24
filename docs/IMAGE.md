# PassAura OS — Debian Hardened Base Image (`image/`)

## Overview

Module 4 defines a reproducible, zero-budget minimal Debian (`stable`) rootfs recipe built for GitHub Actions (`ubuntu-latest`) without privileged hardware or paid cloud VMs.

## Mandatory Access Control Choice: AppArmor

* **Selected MAC:** **AppArmor** (`apparmor` + `apparmor-utils` + custom profile `/etc/apparmor.d/usr.local.bin.pos-register`).
* **Justification:** Debian stable kernels include AppArmor support out of the box and allow lightweight profiles without full SELinux `refpolicy` / targeted policy store compilation during minimal rootfs creation.
* **SELinux Draft (`selinux/passaura_pmgate.te`):** Retained as a policy draft for AOSP + Linux alignment. `checkmodule` / `semodule_package` was **not** run in this generation session because no local shell or SELinux compiler was available here.

## First-Boot Invite Registration Stub

* `image/systemd/passaura-firstboot.service` runs `/usr/local/bin/pos-register` (`image/bin/pos-register`) once on first boot when `/var/lib/passaura/registration.json` does not yet exist.
* `pos-register` reads an invite code from a local file (`PASSAURA_INVITE_FILE`, defaulting to `/etc/passaura/invite.code`), writes a local registration stub record with a SHA-256 digest of the token, and clears the plaintext invite file.
* **No HTTP client or network registration is implemented** in this stub.

## Verification & Honest Test Status

* Run `./image/verify.sh out/rootfs` after `./image/build.sh` to validate the APT gate hook, sysctl hardening file, kernel module blocklist, AppArmor profile, masked services, managed browser policies, and first-boot service.
* **What runs in CI-like conditions:** `mmdebstrap` / `debootstrap` rootfs build on `ubuntu-latest`, `image/verify.sh` static rootfs checks, and a unit-level invocation of `image/bin/pos-register` against a temporary invite file.
* **What was NOT run here and remains untested:** No live shell commands were executed during response generation; full `systemd` PID 1 boot inside a VM/emulator, live kernel `sysctl` / module loading / AppArmor enforcement, `pos-gate` binary integration, and physical/emulator device testing remain untested.


## Integration notes (integrator)
- Gemini's module could not see the repo. Kept our apt-hook (pos-gate has no `check-apt` mode), our kernel profile, our SELinux draft and our browser policies. build.sh now installs the real hook with Pre-Install-Pkgs and requires the pos-gate binary (fails closed).
- MAC: AppArmor is used for the image (Debian default); SELinux stays an uncompiled draft for the Android side.
- Status: not run locally (needs root for debootstrap). CI result is the evidence.
