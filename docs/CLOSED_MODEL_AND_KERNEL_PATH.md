# iOS-style closed model, own kernel, or hardened base: honest comparison

## 1. What an iOS-style model actually requires
iOS blocks "other password managers" mostly through policy in a closed system, not one clever check. The parts:
1. Secure boot chain: ROM-anchored boot, each stage verifies the next, kernel and system volume signed and read-only. Needs control of hardware root of trust or a device whose bootloader trusts YOUR key (Pixel with custom AVB key; Samsung/Oppo do not allow this).
2. Signed-apps-only: kernel/installer refuses unsigned code (code signing enforced at page-fault level on iOS). On Linux/Android: dm-verity/fs-verity + IMA appraisal + a package installer that only accepts store-signed packages.
3. Entitlements: every privileged capability (credential provider, autofill, accessibility) is a signed entitlement granted by the vendor. Modeled in `pos-core::entitlements`: restricted entitlements reserved for the PassAura team.
4. Sandboxing: per-app UID/SELinux domain/seccomp, no cross-app memory or file access, no ptrace.
5. A vetted store: review, developer identity, revocation. Needs people, process and servers.
6. No sideloading: also means no developer mode on end-user devices, which kills open-source community use on the same image.
Cost of this model: it is the opposite of "open source for everyone to modify". Forks can always ship a build without the rules. The closed guarantee holds only on devices whose boot chain trusts only PassAura keys.

## 2. From-scratch kernel/microkernel
"Bigger than the Android and Linux kernels" in features is not realistic from scratch. Honest scale:
- Linux: ~30+ million lines, thousands of contributors over 30 years, thousands of device drivers.
- A microkernel (seL4, Redox, Fuchsia/Zircon exist) can be small and even formally verified (seL4), but the work is drivers, filesystems, networking, graphics, power management, app framework, tooling. A usable phone/PC OS from scratch is typically hundreds of engineers for many years (Fuchsia, Harmony OS scale).
- Hardware: each SoC needs drivers and vendor firmware that are closed. Without them: no Wi-Fi, modem, GPU, camera on real phones. Realistic targets for a small team: QEMU and a few dev boards (Raspberry Pi class), not consumer phones.
- What a tiny team CAN do: build on an existing small kernel (seL4 or Linux) and write the system layer on top.
Verdict: writing our own kernel is not a path to "more secure" in any time frame that matters; the security gain comes from policy, signing, and small trusted code, which we can do on a hardened base.

## 3. Hardened Android/Linux base
- Faster, real hardware, real drivers, proven kernels with SELinux, seccomp, dm-verity, verified boot.
- Android track: AOSP-based image on devices with unlockable bootloaders and custom AVB key; PassAura installer, store, entitlement service in the framework. Closest to iOS-style on real phones. Needs a 16+ core/64+ GB build machine.
- Linux track: Debian base + signed packages only + IMA/dm-verity + our package gate and store.
- Stock Samsung/Oppo: only a managed-device (device owner) layer; not iOS-style, cannot control the boot chain.

## 4. Recommendation
Hardened base now (AOSP-derived for phones, Debian for PCs/servers), iOS-style closed model implemented on top: signed-apps-only, entitlements, PassAura-only credential provider, own store. Keep a research track for a microkernel (seL4-based) only after the base works and only on QEMU/dev boards.
Key decision for the owner: closed or open?
- Closed (iOS-style): strongest enforcement, needs signed store, no sideloading, on devices that trust only PassAura keys; contradicts "open source, anyone can modify".
- Open: anyone can build and modify, enforcement binds only official signed builds.
A split is possible and common: source open (MIT), but official builds are signed with the owner's key, and only official builds get the store, updates and PassAura Premium. State this plainly to users.

## 5. Phases
0. Done here: policy core, invite/seed/admin logic, package gate, entitlement decision logic, hardening audit, browser policies, docs.
1. Buildable here next: manifest format and signing tooling (Ed25519 via a Rust crate), signed package format and verifier, store-side review database model, more tests/fuzzing of the gate.
2. Needs a bigger machine (cloud VM): Debian image with IMA/dm-verity/SELinux and signed-only packages, booted in QEMU; AOSP/LineageOS build for one unlockable device with own AVB key and installer hook.
3. Needs real devices/people: store operations, review process, external security audit, device certification.
4. Research: seL4-based microkernel prototype on QEMU.
Nothing here is shipped enforcement yet. Do not market it as iOS-level.
