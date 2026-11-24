# PassAura OS architecture and honest scope

Goal: a hardened Android variant and a hardened Linux variant, sharing one
security core (`pos-core`).

## What exists and is tested today
- `pos-core`: deny-by-default permission engine (auth, grants, expiry, revoke, explicit deny).
- `pos-android`, `pos-windows`: permission mappers (interfaces only).
- `pos-hardening`: audits a kernel `.config` against `profiles/linux-kernel-hardening.txt`.
- CI: `cargo test --workspace`.

## What this is not (yet)
It is not a bootable OS. No kernel, Android image or ROM is built here.

## Hardened Android track
Do not fork AOSP from scratch. Start from an existing hardened AOSP base
(for example GrapheneOS, which tracks AOSP and supports Pixel devices) and add
PassAura policy on top. Plan:
1. Pick one target device (Pixel recommended: unlockable bootloader, verified boot with custom key).
2. Sync the base source and build on a machine with 16+ cores, 64+ GB RAM, 400+ GB disk (cloud build VM, a few hours per build). The current workspace (1 CPU, 1 GB RAM) cannot.
3. Keep PassAura changes as a patch series and a small system service that calls `pos-core`.
4. Test on a device or the Android emulator on a machine with KVM.

## Hardened Linux track
1. Base: a minimal distro built with Buildroot or Yocto, or a hardened desktop distro.
2. Kernel: mainline LTS built with the profile in `profiles/linux-kernel-hardening.txt`. Enforce with `pos-hardening` in CI against the generated `.config` (this part is testable now).
3. Userspace: SELinux enforcing, read-only dm-verity root, signed modules, secure boot with own keys, full-disk encryption with TPM, default-deny firewall, sandboxed apps (seccomp plus namespaces).
4. Build on a bigger machine; boot-test in QEMU.

## Security design principles
- Deny by default. Least privilege. Explicit deny wins.
- Every decision is auditable (audit log is the next milestone).
- Small trusted core in memory-safe Rust.
- Claims about security are made only after tests and, later, an external review. "Very high security" is a design target, not a property we can claim yet.

## Milestones
1. Audit log and persistent policy store in `pos-core`.
2. Linux kernel hardening CI with a real `.config`.
3. Cloud build VM for the Android and Linux images.
4. Device and QEMU boot tests.

## Update (review input)
- Success metric: repeatable deny tests, not security claims.
- Android base candidates: LineageOS (customization) or GrapheneOS (security reference). Decision pending: target device.
- Linux base: Debian stable.
- Done: policy version constant, audit log (identifiers only, no secrets), boundary tests, `pos-linux` adapter, CI scans (cargo audit, cargo deny licenses, gitleaks).
- Deferred to proper hardware: image builds and flashing.

## Device scope: Samsung, Oppo and all Android devices
Decision from the owner: not Pixel only. What this changes:
- A single hardened ROM cannot cover all devices. Each device needs its own vendor blobs, kernel, bootloader unlock and signing keys. Samsung (Knox fuse trips on unlock, Knox features lost, many regions locked) and Oppo (bootloader unlock often restricted or removed) are hard ROM targets. GrapheneOS supports only Pixels by design because it needs hardware security features and verified boot with custom keys.
- Therefore: two layers.
  1. Portable layer (works on stock Android, any vendor): PassAura app and policy service built on `pos-core` via an Android app (Rust through JNI), device-posture checks (patch level, verified boot state, encryption, root detection), permission audit, app allow/deny policy using Device Policy / work profile APIs, VPN/DNS filtering, hardening checklist.
  2. Full ROM layer (optional, per device): only for devices with unlockable bootloaders and good LineageOS support. Each added device is a separate maintenance and test burden.
- Security claim stays honest: on stock Android we can enforce policy and detect weak posture; we cannot make the underlying vendor kernel and firmware more secure.

## Next steps for the portable layer
1. `pos-android` JNI bindings and an Android Studio app skeleton (needs a bigger build machine for Gradle/NDK).
2. Posture check rules as data, tested in Rust.
3. Pick 1-2 real test devices (user's own Samsung/Oppo) for the portable layer.

## Product rules (owner decisions)
1. Open source. License: MIT (see LICENSE). Anyone may use, modify and redistribute.
2. No ads anywhere in the system. Enforced as a policy default (`ADS_ALLOWED = false`); ad-category components are denied.
3. Only PassAura Premium (paid) works as the password manager in POS. Any other password manager is unsupported: `category_allowed` denies it, even with a license. Premium without an active license is also denied.
4. New project information is shared with the ChatGPT review thread.

Known tension: with an open-source license, anyone can fork POS and remove rule 3. The rule can only bind official PassAura OS builds, not forks.

## Access model: invite codes (owner decision, replaces Egypt-only paid Premium)
- Access to POS, and PassAura Premium inside it, is by invite code.
- Codes are single-use (one person, one redemption).
- Every member gets 2 invites (`INVITES_PER_MEMBER`). The first members come from seed members chosen by the owner.
- Implemented in `pos-core::invite` (issue, redeem, quota, inviter chain) with tests.
- Codes must come from a secure RNG (128+ bits) and be stored hashed. Abuse controls still needed: rate limits on redemption attempts, revoke a code, revoke a member and their unredeemed invites.

Effect on rule 3 (Premium-only password manager): the rule stays (only `passaura.premium` is allowed). `licensed` now means "is an active invited member", not "paid". Premium is included with membership; no payment.

Lapse behavior: nothing lapses by time. A member loses access only if the owner revokes them. Recommended: even then, keep their own data exportable.

## Blocking other password managers (owner decision)
Not just unsupported: technically blocked. `pos-core::blocking` classifies apps by declared capability (autofill provider, credential/passkey provider, accessibility autofill, password vault store), not by name, and blocks every operation (install, launch, autofill and credential provider roles, reading password fields, login import/export) unless the app is the licensed `passaura.premium`.

Enforcement points in the real OS (not built yet): package installer (reject at install), Android autofill/credential-manager service selection (only PassAura selectable), accessibility service grants (deny password-field access), SELinux policy for the Linux track, and app-store allowlist.

Honest limits:
- Forks can remove the block; it binds official builds only.
- Apps that declare nothing (web apps, browsers' built-in managers, screen scrapers) need runtime detection and cannot be fully blocked. Browsers with built-in password saving would need that feature disabled by policy.
- Users with a rooted or unlocked device on stock Android (portable layer) can run anything; the block is complete only on a full POS image.
- Blocking users' existing managers can lock them out of their own passwords: provide an export/migration path into PassAura.

## Seed members (owner decision)
The first 1000 people to register are seed members: they join without a code, in registration order (`register_seed`, `SEED_CAP = 1000`), and each gets 2 invites. After 1000, registration is closed and access is invite-only (`redeem`). Total possible growth from seeds: 1000 + 2000 invites in the first generation, and so on.
Needs: identity checks so one person cannot register many seed slots (phone/email verification, rate limits), and a decision on what "register" means (account on the website vs a device).

## Device registration and free anti-abuse (owner decision)
"Register" means the device. Anti-abuse must be free (no paid SMS or services). Implemented in `pos-core::device`:
1. Hardware-bound identity: device id = hash of a hardware-backed attestation key (Android Key Attestation / StrongKeyMint; TPM on Linux/Windows). Free, survives reinstall. Emulators and unattested devices are rejected.
2. One device = one membership (seed or invite).
3. Free rate limit: max 5 seed registrations per source bucket per day.
4. Optional email verification (free link), flag only, not required.
Limits: a person with several real phones can take several slots; hardware attestation proves "a real device", not "a unique person". Attestation verification needs Google's free root certificates and on-device support (old or uncertified devices may fail). Source-bucket rate limits can hit shared networks (NAT). The attestation parsing itself is not built yet, only the registry logic.

## Membership lifetime (owner decision)
Membership never expires. Only the owner can revoke (`revoke_member`). Revoking voids the member's unredeemed invites and keeps the seed slot used. Export of the member's own data stays allowed after revocation (`can_export`). Premium-only checks use `is_active`.
Note: revoking someone does not revoke people they already invited.

## Review hardening (ChatGPT review) and what is NOT claimed
- Attestation: a hash or a `hardware_backed` flag is only a claim. Real proof needs server-side verification of the attestation certificate chain against vendor roots, bound to a one-time server challenge (`ChallengeStore`, replay and expiry tested). Chain verification is not built. Attestation shows a genuine device key, not a unique person.
- Blocking: self-declared capabilities are not a trust boundary. The OS must feed `blocking::enforce` capabilities it observed itself (installer analysis, runtime service registration). The module is decision logic only; enforcement in the OS is not built. Do not claim other managers are "blocked" until the installer, autofill/credential selection, accessibility and SELinux enforcement exist and are tested.
- First 1000: seed registration is idempotent (retry returns the same seed number, never a second set of invites). In a real service it needs one atomic transaction (a database unique constraint on device id plus a counter row), which this in-memory code only models.
- Admin: see docs/ADMIN_PANEL.md for roles and re-auth.
- Vault keys and export do not depend on membership or payment.
