# Zero-budget roadmap (supersedes the spending items in ROADMAP_12_MONTHS.md)

Owner decision (12:53): no spending for now, everything on emulators. Paid items are deferred decisions, not cancelled.

## Free resources available
- This workspace: 1 CPU, ~1 GB RAM, internet. Good for Rust, tests, docs, small tools. Too small for kernel/AOSP builds or running heavy emulators.
- GitHub Actions free tier: public repo = free Linux runners (2 vCPU, ~7 GB RAM, limited disk), enough for cargo test, linting, cargo audit/deny, gitleaks, a minimal Debian image build (debootstrap, qemu-user), QEMU boot tests of a small image (TCG, no KVM) and kernel config audits. Not enough for a full kernel compile every run or AOSP (needs ~300+ GB disk, 16+ cores). Limits and terms change; verify current free-tier limits before relying on them.
- Free hosted pieces: Supabase free tier (invite/registry backend prototype), GitHub Pages/Vercel free for docs and admin panel prototype.
- Emulators: QEMU (Debian and kernel tests), Android Studio emulator or Cuttlefish for Android app-level work. These need KVM and several GB RAM; they do not run in this workspace and likely not on free CI (no KVM). The owner's own PC could run them if it has 16 GB RAM and virtualization (his choice, no purchase).

## What can be done at zero cost
| Month | Work | Where |
|---|---|---|
| 1-2 | Signing CLI, store review DB model, fuzz gate/verifier, threat models, extended kernel profile, CVE feed checker | workspace + GitHub Actions |
| 2-3 | Debian minimal image built in CI (debootstrap), signed-only installer, apt gate, package gate tests, QEMU TCG boot smoke test, SELinux module compile and policy tests in a CI container (needs root in the container, available on Actions) | GitHub Actions |
| 3-5 | PassAura Premium app prototype (Rust core), invite/registry backend on Supabase free tier, admin panel prototype, attestation verification logic with test vectors | workspace, free tiers |
| 4-8 | Android: app-level portable layer (Kotlin app + Rust JNI) tested on emulator (owner's PC or Android Studio emulator), device-owner policy app (setCredentialManagerPolicy etc.) tested on emulator | owner's PC emulator if available; otherwise design only |
| 6-12 | Documentation, public repo, community contributors (free), security review by volunteers/bug reports, patch pipeline automation | free |

## What cannot be done without spending or hardware (deferred decisions)
1. A full AOSP/GrapheneOS-based image build: needs 16+ cores, 64 GB RAM, 400+ GB disk. Free CI cannot do it. Deferred: cloud VM (paid) or a borrowed powerful PC.
2. Real own-key verified boot and secure boot on a real device: needs an unlockable device (e.g. Pixel). Emulators can test a boot chain model but not hardware attestation or Titan/TEE behavior. Deferred: buy a device.
3. Hardware-backed signing key (HSM/YubiKey) for the store key: until then keep a software key offline and say it is a development key only. Deferred.
4. Real hardware attestation testing (Key Attestation roots, TPM): emulators give fake attestation. Deferred: needs a real device.
5. External security audit: paid. Until then no claim of "very high security". Volunteer review only.
6. Device-owner enforcement on real Samsung/Oppo: needs real devices and factory reset. Emulator only.
7. Performance, battery, driver, radio/camera testing: impossible on emulators.

## Honest status wording
"Prototype security core and tooling, tested in CI and emulators. No hardware-tested or audited release yet."

## Update 13:33: online-only (owner has a 2 GB RAM phone, no computer)
Everything that needs an emulator or a build must run in the browser or on free CI. Nothing runs on the owner's phone.

| Need | Free online option | Limit (verify before relying) |
|---|---|---|
| Rust tests, CI, audits, Debian image build, QEMU boot smoke tests | GitHub Actions on a public repo | Free for public repos. Private repos get a monthly free allowance only. No KVM, so emulation is slow (TCG). |
| Dev shell with a few cores | GitHub Codespaces | Personal accounts get a monthly free quota. GitHub's billing docs say usage past the quota is charged unless a budget with "Stop usage when budget limit is reached" is set. The spending limit must stay at $0. Exact core-hours not verified here. |
| Android emulator in a browser | Appetize.io free plan | Per its pricing page: 1 user, 2 active devices, 30 minutes refilled monthly, 3-minute sessions. Good only for quick demos of an APK, not for development. |
| Android app build | GitHub Actions (Gradle + Android SDK on ubuntu runner) for APKs | Fine for apps and the device-owner policy app. Not for AOSP. |
| Android emulator tests in CI | Actions without KVM: very slow, unreliable. Usually unavailable on free runners. | Treat as unavailable. |
| Backend (invite/registry) | Supabase free tier (account exists: org "Passaura") | Free projects pause after inactivity; limited number of free projects. |

Owner action: before using Codespaces, set the GitHub spending limit to $0 (Settings > Billing and plans) so nothing can be charged. I cannot set that for him.

Consequences:
- Android work stays at the app level (portable layer, device-owner policy app) validated as APK builds in CI and brief Appetize demos. AOSP/GrapheneOS work remains deferred (no build power).
- Linux work is real: Debian image in CI, QEMU TCG boot test, SELinux module tests, hardening audit.
- The repo must be public to use free Actions generously. Owner asked for private at 12:27. Trade-off to decide: public repo (free CI, visible code, matches the open-source decision) vs private (limited free minutes).
