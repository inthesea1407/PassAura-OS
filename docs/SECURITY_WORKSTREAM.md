# Security hardening workstream: weakness catalog and compensating controls

Rule of honesty first: no system can be made free of vulnerabilities. Every OS ships with unknown bugs. The goal is to (1) remove known weakness classes, (2) make exploitation harder, (3) contain damage when something is exploited, (4) fix fast. We never claim "unhackable".

## Known weakness classes and compensating controls
| Weakness (where it shows up) | Compensating control (from which system) | Status |
|---|---|---|
| Memory-safety bugs in C/C++ (Linux kernel, Android native, browsers: roughly two thirds of serious CVEs) | Write new trusted components in Rust (pos-core, gate, pkg); hardened allocator (GrapheneOS hardened_malloc), CFI, shadow call stack, MTE where hardware has it, stack protector/INIT_ON_ALLOC (kernel profile) | Rust parts built; kernel profile audit built; rest needs image builds |
| Kernel exploit gives full control | SELinux mandatory access control, seccomp-bpf per app, lockdown mode, no /dev/mem, signed modules, KASLR, hardened usercopy (profile in profiles/) | Profile + audit tool built; enforcement needs image |
| Malicious or sideloaded apps (Android) | iOS-style signed-only install, entitlements, store review (pos-pkg, entitlements) | Logic built and tested; installer needs AOSP build |
| One compromised app reads another's data | Per-app sandbox/SELinux domains, scoped storage, no cross-app ptrace, Qubes-style compartments for high-risk tasks (separate VMs/profiles) | Design |
| Supply chain (malicious dependency, tampered package) | cargo-audit, cargo-deny, gitleaks in CI (written), reproducible builds, signed releases, pinned lockfile, SBOM | CI written, not yet run on GitHub |
| Boot tampering / rootkits | Verified boot with own key, dm-verity read-only system, TPM measured boot, rollback protection | Design, needs real hardware |
| Phishing and credential theft | Only PassAura password manager with origin-bound autofill, passkeys, hardware keys | Design; PassAura product |
| Baseband/firmware/vendor blobs | Cannot be fixed by us: isolate (IOMMU), disable unused radios, choose devices with good vendor support | Honest limitation |
| Side channels (Spectre-class) | Kernel mitigations on, site isolation in browser, disable SMT where needed | Profile items to add |
| Unpatched devices | Own update pipeline, fast CVE tracking, minimum supported patch level check at boot/registration | Pipeline below |
| Admin/panel compromise | Roles, re-auth, passkeys, audit log (pos-core::admin), separate signing key in HSM | Logic built; panel not built |
| Insider/store abuse | Two-person rule for releases, signed transparency log of releases | Design |

## CVE and patch pipeline
1. Intake: track Android Security Bulletins (monthly), Linux kernel stable releases and CVE feed (kernel.org CNA), Debian Security Tracker, RustSec advisories, browser releases.
2. Triage within 48 h: is the vulnerable code in our image? Severity? Exploited in the wild?
3. Fix: rebase on upstream patch (AOSP/GrapheneOS and Debian already publish them); critical in-the-wild issues target 72 h to a signed update, others next monthly release.
4. Verify: tests (cargo test, hardening audit, boot in QEMU), then staged rollout (1% > 10% > all) with rollback.
5. Disclose: security.txt, private reporting address, public advisories after fixes.
6. Measure: time-to-patch, number of open known CVEs in the image.
Needs people to run it (one on-call person); automatable parts: feed scanning, SBOM diff, CI.

## Buildable here now
- Extend pos-hardening profile with more kernel options (Spectre mitigations, lockdown).
- Add `cargo audit`/`cargo deny` runs (CI already written; run locally when the tools are installed).
- A small tool that diffs a Debian package list against the Debian Security Tracker JSON (needs internet fetch, doable).
- Threat model document per component.

## Timeline fit
Workstream runs across all 12 months: months 1-5 Linux controls and CI, 6-8 Android hardening, 9 attestation/admin, 11 external audit (required before any "highly secure" statement), then continuous patching.
