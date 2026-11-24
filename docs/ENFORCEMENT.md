# Real enforcement: what exists vs design only

Honest rule: nothing below may be called "blocked" for users until it has been
run on the real target (a Linux box with root, a real device, or an AOSP build).

## A. Exists and tested here (user space, Linux/Debian)
| Piece | What it does | Tested how |
|---|---|---|
| `pos-core::blocking` | Decision logic | 5 unit tests |
| `pos-gate` crate + `pos-gate` binary | Observes a package's real contents (installed file paths, .desktop text, known names) and returns allow/block | 5 unit tests + built binary |
| `enforcement/apt-hook.sh` | Reads each real .deb (dpkg-deb), runs pos-gate, fails the install (non-zero) if blocked | Ran against 3 hand-built .debs: native-messaging host package BLOCKED, .desktop "Password Manager" package BLOCKED, ordinary package allowed |
| `policies/browser/*.json` | Chrome/Chromium managed policy and Firefox policies.json that turn off built-in password managers and block all extensions | JSON validated only. Not loaded into a real browser here |

Limits of A: root can bypass or delete the hook; it only covers apt/dpkg installs (not snap, flatpak, AppImage, pip, manual binaries, web apps); heuristics can miss a manager that hides all of it and can false-positive on unrelated packages; the browser policies block extensions wholesale, which is heavy-handed.

## B. Draft written, NOT compiled or tested
- `selinux/passaura_pmgate.te`: policy module draft (vault label only for the PassAura domain, native-messaging manifests write-protected). Needs a SELinux-enabled system, checkpolicy and root to compile, load and test.

## C. Design only: needs kernel/AOSP build machine and a real device
Linux kernel level (full image build, root, QEMU or hardware):
- LSM: SELinux (labels/neverallow as in B) or a small custom LSM; Landlock for per-app filesystem rules (needs kernel >=5.13, testable on a normal Linux with a compatible kernel, not in this sandbox).
- seccomp-bpf profiles to confine apps (cannot ptrace or read other processes' memory, so a competing manager cannot scrape).
- eBPF LSM (CONFIG_BPF_LSM) to deny exec/open of known manager binaries and access to the vault by label; needs root and kernel config.
- fanotify/IMA to measure and allow only signed binaries (turn the apt hook into a real allowlist: only signed packages run).
- dm-verity read-only root + signed packages = root user cannot silently remove the gate.

Android (needs AOSP/LineageOS build, or a device owner on stock Android):
- Credential Manager: `DevicePolicyManager.setCredentialManagerPolicy(PackagePolicy)` (API 34+, device owner or work-profile owner) can allow only PassAura as a credential/passkey provider. Verified to exist in the Android reference: https://developer.android.com/reference/android/app/admin/DevicePolicyManager
- Accessibility: `setPermittedAccessibilityServices` allows only listed packages (same reference).
- Autofill: `UserManager.DISALLOW_AUTOFILL` turns all autofill off; selecting only PassAura needs a framework change in AutofillManagerService (restrict `AutofillService` binding to one package) in a full AOSP build. On stock Android, the nearest option is the work-profile policies above.
- Installer: a PackageInstaller / PackageManagerService hook that runs the same observation (manifest components: AutofillService, CredentialProviderService, AccessibilityService, BIND_ permissions) and rejects the install. Requires AOSP build. On stock Android a device-owner app can only restrict installs by allowlist (`DISALLOW_INSTALL_APPS` plus an approved app list / managed Google Play), not scan.
- SELinux in AOSP: a `.te` domain for the PassAura service and neverallow rules for credential storage. Requires AOSP build; Treble/vendor policy interactions are a big risk.
- A device-owner app (the "portable layer") is the only Android enforcement that works on stock Samsung/Oppo, and it requires the device to be set up as a managed device (factory reset provisioning). That is a hard limit for ordinary consumer phones.

## D. Cannot be fully prevented even with all of the above
- Web apps and browsers (password stored by sites, built-in browser managers on unmanaged browsers), screen scrapers, users typing passwords from a notes app, a rooted/unlocked device, forks of POS.
