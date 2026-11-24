# Linux Hardening: AppArmor Choice for PassAura OS (POS)

PassAura OS (POS) is licensed under **MIT**, uses **free tools only**, requires **no secrets**, and runs CI checks in **GitHub Actions** (`ubuntu-latest`). Official releases are signed solely by the project owner, and **PassAura** is the sole approved password/credential manager.

## Choice: AppArmor (`image/linux/apparmor/usr.bin.passaura-pkg-gate`) over SELinux

We selected **AppArmor** in `complain` mode first (`flags=(complain)`) for `/usr/local/bin/passaura-pkg-gate.sh` and dropped a separate SELinux module for the Debian-based Linux image layer:

1. **Debian / Ubuntu CI & Image Alignment:** The Linux ISO image builds on Debian (`mmdebstrap`) and runs CI on `ubuntu-latest`, where AppArmor and `apparmor-parser` are natively packaged with minimal setup and no secrets.
2. **Low Overhead & Predictable Gate Scope:** The package gate hook only parses package names (`awk`, `cut`, `bash`) and exits non-zero on blocked password managers. Path-based AppArmor rules in `complain` mode let us observe any unexpected file or process access before switching to `enforce` mode without heavy policy-module compilation overhead.
3. **Zero-Budget & Emulator Workflow:** Keeps tooling strictly free and fast in CI (`apparmor_parser -Q`), fitting PassAura OS's zero-budget constraints.

## Status & Verification Scope

نواة أمنية وأدوات نموذجية مختبَرة في CI والمحاكيات، ولا يوجد إصدار مختبَر على عتاد أو مدقَّق خارجيًا بعد.
