# PassAura OS (POS) Linux Live/Installable Image (`image/linux/`)

PassAura OS (POS) is licensed under **MIT**, uses **free tools only**, requires **no secrets**, and runs CI checks in **GitHub Actions**. Official releases are signed solely by the project owner, and **PassAura** is the sole approved password/credential manager.

## Artifacts & Workflow

- `image/linux/build-iso.sh`: Builds a Debian stable (`amd64`) rootfs via `mmdebstrap`, compresses it with `mksquashfs` (`squashfs-tools`), configures GRUB for BIOS + UEFI, and packages the hybrid ISO via `grub-mkrescue` / `xorriso`.
- `image/linux/passaura-pkg-gate.sh`: Package gate hook wired into `/etc/apt/apt.conf.d/99passaura-pkg-gate` (`DPkg::Pre-Invoke`) to allow PassAura and block known competing password manager packages.
- `image/linux/smoke-qemu.sh`: Boots the ISO headlessly in `qemu-system-x86_64` over serial (`ttyS0`) and verifies that a login prompt/banner appears and the PassAura package gate hook is present and active.
- `.github/workflows/linux-image.yml`: Two-job GitHub Actions pipeline (`build-linux-iso` and `smoke-test-qemu`) on free `ubuntu-latest` runners with no secrets.

## Status & Verification Scope

نواة أمنية وأدوات نموذجية مختبَرة في CI والمحاكيات، ولا يوجد إصدار مختبَر على عتاد أو مدقَّق خارجيًا بعد.
