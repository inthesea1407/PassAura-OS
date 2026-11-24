# 12-month roadmap: modified AOSP + modified Debian, closed model on top

Honest basis: a small team (even one person using AI tools) can deliver a hardened, signed-only Debian image and an AOSP-based image for ONE unlockable device in 12 months. A multi-device Android ROM, a polished store and an external audit need more people and money. Dates are estimates, not promises.

Legend: VM = cloud build machine (16+ cores, 64+ GB RAM, 500 GB disk, a few hundred USD/month if kept on; billed, so the owner must approve); DEV = physical test device; PPL = other people needed.

| Month | Milestone | Needs |
|---|---|---|
| 0 (done) | Policy core, invite/seed/admin logic, package gate, entitlements logic, signed package format (Ed25519) with verifier, docs, tests | this workspace |
| 1 | Package signing CLI and store review database model; fuzz the gate and verifier; keypair ceremony plan (store key in an HSM or YubiKey) | workspace; a hardware key (~$50) |
| 2 | Debian image build (debootstrap/live-build) with hardened kernel config audited by pos-hardening; apt replaced by a signed-only installer | VM (a few hours of builds) |
| 3 | Boot the Debian image in QEMU; IMA/dm-verity read-only root; SELinux enforcing; our SELinux module compiled and tested | VM |
| 4 | Secure boot with our own keys (QEMU/OVMF test, then real PC) ; TPM-bound disk encryption | VM, one spare PC |
| 5 | PassAura Premium password manager as first signed app; credential-provider entitlement enforced on Linux (D-Bus secret service/browser native messaging gated) | VM |
| 6 | Choose Android device (Pixel recommended: custom AVB key). Sync GrapheneOS/AOSP sources, first clean build, flash and boot | VM (heavy: 100s GB), DEV (Pixel ~ $300-500, owner purchase) |
| 7 | Android: PassAura installer service (signed-only), entitlement service, restrict AutofillService/CredentialProviderService/Accessibility to PassAura in the framework | VM, DEV |
| 8 | Android SELinux policy for the PassAura domains and vault; verified boot with own key | VM, DEV |
| 9 | Invite/registry backend (free tier: Supabase or similar), device attestation verification server-side, admin panel MVP | PPL optional; free tiers |
| 10 | Private beta: seed members (first 1000 cap in code) on Debian + one Android device model; telemetry-free crash reports | PPL (testers) |
| 11 | External security review of installer, store, attestation, admin panel | PPL (paid auditors; budget decision by owner) |
| 12 | Public release of official signed builds; source published (license decision pending: closed vs open with signed official builds) | PPL, legal review of license and blocking policy |

Risks that can move dates: build machine cost and availability, Android version upgrades (framework patches must be rebased every release), vendor firmware blobs, store key security, anti-competition and platform-policy issues of blocking other password managers, owner decision on closed vs open.
Out of scope for 12 months: own kernel, Samsung/Oppo full ROMs, multi-device support, Windows-like compatibility layer.
