# PassAura OS roadmap (toward a full OS layer on Android, Windows and Linux)

Honest status: a tested policy core, a package gate, a signed-package format, a Debian image recipe, a Windows hardening profile, a draft Android device-owner app, and a drafted Supabase backend with an owner panel. It is NOT yet an operating system, nothing is deployed, and no external security audit exists. See docs/ROADMAP_ZERO_BUDGET.md for cost limits (zero spend, online emulators only).

## Weekly rhythm
1. Collect: merge every model's returned work onto main (disjoint paths, see docs/AI_BACKLOG.md and docs/CONTRACTS.md).
2. Test: cargo test --workspace, Android CI, SQL (pgTAP) CI, image smoke, Windows profile CI. Fix before adding new work.
3. Review: one model reviews the merged tree (security first); findings go to docs/ and are fixed or tracked.
4. Report: what is real (CI-proven), what is draft, what needs the owner.

## Layers
| Layer | State now | Next |
|---|---|---|
| Policy core (Rust) | pos-core, pos-platform scaffold, 127 tests passing | one policy format shared by all three platforms |
| Linux | Debian image recipe builds and verifies in CI; real pos-gate apt hook; AppArmor | boot the image in an emulator (QEMU in CI), enforce credential-manager allowlist on desktop |
| Windows | AppLocker/ASR/registry profile, validated in CI (static checks only) | test on a Windows VM image in CI; WDAC policy |
| Android | device-owner app compiles in CI, credential-manager policy (API 34+) | run on an emulator in CI, QR provisioning, hardened-AOSP path |
| Backend | migrations 0001-0009 + pgTAP pass on plain Postgres in CI; Edge Functions drafted | apply to Supabase (owner), deploy functions (owner), concurrency tests under Docker |
| Owner panel | static app drafted | test against a live project (owner), pin supabase-js SRI |
| Store / updates | signed packages (Ed25519) | update channel and store review model |

## Milestones
- M1 (done): policy engine, package gate, signed packages, CI.
- M2 (done, draft): backend schema, owner panel, device-owner app, Debian image, Windows profile.
- M3: every layer boots or runs in an emulator in CI (QEMU Debian, Android emulator, Windows runner), with the real gate in the loop.
- M4: single enforced policy across Android, Windows and Linux; installer for each; invite registration end to end against a live backend.
- M5: store, updates, Premium entitlement; public beta with invite codes.
- M6: external review (when budget allows); only then claim a security level.

## Known limits
- Open source, so forks can remove the block; only official signed builds enforce.
- Android without a full ROM cannot block apps that need no permissions; Windows and Linux userland can be bypassed by an admin.
- Free tooling only: no hardware tests, no paid audit, emulator time is limited.
