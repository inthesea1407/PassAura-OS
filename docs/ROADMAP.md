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
| Store / updates | signed packages (Ed25519); `pos-update` manifest verifier (threshold Ed25519, per-channel rollback state, expiry; pure functions, no I/O) | update client `pos-cli update` (merged; local-dir and HTTPS transports), key ceremony (owner), store review model (design + owner policies merged; pre-review checker and publish tooling merged; store DB written as 0013 draft, owner applies) |
| Install / network | `pos-install` crash-safe install transaction (real dpkg runner never run); `pos-netpolicy` per-UID nftables generator (nft syntax unverified) | run both in the QEMU image, verify nft rules on a real kernel |
| Crypto / storage | `pos-crypto-suites` (V1, L1 layered, tiered Argon2id, X25519+ML-KEM-768 wrap) and `pos-vault-store` (encrypted single file, rewrap with payload verify, atomic write). Not audited; ml-kem is not independently audited | wire into the apps, rollback counter, data-key rotation, Windows tests |

## Milestones
- M1 (done): policy engine, package gate, signed packages, CI.
- M2 (done, draft): backend schema, owner panel, device-owner app, Debian image, Windows profile.
- M3: every layer boots or runs in an emulator in CI (QEMU Debian, Android emulator, Windows runner), with the real gate in the loop.
- M4: single enforced policy across Android, Windows and Linux; installer for each; invite registration end to end against a live backend.
- M5: store, updates, Premium entitlement; public beta with invite codes.
- M6: external review (when budget allows); only then claim a security level.

## Status as of 2026-11-25
Merged and CI-green: pos-crypto-suites, pos-vault-store, pos-update, pos-install, pos-update-install (update-to-install handoff, see UPDATE_INSTALL_HANDOFF.md), pos-netpolicy. All of it is tested in CI only: nothing has run on real hardware, nothing is audited, releases are unsigned (no release key yet), and payments stay off behind an unset flag.

## Known limits
- Open source, so forks can remove the block; only official signed builds enforce.
- Android without a full ROM cannot block apps that need no permissions; Windows and Linux userland can be bypassed by an admin.
- Free tooling only: no hardware tests, no paid audit, emulator time is limited.
