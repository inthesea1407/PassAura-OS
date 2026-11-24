# PassAura OS (POS) - AI model backlog

Goal: POS becomes a full operating system layer that installs on top of Android, Windows and Linux.
Rules for every task: free tools only, MIT, no secrets in files or prompts, each model touches only its own paths, nothing runs on the live database or live accounts without the owner's approval.

Process
- One task per model at a time. When a model returns a task, the next one in its list is sent.
- Output comes back as full files with repo paths and is merged by the OS agent. Each model states what it did not run.
- Weekly: (1) integrator merges all modules into one build, (2) CI runs every test (cargo test + clippy, gradle assembleDebug testDebugUnitTest, supabase SQL/Deno tests, image build + verify), (3) ONE model reviews the whole merged app (rotating: week 1 ChatGPT, week 2 Gemini, week 3 DeepSeek, week 4 Qwen), (4) findings go back to the owning model as the first task of the next cycle.

## ChatGPT - Rust core and desktop (Windows/Linux)
1. pos-platform crate: PlatformBackend trait (credential-manager allowlist, package gate, hardening status) with Linux, Windows and Android stub backends, plus tests. [round 2, sent]
2. Self-review and hardening pass of pos-client (property tests for hashing/cache, fuzz-style invalid JSON tests).
3. Windows backend: AppLocker/WDAC policy generator and registry-policy writer (dry-run mode, tests).
4. pos-gate package allowlist signing and verification (ed25519 via a free crate), key rotation doc.
5. Linux backend: apt/dpkg and Flatpak gate integration tests.

## Qwen - Android app
1. Arabic/English localization (strings.xml, RTL layout, accessibility labels) and move the hardware-id salt out of code into BuildConfig. [round 2, sent]
2. Gradle wrapper + GitHub Actions fixes so assembleDebug and unit tests pass; lint config.
3. Device-owner provisioning flow (QR/adb docs and in-app status screen), error states for every register/redeem error code.
4. Premium state refresh (WorkManager) and offline cache.
5. Instrumented-test plan and Robolectric tests for UI screens.

## DeepSeek - Backend and admin
1. Extra SQL/Deno tests for races (concurrent invite use, seed limit), indexes and rate-limit performance review. [round 2, sent]
2. Audit log retention and admin action history view (migration + admin UI).
3. Premium key batch generation and expiry reports (owner-only, MFA).
4. Backup/restore and migration runbook for the free Supabase tier.
5. Abuse controls: proof-of-work fallback design for registration (if Turnstile is not available).

## Gemini - Images and platform hardening
1. Windows hardening profile as code (AppLocker/WDAC XML, Defender ASR rules, registry baseline) + verify script. [round 2, sent]
2. Linux live/installable image: add ISO build step (mmdebstrap + squashfs) and boot smoke test under QEMU in CI.
3. Compile and validate selinux/passaura_pmgate.te or drop it and finish the AppArmor profile (justify).
4. Android ROM-side policy notes (AOSP overlay, SELinux contexts) as docs and config files.
5. Reproducible-build check (two builds, compare hashes) in CI.
