# PassAura OS (POS) — `pos-gate` Threat Model & Hardening Checklist

PassAura OS (POS) is licensed under **MIT**, uses **free tools only**, requires **no secrets** in repository files, and enforces **PassAura** as the sole approved password/credential manager. Official releases are signed solely by the project owner, and development follows the zero-budget constraint (`docs/ROADMAP_ZERO_BUDGET.md`) with emulator/CI testing rather than physical hardware or external audits yet.

## Scope & Signed Allowlist Model

`pos-gate` gates package/software installation hooks on Windows (`winget`, MSI / `msiexec`) and Linux (`apt`, `dpkg`, `flatpak`) against an Ed25519-signed allowlist JSON document (`version`, `issued_at`, `expires_at`, `key_id`, `entries[]`, detached signature) verified against a keyring containing active and previous keys overlapping until `retire_at`.

## Threat Model & Concrete Test Cases

### 1. TOCTOU Between Signature/Allowlist Verification and Install
- **Severity:** High
- **Threat:** An attacker swaps or modifies a local installer/package/manifest between `pos-gate` verification and `winget` / `msiexec` / `apt` / `dpkg` / `flatpak` execution.
- **Mitigation:** Bind allowlist entries to exact cryptographic digests (e.g., SHA-256), pass verified immutable paths/digests directly to the installer hook where supported, avoid re-reading unverified paths after approval, and run `pos-gate` immediately before package execution under restricted permissions.
- **Test Case:** Sign an allowlist entry for package X with digest D1, mutate the target installer artifact to digest D2 immediately after verification starts, and assert `pos-gate` / hook rejects installation with non-zero exit status.

### 2. Downgrade / Rollback of the Allowlist
- **Severity:** Critical
- **Threat:** An attacker serves an older, valid Ed25519-signed allowlist that still permits a previously revoked package or password manager or uses an older sequence/version.
- **Mitigation:** Enforce a monotonic sequence number stored in a tamper-evident local state file (`crates/pos-gate/src/rollback.rs`), rejecting any allowlist whose sequence is lower than the persisted sequence.
- **Test Case:** Persist sequence `25` in `RollbackStore`, attempt to apply a signed allowlist with sequence `24`, and assert `RollbackError::DowngradeRejected` is returned and persisted state remains `25`.

### 3. Clock Tampering
- **Severity:** High
- **Threat:** Local system clock rollback or forward jump bypasses `issued_at`, `expires_at`, or key `retire_at` windows.
- **Mitigation:** Combine `issued_at` / `expires_at` / `retire_at` checks with monotonic sequence enforcement (`RollbackStore`), reject allowlists with invalid timestamps (`expires_at <= issued_at`), and require explicit key retirement handling when `key_id` is past `retire_at`.
- **Test Case:** Present an allowlist with `expires_at` in the past or `key_id` past `retire_at` (and advance test clock past `expires_at`) and assert verification fails closed unless explicitly overridden by a valid newer policy window.

### 4. Command Injection via Package Names
- **Severity:** High
- **Threat:** Crafted package names, versions, or arguments containing shell metacharacters (`;`, `|`, `$()`, backticks) or leading `-` flags inject commands or options into `winget`, `msiexec`, `apt`, `dpkg`, or `flatpak`.
- **Mitigation:** Never invoke shells (`sh -c` / `cmd /c`) with interpolated package strings; validate package identifiers against strict allowlisted character sets, pass `--` before positional package arguments where supported, and use argument arrays (`std::process::Command::args`).
- **Test Case:** Supply candidate package names such as `foo;id`, `$(touch /tmp/pwn)`, and `--install-from-file=/tmp/evil` and assert `pos-gate` rejects them prior to spawning any child process.

### 5. Path Traversal
- **Severity:** Critical
- **Threat:** Malicious `key_id`, `entries[].path`, or state/cache paths containing `..`, symlinks, or drive/root escapes overwrite privileged files or read unauthorized files.
- **Mitigation:** Canonicalize and confine paths under approved directories (`fs::canonicalize` + prefix check), reject `..` path components on untrusted inputs, and use `create_new(true)` + atomic rename (`crates/pos-gate/src/rollback.rs`).
- **Test Case:** Pass a `key_id` or artifact path containing `../../etc/passwd` or a symlink pointing outside the allowed directory and assert path validation fails closed.

### 6. Log Leakage
- **Severity:** Medium
- **Threat:** Diagnostic logs or error messages leak sensitive tokens, invitation/registration metadata, internal file paths, or raw untrusted payloads.
- **Mitigation:** Sanitize and bound error/log strings, never log secrets or tokens (none are stored in repo files), and keep structured logs free of sensitive user/credential material.
- **Test Case:** Trigger signature failure, corrupt state error, and downgrade rejection and inspect emitted log/error outputs to verify no sensitive fields or raw unescaped control sequences appear.

### 7. Privilege Escalation
- **Severity:** Critical
- **Threat:** An unprivileged caller abuses `pos-gate` or its state/hook files to execute arbitrary binaries or modify the rollback state file as a higher-privileged user (`root` or `SYSTEM`).
- **Mitigation:** Restrict permissions (`0755`/`0644` or ACLs) on `pos-gate` binary, keyring, and rollback state directory; avoid setuid binaries; validate inputs before privileged actions; and pair with OS-level controls (AppLocker / AppArmor / AOSP ROM policies).
- **Test Case:** Attempt to write to the rollback state directory or invoke privileged hook actions as an unprivileged user and assert permission denial / failure.

### 8. Supply Chain of the Crate Itself
- **Severity:** High
- **Threat:** Compromised upstream crate dependency, tampered `Cargo.lock`, or unverified build environment injects malicious code into `pos-gate`.
- **Mitigation:** Pin exact dependency versions in `Cargo.lock`, build with `cargo build --release --locked` and `RUSTFLAGS=--remap-path-prefix`, use free CI checks (`cargo audit` / `cargo clippy` / reproducible build checks) with no secrets, and sign official POS releases solely by the project owner.
- **Test Case:** Run `cargo build --release --locked` offline/with locked dependencies and verify deterministic artifact hashes and clean dependency resolution without network drift.

## Hardening Checklist

- [ ] Verify detached Ed25519 signature over canonical allowlist payload using matching `key_id` from keyring.
- [ ] Enforce key overlap window (`issued_at` to `retire_at`) for active and previous keys; reject retired or unknown keys.
- [ ] Check monotonic sequence (`RollbackStore`) before accepting any allowlist update.
- [ ] Validate `issued_at < expires_at` and check expiration window.
- [ ] Bind verified package digest and canonical path prior to invoking `winget`, `msiexec`, `apt`, `dpkg`, or `flatpak`.
- [ ] Reject malformed package names and pass arguments via `Command::args` without shell interpolation.
- [ ] Canonicalize paths and block `..` traversal or unintended symlink escapes.
- [ ] Scrub sensitive data from logs and error outputs.
- [ ] Lock down permissions on `pos-gate` binary, keyring, and rollback state directory.
- [ ] Build with `--locked`, fixed `SOURCE_DATE_EPOCH` / `--remap-path-prefix`, and no secrets in source or CI.

## Status & Verification Scope

نواة أمنية وأدوات نموذجية مختبَرة في CI والمحاكيات، ولا يوجد إصدار مختبَر على عتاد أو مدقَّق خارجيًا بعد.


No continue prompt is needed; the full response for Round 3 (crates/pos-gate/src/rollback.rs and docs/THREAT_MODEL.md) fits cleanly within the character limit without truncation.
