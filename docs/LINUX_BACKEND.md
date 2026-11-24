
# PassAura OS — Linux Package Backend

## Overview

The Linux backend provides a package-install policy gate for APT and Flatpak.

The policy gate:

1. Validates package identifiers.
2. Verifies the signed allowlist using `pos-gate` verification.
3. Rejects unsigned, expired, future-issued, untrusted, or invalid documents.
4. Rejects packages that do not match an allowlist entry.
5. Constructs commands as program + argv.
6. Uses an injected `CommandRunner`.
7. Supports dry-run mode without calling the runner.

It does not directly invoke apt, dpkg, or flatpak.

## Backends

### AptDpkgBackend

Program:

`apt-get`

Arguments:

`install --no-install-recommends -y -- PACKAGE`

The package name is passed as a separate argv element after `--`.

Package names are rejected when they contain:

- Spaces or whitespace
- Semicolons
- Newlines
- Leading dashes
- `/` or `\`
- Characters outside the conservative package-name allowlist

### FlatpakBackend

Program:

`flatpak`

Arguments:

`install --noninteractive REMOTE APP_ID`

The remote and application ID are validated before execution.

The remote allows a restricted ASCII character set.

Application IDs require multiple dot-separated segments and conservative segment validation.

## Authorization

The backend uses `verify_allowlist()` before authorization.

An install is allowed only if:

- The signature is valid.
- The signing key is trusted and not retired.
- The document has not expired.
- The document is not future-issued.
- The package name exactly matches an allowlist entry.

No runner call occurs when verification or authorization fails.

## CommandRunner

`CommandRunner` abstracts process execution.

A production implementation should use `std::process::Command` with
`Command::new(program).args(args)`.

It must not:

- Concatenate the command into a shell string.
- Invoke `sh -c`.
- Invoke `bash -c`.
- Interpret package names as shell commands.
- Allow package input to change the executable path.

The tests use `FakeRunner`, which records the exact program and arguments.

No real package-manager command is executed by these tests.

## Dry run

`InstallMode::DryRun`:

- Performs package validation.
- Verifies the allowlist.
- Checks package membership.
- Builds the command.
- Returns `InstallReport`.
- Never calls `CommandRunner`.

Dry-run is not an authorization bypass.

## Threat model

This backend is intended to reduce risks from:

- Unauthorized package installation attempts.
- Package-name command injection.
- Shell interpretation of untrusted package input.
- Expired or unsigned allowlist documents.
- Packages outside the signed allowlist.
- Invalid Flatpak remotes and application IDs.

## Not covered

This backend does not:

- Verify package contents after installation.
- Verify APT repository signatures or repository configuration.
- Verify Flatpak runtime integrity.
- Prevent privileged users from bypassing the backend.
- Prevent installation through other package-management tools.
- Enforce OS-wide restrictions by itself.
- Prevent malicious packages that were explicitly allowlisted.
- Replace Linux sandboxing, permissions, MAC policy, or system hardening.
- Execute commands or modify the system during tests.

The package-name match uses the allowlist `name` field. For Flatpak,
that name is expected to be the Flatpak application ID.

## Testing

Run the integration tests with:

```bash
cargo test -p pos-gate --test linux_backend
```

Run all tests:

```bash
cargo test -p pos-gate
```

Optional linting:

```bash
cargo clippy -p pos-gate --all-targets --all-features
```

Tests use a fake runner and do not invoke apt, dpkg, or flatpak.

## Integration requirements

The crate must export the modules required by the integration tests,
for example:

```rust
pub mod allowlist_signing;
pub mod linux_backend;
```

The signing module must expose the API expected by the backend:

- `verify_allowlist`
- `AllowlistDocument`
- `AllowlistError`
- `TrustedPublicKey`

The exact exports must be checked against the current crate source
before integration.

API and dependency assumptions

This implementation assumes the existing crate has:

allowlist_signing exported as a public module.

The exact Task 4 types and verify_allowlist() signature.

pos-gate as the library crate name (pos_gate in Rust imports).
