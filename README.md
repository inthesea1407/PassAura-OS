# PassAura OS

Early security core, tooling and Android client for PassAura OS. Free (MIT), no ads.

**Status:** a tested policy core, a signed-allowlist install gate, a CLI, an
Android app, an admin panel and backend functions. It is not a standalone
operating system or kernel yet. Everything is tested in CI and emulators only.
Nothing has run on real hardware and nothing has been externally audited. See
`docs/ARCHITECTURE.md` (honest-scope section) before relying on any claim.

## Crates
- `pos-core`: deny-by-default grants, TOML policy, hash-chained audit log, admin roles, invites, entitlements, device registry, app-category blocking.
- `pos-gate`: install gate. Ed25519-signed allowlists (v1 and v2 are not unified yet), key rotation, rollback state, name validation, apt/dpkg and Flatpak backends.
- `pos-cli`: verify, sign, keygen, install (dry-run), audit verify/tail.
- `pos-client`: client for the register and redeem-key Edge Functions.
- `pos-pkg`: signed package manifest and payload hash check.
- `pos-hardening`: kernel .config audit against a profile.
- `pos-platform`: platform policy abstraction.
- `pos-android`, `pos-windows`, `pos-linux`: name-mapping adapters only. They do not call real OS APIs.

Also in the tree: `android/` (app), `admin/` (web panel), `enforcement/` (apt hook), `docs/`.

## Test
    cargo test --workspace --locked

CI also runs gitleaks, cargo-audit and cargo-deny (licenses), shell tests and an Android build.

## License
MIT. Product rules: no ads, and only PassAura Premium works as a password manager in official signed builds.

## Roadmap
See `docs/ROADMAP.md`.
