# Contributing to PassAura OS

## Build and test

```bash
cargo build
cargo test --workspace
cargo test -p pos-core        # one crate
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
```

Fix what Clippy reports before opening a pull request.

## Commits and pull requests

- Short, imperative subject lines ("Add policy parser"). Focus the body on why.
- One logical change per commit when practical. Include tests for new behavior.
- Do not commit secrets, credentials or personal data. Public values only (for example the Supabase URL and anon key).
- Do not add paid services, telemetry or secret-dependent build steps. Free tools only.
- Do not claim security or audit status the code does not have. Mark untested pieces as untested.

## Security reports

Do not open public issues for security problems. Follow SECURITY.md.
