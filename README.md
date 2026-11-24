# PassAura OS

Early security core for PassAura OS, written in Rust.

**Status:** this is a permission and policy engine plus platform adapter
stubs. It is not a standalone operating system or kernel.

## Crates
- `pos-core`: deny-by-default policy engine. Authentication check, grants with
  expiry, revoke, explicit deny that always wins.
- `pos-android`: maps Android permission names to core actions (interface only).
- `pos-windows`: maps Windows capability names to core actions (interface only).

## Test
    cargo test --workspace

## License
MIT. No ads. Only PassAura Premium works as password manager in official builds.

## Roadmap
1. Audit log of decisions.
2. Persistent policy store.
3. Real Android and Windows integrations.
4. Linux adapter.
