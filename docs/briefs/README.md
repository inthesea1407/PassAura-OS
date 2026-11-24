# Parallel module plan
4 modules, disjoint paths, shared frozen contract docs/CONTRACTS.md. Integrator merges returned patches, runs `cargo test --workspace`, applies in order 1,3,4,2 (Rust and backend first), resolves conflicts (paths are disjoint, so only workspace Cargo.toml and docs index are shared and owned by the integrator).
