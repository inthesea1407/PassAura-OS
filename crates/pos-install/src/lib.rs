//! Crash-safe, allowlist-gated install transaction.
//!
//! See `docs/INSTALL_PIPELINE.md` for the state machine, the journal, the
//! recovery table and the limits. Linux-first; needs Rust 1.89 or newer
//! (`File::try_lock`). No network. Installs only a local file whose SHA-256
//! matches the signed allowlist entry.
#![forbid(unsafe_code)]

pub mod journal;
pub mod lock;
pub mod pipeline;
pub mod stage;

pub use pipeline::{
    DryRunReport, Fetcher, InstallError, InstallPaths, LocalFileFetcher, Outcome, Pipeline,
    RecoveryStatus, Request,
};
