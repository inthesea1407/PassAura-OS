//! Handoff adapter from `pos-update` to `pos-install`.
//!
//! Release convention: a manifest artifact `X.deb` is installed only when the
//! same manifest carries `X.allowlist.json`, a signed v2 allowlist whose
//! entries include one whose SHA-256 equals the staged `X.deb` bytes. The
//! adapter changes nothing in pos-install's trust model: the pipeline
//! re-verifies the allowlist signature, keyring, time window and rollback
//! state, re-hashes the staged bytes against the signed entry, stages them
//! privately and runs the backend's exact-file install (the real dpkg backend
//! verifies the allowlist once more and binds the deb's control identity to
//! the entry). The update manifest authorizes the fetch and staging; the
//! signed allowlist alone authorizes the install.
//!
//! Installs run in manifest order and the first failure stops the handoff.
//! The adapter never retries: a blocked (indeterminate) attempt needs
//! operator recovery through pos-install's own entry points. A manifest with
//! no `.deb` artifacts is a no-op.
//!
//! Limits: everything here is CI-tested only, against a fake backend; the real
//! dpkg path has never run. The `now` passed at construction authorizes every
//! install of the handoff (allowlist time windows are checked against it).
#![forbid(unsafe_code)]

use pos_gate::allowlist::Keyring;
use pos_gate::allowlist_v2::V2Allowlist;
use pos_gate::linux_backend::{InstallMode, InstallReport, PackageBackend, PackageBackendError};
use pos_gate::rollback::FileOps;
use pos_install::pipeline::{InstallPaths, LocalFileFetcher, Pipeline, Request};
use pos_update::flow::{Handoff, HandoffError, StagedUpdate};
use pos_update::Verified;
use std::path::Path;

/// Manifest artifact suffix for installable packages.
pub const DEB_SUFFIX: &str = ".deb";
/// Manifest artifact suffix for the signed allowlist authorizing `X.deb`: `X.allowlist.json`.
pub const ALLOWLIST_SUFFIX: &str = ".allowlist.json";

/// Owns everything a handoff needs. `now` is Unix seconds, like everywhere in
/// pos-install. Construct one per device and reuse it.
pub struct InstallHandoff<B, O> {
    pub paths: InstallPaths,
    pub backend: B,
    pub ops: O,
    pub trusted: Keyring,
    pub now: i64,
}

impl<B, O> InstallHandoff<B, O> {
    pub fn new(paths: InstallPaths, backend: B, ops: O, trusted: Keyring, now: i64) -> Self {
        InstallHandoff {
            paths,
            backend,
            ops,
            trusted,
            now,
        }
    }
}

/// Lets one backend serve a fresh `Pipeline` per package without moving out of
/// the adapter. Forwards both trait methods; the pipeline's exact-file path
/// needs the real `install_staged_file`, not the trait default.
struct Borrowed<'a, B: PackageBackend + ?Sized>(&'a mut B);

impl<B: PackageBackend + ?Sized> PackageBackend for Borrowed<'_, B> {
    fn install(
        &mut self,
        p: &str,
        d: &V2Allowlist,
        t: &Keyring,
        n: i64,
        s: Option<(u64, &str)>,
        m: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        self.0.install(p, d, t, n, s, m)
    }

    fn install_staged_file(
        &mut self,
        p: &str,
        staged: &Path,
        d: &V2Allowlist,
        t: &Keyring,
        n: i64,
        s: Option<(u64, &str)>,
        m: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        self.0.install_staged_file(p, staged, d, t, n, s, m)
    }
}

impl<B: PackageBackend, O: FileOps + Clone> Handoff for InstallHandoff<B, O> {
    fn handoff(&mut self, _verified: &Verified, staged: &StagedUpdate) -> Result<(), HandoffError> {
        for f in &staged.files {
            if !f.name.ends_with(DEB_SUFFIX) {
                continue;
            }
            let base = &f.name[..f.name.len() - DEB_SUFFIX.len()];
            let list_name = format!("{base}{ALLOWLIST_SUFFIX}");
            if !staged.files.iter().any(|g| g.name == list_name) {
                return Err(HandoffError(format!(
                    "{list_name}: missing; no signed allowlist authorizes {}",
                    f.name
                )));
            }
            let bytes = std::fs::read(staged.dir.join(&list_name))
                .map_err(|e| HandoffError(format!("{list_name}: unreadable ({e})")))?;
            let doc: V2Allowlist = serde_json::from_slice(&bytes)
                .map_err(|_| HandoffError(format!("{list_name}: not a v2 allowlist document")))?;
            let entry = doc
                .entries
                .iter()
                .find(|e| e.sha256.eq_ignore_ascii_case(&f.sha256))
                .ok_or_else(|| {
                    HandoffError(format!(
                        "{list_name}: no entry matches the SHA-256 of {}",
                        f.name
                    ))
                })?;
            let package = entry.name.clone();
            let fetcher = LocalFileFetcher {
                path: staged.dir.join(&f.name),
            };
            let mut pipe = Pipeline::new(
                self.paths.clone(),
                Borrowed(&mut self.backend),
                fetcher,
                self.ops.clone(),
            );
            let req = Request {
                package: &package,
                doc: &doc,
                trusted: &self.trusted,
                now: self.now,
            };
            pipe.install(&req)
                .map_err(|e| HandoffError(format!("{package}: install failed: {e}")))?;
        }
        Ok(())
    }
}
