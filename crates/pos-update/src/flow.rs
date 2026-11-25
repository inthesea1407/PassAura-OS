//! Update flow: fetch manifest -> verify -> fetch and stage payloads -> hand off -> persist state.
//!
//! This module does file I/O (the stage directory). `verify_envelope` stays pure. There is no network
//! code: the caller supplies a `Transport`, a `StateStore` and a `Handoff`.
//!
//! Order and why: the accepted state is persisted AFTER a successful handoff. If the process stops after
//! the handoff and before the persist, the next run sees the old state and replays the same manifest, so
//! the handoff runs again with the same `Verified` and the same staged bytes. Therefore:
//!
//! **Handoff contract: `Handoff::handoff` MUST be idempotent for the same (channel, sequence, manifest
//! digest). It can be called more than once for one accepted update.** If the manifest equals the already
//! persisted state, `run_update` does not fetch or hand off again (`Outcome::AlreadyCurrent`).
//!
//! Concurrency contract: one `run_update` per channel and state at a time. This module takes no lock. The
//! optional `file_state` module (feature `file-state`) takes a bounded per-channel advisory lock.
//!
//! Stage directory: `<root>/<channel key>.<sequence>.<first 8 digest bytes hex>`, mode 0700 on unix, files
//! `create_new` with mode 0600, symlinks refused. Each payload is streamed to a temp file while its size,
//! SHA-256 and the total cap are enforced, then renamed to its manifest name. This module removes only
//! what the current run created. Leftovers of a crashed earlier run (temp files, a stage directory) are
//! never deleted automatically; a verified payload that already sits under its final name is reused, and a
//! different file under a final name is `StageError::Conflict` (nothing is overwritten).
//!
//! Limits: no power-loss claim. Directory fsync is unix only. Windows is untested.

use crate::{
    is_safe_name, verify_envelope, AcceptedState, Artifact, UpdateError, Verified, VerifyPolicy,
};
use crate::{MAX_ARTIFACT_NAME_LEN, MAX_CHANNEL_LEN};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default cap on the sum of manifest artifact sizes (1 GiB).
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1 << 30;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Source of manifest and payload bytes. No network code lives in this crate.
pub trait Transport {
    /// Raw envelope bytes for `channel`. The caller bounds what it returns; `verify_envelope` rejects
    /// anything over `MAX_ENVELOPE_BYTES`.
    fn fetch_manifest(&mut self, channel: &str) -> io::Result<Vec<u8>>;
    /// A reader for one payload. The flow never reads more than `artifact.size + 1` bytes from it.
    fn fetch_artifact<'a>(
        &'a mut self,
        channel: &str,
        artifact: &Artifact,
    ) -> io::Result<Box<dyn Read + 'a>>;
}

/// Per-channel rollback state. `store` must be atomic: after it returns Ok, a later `load` returns the new
/// state; after it fails, `load` returns the old state (or nothing, if there was none).
pub trait StateStore {
    fn load(&mut self, channel: &str) -> io::Result<Option<AcceptedState>>;
    fn store(&mut self, state: &AcceptedState) -> io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffError(pub String);

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "handoff failed: {}", self.0)
    }
}
impl std::error::Error for HandoffError {}

/// Takes the verified, staged update. MUST be idempotent (see the module docs).
pub trait Handoff {
    fn handoff(&mut self, verified: &Verified, staged: &StagedUpdate) -> Result<(), HandoffError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFile {
    pub name: String,
    /// Lowercase hex SHA-256, equal to the manifest value.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedUpdate {
    pub dir: PathBuf,
    pub files: Vec<StagedFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageError {
    BadName,
    RootNotPrivate,
    NotADirectory,
    Symlink,
    TotalCapExceeded,
    TooLong(String),
    TooShort(String),
    HashMismatch(String),
    /// A different file already sits under this final name. Nothing is overwritten or deleted.
    Conflict(String),
    Io(io::ErrorKind),
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "staging error: {self:?}")
    }
}
impl std::error::Error for StageError {}

impl From<io::Error> for StageError {
    fn from(e: io::Error) -> Self {
        StageError::Io(e.kind())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// The channel is not a safe name (the same rule as manifests).
    BadChannel,
    /// `channel` and `policy.expected_channel` differ.
    ChannelMismatch,
    Transport(io::ErrorKind),
    Verify(UpdateError),
    State(io::ErrorKind),
    Stage(StageError),
    Handoff(HandoffError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "update flow error: {self:?}")
    }
}
impl std::error::Error for FlowError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The manifest equals the persisted state. Nothing was fetched or handed off.
    AlreadyCurrent { sequence: u64 },
    /// Handed off and persisted. `cleanup_complete` is false when something this run created could not be
    /// removed, or when a stage directory or payload of an earlier run was reused (left in place, never
    /// deleted here).
    Applied {
        sequence: u64,
        cleanup_complete: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Cap on the sum of manifest artifact sizes, checked before any payload is fetched.
    pub max_total_bytes: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

/// Injective, portable file key for a channel: `ch-` then each byte outside `[a-z0-9_-]` as `%XX`
/// (uppercase hex). Uppercase letters and dots are encoded, so two channels never share a key, even on a
/// case-insensitive filesystem, and a key never starts or ends with a dot.
pub fn channel_key(channel: &str) -> Result<String, FlowError> {
    if !is_safe_name(channel, MAX_CHANNEL_LEN) {
        return Err(FlowError::BadChannel);
    }
    let mut k = String::with_capacity(3 + channel.len());
    k.push_str("ch-");
    for b in channel.bytes() {
        if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' {
            k.push(b as char);
        } else {
            k.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(k)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageStep {
    AfterTmpCreate,
    AfterWrite,
    AfterVerify,
    BeforeRename,
    AfterRename,
}

#[cfg(test)]
type StageHook = Box<dyn FnMut(StageStep, &str) -> io::Result<()>>;

/// What this run created, for cleanup.
#[derive(Default)]
struct Created {
    /// Directories this run created, outermost first.
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    /// A directory or payload from an earlier run was reused and is left in place.
    reused: bool,
}

struct Stager {
    root: PathBuf,
    /// Test-only failure injection. Compiled out of every non-test build.
    #[cfg(test)]
    hook: Option<StageHook>,
}

fn is_private_dir(md: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        true
    }
}

fn make_private_dir(path: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

impl Stager {
    fn new(root: &Path) -> Stager {
        Stager {
            root: root.to_path_buf(),
            #[cfg(test)]
            hook: None,
        }
    }

    #[cfg(test)]
    fn fire(&mut self, step: StageStep, name: &str) -> io::Result<()> {
        match self.hook.as_mut() {
            Some(h) => h(step, name),
            None => Ok(()),
        }
    }

    #[cfg(not(test))]
    #[inline(always)]
    fn fire(&mut self, _step: StageStep, _name: &str) -> io::Result<()> {
        Ok(())
    }

    fn check_dir(path: &Path) -> Result<(), StageError> {
        let md = fs::symlink_metadata(path)?;
        if md.file_type().is_symlink() {
            return Err(StageError::Symlink);
        }
        if !md.is_dir() {
            return Err(StageError::NotADirectory);
        }
        if !is_private_dir(&md) {
            return Err(StageError::RootNotPrivate);
        }
        Ok(())
    }

    /// The root must exist as a private directory, or its parent must exist so it can be created.
    fn ensure_root(&self, created: &mut Created) -> Result<(), StageError> {
        match fs::symlink_metadata(&self.root) {
            Ok(_) => Self::check_dir(&self.root),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                make_private_dir(&self.root)?;
                created.dirs.push(self.root.clone());
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Hash a file already under its final name.
    fn existing_matches(path: &Path, a: &Artifact) -> Result<bool, StageError> {
        let md = fs::symlink_metadata(path)?;
        if !md.file_type().is_file() {
            return Err(StageError::Symlink);
        }
        if md.len() != a.size {
            return Ok(false);
        }
        let mut f = File::open(path)?;
        let mut h = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()) == a.sha256)
    }

    fn stage<T: Transport>(
        &mut self,
        channel: &str,
        verified: &Verified,
        transport: &mut T,
        max_total: u64,
        created: &mut Created,
    ) -> Result<StagedUpdate, StageError> {
        let key = channel_key(channel).map_err(|_| StageError::BadName)?;
        let mut declared: u64 = 0;
        let mut names = BTreeSet::new();
        for a in &verified.manifest.artifacts {
            if !is_safe_name(&a.name, MAX_ARTIFACT_NAME_LEN) || !names.insert(a.name.as_str()) {
                return Err(StageError::BadName);
            }
            declared = declared
                .checked_add(a.size)
                .ok_or(StageError::TotalCapExceeded)?;
        }
        if declared > max_total {
            return Err(StageError::TotalCapExceeded);
        }
        self.ensure_root(created)?;
        let dir_name = format!(
            "{key}.{}.{}",
            verified.state.sequence,
            hex::encode(&verified.state.digest[..8])
        );
        let dir = self.root.join(dir_name);
        match make_private_dir(&dir) {
            Ok(()) => created.dirs.push(dir.clone()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Self::check_dir(&dir)?;
                created.reused = true;
            }
            Err(e) => return Err(e.into()),
        }
        let mut files = Vec::with_capacity(verified.manifest.artifacts.len());
        for a in &verified.manifest.artifacts {
            let fin = dir.join(&a.name);
            match fs::symlink_metadata(&fin) {
                Ok(_) => {
                    if !Self::existing_matches(&fin, a)? {
                        return Err(StageError::Conflict(a.name.clone()));
                    }
                    created.reused = true;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let r = self.fetch_one(channel, a, &dir, &fin, transport);
                    // The name was absent before the fetch, so if it exists now (also after a failure that
                    // came after the rename) this run created it and must clean it up.
                    if fs::symlink_metadata(&fin).is_ok() {
                        created.files.push(fin.clone());
                    }
                    r?;
                }
                Err(e) => return Err(e.into()),
            }
            files.push(StagedFile {
                name: a.name.clone(),
                sha256: a.sha256.clone(),
                size: a.size,
            });
        }
        Ok(StagedUpdate { dir, files })
    }

    fn fetch_one<T: Transport>(
        &mut self,
        channel: &str,
        a: &Artifact,
        dir: &Path,
        fin: &Path,
        transport: &mut T,
    ) -> Result<(), StageError> {
        let reader = transport.fetch_artifact(channel, a)?;
        // A leading dot is not allowed in artifact names, so a temp name never collides with a payload.
        let tmp = dir.join(format!(
            ".stage-tmp-{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut oo = OpenOptions::new();
        oo.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let mut f = oo.open(&tmp)?;
        let res = self.fill_and_publish(reader, a, &mut f, &tmp, fin, dir);
        drop(f);
        if res.is_err() {
            // Only the temp file this call created. After a successful rename it no longer exists.
            let _ = fs::remove_file(&tmp);
        }
        res
    }

    fn fill_and_publish(
        &mut self,
        reader: Box<dyn Read + '_>,
        a: &Artifact,
        f: &mut File,
        tmp: &Path,
        fin: &Path,
        dir: &Path,
    ) -> Result<(), StageError> {
        self.fire(StageStep::AfterTmpCreate, &a.name)?;
        let mut limited = reader.take(a.size.saturating_add(1));
        let mut h = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut got: u64 = 0;
        loop {
            let n = limited.read(&mut buf)?;
            if n == 0 {
                break;
            }
            got += n as u64;
            if got > a.size {
                return Err(StageError::TooLong(a.name.clone()));
            }
            h.update(&buf[..n]);
            f.write_all(&buf[..n])?;
        }
        if got < a.size {
            return Err(StageError::TooShort(a.name.clone()));
        }
        self.fire(StageStep::AfterWrite, &a.name)?;
        if hex::encode(h.finalize()) != a.sha256 {
            return Err(StageError::HashMismatch(a.name.clone()));
        }
        self.fire(StageStep::AfterVerify, &a.name)?;
        f.sync_all()?;
        self.fire(StageStep::BeforeRename, &a.name)?;
        fs::rename(tmp, fin)?;
        self.fire(StageStep::AfterRename, &a.name)?;
        sync_dir(dir)?;
        Ok(())
    }
}

/// Removes only what this run created. Returns true when everything was removed.
fn cleanup(created: &Created) -> bool {
    let mut ok = true;
    for f in &created.files {
        match fs::remove_file(f) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => ok = false,
        }
    }
    for d in created.dirs.iter().rev() {
        match fs::remove_dir(d) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => ok = false, // not empty (leftovers of something else): left in place
        }
    }
    ok
}

/// Run one update for `channel`. See the module docs for the order, the handoff contract and the limits.
pub fn run_update<T, S, H>(
    channel: &str,
    policy: &VerifyPolicy<'_>,
    transport: &mut T,
    store: &mut S,
    handoff: &mut H,
    stage_root: &Path,
    opts: &Options,
) -> Result<Outcome, FlowError>
where
    T: Transport,
    S: StateStore,
    H: Handoff,
{
    run_with_stager(
        channel,
        policy,
        transport,
        store,
        handoff,
        Stager::new(stage_root),
        opts,
    )
}

fn run_with_stager<T, S, H>(
    channel: &str,
    policy: &VerifyPolicy<'_>,
    transport: &mut T,
    store: &mut S,
    handoff: &mut H,
    mut stager: Stager,
    opts: &Options,
) -> Result<Outcome, FlowError>
where
    T: Transport,
    S: StateStore,
    H: Handoff,
{
    channel_key(channel)?;
    if policy.expected_channel != channel {
        return Err(FlowError::ChannelMismatch);
    }
    let prev = store
        .load(channel)
        .map_err(|e| FlowError::State(e.kind()))?;
    let bytes = transport
        .fetch_manifest(channel)
        .map_err(|e| FlowError::Transport(e.kind()))?;
    let verified = verify_envelope(&bytes, policy, prev.as_ref()).map_err(FlowError::Verify)?;
    if verified.idempotent {
        return Ok(Outcome::AlreadyCurrent {
            sequence: verified.state.sequence,
        });
    }
    let mut created = Created::default();
    let staged = match stager.stage(
        channel,
        &verified,
        transport,
        opts.max_total_bytes,
        &mut created,
    ) {
        Ok(s) => s,
        Err(e) => {
            cleanup(&created);
            return Err(FlowError::Stage(e));
        }
    };
    if let Err(e) = handoff.handoff(&verified, &staged) {
        cleanup(&created);
        return Err(FlowError::Handoff(e));
    }
    if let Err(e) = store.store(&verified.state) {
        cleanup(&created);
        return Err(FlowError::State(e.kind()));
    }
    let cleanup_complete = cleanup(&created) && !created.reused;
    Ok(Outcome::Applied {
        sequence: verified.state.sequence,
        cleanup_complete,
    })
}

#[cfg(test)]
mod tests;
