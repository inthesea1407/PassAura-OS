//! Monotonic allowlist-sequence store with digest binding and pluggable `FileOps`.
//!
//! Stores `(last_seq, last_digest_hex, updated_at_unix)` to reject lower
//! sequence numbers and reject equal sequence numbers with a different digest.
//! Uses a temporary file + `fsync` + `rename` (and parent directory sync on Unix)
//! for atomic updates, with Windows `ERROR_ACCESS_DENIED` retry handling in `StdFileOps`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
const WINDOWS_ACCESS_DENIED_CODE: i32 = 5;
#[cfg(windows)]
const WINDOWS_RENAME_MAX_RETRIES: usize = 8;
#[cfg(windows)]
const WINDOWS_RENAME_BACKOFF_MS: u64 = 15;

/// Abstraction over filesystem rename-replace and sync primitives so unit tests
/// can simulate mid-write crashes or transient rename contention deterministically.
pub trait FileOps {
    fn rename_replace(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn fsync_file(&self, file: &File) -> io::Result<()>;
    fn fsync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// Real filesystem implementation using `std::fs::rename` and `sync_all()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdFileOps;

impl StdFileOps {
    #[cfg(windows)]
    fn is_access_denied(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::PermissionDenied
            || err.raw_os_error() == Some(WINDOWS_ACCESS_DENIED_CODE)
    }

    #[cfg(windows)]
    fn rename_windows_with_retry(from: &Path, to: &Path) -> io::Result<()> {
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..WINDOWS_RENAME_MAX_RETRIES {
            match fs::rename(from, to) {
                Ok(()) => return Ok(()),
                Err(err) if Self::is_access_denied(&err) && attempt + 1 < WINDOWS_RENAME_MAX_RETRIES => {
                    last_err = Some(err);
                    thread::sleep(Duration::from_millis(
                        WINDOWS_RENAME_BACKOFF_MS * (attempt as u64 + 1),
                    ));
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Windows rename exhausted ERROR_ACCESS_DENIED retries",
            )
        }))
    }
}

impl FileOps for StdFileOps {
    fn rename_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
        #[cfg(windows)]
        {
            Self::rename_windows_with_retry(from, to)
        }
        #[cfg(not(windows))]
        {
            fs::rename(from, to)
        }
    }

    fn fsync_file(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn fsync_dir(&self, dir: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            let handle = File::open(dir)?;
            handle.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = dir;
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    Io(String),
    Serialize(String),
    CorruptState(String),
    DowngradeRejected {
        current_seq: u64,
        candidate_seq: u64,
    },
    DigestMismatch {
        seq: u64,
        stored_hex: String,
        candidate_hex: String,
    },
}

impl fmt::Display for RollbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RollbackError::Io(m) => write!(f, "rollback state I/O error: {m}"),
            RollbackError::Serialize(m) => write!(f, "rollback state serialization error: {m}"),
            RollbackError::CorruptState(m) => write!(f, "rollback state corrupt: {m}"),
            RollbackError::DowngradeRejected {
                current_seq,
                candidate_seq,
            } => write!(
                f,
                "rollback rejected: candidate sequence {candidate_seq} < stored {current_seq}"
            ),
            RollbackError::DigestMismatch {
                seq,
                stored_hex,
                candidate_hex,
            } => write!(
                f,
                "rollback rejected: sequence {seq} already accepted with digest {stored_hex}, \
                 candidate digest {candidate_hex} differs"
            ),
        }
    }
}

impl std::error::Error for RollbackError {}

impl From<io::Error> for RollbackError {
    fn from(err: io::Error) -> Self {
        RollbackError::Io(err.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackRecord {
    pub last_seq: u64,
    #[serde(default)]
    pub last_digest_hex: String,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct RollbackStore {
    state_path: PathBuf,
    last_seq: u64,
    last_digest_hex: String,
    initialized: bool,
}

impl RollbackStore {
    pub fn open(state_path: impl AsRef<Path>) -> Result<Self, RollbackError> {
        Self::open_with_ops(state_path, &StdFileOps)
    }

    pub fn open_with_ops<O: FileOps>(
        state_path: impl AsRef<Path>,
        ops: &O,
    ) -> Result<Self, RollbackError> {
        let state_path = state_path.as_ref().to_path_buf();
        if let Some(parent) = state_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        if !state_path.exists() {
            let initial = RollbackRecord {
                last_seq: 0,
                last_digest_hex: String::new(),
                updated_at_unix: now_unix_i64(),
            };
            let payload = serde_json::to_vec_pretty(&initial)
                .map_err(|e| RollbackError::Serialize(e.to_string()))?;
            write_atomic_bytes_with_ops(&state_path, &payload, ops)?;
            return Ok(Self {
                state_path,
                last_seq: 0,
                last_digest_hex: String::new(),
                initialized: true,
            });
        }

        let raw = fs::read_to_string(&state_path)?;
        if raw.trim().is_empty() {
            return Err(RollbackError::CorruptState("state file is empty".into()));
        }

        let record: RollbackRecord = serde_json::from_str(&raw)
            .map_err(|e| RollbackError::CorruptState(format!("invalid JSON: {e}")))?;

        Ok(Self {
            state_path,
            last_seq: record.last_seq,
            last_digest_hex: record.last_digest_hex,
            initialized: true,
        })
    }

    fn refresh_from_disk(&mut self) -> Result<(), RollbackError> {
        if !self.state_path.exists() {
            return Ok(());
        }
        let raw = fs::read_to_string(&self.state_path)?;
        let record: RollbackRecord = serde_json::from_str(&raw)
            .map_err(|e| RollbackError::CorruptState(format!("invalid JSON: {e}")))?;
        if record.last_seq >= self.last_seq {
            self.last_seq = record.last_seq;
            self.last_digest_hex = record.last_digest_hex;
        }
        Ok(())
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn last_digest_hex(&self) -> &str {
        &self.last_digest_hex
    }

    pub fn check_candidate(
        &self,
        candidate_seq: u64,
        candidate_digest_hex: &str,
    ) -> Result<(), RollbackError> {
        if self.initialized && candidate_seq < self.last_seq {
            return Err(RollbackError::DowngradeRejected {
                current_seq: self.last_seq,
                candidate_seq,
            });
        }
        if self.initialized
            && candidate_seq == self.last_seq
            && !self.last_digest_hex.is_empty()
            && candidate_digest_hex != self.last_digest_hex
        {
            return Err(RollbackError::DigestMismatch {
                seq: candidate_seq,
                stored_hex: self.last_digest_hex.clone(),
                candidate_hex: candidate_digest_hex.to_string(),
            });
        }
        Ok(())
    }

    pub fn accept_and_persist(
        &mut self,
        candidate_seq: u64,
        candidate_digest_hex: &str,
        now_unix: Option<i64>,
    ) -> Result<u64, RollbackError> {
        self.accept_and_persist_with_ops(candidate_seq, candidate_digest_hex, now_unix, &StdFileOps)
    }

    pub fn accept_and_persist_with_ops<O: FileOps>(
        &mut self,
        candidate_seq: u64,
        candidate_digest_hex: &str,
        now_unix: Option<i64>,
        ops: &O,
    ) -> Result<u64, RollbackError> {
        // Another process may have advanced the state since we opened it.
        // Re-read it so a stale in-memory value cannot let an older document
        // overwrite a newer one. A missing file keeps the in-memory state.
        self.refresh_from_disk()?;
        self.check_candidate(candidate_seq, candidate_digest_hex)?;

        let should_write = candidate_seq > self.last_seq
            || (candidate_seq == self.last_seq
                && self.last_digest_hex.is_empty()
                && !candidate_digest_hex.is_empty());

        if should_write {
            let ts = now_unix.unwrap_or_else(now_unix_i64);
            let record = RollbackRecord {
                last_seq: candidate_seq,
                last_digest_hex: candidate_digest_hex.to_string(),
                updated_at_unix: ts,
            };
            let payload = serde_json::to_vec_pretty(&record)
                .map_err(|e| RollbackError::Serialize(e.to_string()))?;
            write_atomic_bytes_with_ops(&self.state_path, &payload, ops)?;
            self.last_seq = candidate_seq;
            self.last_digest_hex = candidate_digest_hex.to_string();
            self.initialized = true;
        }

        Ok(self.last_seq)
    }
}

fn now_unix_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn write_atomic_bytes_with_ops<O: FileOps>(
    target_path: &Path,
    bytes: &[u8],
    ops: &O,
) -> Result<(), RollbackError> {
    let parent = target_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let file_name = target_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rollback-state.json");

    let pid = std::process::id();
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let tmp_path = parent.join(format!(".{file_name}.tmp.{pid}.{counter}.{nanos}"));

    let write_res: Result<(), RollbackError> = (|| {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        tmp_file.write_all(bytes)?;
        ops.fsync_file(&tmp_file)?;
        drop(tmp_file);

        ops.rename_replace(&tmp_path, target_path)?;
        ops.fsync_dir(parent)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// Fake `FileOps` that can fail mid-write (during `fsync_file` or before `rename_replace`)
    /// or fail the first N `rename_replace` calls before succeeding.
    struct FakeFileOps {
        fail_before_rename: AtomicBool,
        rename_failures_remaining: AtomicU64,
        fail_on_rename_error_kind: io::ErrorKind,
    }

    impl FakeFileOps {
        fn crash_before_rename() -> Self {
            Self {
                fail_before_rename: AtomicBool::new(true),
                rename_failures_remaining: AtomicU64::new(0),
                fail_on_rename_error_kind: io::ErrorKind::Other,
            }
        }

        fn transient_rename_failures(count: u64, kind: io::ErrorKind) -> Self {
            Self {
                fail_before_rename: AtomicBool::new(false),
                rename_failures_remaining: AtomicU64::new(count),
                fail_on_rename_error_kind: kind,
            }
        }
    }

    impl FileOps for FakeFileOps {
        fn rename_replace(&self, from: &Path, to: &Path) -> io::Result<()> {
            let rem = self.rename_failures_remaining.load(Ordering::SeqCst);
            if rem > 0 {
                self.rename_failures_remaining
                    .store(rem - 1, Ordering::SeqCst);
                return Err(io::Error::new(
                    self.fail_on_rename_error_kind,
                    "simulated transient rename failure",
                ));
            }
            fs::rename(from, to)
        }

        fn fsync_file(&self, file: &File) -> io::Result<()> {
            file.sync_all()?;
            if self.fail_before_rename.swap(false, Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "simulated crash between write/fsync and rename",
                ));
            }
            Ok(())
        }

        fn fsync_dir(&self, dir: &Path) -> io::Result<()> {
            StdFileOps.fsync_dir(dir)
        }
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("pos-rollback-{label}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).expect("create test temp dir");
        dir
    }

    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const D3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    #[test]
    fn crash_between_write_and_rename_leaves_old_state_intact() {
        let dir = unique_test_dir("crash-before-rename");
        let state_file = dir.join("rollback.json");

        let mut store = RollbackStore::open(&state_file).expect("open");
        store.accept_and_persist(10, D1, Some(1735689600)).unwrap();

        let fake_ops = FakeFileOps::crash_before_rename();
        let err = store
            .accept_and_persist_with_ops(20, D2, Some(1735689700), &fake_ops)
            .expect_err("simulated crash must fail write");
        assert!(matches!(err, RollbackError::Io(_)));

        // In-memory and on-disk state must remain at seq=10, digest=D1
        assert_eq!(store.last_seq(), 10);
        assert_eq!(store.last_digest_hex(), D1);

        let reopened = RollbackStore::open(&state_file).expect("reopen");
        assert_eq!(reopened.last_seq(), 10);
        assert_eq!(reopened.last_digest_hex(), D1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retry_succeeds_after_transient_rename_failure_and_counter_never_goes_backwards() {
        let dir = unique_test_dir("retry-rename");
        let state_file = dir.join("rollback.json");

        let mut store = RollbackStore::open(&state_file).expect("open");
        store.accept_and_persist(10, D1, Some(1735689600)).unwrap();

        // First attempt fails twice on rename, then succeeds on retry
        let flaky_ops = FakeFileOps::transient_rename_failures(2, io::ErrorKind::PermissionDenied);
        assert!(store
            .accept_and_persist_with_ops(15, D2, Some(1735689650), &flaky_ops)
            .is_err());
        assert_eq!(store.last_seq(), 10);

        assert!(store
            .accept_and_persist_with_ops(15, D2, Some(1735689650), &flaky_ops)
            .is_err());
        assert_eq!(store.last_seq(), 10);

        let committed = store
            .accept_and_persist_with_ops(15, D2, Some(1735689650), &flaky_ops)
            .expect("third attempt succeeds");
        assert_eq!(committed, 15);
        assert_eq!(store.last_seq(), 15);
        assert_eq!(store.last_digest_hex(), D2);

        // Counter must never go backwards
        let downgrade = store.accept_and_persist(14, D1, Some(1735689700));
        assert_eq!(
            downgrade,
            Err(RollbackError::DowngradeRejected {
                current_seq: 15,
                candidate_seq: 14,
            })
        );
        assert_eq!(store.last_seq(), 15);

        // Equal seq with different digest must also fail
        let mismatch = store.accept_and_persist(15, D3, Some(1735689750));
        assert!(matches!(mismatch, Err(RollbackError::DigestMismatch { seq: 15, .. })));
        assert_eq!(store.last_seq(), 15);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn std_file_ops_rename_replace_works_on_existing_target() {
        let dir = unique_test_dir("std-rename-replace");
        let target = dir.join("rollback.json");
        let replacement = dir.join("replacement.tmp");

        fs::write(&target, b"old-state").unwrap();
        fs::write(&replacement, b"new-state").unwrap();

        StdFileOps.rename_replace(&replacement, &target).unwrap();
        assert!(!replacement.exists());
        assert_eq!(fs::read_to_string(&target).unwrap(), "new-state");

        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod stale_state_tests {
    use super::*;

    #[test]
    fn second_handle_cannot_roll_back_state_written_by_first() {
        let dir = std::env::temp_dir().join(format!("pos-rb-stale-{}", std::process::id()));
        let path = dir.join("state.json");
        let _ = std::fs::remove_dir_all(&dir);
        let mut a = RollbackStore::open(&path).unwrap();
        let mut b = RollbackStore::open(&path).unwrap(); // both see seq 0
        a.accept_and_persist(5, "aa", Some(1)).unwrap();
        // b still thinks seq is 0, but disk says 5: seq 3 must be rejected.
        let r = b.accept_and_persist(3, "bb", Some(2));
        assert!(matches!(r, Err(RollbackError::DowngradeRejected { .. })), "{r:?}");
        assert_eq!(RollbackStore::open(&path).unwrap().last_seq(), 5);
    }
}
