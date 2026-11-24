//! Monotonic allowlist-sequence store with digest binding.
//!
//! Stores `(last_seq, last_digest_hex, updated_at_unix)` to reject lower
//! sequence numbers and reject equal sequence numbers with a different digest.
//! Uses a temporary file + `sync_all()` + `rename` (and parent directory sync
//! on Unix) for atomic updates.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
            write_atomic_bytes(&state_path, &payload)?;
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
            write_atomic_bytes(&self.state_path, &payload)?;
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

fn write_atomic_bytes(target_path: &Path, bytes: &[u8]) -> Result<(), RollbackError> {
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
        tmp_file.sync_all()?;
        drop(tmp_file);

        fs::rename(&tmp_path, target_path)?;
        sync_parent_dir(parent)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let dir = File::open(parent)?;
        dir.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn accepts_higher_sequence_and_persists() {
        let dir = unique_test_dir("accept-higher");
        let state_file = dir.join("rollback.json");
        let mut store = RollbackStore::open(&state_file).expect("open");
        assert_eq!(store.accept_and_persist(10, D1, Some(1735689600)).unwrap(), 10);
        assert_eq!(store.accept_and_persist(25, D2, Some(1735689700)).unwrap(), 25);
        let reopened = RollbackStore::open(&state_file).expect("reopen");
        assert_eq!(reopened.last_seq(), 25);
        assert_eq!(reopened.last_digest_hex(), D2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_lower_sequence() {
        let dir = unique_test_dir("reject-lower");
        let state_file = dir.join("rollback.json");
        let mut store = RollbackStore::open(&state_file).expect("open");
        store.accept_and_persist(42, D1, Some(1735689600)).unwrap();
        let err = store
            .accept_and_persist(41, D1, Some(1735689800))
            .expect_err("must reject lower");
        assert_eq!(
            err,
            RollbackError::DowngradeRejected {
                current_seq: 42,
                candidate_seq: 41
            }
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_equal_sequence_with_different_digest() {
        let dir = unique_test_dir("reject-equal-digest");
        let state_file = dir.join("rollback.json");
        let mut store = RollbackStore::open(&state_file).expect("open");
        store.accept_and_persist(25, D1, Some(1735689600)).unwrap();
        let err = store
            .accept_and_persist(25, D2, Some(1735689700))
            .expect_err("must reject replay at same seq");
        assert!(matches!(err, RollbackError::DigestMismatch { seq: 25, .. }));
        assert_eq!(store.last_seq(), 25);
        assert_eq!(store.last_digest_hex(), D1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn accepts_equal_sequence_with_same_digest_idempotently() {
        let dir = unique_test_dir("idempotent");
        let state_file = dir.join("rollback.json");
        let mut store = RollbackStore::open(&state_file).expect("open");
        store.accept_and_persist(25, D1, Some(1735689600)).unwrap();
        assert_eq!(store.accept_and_persist(25, D1, Some(1735689700)).unwrap(), 25);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fails_closed_on_corrupt_state_file() {
        let dir = unique_test_dir("corrupt");
        let state_file = dir.join("rollback.json");
        fs::write(&state_file, "{not valid json").unwrap();
        let err = RollbackStore::open(&state_file).expect_err("must reject corrupt");
        assert!(matches!(err, RollbackError::CorruptState(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_open_persists_initial_state() {
        let dir = unique_test_dir("first-open");
        let state_file = dir.join("rollback.json");
        assert!(!state_file.exists());
        let _store = RollbackStore::open(&state_file).expect("open");
        assert!(state_file.exists());
        let raw = fs::read_to_string(&state_file).unwrap();
        assert!(raw.contains("\"last_seq\": 0"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_ignores_stale_partial_tmp_file() {
        let dir = unique_test_dir("partial-tmp");
        let state_file = dir.join("rollback.json");
        let mut store = RollbackStore::open(&state_file).expect("open");
        store.accept_and_persist(15, D1, Some(1735689600)).unwrap();

        let partial_tmp = dir.join(".rollback.json.tmp.999999.0.0");
        fs::write(&partial_tmp, "{\"last_seq\": 999, \"partial\": true").unwrap();

        assert_eq!(store.accept_and_persist(16, D2, Some(1735689650)).unwrap(), 16);
        let reopened = RollbackStore::open(&state_file).expect("reopen");
        assert_eq!(reopened.last_seq(), 16);
        assert!(partial_tmp.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
