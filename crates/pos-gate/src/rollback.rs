use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackError {
    Io(String),
    Serialize(String),
    CorruptState(String),
    DowngradeRejected {
        current_seq: u64,
        candidate_seq: u64,
    },
}

impl fmt::Display for RollbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RollbackError::Io(msg) => write!(f, "rollback state I/O error: {msg}"),
            RollbackError::Serialize(msg) => write!(f, "rollback state serialization error: {msg}"),
            RollbackError::CorruptState(msg) => write!(f, "rollback state corrupt: {msg}"),
            RollbackError::DowngradeRejected {
                current_seq,
                candidate_seq,
            } => write!(
                f,
                "rollback rejected: candidate sequence {candidate_seq} is lower than stored sequence {current_seq}"
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
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct RollbackStore {
    state_path: PathBuf,
    last_seq: u64,
    initialized: bool,
}

impl RollbackStore {
    /// Opens or initializes a monotonic sequence store at `state_path`.
    /// Rejects malformed or truncated non-empty state files instead of silently resetting.
    pub fn open(state_path: impl AsRef<Path>) -> Result<Self, RollbackError> {
        let state_path = state_path.as_ref().to_path_buf();
        if let Some(parent) = state_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        if !state_path.exists() {
            return Ok(Self {
                state_path,
                last_seq: 0,
                initialized: false,
            });
        }

        let raw = fs::read_to_string(&state_path)?;
        if raw.trim().is_empty() {
            return Err(RollbackError::CorruptState(
                "state file is empty".to_string(),
            ));
        }

        let record: RollbackRecord = serde_json::from_str(&raw)
            .map_err(|e| RollbackError::CorruptState(format!("invalid JSON: {e}")))?;

        Ok(Self {
            state_path,
            last_seq: record.last_seq,
            initialized: true,
        })
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// Checks whether `candidate_seq` is allowed given current stored state.
    /// Allows equal sequence for idempotent re-verification; rejects strictly lower sequence.
    pub fn check_candidate(&self, candidate_seq: u64) -> Result<(), RollbackError> {
        if self.initialized && candidate_seq < self.last_seq {
            return Err(RollbackError::DowngradeRejected {
                current_seq: self.last_seq,
                candidate_seq,
            });
        }
        Ok(())
    }

    /// Validates `candidate_seq` and, if accepted and higher (or first initialization),
    /// atomically persists the new sequence to disk using temp file + fsync + rename.
    pub fn accept_and_persist(
        &mut self,
        candidate_seq: u64,
        now_unix: Option<i64>,
    ) -> Result<u64, RollbackError> {
        self.check_candidate(candidate_seq)?;

        let ts = now_unix.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });

        let should_write = !self.initialized || candidate_seq > self.last_seq;
        if should_write {
            let record = RollbackRecord {
                last_seq: candidate_seq,
                updated_at_unix: ts,
            };
            let payload = serde_json::to_vec_pretty(&record)
                .map_err(|e| RollbackError::Serialize(e.to_string()))?;

            write_atomic_bytes(&self.state_path, &payload)?;
            self.last_seq = candidate_seq;
            self.initialized = true;
        }

        Ok(self.last_seq)
    }
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
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let tmp_path = parent.join(format!(".{file_name}.tmp.{pid}.{nanos}"));

    let write_res: Result<(), RollbackError> = (|| {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        tmp_file.write_all(bytes)?;
        tmp_file.sync_all()?;
        drop(tmp_file);

        #[cfg(windows)]
        if target_path.exists() {
            fs::remove_file(target_path)?;
        }

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

    #[test]
    fn accepts_higher_sequence_and_persists() {
        let dir = unique_test_dir("accept-higher");
        let state_file = dir.join("rollback.json");

        let mut store = RollbackStore::open(&state_file).expect("open store");
        let seq1 = store
            .accept_and_persist(10, Some(1735689600))
            .expect("accept seq 10");
        assert_eq!(seq1, 10);

        let seq2 = store
            .accept_and_persist(25, Some(1735689700))
            .expect("accept seq 25");
        assert_eq!(seq2, 25);

        let reopened = RollbackStore::open(&state_file).expect("reopen store");
        assert_eq!(reopened.last_seq(), 25);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_lower_sequence() {
        let dir = unique_test_dir("reject-lower");
        let state_file = dir.join("rollback.json");

        let mut store = RollbackStore::open(&state_file).expect("open store");
        store
            .accept_and_persist(42, Some(1735689600))
            .expect("accept seq 42");

        let err = store
            .accept_and_persist(41, Some(1735689800))
            .expect_err("must reject lower sequence");

        assert_eq!(
            err,
            RollbackError::DowngradeRejected {
                current_seq: 42,
                candidate_seq: 41,
            }
        );

        let reopened = RollbackStore::open(&state_file).expect("reopen store");
        assert_eq!(reopened.last_seq(), 42);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fails_closed_on_corrupt_state_file() {
        let dir = unique_test_dir("corrupt-state");
        let state_file = dir.join("rollback.json");
        fs::write(&state_file, "{not valid json").expect("write corrupt state");

        let err = RollbackStore::open(&state_file).expect_err("must reject corrupt JSON");
        assert!(matches!(err, RollbackError::CorruptState(_)));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_survives_partial_temp_file() {
        let dir = unique_test_dir("partial-tmp");
        let state_file = dir.join("rollback.json");

        let mut store = RollbackStore::open(&state_file).expect("open store");
        store
            .accept_and_persist(15, Some(1735689600))
            .expect("write initial state");

        // Simulate an interrupted/partial temp file left behind in the state directory
        let partial_tmp = dir.join(".rollback.json.tmp.999999.0");
        fs::write(&partial_tmp, "{\"last_seq\": 999, \"partial\": true").expect("write partial tmp");

        let seq = store
            .accept_and_persist(16, Some(1735689650))
            .expect("atomic update should succeed despite partial temp file");
        assert_eq!(seq, 16);

        let reopened = RollbackStore::open(&state_file).expect("reopen final state");
        assert_eq!(reopened.last_seq(), 16);
        assert!(partial_tmp.exists(), "unrelated stale temp file untouched");

        let _ = fs::remove_dir_all(&dir);
    }
}
