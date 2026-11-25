//! Cross-process advisory lock on a lockfile next to the rollback state.
//!
//! Uses `std::fs::File::try_lock` (stable since Rust 1.89), so the OS drops
//! the lock when the process dies: a leftover lockfile with no live holder
//! never blocks. The lockfile itself is never deleted (deleting it would let
//! two processes lock two different files). The wait is bounded.
//!
//! Limits: advisory (only cooperating processes that take this same lock are
//! excluded), semantics on network filesystems vary, tested on Linux only.

use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum LockError {
    /// Another holder kept the lock for the whole timeout.
    Held {
        path: PathBuf,
        waited: Duration,
    },
    Io(io::Error),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Held { path, waited } => write!(
                f,
                "install lock {} is held by another process (waited {:?})",
                path.display(),
                waited
            ),
            LockError::Io(e) => write!(f, "install lock I/O error: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<io::Error> for LockError {
    fn from(e: io::Error) -> Self {
        LockError::Io(e)
    }
}

/// Holds the lock until dropped.
#[derive(Debug)]
pub struct StateLock {
    _file: File,
}

/// `<state path>.lock`
pub fn lock_path(state_path: &Path) -> PathBuf {
    let mut s = state_path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

impl StateLock {
    /// Take the lock, polling until `timeout`. Never waits forever.
    pub fn acquire(state_path: &Path, timeout: Duration) -> Result<StateLock, LockError> {
        let path = lock_path(state_path);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(StateLock { _file: file }),
                Err(TryLockError::WouldBlock) => {
                    let waited = start.elapsed();
                    if waited >= timeout {
                        return Err(LockError::Held { path, waited });
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(TryLockError::Error(e)) => return Err(LockError::Io(e)),
            }
        }
    }
}
