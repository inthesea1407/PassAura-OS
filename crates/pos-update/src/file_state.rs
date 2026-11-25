//! File-backed `StateStore` (feature `file-state`). One state file per channel, written with
//! `pos_vault_store::write_file_atomic`, plus a bounded per-channel advisory lock.
//!
//! Lock: `std::fs::File::try_lock` (stable since Rust 1.89) on a never-deleted `<key>.lock` file, polled
//! until a timeout and never waited on forever. The OS drops the lock when the process ends, so a leftover
//! lock file with no live holder never blocks. Limits: advisory (only cooperating processes), network
//! filesystems vary, tested on Linux only, Windows untested.
//!
//! File names use `flow::channel_key`, so "Stable" and "stable" never share a file. The exact channel is
//! stored inside the file and checked on load.
//!
//! Temp files of a crashed write (`<key>.state.pavs-tmp-*`) are never deleted here; `list_orphan_temps`
//! only lists them.

use crate::flow::{channel_key, StateStore};
use crate::AcceptedState;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_STATE_BYTES: u64 = 512;
const HEADER_LINE: &str = "pos-update-state-v1";

#[derive(Debug)]
pub enum FileStateError {
    BadChannel,
    /// Another holder kept the lock for the whole timeout.
    Held { path: PathBuf, waited: Duration },
    Io(io::Error),
}

impl std::fmt::Display for FileStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileStateError::BadChannel => write!(f, "invalid channel name"),
            FileStateError::Held { path, waited } => {
                write!(f, "state lock {} is held by another process (waited {waited:?})", path.display())
            }
            FileStateError::Io(e) => write!(f, "state I/O error: {e}"),
        }
    }
}
impl std::error::Error for FileStateError {}

impl From<io::Error> for FileStateError {
    fn from(e: io::Error) -> Self {
        FileStateError::Io(e)
    }
}

/// State for ONE channel, holding that channel's lock until dropped.
pub struct FileStateStore {
    dir: PathBuf,
    channel: String,
    key: String,
    _lock: File,
    #[cfg(feature = "fault-injection")]
    hook: Option<Box<dyn FnMut(pos_vault_store::WriteStep) -> pos_vault_store::HookAction>>,
}

impl FileStateStore {
    /// `dir` must exist. Takes `<dir>/<key>.lock`, waiting at most `timeout`.
    pub fn acquire(dir: &Path, channel: &str, timeout: Duration) -> Result<FileStateStore, FileStateError> {
        let key = channel_key(channel).map_err(|_| FileStateError::BadChannel)?;
        let lock_path = dir.join(format!("{key}.lock"));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&lock_path)?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => {
                    let waited = start.elapsed();
                    if waited >= timeout {
                        return Err(FileStateError::Held { path: lock_path, waited });
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(TryLockError::Error(e)) => return Err(FileStateError::Io(e)),
            }
        }
        Ok(FileStateStore {
            dir: dir.to_path_buf(),
            channel: channel.to_string(),
            key,
            _lock: file,
            #[cfg(feature = "fault-injection")]
            hook: None,
        })
    }

    pub fn state_path(&self) -> PathBuf {
        self.dir.join(format!("{}.state", self.key))
    }

    /// Temp files left by an interrupted write. Informational: nothing is deleted.
    pub fn list_orphan_temps(&self) -> io::Result<Vec<PathBuf>> {
        let prefix = format!("{}.state.pavs-tmp-", self.key);
        let mut v = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let e = e?;
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                v.push(e.path());
            }
        }
        v.sort();
        Ok(v)
    }

    /// Test-only failure injection for the state write. Compiled only with feature `fault-injection`.
    #[cfg(feature = "fault-injection")]
    pub fn set_fault_hook(&mut self, hook: Box<dyn FnMut(pos_vault_store::WriteStep) -> pos_vault_store::HookAction>) {
        self.hook = Some(hook);
    }

    fn check_channel(&self, channel: &str) -> io::Result<()> {
        if channel != self.channel {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "store is bound to another channel"));
        }
        Ok(())
    }
}

fn encode(s: &AcceptedState) -> Vec<u8> {
    format!("{HEADER_LINE}\nchannel={}\nsequence={}\ndigest={}\n", s.channel, s.sequence, hex::encode(s.digest)).into_bytes()
}

fn decode(bytes: &[u8]) -> Option<AcceptedState> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.strip_suffix('\n')?.split('\n');
    if lines.next()? != HEADER_LINE {
        return None;
    }
    let channel = lines.next()?.strip_prefix("channel=")?.to_string();
    let sequence_text = lines.next()?.strip_prefix("sequence=")?;
    let digest_hex = lines.next()?.strip_prefix("digest=")?;
    if lines.next().is_some() || sequence_text.is_empty() || !sequence_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let sequence = sequence_text.parse::<u64>().ok()?;
    if digest_hex.len() != 64 || !digest_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut digest = [0u8; 32];
    hex::decode_to_slice(digest_hex, &mut digest).ok()?;
    Some(AcceptedState { channel, sequence, digest })
}

fn vault_err(e: pos_vault_store::Error) -> io::Error {
    match e {
        pos_vault_store::Error::Io(k) => io::Error::from(k),
        other => io::Error::other(format!("{other:?}")),
    }
}

impl StateStore for FileStateStore {
    fn load(&mut self, channel: &str) -> io::Result<Option<AcceptedState>> {
        self.check_channel(channel)?;
        let f = match File::open(self.state_path()) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut buf = Vec::new();
        f.take(MAX_STATE_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_STATE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "state file too large"));
        }
        let st = decode(&buf).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed state file"))?;
        if st.channel != self.channel {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "state file is for another channel"));
        }
        Ok(Some(st))
    }

    fn store(&mut self, state: &AcceptedState) -> io::Result<()> {
        self.check_channel(&state.channel)?;
        let bytes = encode(state);
        let path = self.state_path();
        #[cfg(feature = "fault-injection")]
        if let Some(h) = self.hook.as_mut() {
            return pos_vault_store::write_file_atomic_with_hook(&path, &bytes, h).map_err(vault_err);
        }
        pos_vault_store::write_file_atomic(&path, &bytes).map_err(vault_err)
    }
}
