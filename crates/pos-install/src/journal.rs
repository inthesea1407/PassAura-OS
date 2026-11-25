//! Write-ahead journal: one JSON object per line, fsynced after every step.
//!
//! Strict reader: truncated (no final newline), garbage, wrong-shape,
//! duplicate, skipped and out-of-order steps are all errors, so a damaged
//! journal blocks installs instead of being guessed at. A zero-length file
//! (crash after create, before the first line was durable) means no step was
//! recorded and is treated as no journal.

use pos_core::audit::AuditRecord;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailKind {
    HashMismatch,
    InstallFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Step {
    Begun {
        package: String,
        sequence: u64,
        digest: String,
        sha256: String,
        source: String,
        parent: Option<String>,
    },
    Verified,
    Fetched,
    Staged {
        file: String,
    },
    /// Written and synced BEFORE the install command runs.
    InstallStarted,
    /// Written and synced AFTER the command reported success.
    Installed,
    /// The rollback state now holds this attempt's sequence.
    SeqPersisted,
    Committed,
    AuditIntent {
        record: AuditRecord,
    },
    AuditWritten {
        seq: u64,
    },
    Failed {
        kind: FailKind,
    },
    Aborted,
    AbandonRequested,
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub attempt: String,
    #[serde(flatten)]
    pub step: Step,
}

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    /// The file is damaged or violates the step order.
    Corrupt(String),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "install journal I/O error: {e}"),
            JournalError::Corrupt(m) => write!(f, "install journal corrupt: {m}"),
        }
    }
}
impl std::error::Error for JournalError {}
impl From<io::Error> for JournalError {
    fn from(e: io::Error) -> Self {
        JournalError::Io(e)
    }
}

fn corrupt<T>(m: impl Into<String>) -> Result<T, JournalError> {
    Err(JournalError::Corrupt(m.into()))
}

/// Main-line progress of one attempt.
pub const R_BEGUN: u8 = 0;
pub const R_VERIFIED: u8 = 1;
pub const R_FETCHED: u8 = 2;
pub const R_STAGED: u8 = 3;
pub const R_STARTED: u8 = 4;
pub const R_INSTALLED: u8 = 5;
pub const R_SEQ: u8 = 6;
pub const R_COMMITTED: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    Failed(FailKind),
    Aborted,
    Abandoned,
}

/// What the journal says about one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub id: String,
    pub parent: Option<String>,
    pub package: String,
    pub sequence: u64,
    pub digest: String,
    pub sha256: String,
    pub source: String,
    pub rank: u8,
    pub staged: Option<String>,
    pub terminal: Option<Terminal>,
    pub abandon_requested: bool,
    /// Latest audit record that was journaled but not yet marked written.
    pub pending_audit: Option<AuditRecord>,
    /// Audit records marked written, in order.
    pub written_audits: Vec<AuditRecord>,
}

impl Attempt {
    pub fn has_written(&self, event: pos_core::audit::AuditEvent) -> bool {
        self.written_audits.iter().any(|r| r.event == event)
    }
}

fn validate_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// Validate a whole entry list and fold it into attempts.
pub fn fold(entries: &[Entry]) -> Result<Vec<Attempt>, JournalError> {
    let mut attempts: Vec<Attempt> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if !validate_id(&e.attempt) {
            return corrupt(format!("line {}: bad attempt id", i + 1));
        }
        if let Step::Begun {
            package,
            sequence,
            digest,
            sha256,
            source,
            parent,
        } = &e.step
        {
            if attempts.iter().any(|a| a.id == e.attempt) {
                return corrupt(format!("line {}: duplicate attempt id", i + 1));
            }
            match (attempts.last(), parent) {
                (None, None) => {}
                (None, Some(_)) => {
                    return corrupt(format!("line {}: first attempt has a parent", i + 1))
                }
                (Some(_), None) => {
                    return corrupt(format!("line {}: later attempt without parent", i + 1))
                }
                (Some(prev), Some(p)) => {
                    if &prev.id != p {
                        return corrupt(format!(
                            "line {}: parent is not the previous attempt",
                            i + 1
                        ));
                    }
                    let indeterminate = prev.rank == R_STARTED
                        && prev.terminal.is_none()
                        && !prev.abandon_requested;
                    let aborted_retry = prev.terminal == Some(Terminal::Aborted)
                        && prev.parent.is_some()
                        && prev.rank < R_STARTED
                        && !prev.abandon_requested;
                    if !(indeterminate || aborted_retry) {
                        return corrupt(format!(
                            "line {}: previous attempt was not left indeterminate",
                            i + 1
                        ));
                    }
                    if prev.pending_audit.is_some() {
                        return corrupt(format!(
                            "line {}: previous attempt has an unwritten audit",
                            i + 1
                        ));
                    }
                }
            }
            attempts.push(Attempt {
                id: e.attempt.clone(),
                parent: parent.clone(),
                package: package.clone(),
                sequence: *sequence,
                digest: digest.clone(),
                sha256: sha256.clone(),
                source: source.clone(),
                rank: R_BEGUN,
                staged: None,
                terminal: None,
                abandon_requested: false,
                pending_audit: None,
                written_audits: Vec::new(),
            });
            continue;
        }
        let Some(a) = attempts.last_mut() else {
            return corrupt(format!("line {}: step before any attempt began", i + 1));
        };
        if a.id != e.attempt {
            return corrupt(format!(
                "line {}: step for a different or older attempt",
                i + 1
            ));
        }
        match &e.step {
            Step::Begun { .. } => unreachable!(),
            Step::AuditIntent { record } => {
                // A newer intent replaces an unwritten older one (the chain
                // moved before the older record could be appended).
                a.pending_audit = Some(record.clone());
            }
            Step::AuditWritten { seq } => match a.pending_audit.take() {
                Some(r) if r.seq == *seq => a.written_audits.push(r),
                _ => {
                    return corrupt(format!(
                        "line {}: audit_written without matching intent",
                        i + 1
                    ))
                }
            },
            Step::Failed { kind } => {
                if a.terminal.is_some() || a.abandon_requested {
                    return corrupt(format!("line {}: duplicate or late terminal step", i + 1));
                }
                a.terminal = Some(Terminal::Failed(*kind));
            }
            Step::Aborted => {
                if a.terminal.is_some() || a.abandon_requested {
                    return corrupt(format!("line {}: duplicate or late terminal step", i + 1));
                }
                a.terminal = Some(Terminal::Aborted);
            }
            Step::AbandonRequested => {
                let aborted_retry = a.terminal == Some(Terminal::Aborted) && a.parent.is_some();
                if (a.terminal.is_some() && !aborted_retry) || a.abandon_requested {
                    return corrupt(format!(
                        "line {}: duplicate or late abandon_requested",
                        i + 1
                    ));
                }
                a.abandon_requested = true;
            }
            Step::Abandoned => {
                let ok_terminal = a.terminal.is_none() || a.terminal == Some(Terminal::Aborted);
                if !a.abandon_requested || !ok_terminal || a.pending_audit.is_some() {
                    return corrupt(format!("line {}: abandoned out of order", i + 1));
                }
                a.terminal = Some(Terminal::Abandoned);
            }
            main => {
                if a.terminal.is_some() || a.abandon_requested {
                    return corrupt(format!("line {}: main step after a terminal step", i + 1));
                }
                let (rank, staged) = match main {
                    Step::Verified => (R_VERIFIED, None),
                    Step::Fetched => (R_FETCHED, None),
                    Step::Staged { file } => {
                        if !crate::stage::valid_stage_name(file) {
                            return corrupt(format!("line {}: invalid staged file name", i + 1));
                        }
                        (R_STAGED, Some(file.clone()))
                    }
                    Step::InstallStarted => (R_STARTED, None),
                    Step::Installed => (R_INSTALLED, None),
                    Step::SeqPersisted => (R_SEQ, None),
                    Step::Committed => (R_COMMITTED, None),
                    _ => unreachable!(),
                };
                if rank != a.rank + 1 {
                    return corrupt(format!(
                        "line {}: step out of order, skipped or duplicated",
                        i + 1
                    ));
                }
                a.rank = rank;
                if staged.is_some() {
                    a.staged = staged;
                }
            }
        }
    }
    Ok(attempts)
}

/// Parse journal bytes strictly.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, JournalError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| JournalError::Corrupt("not UTF-8".into()))?;
    if !text.ends_with('\n') {
        return corrupt("truncated: last line has no newline");
    }
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            return corrupt(format!("line {}: empty line", i + 1));
        }
        let e: Entry = serde_json::from_str(line)
            .map_err(|e| JournalError::Corrupt(format!("line {}: {e}", i + 1)))?;
        out.push(e);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct Journal {
    path: PathBuf,
}

impl Journal {
    /// `<state path>.install-journal`
    pub fn for_state(state_path: &Path) -> Journal {
        let mut s = state_path.as_os_str().to_owned();
        s.push(".install-journal");
        Journal {
            path: PathBuf::from(s),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read and validate. `Ok(vec![])` when there is no journal.
    pub fn load(&self) -> Result<Vec<Attempt>, JournalError> {
        match fs::read(&self.path) {
            Ok(bytes) => fold(&parse(&bytes)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// True if a journal file exists (read-only check).
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Validate that `entry` is legal after the current content, then append
    /// it as one line and fsync (and fsync the directory when the file is new).
    pub fn append(&self, entry: &Entry) -> Result<(), JournalError> {
        let mut entries = match fs::read(&self.path) {
            Ok(bytes) => parse(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        entries.push(entry.clone());
        fold(&entries)?;
        let existed = self.path.exists();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut line =
            serde_json::to_string(entry).map_err(|e| JournalError::Corrupt(e.to_string()))?;
        line.push('\n');
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
        if !existed {
            sync_dir(&self.path)?;
        }
        Ok(())
    }

    /// Delete the journal and fsync the directory. Missing is fine.
    pub fn remove(&self) -> Result<(), JournalError> {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        sync_dir(&self.path)?;
        Ok(())
    }
}

fn sync_dir(file: &Path) -> io::Result<()> {
    let dir = file
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(dir)?.sync_all()
}
