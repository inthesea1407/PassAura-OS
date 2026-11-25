//! The install transaction. See docs/INSTALL_PIPELINE.md.
//!
//! Order: lock, recover any earlier attempt, verify the signed allowlist
//! (including the rollback check, without persisting), package membership,
//! fetch from a local file, SHA-256 against the signed entry BEFORE staging,
//! private staging, journaled `install_started`, the backend's exact-file
//! install, journaled `installed`, only then persist the sequence, then
//! `committed`, then the audit record, then delete the journal.

use crate::journal::{Attempt, Entry, FailKind, Journal, JournalError, Step, Terminal};
use crate::journal::{R_COMMITTED, R_INSTALLED, R_SEQ, R_STARTED};
use crate::lock::{LockError, StateLock};
use crate::stage::{StageError, Stager};
use pos_core::audit::{append_planned_durable, plan_next_record, AuditEvent, AuditRecord};
use pos_gate::allowlist::Keyring;
use pos_gate::allowlist_v2::{
    canonical_digest_hex, verify_v2_trusted, V2Allowlist, V2Entry, V2Error,
};
use pos_gate::linux_backend::{
    valid_package_name, InstallMode, PackageBackend, PackageBackendError,
};
use pos_gate::rollback::{FileOps, RollbackError, RollbackStore};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Largest package file the local fetcher reads into memory (1 GiB).
pub const MAX_PACKAGE_BYTES: u64 = 1 << 30;

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Source of package bytes. Production: a local file chosen by the operator.
pub trait Fetcher {
    fn fetch(&mut self, package: &str, entry: &V2Entry) -> io::Result<Vec<u8>>;
    /// Recorded in the journal (never used to fetch again).
    fn describe(&self) -> String;
}

/// Reads one local file. No URL, no network. A symlink is refused.
#[derive(Debug, Clone)]
pub struct LocalFileFetcher {
    pub path: PathBuf,
}

impl Fetcher for LocalFileFetcher {
    fn fetch(&mut self, _package: &str, _entry: &V2Entry) -> io::Result<Vec<u8>> {
        let md = fs::symlink_metadata(&self.path)?;
        if !md.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "package source is not a regular file (symlinks are refused)",
            ));
        }
        if md.len() > MAX_PACKAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "package source is too large",
            ));
        }
        fs::read(&self.path)
    }

    fn describe(&self) -> String {
        format!("local-file:{}", self.path.display())
    }
}

#[derive(Debug, Clone)]
pub struct InstallPaths {
    /// Rollback state file. The lockfile, journal and stage directory sit next to it.
    pub state: PathBuf,
    /// Hash-chained audit log (JSON lines).
    pub audit: PathBuf,
    pub lock_timeout: Duration,
}

impl InstallPaths {
    pub fn new(state: impl Into<PathBuf>, audit: impl Into<PathBuf>) -> Self {
        InstallPaths {
            state: state.into(),
            audit: audit.into(),
            lock_timeout: Duration::from_secs(5),
        }
    }
}

pub struct Request<'a> {
    pub package: &'a str,
    pub doc: &'a V2Allowlist,
    pub trusted: &'a Keyring,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Committed { sequence: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunReport {
    pub package: String,
    pub sequence: u64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryStatus {
    Clean,
    ClosedCommitted,
    ClosedFailed,
    ClosedAbandoned,
    /// The install command may or may not have run. Sequence NOT advanced.
    /// Needs an operator: retry (may repeat side effects) or abandon.
    Indeterminate {
        attempt: String,
    },
    /// The installed attempt can no longer be committed because the stored
    /// sequence moved. Needs an operator (abandon).
    Superseded {
        attempt: String,
    },
}

#[derive(Debug)]
pub enum InstallError {
    Lock(LockError),
    Journal(JournalError),
    Rollback(RollbackError),
    Verification(V2Error),
    InvalidPackageName,
    InvalidEntry(String),
    NotAllowed,
    HashMismatch {
        expected: String,
        actual: String,
    },
    Fetch(String),
    Stage(StageError),
    Backend(PackageBackendError),
    Audit(String),
    /// An earlier attempt is unresolved; installs are refused until an operator acts.
    Blocked(RecoveryStatus),
    NothingToRecover,
    RetryRefused(String),
    /// Fault injection only: simulated process death at the named point.
    Crashed(String),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallError::Lock(e) => write!(f, "{e}"),
            InstallError::Journal(e @ JournalError::Corrupt(_)) => write!(
                f,
                "{e}. Refusing to continue. The install may have started. Do NOT delete or edit the journal. \
                 Back it up, inspect the package state by hand (dpkg --audit, dpkg -l <package>) and see \
                 docs/INSTALL_PIPELINE.md (torn or corrupt journal)"
            ),
            InstallError::Journal(e) => write!(f, "{e}"),
            InstallError::Rollback(e) => write!(f, "{e}"),
            InstallError::Verification(e) => write!(f, "verification failed: {e}"),
            InstallError::InvalidPackageName => f.write_str("invalid package name"),
            InstallError::InvalidEntry(m) => write!(f, "invalid allowlist entry: {m}"),
            InstallError::NotAllowed => f.write_str("package is not in the allowlist"),
            InstallError::HashMismatch { expected, actual } => write!(
                f,
                "package SHA-256 mismatch: signed entry says {expected}, file is {actual}; nothing was staged or installed"
            ),
            InstallError::Fetch(m) => write!(f, "cannot read package source: {m}"),
            InstallError::Stage(e) => write!(f, "{e}"),
            InstallError::Backend(e) => write!(f, "install failed: {e}"),
            InstallError::Audit(m) => write!(f, "audit log error: {m}"),
            InstallError::Blocked(RecoveryStatus::Indeterminate { attempt }) => write!(
                f,
                "an earlier install attempt ({attempt}) has an unknown outcome and the sequence was not advanced; \
                 resolve it with --recover retry (may repeat package script side effects) or --recover abandon"
            ),
            InstallError::Blocked(RecoveryStatus::Superseded { attempt }) => write!(
                f,
                "an earlier attempt ({attempt}) installed but its sequence can no longer be committed; resolve it with --recover abandon"
            ),
            InstallError::Blocked(_) => f.write_str("blocked by an unresolved earlier attempt"),
            InstallError::NothingToRecover => f.write_str("there is no unresolved install attempt"),
            InstallError::RetryRefused(m) => write!(f, "retry refused: {m}"),
            InstallError::Crashed(p) => write!(f, "simulated crash at {p}"),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<LockError> for InstallError {
    fn from(e: LockError) -> Self {
        InstallError::Lock(e)
    }
}
impl From<JournalError> for InstallError {
    fn from(e: JournalError) -> Self {
        InstallError::Journal(e)
    }
}
impl From<RollbackError> for InstallError {
    fn from(e: RollbackError) -> Self {
        InstallError::Rollback(e)
    }
}
impl From<StageError> for InstallError {
    fn from(e: StageError) -> Self {
        InstallError::Stage(e)
    }
}

/// What a failed backend call tells us about the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandFate {
    /// Refused before any command was built or run: nothing happened.
    NotRun,
    /// The runner proved the program was never started: nothing happened.
    NotStarted,
    /// The program ran and exited with a nonzero code. The attempt failed and
    /// the sequence stays put, but the package system can hold PARTIAL
    /// effects (for example a half-configured package).
    ExitedNonzero,
    /// Could not prove either way (wait/read failure after spawn, killed by a
    /// signal, interrupted). Treated as an unknown outcome, never as failure.
    Unknown,
}

pub fn classify_failure(e: &PackageBackendError) -> CommandFate {
    match e {
        PackageBackendError::RunnerNotStarted { .. } => CommandFate::NotStarted,
        PackageBackendError::RunnerFailure { code: Some(_), .. } => CommandFate::ExitedNonzero,
        // No exit code and no typed proof of non-start: unknown, whatever the text says.
        PackageBackendError::RunnerFailure { code: None, .. } => CommandFate::Unknown,
        _ => CommandFate::NotRun,
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn new_attempt_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}-{:x}", nanos, std::process::id(), n)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn step_label(s: &Step) -> &'static str {
    match s {
        Step::Begun { .. } => "begun",
        Step::Verified => "verified",
        Step::Fetched => "fetched",
        Step::Staged { .. } => "staged",
        Step::InstallStarted => "install_started",
        Step::Installed => "installed",
        Step::SeqPersisted => "seq_persisted",
        Step::Committed => "committed",
        Step::AuditIntent { .. } => "audit_intent",
        Step::AuditWritten { .. } => "audit_written",
        Step::Failed { .. } => "failed",
        Step::Aborted => "aborted",
        Step::AbandonRequested => "abandon_requested",
        Step::Abandoned => "abandoned",
    }
}

/// Index of the attempt whose state decides recovery: an aborted retry
/// prelude falls back to the attempt it was retrying.
fn effective_index(atts: &[Attempt]) -> usize {
    let mut i = atts.len() - 1;
    while i > 0
        && atts[i].terminal == Some(Terminal::Aborted)
        && atts[i].parent.is_some()
        && !atts[i].abandon_requested
    {
        i -= 1;
    }
    i
}

/// Test-only fault injection hook: returns true to abort at the named step.
type FaultHook = Box<dyn FnMut(&str) -> bool>;

/// Result of resolving a request: allowlist entry, package file name, optional (sequence, digest).
type Resolved = (V2Entry, String, Option<(u64, String)>);

pub struct Pipeline<B, F, O> {
    paths: InstallPaths,
    backend: B,
    fetcher: F,
    ops: O,
    fault: Option<FaultHook>,
}

impl<B: PackageBackend, F: Fetcher, O: FileOps> Pipeline<B, F, O> {
    pub fn new(paths: InstallPaths, backend: B, fetcher: F, ops: O) -> Self {
        Pipeline {
            paths,
            backend,
            fetcher,
            ops,
            fault: None,
        }
    }

    /// Fault injection for tests: the hook is called with a label after every
    /// journal append, before the command, after the command, around the state
    /// write and around each audit write. Returning true simulates the process
    /// dying right there (the call returns `Crashed`, nothing is cleaned up).
    pub fn set_fault(&mut self, hook: impl FnMut(&str) -> bool + 'static) {
        self.fault = Some(Box::new(hook));
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn paths(&self) -> &InstallPaths {
        &self.paths
    }

    fn hit(&mut self, label: &str) -> Result<(), InstallError> {
        if let Some(h) = self.fault.as_mut() {
            if h(label) {
                return Err(InstallError::Crashed(label.to_string()));
            }
        }
        Ok(())
    }

    fn journal(&self) -> Journal {
        Journal::for_state(&self.paths.state)
    }

    fn stager(&self) -> Stager {
        Stager::for_state(&self.paths.state)
    }

    fn jappend(&mut self, attempt: &str, step: Step) -> Result<(), InstallError> {
        let label = format!("journal:{}", step_label(&step));
        self.journal().append(&Entry {
            attempt: attempt.to_string(),
            step,
        })?;
        self.hit(&label)
    }

    fn load_attempt(&self, id: &str) -> Result<Attempt, InstallError> {
        self.journal()
            .load()?
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| InstallError::Journal(JournalError::Corrupt("attempt vanished".into())))
    }

    fn cleanup_stage(&self, atts: &[Attempt]) -> Result<(), InstallError> {
        let stager = self.stager();
        for a in atts {
            if let Some(name) = &a.staged {
                stager.remove(name)?;
            }
        }
        Ok(())
    }

    fn close_journal(&self) -> Result<(), InstallError> {
        self.journal().remove()?;
        Ok(())
    }

    /// One audit record for an attempt, through the journal's intent, with
    /// the dedup rule: if the planned record is already in the log it is not
    /// appended again.
    fn emit_audit(&mut self, attempt: &str, event: AuditEvent) -> Result<(), InstallError> {
        let a = self.load_attempt(attempt)?;
        if a.has_written(event) {
            return Ok(());
        }
        let audit = self.paths.audit.clone();
        let rec: AuditRecord = match &a.pending_audit {
            Some(r) if r.event == event => r.clone(),
            _ => {
                let r = plan_next_record(&audit, now_unix().max(0) as u64, event)
                    .map_err(|e| InstallError::Audit(e.to_string()))?;
                self.jappend(attempt, Step::AuditIntent { record: r.clone() })?;
                r
            }
        };
        self.hit("audit:before_write")?;
        let rec = match append_planned_durable(&audit, &rec) {
            Ok(_) => rec,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let r2 = plan_next_record(&audit, now_unix().max(0) as u64, event)
                    .map_err(|e| InstallError::Audit(e.to_string()))?;
                self.jappend(attempt, Step::AuditIntent { record: r2.clone() })?;
                append_planned_durable(&audit, &r2)
                    .map_err(|e| InstallError::Audit(e.to_string()))?;
                r2
            }
            Err(e) => return Err(InstallError::Audit(e.to_string())),
        };
        self.hit("audit:after_write")?;
        self.jappend(attempt, Step::AuditWritten { seq: rec.seq })
    }

    /// Audit a request rejected before any journal exists (one record).
    fn audit_denied(&mut self) -> Result<(), InstallError> {
        let audit = self.paths.audit.clone();
        for _ in 0..2 {
            let r = plan_next_record(&audit, now_unix().max(0) as u64, AuditEvent::GateDenied)
                .map_err(|e| InstallError::Audit(e.to_string()))?;
            match append_planned_durable(&audit, &r) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
                Err(e) => return Err(InstallError::Audit(e.to_string())),
            }
        }
        Err(InstallError::Audit("audit chain kept changing".into()))
    }

    /// Verification and package checks, read-only. Returns the entry, the
    /// canonical digest and the stored rollback pair.
    fn check_request(&self, req: &Request) -> Result<Resolved, InstallError> {
        if !valid_package_name(req.package) {
            return Err(InstallError::InvalidPackageName);
        }
        let stored = RollbackStore::read_state_readonly(&self.paths.state)?;
        let stored_pair: Option<(u64, String)> = stored
            .filter(|r| !(r.last_seq == 0 && r.last_digest_hex.is_empty()))
            .map(|r| (r.last_seq, r.last_digest_hex));
        verify_v2_trusted(
            req.doc,
            req.trusted,
            req.now,
            stored_pair.as_ref().map(|(s, d)| (*s, d.as_str())),
        )
        .map_err(InstallError::Verification)?;
        let entry = req
            .doc
            .entries
            .iter()
            .find(|e| e.name == req.package)
            .cloned()
            .ok_or(InstallError::NotAllowed)?;
        let sha = entry.sha256.to_ascii_lowercase();
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(InstallError::InvalidEntry(
                "sha256 is not 64 hex characters".into(),
            ));
        }
        let digest = canonical_digest_hex(req.doc).map_err(InstallError::Verification)?;
        Ok((
            V2Entry {
                sha256: sha,
                ..entry
            },
            digest,
            stored_pair,
        ))
    }

    /// Verification and local-file hash check only. Writes nothing and does
    /// not even create the lockfile.
    pub fn dry_run(&mut self, req: &Request) -> Result<DryRunReport, InstallError> {
        let atts = self.journal().load()?;
        if !atts.is_empty() {
            let idx = effective_index(&atts);
            return Err(InstallError::Blocked(RecoveryStatus::Indeterminate {
                attempt: atts[idx].id.clone(),
            }));
        }
        let (entry, _digest, _stored) = self.check_request(req)?;
        let bytes = self
            .fetcher
            .fetch(req.package, &entry)
            .map_err(|e| InstallError::Fetch(e.to_string()))?;
        let actual = sha256_hex(&bytes);
        if actual != entry.sha256 {
            return Err(InstallError::HashMismatch {
                expected: entry.sha256,
                actual,
            });
        }
        Ok(DryRunReport {
            package: req.package.to_string(),
            sequence: req.doc.sequence,
            source: self.fetcher.describe(),
        })
    }

    /// Recover any earlier attempt (startup entry point).
    pub fn recover(&mut self) -> Result<RecoveryStatus, InstallError> {
        let _lock = StateLock::acquire(&self.paths.state, self.paths.lock_timeout)?;
        self.recover_locked()
    }

    pub fn install(&mut self, req: &Request) -> Result<Outcome, InstallError> {
        let _lock = StateLock::acquire(&self.paths.state, self.paths.lock_timeout)?;
        if let s @ (RecoveryStatus::Indeterminate { .. } | RecoveryStatus::Superseded { .. }) =
            self.recover_locked()?
        {
            return Err(InstallError::Blocked(s));
        }
        self.run_attempt(req, None, None)
    }

    /// Explicit operator action for an indeterminate attempt: run the install
    /// command again for the SAME signed document and package. This can repeat
    /// package maintainer-script side effects; nothing here claims otherwise.
    pub fn retry(&mut self, req: &Request) -> Result<Outcome, InstallError> {
        let _lock = StateLock::acquire(&self.paths.state, self.paths.lock_timeout)?;
        let attempt = match self.recover_locked()? {
            RecoveryStatus::Indeterminate { attempt } => attempt,
            RecoveryStatus::Superseded { .. } => {
                return Err(InstallError::RetryRefused(
                    "the attempt is superseded; abandon it".into(),
                ))
            }
            _ => return Err(InstallError::NothingToRecover),
        };
        let a = self.load_attempt(&attempt)?;
        let (entry, digest, _stored) = self.check_request(req)?;
        if a.package != req.package
            || a.sequence != req.doc.sequence
            || a.digest != digest
            || a.sha256 != entry.sha256
        {
            return Err(InstallError::RetryRefused(
                "the supplied allowlist or package is not the one journaled for the unresolved attempt; \
                 a different document is a new install, so abandon first"
                    .into(),
            ));
        }
        let staged = a
            .staged
            .clone()
            .ok_or_else(|| InstallError::RetryRefused("no staged file recorded".into()))?;
        let bytes = self.stager().read_checked(&staged)?;
        let actual = sha256_hex(&bytes);
        if actual != entry.sha256 {
            return Err(InstallError::HashMismatch {
                expected: entry.sha256,
                actual,
            });
        }
        // The journal chains each attempt to the one before it, so an aborted
        // retry prelude stays in the chain between the base attempt and this one.
        let last = self
            .journal()
            .load()?
            .last()
            .map(|a| a.id.clone())
            .unwrap_or(attempt);
        self.run_attempt(req, Some(last), Some(staged))
    }

    /// Explicit operator action: give up on an unresolved attempt. Order:
    /// `abandon_requested` (installs stay blocked), durable audit, stage
    /// removal, `abandoned`, journal delete. A crash anywhere before the
    /// delete leaves the block in place and this call can be run again.
    /// Nothing is uninstalled and the sequence is not advanced.
    pub fn abandon(&mut self) -> Result<(), InstallError> {
        let _lock = StateLock::acquire(&self.paths.state, self.paths.lock_timeout)?;
        match self.recover_locked()? {
            RecoveryStatus::ClosedAbandoned => Ok(()),
            RecoveryStatus::Indeterminate { .. } | RecoveryStatus::Superseded { .. } => {
                let atts = self.journal().load()?;
                let last = atts.last().expect("unresolved attempt exists").id.clone();
                self.jappend(&last, Step::AbandonRequested)?;
                self.finish_abandon()?;
                Ok(())
            }
            _ => Err(InstallError::NothingToRecover),
        }
    }

    fn finish_abandon(&mut self) -> Result<RecoveryStatus, InstallError> {
        let atts = self.journal().load()?;
        let last = atts.last().expect("journal has attempts").clone();
        self.emit_audit(&last.id, AuditEvent::InstallAbandoned)?;
        self.cleanup_stage(&atts)?;
        if last.terminal != Some(Terminal::Abandoned) {
            self.jappend(&last.id, Step::Abandoned)?;
        }
        self.close_journal()?;
        Ok(RecoveryStatus::ClosedAbandoned)
    }

    /// Fail an attempt that definitely did not install: record, audit, clean up.
    fn fail(&mut self, attempt: &str, kind: FailKind) -> Result<(), InstallError> {
        self.jappend(attempt, Step::Failed { kind })?;
        let event = match kind {
            FailKind::HashMismatch => AuditEvent::InstallHashMismatch,
            FailKind::InstallFailed => AuditEvent::InstallFailed,
        };
        self.emit_audit(attempt, event)?;
        let atts = self.journal().load()?;
        self.cleanup_stage(&atts)?;
        self.close_journal()
    }

    fn run_attempt(
        &mut self,
        req: &Request,
        parent: Option<String>,
        existing_staged: Option<String>,
    ) -> Result<Outcome, InstallError> {
        let (entry, digest, stored_pair) = match self.check_request(req) {
            Ok(v) => v,
            Err(e) => {
                self.audit_denied()?;
                return Err(e);
            }
        };
        let attempt = new_attempt_id();
        self.jappend(
            &attempt,
            Step::Begun {
                package: req.package.to_string(),
                sequence: req.doc.sequence,
                digest: digest.clone(),
                sha256: entry.sha256.clone(),
                source: self.fetcher.describe(),
                parent: parent.clone(),
            },
        )?;
        self.jappend(&attempt, Step::Verified)?;
        if parent.is_some() {
            self.emit_audit(&attempt, AuditEvent::InstallRetried)?;
        }

        let staged_name = match existing_staged {
            Some(name) => {
                self.jappend(&attempt, Step::Fetched)?;
                self.jappend(&attempt, Step::Staged { file: name.clone() })?;
                name
            }
            None => {
                let bytes = match self.fetcher.fetch(req.package, &entry) {
                    Ok(b) => b,
                    Err(e) => {
                        self.fail(&attempt, FailKind::InstallFailed)?;
                        return Err(InstallError::Fetch(e.to_string()));
                    }
                };
                let actual = sha256_hex(&bytes);
                if actual != entry.sha256 {
                    self.fail(&attempt, FailKind::HashMismatch)?;
                    return Err(InstallError::HashMismatch {
                        expected: entry.sha256,
                        actual,
                    });
                }
                self.jappend(&attempt, Step::Fetched)?;
                let name = format!("{attempt}.deb");
                if let Err(e) = self.stager().write_new(&name, &bytes, &self.ops) {
                    self.fail(&attempt, FailKind::InstallFailed)?;
                    return Err(InstallError::Stage(e));
                }
                self.jappend(&attempt, Step::Staged { file: name.clone() })?;
                name
            }
        };

        self.jappend(&attempt, Step::InstallStarted)?;
        let path = self.stager().file_path(&staged_name)?;
        let res = self.backend.install_staged_file(
            req.package,
            &path,
            req.doc,
            req.trusted,
            req.now,
            stored_pair.as_ref().map(|(s, d)| (*s, d.as_str())),
            InstallMode::Apply,
        );
        if let Err(e) = res {
            if classify_failure(&e) == CommandFate::Unknown {
                // Outcome unknown: stay at install_started, record the unknown
                // outcome, block. No failure is claimed and nothing is re-run.
                self.emit_audit(&attempt, AuditEvent::InstallIndeterminate)?;
                return Err(InstallError::Blocked(RecoveryStatus::Indeterminate {
                    attempt: attempt.clone(),
                }));
            }
            self.fail(&attempt, FailKind::InstallFailed)?;
            return Err(InstallError::Backend(e));
        }
        self.hit("command:ran")?;
        self.jappend(&attempt, Step::Installed)?;
        match self.commit_forward(&attempt)? {
            RecoveryStatus::ClosedCommitted => Ok(Outcome::Committed {
                sequence: req.doc.sequence,
            }),
            other => Err(InstallError::Blocked(other)),
        }
    }

    fn persist_sequence(&mut self, a: &Attempt) -> Result<(), RollbackError> {
        // Hook errors cannot be returned through RollbackError; a crash here
        // is injected via the label check below by callers.
        let mut store = RollbackStore::open_with_ops(&self.paths.state, &self.ops)?;
        store.accept_and_persist_with_ops(a.sequence, &a.digest, Some(now_unix()), &self.ops)?;
        Ok(())
    }

    /// From `installed` (or later) to closed: persist the sequence, mark
    /// committed, write the audit record, clean up, delete the journal.
    fn commit_forward(&mut self, attempt: &str) -> Result<RecoveryStatus, InstallError> {
        let a = self.load_attempt(attempt)?;
        if a.rank == R_INSTALLED {
            self.hit("state:before_persist")?;
            match self.persist_sequence(&a) {
                Ok(()) => {}
                Err(RollbackError::DowngradeRejected { .. })
                | Err(RollbackError::DigestMismatch { .. }) => {
                    return Ok(RecoveryStatus::Superseded {
                        attempt: attempt.to_string(),
                    });
                }
                Err(e) => return Err(InstallError::Rollback(e)),
            }
            self.hit("state:after_persist")?;
            self.jappend(attempt, Step::SeqPersisted)?;
        }
        let a = self.load_attempt(attempt)?;
        if a.rank == R_SEQ {
            self.jappend(attempt, Step::Committed)?;
        }
        self.emit_audit(attempt, AuditEvent::InstallCommitted)?;
        let atts = self.journal().load()?;
        self.cleanup_stage(&atts)?;
        self.close_journal()?;
        Ok(RecoveryStatus::ClosedCommitted)
    }

    /// The recovery table. Runs under the lock.
    ///
    /// - no journal: nothing to do
    /// - abandon requested: finish the abandon
    /// - failed / aborted / abandoned recorded: finish audit and cleanup
    /// - before `install_started`: no command could have run; abort, audit, clean up
    /// - `install_started` without `installed`: UNKNOWN outcome; block, never re-run
    /// - `installed`, `seq_persisted`, `committed`: roll forward to committed
    fn recover_locked(&mut self) -> Result<RecoveryStatus, InstallError> {
        let atts = self.journal().load()?;
        if atts.is_empty() {
            self.close_journal()?;
            return Ok(RecoveryStatus::Clean);
        }
        let last = atts.last().unwrap().clone();
        if last.abandon_requested {
            return self.finish_abandon();
        }
        // A retry that died before its command: complete its audit, mark it
        // aborted, and fall back to the attempt it was retrying.
        if last.parent.is_some() && last.terminal.is_none() && last.rank < R_STARTED {
            if matches!(&last.pending_audit, Some(r) if r.event == AuditEvent::InstallRetried) {
                self.emit_audit(&last.id, AuditEvent::InstallRetried)?;
            }
            self.jappend(&last.id, Step::Aborted)?;
            return self.recover_locked();
        }
        let a = atts[effective_index(&atts)].clone();
        match a.terminal {
            Some(Terminal::Failed(kind)) => {
                let event = match kind {
                    FailKind::HashMismatch => AuditEvent::InstallHashMismatch,
                    FailKind::InstallFailed => AuditEvent::InstallFailed,
                };
                self.emit_audit(&a.id, event)?;
                self.cleanup_stage(&atts)?;
                self.close_journal()?;
                return Ok(RecoveryStatus::ClosedFailed);
            }
            Some(Terminal::Aborted) => {
                self.emit_audit(&a.id, AuditEvent::InstallFailed)?;
                self.cleanup_stage(&atts)?;
                self.close_journal()?;
                return Ok(RecoveryStatus::ClosedFailed);
            }
            Some(Terminal::Abandoned) => {
                self.cleanup_stage(&atts)?;
                self.close_journal()?;
                return Ok(RecoveryStatus::ClosedAbandoned);
            }
            None => {}
        }
        if a.rank < R_STARTED {
            self.jappend(&a.id, Step::Aborted)?;
            self.emit_audit(&a.id, AuditEvent::InstallFailed)?;
            self.cleanup_stage(&atts)?;
            self.close_journal()?;
            return Ok(RecoveryStatus::ClosedFailed);
        }
        if a.rank == R_STARTED {
            self.emit_audit(&a.id, AuditEvent::InstallIndeterminate)?;
            return Ok(RecoveryStatus::Indeterminate { attempt: a.id });
        }
        debug_assert!(a.rank >= R_INSTALLED && a.rank <= R_COMMITTED);
        self.commit_forward(&a.id)
    }
}

/// Convenience for callers that only need to know whether a journal exists.
pub fn journal_present(state: &Path) -> bool {
    Journal::for_state(state).exists()
}
