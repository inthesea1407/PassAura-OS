//! Append-only, hash-chained audit log for PassAura OS.
//!
//! Each record carries a monotonic sequence number, a timestamp obtained
//! from an injected [`Clock`], a structured [`AuditEvent`], the hash of
//! the previous record, and the SHA-256 hash of its own canonical byte
//! form. [`AuditLog::verify_chain`] detects tampering (event, timestamp,
//! seq or hash edits), swallowed record boundaries, and reordering.
//!
//! Persistence is JSON lines: one record per line, append-only.
//!
//! Dependencies: `std`, `serde`, `serde_json`, `sha2` only. The log holds
//! identifiers and decisions; callers must never place secrets in event
//! payloads.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Hash of the empty chain's virtual "previous record".
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Hex length of a SHA-256 digest.
pub const HASH_LEN: usize = 64;

/// Monotonic wall-clock source, injected so tests control time.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// Wall-clock implementation used in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            // Clock went backwards past epoch: clamp, never panic.
            .unwrap_or(0)
    }
}

/// Fixed-time clock for tests.
#[derive(Debug, Clone)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// Structured audit events. Serialized as snake_case names; one enum
/// value per line means no free-form injection surface into the JSONL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    GateAllowed,
    GateDenied,
    GateAudited,
    KeyRotated,
    RollbackDetected,
    // --- Install transaction events (pos-install). Additive: the canonical
    // hash format is unchanged, but a reader built before these variants
    // existed fails to parse a log that contains them.
    /// Staged bytes did not match the signed SHA-256; nothing was installed.
    InstallHashMismatch,
    /// Install did not complete (command failed, or attempt aborted before the command).
    InstallFailed,
    /// Install command succeeded, sequence persisted, attempt committed.
    InstallCommitted,
    /// Outcome of the install command is unknown (crash around the command).
    InstallIndeterminate,
    /// An operator explicitly retried an indeterminate attempt.
    InstallRetried,
    /// An operator explicitly abandoned an unresolved attempt.
    InstallAbandoned,
}

/// One hash-chained audit record.
///
/// hash = sha256("{seq}\n{timestamp}\n{event}\n{prev_hash}\n") in hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// 1-based, strictly increasing, gapless position in the chain.
    pub seq: u64,
    /// Unix timestamp in seconds, from the injected clock.
    pub timestamp: u64,
    /// What happened.
    pub event: AuditEvent,
    /// Hash of the previous record (genesis: [`GENESIS_PREV_HASH`]).
    pub prev_hash: String,
    /// SHA-256 of this record's canonical form.
    pub hash: String,
}

impl AuditRecord {
    /// The exact bytes covered by `hash`.
    pub fn canonical_bytes(
        seq: u64,
        timestamp: u64,
        event: AuditEvent,
        prev_hash: &str,
    ) -> Vec<u8> {
        format!(
            "{seq}\n{timestamp}\n{}\n{prev_hash}\n",
            event_json_name(event)
        )
        .into_bytes()
    }

    /// Compute a record's hash from its fields.
    pub fn compute_hash(seq: u64, timestamp: u64, event: AuditEvent, prev_hash: &str) -> String {
        let mut h = Sha256::new();
        h.update(Self::canonical_bytes(seq, timestamp, event, prev_hash));
        hex(&h.finalize())
    }
}

/// A record's event name as serialized in the JSONL form.
fn event_json_name(e: AuditEvent) -> &'static str {
    match e {
        AuditEvent::GateAllowed => "gate_allowed",
        AuditEvent::GateDenied => "gate_denied",
        AuditEvent::GateAudited => "gate_audited",
        AuditEvent::KeyRotated => "key_rotated",
        AuditEvent::RollbackDetected => "rollback_detected",
        AuditEvent::InstallHashMismatch => "install_hash_mismatch",
        AuditEvent::InstallFailed => "install_failed",
        AuditEvent::InstallCommitted => "install_committed",
        AuditEvent::InstallIndeterminate => "install_indeterminate",
        AuditEvent::InstallRetried => "install_retried",
        AuditEvent::InstallAbandoned => "install_abandoned",
    }
}

/// Hex-encode bytes (lowercase).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Detected chain defect. `index` is the 0-based position in the loaded
/// list of records where the defect was found, `seq` the record's seq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainError {
    /// Failure category.
    pub kind: ChainErrorKind,
    /// 0-based position in the record list, when applicable.
    pub index: usize,
    /// The record's own seq, when parseable.
    pub seq: Option<u64>,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at index {}", self.kind, self.index)?;
        if let Some(seq) = self.seq {
            write!(f, " (seq {seq})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ChainError {}

/// Kinds of chain defect detected by [`AuditLog::verify_chain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainErrorKind {
    /// A JSON line failed to parse.
    CorruptLine,
    /// seq must start at 1 and increase by exactly 1.
    BadSequence,
    /// seq or timestamp went backwards; catches reordering.
    OutOfOrder,
    /// Stored `prev_hash` does not match the previous record's hash.
    PrevHashMismatch,
    /// Stored `hash` does not match the recomputed hash of the fields:
    /// the record content was tampered with.
    HashMismatch,
}

/// In-memory hash-chained audit log with JSON-lines persistence.
#[derive(Debug)]
pub struct AuditLog<C: Clock> {
    clock: C,
    records: Vec<AuditRecord>,
}

impl Default for AuditLog<SystemClock> {
    fn default() -> Self {
        Self::with_clock(SystemClock)
    }
}

impl<C: Clock> AuditLog<C> {
    /// Empty log bound to the given clock.
    pub fn with_clock(clock: C) -> Self {
        Self {
            clock,
            records: Vec::new(),
        }
    }

    /// Append one event. Returns the freshly computed record.
    pub fn append(&mut self, event: AuditEvent) -> &AuditRecord {
        let seq = self.records.len() as u64 + 1;
        let timestamp = self.clock.now_unix();
        // Timestamps must never go backwards, even if the clock does:
        // clamp to the last recorded timestamp to keep the chain orderable.
        let timestamp = match self.records.last() {
            Some(prev) => timestamp.max(prev.timestamp),
            None => timestamp,
        };
        let prev_hash = self
            .records
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let hash = AuditRecord::compute_hash(seq, timestamp, event, &prev_hash);
        self.records.push(AuditRecord {
            seq,
            timestamp,
            event,
            prev_hash,
            hash,
        });
        self.records.last().expect("just pushed")
    }

    /// All records, oldest first.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Head hash: the hash of the newest record, or [`GENESIS_PREV_HASH`]
    /// if empty. Publish this value externally to detect tail truncation.
    pub fn head_hash(&self) -> &str {
        self.records
            .last()
            .map(|r| r.hash.as_str())
            .unwrap_or(GENESIS_PREV_HASH)
    }

    /// Serialize every record as JSON lines (one record per line).
    pub fn to_json_lines(&self) -> String {
        let mut out = String::new();
        for r in &self.records {
            out.push_str(
                &serde_json::to_string(r).expect("AuditRecord serializes by construction"),
            );
            out.push('\n');
        }
        out
    }

    /// Load a log from JSON lines, verifying integrity. Returns the log
    /// and any external anchor check result is the caller's job (see
    /// [`AuditLog::verify_anchored`]).
    pub fn from_json_lines(lines: &str, clock: C) -> Result<Self, ChainError> {
        let mut records = Vec::new();
        for line in lines.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // `index` is the record position (blank lines do not count).
            let index = records.len();
            let r: AuditRecord = serde_json::from_str(line).map_err(|_| ChainError {
                kind: ChainErrorKind::CorruptLine,
                index,
                seq: None,
            })?;
            records.push(r);
        }
        verify_records(&records)?;
        Ok(Self { clock, records })
    }

    /// Append the JSONL representation of all records to a file,
    /// creating it if necessary. Existing content is never rewritten or
    /// truncated: append-only by construction.
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        for r in &self.records {
            let line = serde_json::to_string(r).expect("AuditRecord serializes");
            writeln!(f, "{line}")?;
        }
        Ok(())
    }

    /// Load all records from a JSON-lines file, verifying integrity.
    pub fn load_from_file(path: &Path, clock: C) -> std::io::Result<Self> {
        let f = File::open(path)?;
        // A read error must fail the load. Dropping it would silently
        // shorten the chain, which still verifies.
        let lines = BufReader::new(f)
            .lines()
            .collect::<Result<Vec<String>, _>>()?;
        Self::from_json_lines_lines(lines.into_iter(), clock)
    }

    /// As `from_json_lines`, from an iterator of lines.
    pub fn from_json_lines_lines<I: Iterator<Item = String>>(
        lines: I,
        clock: C,
    ) -> std::io::Result<Self> {
        let joined = lines.collect::<Vec<_>>().join("\n");
        // Keep the ChainError as the error source so callers can inspect it.
        Self::from_json_lines(&joined, clock)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Verify the loaded chain and, additionally, compare its length and
    /// head hash against an externally published anchor. This is the only
    /// way to detect tail truncation (removal of the newest records):
    /// a truncated chain is internally consistent by design.
    pub fn verify_anchored(records: &[AuditRecord], anchor: &Anchor) -> Result<(), ChainError> {
        verify_records(records)?;
        if records.len() as u64 != anchor.len {
            return Err(ChainError {
                kind: ChainErrorKind::BadSequence, // length mismatch against anchor
                index: records.len(),
                seq: None,
            });
        }
        let head = records
            .last()
            .map(|r| r.hash.as_str())
            .unwrap_or(GENESIS_PREV_HASH);
        if head != anchor.head_hash {
            return Err(ChainError {
                kind: ChainErrorKind::PrevHashMismatch,
                index: records.len().saturating_sub(1),
                seq: records.last().map(|r| r.seq),
            });
        }
        Ok(())
    }
}

/// Plan the next record of the log stored at `path` (a missing file is an
/// empty chain) without writing it. The whole chain is verified first. The
/// timestamp is clamped to the last record's, as in [`AuditLog::append`].
pub fn plan_next_record(
    path: &Path,
    timestamp: u64,
    event: AuditEvent,
) -> std::io::Result<AuditRecord> {
    let records = read_verified_records(path)?;
    Ok(plan_after(&records, timestamp, event))
}

fn plan_after(records: &[AuditRecord], timestamp: u64, event: AuditEvent) -> AuditRecord {
    let seq = records.len() as u64 + 1;
    let timestamp = match records.last() {
        Some(prev) => timestamp.max(prev.timestamp),
        None => timestamp,
    };
    let prev_hash = records
        .last()
        .map(|r| r.hash.clone())
        .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
    let hash = AuditRecord::compute_hash(seq, timestamp, event, &prev_hash);
    AuditRecord {
        seq,
        timestamp,
        event,
        prev_hash,
        hash,
    }
}

fn read_verified_records(path: &Path) -> std::io::Result<Vec<AuditRecord>> {
    match File::open(path) {
        Ok(_) => Ok(AuditLog::load_from_file(path, FixedClock(0))?.records),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Outcome of [`append_planned_durable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The record was written and synced by this call.
    Written,
    /// The identical record (same seq and hash) was already in the log.
    AlreadyPresent,
}

/// Durably append a record produced by [`plan_next_record`]. The chain is
/// re-verified; if the log already holds this exact record nothing is
/// written. If the chain moved on (another record at that position, or a
/// different head), this fails with `InvalidData` so the caller can re-plan.
/// One line is appended with `O_APPEND`, then the file (and, when the file
/// was created, its directory) is synced. Existing content is never rewritten.
pub fn append_planned_durable(path: &Path, rec: &AuditRecord) -> std::io::Result<AppendOutcome> {
    let records = read_verified_records(path)?;
    if let Some(existing) = records.get((rec.seq as usize).wrapping_sub(1)) {
        if existing == rec {
            return Ok(AppendOutcome::AlreadyPresent);
        }
    }
    let planned = plan_after(&records, rec.timestamp, rec.event);
    if planned != *rec {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "audit chain changed since the record was planned",
        ));
    }
    let existed = path.exists();
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(rec).expect("AuditRecord serializes");
    writeln!(f, "{line}")?;
    f.sync_all()?;
    if !existed {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            File::open(dir)?.sync_all()?;
        }
    }
    Ok(AppendOutcome::Written)
}

/// External anchor published by the operator alongside the log file:
/// expected record count and head hash. Without an anchor, tail
/// truncation is undetectable by hash chaining alone; this is stated as a
/// limitation, not hidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub len: u64,
    pub head_hash: String,
}

impl Anchor {
    /// Anchor from the current state of an in-memory log.
    pub fn from_log<C: Clock>(log: &AuditLog<C>) -> Self {
        Self {
            len: log.records().len() as u64,
            head_hash: log.head_hash().to_string(),
        }
    }
}

/// Validate a slice of records: continuity, monotonic timestamps, hash
/// links, and content hashes.
fn verify_records(records: &[AuditRecord]) -> Result<(), ChainError> {
    let mut expected_prev = GENESIS_PREV_HASH.to_string();
    for (index, r) in records.iter().enumerate() {
        // Structure checks before hashing (cheap, and give better errors).
        if r.seq != index as u64 + 1 {
            return Err(ChainError {
                kind: if index > 0 && r.seq > records[index - 1].seq {
                    ChainErrorKind::OutOfOrder
                } else {
                    ChainErrorKind::BadSequence
                },
                index,
                seq: Some(r.seq),
            });
        }
        if index > 0 && r.timestamp < records[index - 1].timestamp {
            return Err(ChainError {
                kind: ChainErrorKind::OutOfOrder,
                index,
                seq: Some(r.seq),
            });
        }
        if r.prev_hash != expected_prev {
            return Err(ChainError {
                kind: ChainErrorKind::PrevHashMismatch,
                index,
                seq: Some(r.seq),
            });
        }
        if r.hash.len() != HASH_LEN
            || AuditRecord::compute_hash(r.seq, r.timestamp, r.event, &r.prev_hash) != r.hash
        {
            return Err(ChainError {
                kind: ChainErrorKind::HashMismatch,
                index,
                seq: Some(r.seq),
            });
        }
        expected_prev = r.hash.clone();
    }
    Ok(())
}

/// Recompute and compare a full chain (free function form usable without
/// constructing a log).
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), ChainError> {
    verify_records(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_two_events() -> AuditLog<FixedClock> {
        let mut log = AuditLog::with_clock(FixedClock(1000));
        log.append(AuditEvent::GateAllowed);
        log.append(AuditEvent::GateDenied);
        log
    }

    #[test]
    fn appends_with_monotonic_seq_and_chain_links() {
        let log = log_two_events();
        assert_eq!(log.records().len(), 2);
        assert_eq!(log.records()[0].seq, 1);
        assert_eq!(log.records()[1].seq, 2);
        assert_eq!(log.records()[0].prev_hash, GENESIS_PREV_HASH);
        assert_eq!(log.records()[1].prev_hash, log.records()[0].hash);
    }

    #[test]
    fn timestamps_are_injected_and_never_go_backwards() {
        let mut log = AuditLog::with_clock(FixedClock(100));
        log.append(AuditEvent::GateAllowed);
        log.clock.0 = 50; // clock rewound
        let r = log.append(AuditEvent::GateDenied).clone();
        assert_ge(r.timestamp, 100);
    }

    fn assert_ge(a: u64, b: u64) {
        assert!(a >= b, "timestamp {a} went backwards below {b}");
    }

    #[test]
    fn head_hash_matches_last_record() {
        let log = log_two_events();
        assert_eq!(log.head_hash(), log.records()[1].hash);
        assert_eq!(
            AuditLog::<FixedClock>::with_clock(FixedClock(1)).head_hash(),
            GENESIS_PREV_HASH
        );
    }

    #[test]
    fn valid_chain_verifies() {
        let log = log_two_events();
        verify_chain(log.records()).expect("clean chain must verify");
        assert_jsonl_roundtrip(&log);
    }

    fn assert_jsonl_roundtrip(log: &AuditLog<FixedClock>) {
        let loaded = AuditLog::from_json_lines(&log.to_json_lines(), FixedClock(0))
            .expect("clean chain loads");
        assert_eq!(loaded.records(), log.records());
    }

    #[test]
    fn tampered_event_is_detected() {
        let log = log_two_events();
        let mut recs: Vec<AuditRecord> = log.records().to_vec();
        recs[1].event = AuditEvent::GateAllowed; // rewrite history
        match verify_chain(&recs) {
            Err(ChainError {
                kind: ChainErrorKind::HashMismatch,
                index: 1,
                seq: Some(2),
            }) => {}
            other => panic!("expected HashMismatch at index 1, got {other:?}"),
        }
    }

    #[test]
    fn tampered_timestamp_is_detected() {
        let log = log_two_events();
        let mut recs = log.records().to_vec();
        recs[0].timestamp += 3600;
        assert!(matches!(
            verify_chain(&recs),
            Err(ChainError {
                kind: ChainErrorKind::HashMismatch,
                index: 0,
                ..
            })
        ));
    }

    #[test]
    fn tampered_hash_field_is_detected_as_mismatch() {
        let log = log_two_events();
        let mut recs = log.records().to_vec();
        // Attacker flips a hash bit without touching fields: recompute fails.
        let mut bytes: Vec<char> = recs[1].hash.chars().collect();
        bytes[0] = if bytes[0] == '0' { '1' } else { '0' };
        recs[1].hash = bytes.iter().collect();
        assert!(matches!(
            verify_chain(&recs),
            Err(ChainError {
                kind: ChainErrorKind::HashMismatch,
                index: 1,
                ..
            })
        ));
    }

    #[test]
    fn reordering_adjacent_records_is_detected() {
        let mut log = AuditLog::with_clock(FixedClock(1000));
        log.append(AuditEvent::GateAllowed);
        log.append(AuditEvent::GateDenied);
        log.append(AuditEvent::KeyRotated);
        let mut recs = log.records().to_vec();
        recs.swap(1, 2); // swap two middle records
                         // Either seq/OutOfOrder or PrevHashMismatch fires; must not pass.
        assert!(
            verify_chain(&recs).is_err(),
            "reordered chain must be rejected"
        );
    }

    #[test]
    fn internal_truncation_gap_is_detected() {
        // Removing a middle record breaks seq continuity: 1,3.
        let mut log = AuditLog::with_clock(FixedClock(1000));
        log.append(AuditEvent::GateAllowed);
        log.append(AuditEvent::GateDenied);
        log.append(AuditEvent::KeyRotated);
        let recs: Vec<AuditRecord> = log
            .records()
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, r)| r.clone())
            .collect();
        assert!(matches!(
            verify_chain(&recs),
            Err(ChainError {
                index: 1,
                seq: Some(3),
                ..
            })
        ));
    }

    #[test]
    fn tail_truncation_needs_anchor() {
        let mut log = AuditLog::with_clock(FixedClock(1000));
        log.append(AuditEvent::GateAllowed);
        log.append(AuditEvent::GateDenied);
        let full = log.records().to_vec();
        let anchor = Anchor::from_log(&log);

        // A chain cut to its head is internally consistent: verify_chain
        // passes, as documented. Only the anchor exposes the loss.
        verify_chain(&full[..1]).expect("truncated prefix is locally valid");
        let truncated = &full[..1];
        assert!(AuditLog::<FixedClock>::verify_anchored(truncated, &anchor).is_err());
        AuditLog::<FixedClock>::verify_anchored(&full, &anchor).expect("full chain matches anchor");
    }

    #[test]
    fn corrupt_json_line_is_reported() {
        let mut log = AuditLog::with_clock(FixedClock(1000));
        log.append(AuditEvent::GateAllowed);
        let mut text = log.to_json_lines();
        text.push_str("{not json}\n");
        assert!(matches!(
            AuditLog::from_json_lines(&text, FixedClock(0)),
            Err(ChainError {
                kind: ChainErrorKind::CorruptLine,
                index: 1,
                ..
            })
        ));
    }

    #[test]
    fn jsonl_roundtrip_preserves_records() {
        let log = log_two_events();
        assert_jsonl_roundtrip(&log);
    }

    #[test]
    fn tampered_jsonl_text_fails_to_load() {
        let log = log_two_events();
        let text = log.to_json_lines().replace("gate_denied", "gate_allowed");
        assert!(AuditLog::from_json_lines(&text, FixedClock(0)).is_err());
    }

    #[test]
    fn save_and_load_file_roundtrip() {
        let dir = std::env::temp_dir().join("pos_core_audit_test_r6");
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut log = AuditLog::with_clock(FixedClock(1000));
        log.append(AuditEvent::GateAllowed);
        log.append(AuditEvent::KeyRotated);
        log.save_to_file(&path).expect("append write");
        // Append-only: calling save again appends, never rewrites.
        log.save_to_file(&path).expect("second append");

        // The file now has each record twice; loading must fail because
        // seq continuity breaks at the repetition.
        assert!(AuditLog::load_from_file(&path, FixedClock(0)).is_err());
    }

    #[test]
    fn empty_chain_verifies() {
        verify_chain(&[]).expect("empty chain is valid");
    }

    #[test]
    fn hash_is_deterministic_and_event_sensitive() {
        let a = AuditRecord::compute_hash(1, 100, AuditEvent::GateAllowed, GENESIS_PREV_HASH);
        let b = AuditRecord::compute_hash(1, 100, AuditEvent::GateAllowed, GENESIS_PREV_HASH);
        let c = AuditRecord::compute_hash(1, 100, AuditEvent::GateDenied, GENESIS_PREV_HASH);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), HASH_LEN);
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn event_names_match_serde_names() {
        // The hash input uses event_json_name; the JSONL uses serde. They must agree.
        for e in [
            AuditEvent::GateAllowed,
            AuditEvent::GateDenied,
            AuditEvent::GateAudited,
            AuditEvent::KeyRotated,
            AuditEvent::RollbackDetected,
        ] {
            let j = serde_json::to_string(&e).unwrap();
            assert_eq!(j, format!("\"{}\"", event_json_name(e)));
        }
    }

    #[test]
    fn corrupt_line_index_ignores_blank_lines() {
        let mut log = AuditLog::with_clock(FixedClock(5));
        log.append(AuditEvent::GateAllowed);
        let good = log.to_json_lines();
        let text = format!("\n\n{good}\n\nnot json\n");
        let err = AuditLog::from_json_lines(&text, FixedClock(5)).unwrap_err();
        assert_eq!(err.kind, ChainErrorKind::CorruptLine);
        assert_eq!(err.index, 1);
    }

    #[test]
    fn chain_error_is_kept_as_io_error_source() {
        let e =
            AuditLog::from_json_lines_lines(["not json".to_string()].into_iter(), FixedClock(1))
                .unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(e
            .get_ref()
            .and_then(|s| s.downcast_ref::<ChainError>())
            .is_some());
    }

    #[test]
    fn load_from_file_fails_on_non_utf8_instead_of_truncating() {
        let dir = std::env::temp_dir().join(format!("pos-audit-io-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.jsonl");
        let mut log = AuditLog::with_clock(FixedClock(5));
        log.append(AuditEvent::GateAllowed);
        log.append(AuditEvent::GateDenied);
        let mut bytes = log.to_json_lines().into_bytes();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']); // invalid UTF-8 line after valid records
        std::fs::write(&f, bytes).unwrap();
        assert!(AuditLog::load_from_file(&f, FixedClock(5)).is_err());
    }
}
