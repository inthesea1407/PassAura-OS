//! (Lives in pos-install tests to avoid a pos-core manifest change.) Additive audit pieces used by pos-install: new event kinds, planned
//! record, durable single-record append. Existing vectors are untouched
//! (see conformance_audit.rs).
use pos_core::audit::{
    append_planned_durable, plan_next_record, AppendOutcome, AuditEvent, AuditLog, AuditRecord,
    FixedClock, GENESIS_PREV_HASH,
};

#[test]
fn old_event_hashes_are_unchanged_and_new_events_use_snake_case_names() {
    // Same call the existing unit test uses for the first record shape.
    let h = AuditRecord::compute_hash(1, 100, AuditEvent::GateAllowed, GENESIS_PREV_HASH);
    assert_eq!(h.len(), 64);
    let canon = AuditRecord::canonical_bytes(1, 100, AuditEvent::GateAllowed, GENESIS_PREV_HASH);
    assert_eq!(
        canon,
        format!("1\n100\ngate_allowed\n{GENESIS_PREV_HASH}\n").into_bytes()
    );
    for (e, name) in [
        (AuditEvent::InstallHashMismatch, "install_hash_mismatch"),
        (AuditEvent::InstallFailed, "install_failed"),
        (AuditEvent::InstallCommitted, "install_committed"),
        (AuditEvent::InstallIndeterminate, "install_indeterminate"),
        (AuditEvent::InstallRetried, "install_retried"),
        (AuditEvent::InstallAbandoned, "install_abandoned"),
    ] {
        assert_eq!(serde_json::to_string(&e).unwrap(), format!("\"{name}\""));
        let c = AuditRecord::canonical_bytes(1, 5, e, GENESIS_PREV_HASH);
        assert_eq!(
            c,
            format!("1\n5\n{name}\n{GENESIS_PREV_HASH}\n").into_bytes()
        );
    }
}

#[test]
fn plan_and_append_builds_a_chain_that_verifies_and_appends_only() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    let r1 = plan_next_record(&p, 100, AuditEvent::InstallCommitted).unwrap();
    assert_eq!(r1.seq, 1);
    assert_eq!(
        append_planned_durable(&p, &r1).unwrap(),
        AppendOutcome::Written
    );
    // Same record again: already present, nothing appended.
    assert_eq!(
        append_planned_durable(&p, &r1).unwrap(),
        AppendOutcome::AlreadyPresent
    );
    let r2 = plan_next_record(&p, 50, AuditEvent::InstallFailed).unwrap();
    assert_eq!(
        r2.timestamp, 100,
        "timestamp is clamped, never goes backwards"
    );
    let before = std::fs::read(&p).unwrap();
    append_planned_durable(&p, &r2).unwrap();
    let after = std::fs::read(&p).unwrap();
    assert!(
        after.starts_with(&before),
        "existing bytes are never rewritten"
    );
    let log = AuditLog::load_from_file(&p, FixedClock(0)).unwrap();
    assert_eq!(log.records().len(), 2);
}

#[test]
fn a_stale_plan_is_refused_so_the_caller_can_replan() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    let stale = plan_next_record(&p, 10, AuditEvent::InstallCommitted).unwrap();
    let other = plan_next_record(&p, 11, AuditEvent::InstallFailed).unwrap();
    append_planned_durable(&p, &other).unwrap();
    let err = append_planned_durable(&p, &stale).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        AuditLog::load_from_file(&p, FixedClock(0))
            .unwrap()
            .records()
            .len(),
        1
    );
}

#[test]
fn a_tampered_log_is_not_extended() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    let r = plan_next_record(&p, 10, AuditEvent::InstallCommitted).unwrap();
    append_planned_durable(&p, &r).unwrap();
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("install_committed", "install_failed");
    std::fs::write(&p, text).unwrap();
    assert!(plan_next_record(&p, 11, AuditEvent::InstallFailed).is_err());
}
