//! Conformance vectors for the audit chain, generated from the real code.
//! Committed file: tests/vectors/audit_chain.json.
//! Regenerate with: UPDATE_VECTORS=1 cargo test -p pos-core --test conformance_audit

use pos_core::audit::{verify_chain, AuditEvent, AuditLog, AuditRecord, FixedClock};
use serde_json::{json, Value};

fn log() -> Vec<AuditRecord> {
    let mut l = AuditLog::with_clock(FixedClock(1000));
    l.append(AuditEvent::GateAllowed);
    l.append(AuditEvent::GateDenied);
    l.append(AuditEvent::KeyRotated);
    l.records().to_vec()
}

fn verdict(r: &[AuditRecord]) -> String {
    match verify_chain(r) {
        Ok(()) => "ok".into(),
        Err(e) => format!("{:?}", e.kind),
    }
}

fn case(name: &str, r: Vec<AuditRecord>) -> Value {
    json!({ "name": name, "records": r, "expect": verdict(&r) })
}

fn build() -> Value {
    let base = log();
    let mut cases = vec![case("valid", base.clone())];
    cases.push(case("empty", vec![]));
    let mut t = base.clone();
    t[1].event = AuditEvent::GateAllowed;
    cases.push(case("event_tampered", t));
    let mut t = base.clone();
    t[1].timestamp += 1;
    cases.push(case("timestamp_tampered", t));
    let mut t = base.clone();
    t.remove(1);
    cases.push(case("middle_record_removed", t));
    let mut t = base.clone();
    t.swap(1, 2);
    cases.push(case("records_reordered", t));
    let mut t = base.clone();
    t[2].prev_hash = "0".repeat(64);
    cases.push(case("prev_hash_wrong", t));
    let t = base[1..].to_vec();
    cases.push(case("first_record_removed", t));
    let t = base[..2].to_vec();
    cases.push(case("tail_truncated_undetectable", t));
    json!({
        "description": "Audit hash chain vectors from the Rust implementation; not independently verified. Truncating the newest records is NOT detected without an external anchor.",
        "hash": "hex(SHA-256(\"{seq}\\n{timestamp}\\n{event}\\n{prev_hash}\\n\")); seq starts at 1",
        "cases": cases,
    })
}

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/audit_chain.json"
);

#[test]
fn vectors_match_committed_file_and_implementation() {
    let text = serde_json::to_string_pretty(&build()).unwrap() + "\n";
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(PATH, &text).unwrap();
    }
    let committed = std::fs::read_to_string(PATH).expect("run with UPDATE_VECTORS=1");
    assert_eq!(committed, text, "vector file out of date");
    let parsed: Value = serde_json::from_str(&committed).unwrap();
    for c in parsed["cases"].as_array().unwrap() {
        let r: Vec<AuditRecord> = serde_json::from_value(c["records"].clone()).unwrap();
        assert_eq!(
            verdict(&r),
            c["expect"].as_str().unwrap(),
            "case {}",
            c["name"]
        );
    }
    let exp = |n: &str| {
        parsed["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == n)
            .unwrap()["expect"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(exp("valid"), "ok");
    assert_eq!(exp("event_tampered"), "HashMismatch");
    assert_ne!(exp("middle_record_removed"), "ok");
    assert_eq!(exp("tail_truncated_undetectable"), "ok");
}
