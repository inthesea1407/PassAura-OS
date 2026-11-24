// Integration tests for pos-cli using assert_cmd + tempfile.
// Run: cargo test -p pos-cli
//
// Real Ed25519 flow: keygen, then sign an allowlist, then verify/install.
// Exit codes are documented in docs/CLI.md.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("pos-cli").expect("pos-cli binary builds")
}

fn write(dir: &TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let p = dir.path().join(name);
    fs::write(&p, contents).expect("write temp file");
    p
}


/// keygen + sign: returns (keyring path, signed allowlist path).
fn signed(dir: &TempDir, issued: u64, expires: u64, pkgs: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let keys = dir.path().join("keys");
    bin().args(["keygen", "--out", keys.to_str().unwrap()]).assert().code(0);
    let kr: serde_json::Value = serde_json::from_str(&fs::read_to_string(keys.join("keyring.json")).unwrap()).unwrap();
    let kid = kr["keys"][0]["key_id"].as_str().unwrap().to_string();
    let unsigned = write(dir, "unsigned.json", &format!(
        r#"{{"signed_by":"{kid}","signature_hex":"","issued_at":{issued},"expires_at":{expires},"packages":{pkgs}}}"#));
    let out = dir.path().join("allowlist.json");
    bin().args(["sign", unsigned.to_str().unwrap(), "--private-key", keys.join("private-key.json").to_str().unwrap(), "--out", out.to_str().unwrap()]).assert().code(0);
    (keys.join("keyring.json"), out)
}

// --- usage / exit 4 -------------------------------------------------------

#[test]
fn no_args_is_usage_error() {
    bin().assert().code(4);
}

#[test]
fn unknown_subcommand_is_usage_error() {
    bin().arg("frobnicate").assert().code(4);
}

#[test]
fn verify_missing_keyring_flag_is_usage_error() {
    bin().args(["verify", "allowlist.json"]).assert().code(4);
}

#[test]
fn install_missing_allowlist_flag_is_usage_error() {
    bin().args(["install", "ripgrep", "--dry-run"]).assert().code(4);
}

#[test]
fn help_exits_zero() {
    // clap prints help and exits 0; our main() returns 4 for try_parse errors,
    // so this test pins the intended behavior. If clap's help path returns Err
    // with use_stderr()=false, we must special-case it in main(). This test
    // documents the requirement.
    bin().arg("--help").assert().code(0);
}

// --- verify: happy path ---------------------------------------------------

#[test]
fn verify_ok_with_valid_signature() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, "[]");
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ok"));
}

#[test]
fn verify_fake_signature_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, _) = signed(&dir, 0, 9999999999, "[]");
    let kid = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&keyring).unwrap()).unwrap()["keys"][0]["key_id"].as_str().unwrap().to_string();
    let bad = write(&dir, "bad.json", &format!(r#"{{"signed_by":"{kid}","signature_hex":"00","issued_at":0,"expires_at":9999999999,"packages":[]}}"#));
    bin()
        .args(["verify", bad.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2);
}

#[test]
fn verify_tampered_allowlist_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, r#"[{"name":"ripgrep","version":"14"}]"#);
    let t = fs::read_to_string(&allowlist).unwrap().replace("ripgrep", "bitwarden");
    fs::write(&allowlist, t).unwrap();
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2);
}

// --- verify: bad JSON -----------------------------------------------------

#[test]
fn verify_bad_keyring_json_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let keyring = write(&dir, "keyring.json", "{not json");
    let allowlist = write(&dir, "allowlist.json", "{}");
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid keyring"));
}

#[test]
fn verify_bad_allowlist_json_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let keyring = write(&dir, "keyring.json", r#"{"keys":[]}"#);
    let allowlist = write(&dir, "allowlist.json", "{not json");
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid allowlist"));
}

// --- verify: missing file -------------------------------------------------

#[test]
fn verify_missing_allowlist_file_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let keyring = write(&dir, "keyring.json", "{}");
    bin()
        .args(["verify", "/nonexistent/allowlist.json", "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read"));
}

#[test]
fn verify_missing_keyring_file_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let allowlist = write(&dir, "allowlist.json", "{}");
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", "/nonexistent/keyring.json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read"));
}

// --- verify: expired allowlist -------------------------------------------

#[test]
fn verify_expired_allowlist_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 1, "[]");
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("verification failed"));
}

// --- install: allowed / not allowed --------------------------------------

const RG: &str = r#"[{"name":"ripgrep","version":"14.1.0"}]"#;

#[test]
fn install_allowed_dry_run_is_exit_0() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, RG);
    bin()
        .args(["install", "ripgrep", "--allowlist", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap(), "--dry-run"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("dry-run: would install ripgrep"));
}

#[test]
fn install_not_allowed_is_exit_3() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, RG);
    bin()
        .args(["install", "curl", "--allowlist", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap(), "--dry-run"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not allowed"));
}

#[test]
fn install_with_unverified_allowlist_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, RG);
    let t = fs::read_to_string(&allowlist).unwrap().replace("ripgrep", "bitwarden");
    fs::write(&allowlist, t).unwrap();
    bin()
        .args(["install", "bitwarden", "--allowlist", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap(), "--dry-run"])
        .assert()
        .code(2);
}

#[test]
fn install_bad_allowlist_json_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let allowlist = write(&dir, "allowlist.json", "not json at all");
    let keyring = write(&dir, "keyring.json", "{}");
    bin()
        .args(["install", "ripgrep", "--allowlist", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap(), "--dry-run"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid allowlist"));
}

#[test]
fn install_missing_allowlist_file_is_exit_2() {
    bin()
        .args(["install", "ripgrep", "--allowlist", "/nonexistent/allowlist.json", "--keyring", "/nonexistent/k.json", "--dry-run"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read"));
}

// --- keygen ---------------------------------------------------------------

#[test]
fn keygen_writes_keyring_and_private_key() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("keys");
    bin()
        .args(["keygen", "--out", out.to_str().unwrap()])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("keyring.json"));

    let keyring = fs::read_to_string(out.join("keyring.json")).expect("keyring written");
    let private = fs::read_to_string(out.join("private-key.json")).expect("private key written");
    assert!(keyring.contains("keys"));
    assert!(private.contains("private_key_hex"));
    assert!(private.contains("KEEP THIS FILE SECRET"));
}

#[test]
fn keygen_creates_missing_directory() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("nested").join("keys");
    bin()
        .args(["keygen", "--out", out.to_str().unwrap()])
        .assert()
        .code(0);
    assert!(out.join("keyring.json").exists());
}

// --- malformed input does not panic --------------------------------------

#[test]
fn verify_empty_files_do_not_panic() {
    let dir = TempDir::new().unwrap();
    let keyring = write(&dir, "keyring.json", "");
    let allowlist = write(&dir, "allowlist.json", "");
    // Must exit 2, not abort. A panic would show up as code 101 or a signal.
    bin()
        .args(["verify", allowlist.to_str().unwrap(), "--keyring", keyring.to_str().unwrap()])
        .assert()
        .code(2);
}

#[test]
fn install_binary_garbage_does_not_panic() {
    let dir = TempDir::new().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    fs::write(&allowlist, [0xff, 0xfe, 0x00, 0x01]).unwrap();
    bin()
        .args(["install", "x", "--allowlist", allowlist.to_str().unwrap(), "--keyring", allowlist.to_str().unwrap(), "--dry-run"])
        .assert()
        .code(2);
}

#[test]
fn audit_verify_and_tamper() {
    use pos_core::audit::{AuditEvent, AuditLog, FixedClock};
    let dir = std::env::temp_dir().join(format!("pos-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("a.jsonl");
    let mut log = AuditLog::with_clock(FixedClock(100));
    log.append(AuditEvent::GateAllowed);
    log.append(AuditEvent::GateDenied);
    log.save_to_file(&f).unwrap();
    let bin = || assert_cmd::Command::cargo_bin("pos-cli").unwrap();
    bin().args(["audit", "verify"]).arg(&f).assert().code(0);
    bin().args(["audit", "tail", "-n", "1"]).arg(&f).assert().code(0);
    let t = std::fs::read_to_string(&f).unwrap().replace("gate_denied", "gate_allowed");
    std::fs::write(&f, t).unwrap();
    bin().args(["audit", "verify"]).arg(&f).assert().code(2);
    bin().args(["audit", "verify"]).arg(dir.join("missing")).assert().code(3);
}

// --- v2 allowlists (rotation format) --------------------------------------

fn v2_doc(dir: &TempDir, seed: u8, trusted_seed: u8, seq: u64) -> (std::path::PathBuf, std::path::PathBuf) {
    use ed25519_dalek::{Signer, SigningKey};
    use pos_gate::allowlist_v2::*;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let id = derive_key_id(&pk);
    let mut d = V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence: seq,
        issued_at: now - 100,
        expires_at: now + 86400,
        signed_by: id.clone(),
        keyring: V2Keyring { keys: vec![V2Key { key_id: id, public_key_hex: pk, valid_from: 0, valid_until: now + 86400, retired: false }] },
        entries: vec![V2Entry { name: "ripgrep".into(), version: None, sha256: "a".repeat(64) }],
        signature_hex: String::new(),
    };
    d.signature_hex = hex::encode(sk.sign(&canonical_payload_bytes(&d).unwrap()).to_bytes());
    let tsk = SigningKey::from_bytes(&[trusted_seed; 32]);
    let tpk = hex::encode(tsk.verifying_key().to_bytes());
    let kr = format!(r#"{{"keys":[{{"key_id":"{}","public_key_hex":"{}"}}]}}"#, derive_key_id(&tpk), tpk);
    (write(dir, "v2.json", &serde_json::to_string(&d).unwrap()), write(dir, "kr2.json", &kr))
}

#[test]
fn v2_verify_install_and_rollback() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = v2_doc(&dir, 5, 5, 3);
    bin().args(["verify", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()]).assert().code(0);
    let state = dir.path().join("state.json");
    let a = |c: &str| vec![c.to_string(), "ripgrep".into(), "--allowlist".into(), al.to_str().unwrap().into(), "--keyring".into(), kr.to_str().unwrap().into(), "--state".into(), state.to_str().unwrap().into()];
    bin().args(a("install")).assert().code(0);
    // older sequence is rejected after the state was recorded
    let (al2, _) = v2_doc(&dir, 5, 5, 2);
    bin().args(["verify", al2.to_str().unwrap(), "--keyring", kr.to_str().unwrap(), "--state", state.to_str().unwrap()]).assert().code(2);
    // package not in allowlist
    bin().args(["install", "nmap", "--dry-run", "--allowlist", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()]).assert().code(3);
}

#[test]
fn v2_self_signed_document_is_rejected_when_signer_not_trusted() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = v2_doc(&dir, 5, 6, 1); // signed by key 5, trusted ring holds key 6
    bin().args(["verify", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()]).assert().code(2);
    bin().args(["install", "ripgrep", "--allowlist", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()]).assert().code(2);
}

#[test]
fn keygen_refuses_to_overwrite_existing_keys() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("k");
    bin().args(["keygen", "--out", out.to_str().unwrap()]).assert().code(0);
    let before = fs::read_to_string(out.join("private-key.json")).unwrap();
    bin().args(["keygen", "--out", out.to_str().unwrap()]).assert().code(2);
    assert_eq!(before, fs::read_to_string(out.join("private-key.json")).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(out.join("private-key.json")).unwrap().permissions().mode();
        assert_eq!(m & 0o077, 0, "private key must not be group/world accessible");
    }
}

#[test]
fn v2_real_install_requires_state() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = v2_doc(&dir, 5, 5, 3);
    bin().args(["install", "ripgrep", "--allowlist", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()]).assert().code(4);
    bin().args(["install", "ripgrep", "--dry-run", "--allowlist", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()]).assert().code(0);
}

// --- extra pinning tests (round 15) ---------------------------------------

#[test]
fn install_rejects_bad_package_identifiers_with_exit_4() {
    let dir = TempDir::new().unwrap();
    let (kr, al) = signed(&dir, 1, 4_000_000_000, r#"[{"name":"ripgrep","version":"14"}]"#);
    for bad in ["", "-evil", "a/b", "a b", "a;b", "$(x)", "a\\b"] {
        bin()
            .args(["install", bad, "--dry-run", "--allowlist", al.to_str().unwrap(), "--keyring", kr.to_str().unwrap()])
            .assert()
            .code(4);
    }
}

#[test]
fn v1_allowlist_checked_against_a_different_keyring_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (_kr, al) = signed(&dir, 1, 4_000_000_000, r#"[{"name":"ripgrep","version":"14"}]"#);
    let other = dir.path().join("other");
    bin().args(["keygen", "--out", other.to_str().unwrap()]).assert().code(0);
    bin()
        .args(["verify", al.to_str().unwrap(), "--keyring", other.join("keyring.json").to_str().unwrap()])
        .assert()
        .code(2);
}

#[test]
fn audit_tamper_really_changes_file_and_tail_prints_last_record() {
    use pos_core::audit::{AuditEvent, AuditLog, FixedClock};
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("a.jsonl");
    let mut log = AuditLog::with_clock(FixedClock(100));
    log.append(AuditEvent::GateAllowed);
    log.append(AuditEvent::GateDenied);
    log.save_to_file(&f).unwrap();
    bin().args(["audit", "tail", "-n", "1"]).arg(&f).assert().code(0)
        .stdout(predicate::str::contains("GateDenied"))
        .stdout(predicate::str::contains("GateAllowed").not());
    let before = fs::read_to_string(&f).unwrap();
    let after = before.replace("gate_denied", "gate_allowed");
    assert_ne!(before, after, "tamper must change the file");
    fs::write(&f, after).unwrap();
    bin().args(["audit", "verify"]).arg(&f).assert().code(2);
}
