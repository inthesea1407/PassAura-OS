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
