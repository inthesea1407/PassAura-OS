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

/// keygen + sign: returns (keyring path, signed v2 allowlist path).
/// `pkgs` is a JSON array of {name, version}; each becomes a v2 entry.
fn signed(
    dir: &TempDir,
    issued: u64,
    expires: u64,
    pkgs: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    signed_sha(dir, issued, expires, pkgs, &"a".repeat(64))
}

fn signed_sha(
    dir: &TempDir,
    issued: u64,
    expires: u64,
    pkgs: &str,
    sha: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let keys = dir.path().join("keys");
    bin()
        .args(["keygen", "--out", keys.to_str().unwrap()])
        .assert()
        .code(0);
    let kr: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(keys.join("keyring.json")).unwrap()).unwrap();
    let kid = kr["keys"][0]["key_id"].as_str().unwrap().to_string();
    let pk = kr["keys"][0]["public_key_hex"]
        .as_str()
        .unwrap()
        .to_string();
    let list: Vec<serde_json::Value> = serde_json::from_str(pkgs).unwrap();
    let entries: Vec<serde_json::Value> = list
        .iter()
        .map(|e| serde_json::json!({"name": e["name"], "version": e["version"], "sha256": sha}))
        .collect();
    let doc = serde_json::json!({
        "format": "passaura-allowlist", "version": 2, "sequence": 1,
        "issued_at": issued, "expires_at": expires, "signed_by": kid,
        "keyring": {"keys": [{"key_id": kid, "public_key_hex": pk, "valid_from": 0, "valid_until": expires, "retired": false}]},
        "entries": entries, "signature_hex": ""
    });
    let unsigned = write(dir, "unsigned.json", &doc.to_string());
    let out = dir.path().join("allowlist.json");
    bin()
        .args([
            "sign",
            unsigned.to_str().unwrap(),
            "--private-key",
            keys.join("private-key.json").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(0);
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
    bin()
        .args(["install", "ripgrep", "--dry-run"])
        .assert()
        .code(4);
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
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("ok"));
}

#[test]
fn verify_fake_signature_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, _) = signed(&dir, 0, 9999999999, "[]");
    let kid = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&keyring).unwrap())
        .unwrap()["keys"][0]["key_id"]
        .as_str()
        .unwrap()
        .to_string();
    let bad = write(
        &dir,
        "bad.json",
        &format!(
            r#"{{"format":"passaura-allowlist","version":2,"sequence":1,"issued_at":0,"expires_at":9999999999,"signed_by":"{kid}","keyring":{{"keys":[]}},"entries":[],"signature_hex":"00"}}"#
        ),
    );
    bin()
        .args([
            "verify",
            bad.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}

#[test]
fn verify_tampered_allowlist_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(
        &dir,
        0,
        9999999999,
        r#"[{"name":"ripgrep","version":"14"}]"#,
    );
    let t = fs::read_to_string(&allowlist)
        .unwrap()
        .replace("ripgrep", "bitwarden");
    fs::write(&allowlist, t).unwrap();
    bin()
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
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
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
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
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
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
        .args([
            "verify",
            "/nonexistent/allowlist.json",
            "--keyring",
            keyring.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot read"));
}

#[test]
fn verify_missing_keyring_file_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let allowlist = write(&dir, "allowlist.json", "{}");
    bin()
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            "/nonexistent/keyring.json",
        ])
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
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
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
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("dry-run: would install ripgrep"));
}

#[test]
fn install_not_allowed_is_exit_3() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, RG);
    bin()
        .args([
            "install",
            "curl",
            "--allowlist",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not allowed"));
}

#[test]
fn install_with_unverified_allowlist_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (keyring, allowlist) = signed(&dir, 0, 9999999999, RG);
    let t = fs::read_to_string(&allowlist)
        .unwrap()
        .replace("ripgrep", "bitwarden");
    fs::write(&allowlist, t).unwrap();
    bin()
        .args([
            "install",
            "bitwarden",
            "--allowlist",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(2);
}

#[test]
fn install_bad_allowlist_json_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let allowlist = write(&dir, "allowlist.json", "not json at all");
    let keyring = write(&dir, "keyring.json", "{}");
    bin()
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid allowlist"));
}

#[test]
fn install_missing_allowlist_file_is_exit_2() {
    bin()
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            "/nonexistent/allowlist.json",
            "--keyring",
            "/nonexistent/k.json",
            "--dry-run",
        ])
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
        .args([
            "verify",
            allowlist.to_str().unwrap(),
            "--keyring",
            keyring.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}

#[test]
fn install_binary_garbage_does_not_panic() {
    let dir = TempDir::new().unwrap();
    let allowlist = dir.path().join("allowlist.json");
    fs::write(&allowlist, [0xff, 0xfe, 0x00, 0x01]).unwrap();
    bin()
        .args([
            "install",
            "x",
            "--allowlist",
            allowlist.to_str().unwrap(),
            "--keyring",
            allowlist.to_str().unwrap(),
            "--dry-run",
        ])
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
    bin()
        .args(["audit", "tail", "-n", "1"])
        .arg(&f)
        .assert()
        .code(0);
    let t = std::fs::read_to_string(&f)
        .unwrap()
        .replace("gate_denied", "gate_allowed");
    std::fs::write(&f, t).unwrap();
    bin().args(["audit", "verify"]).arg(&f).assert().code(2);
    bin()
        .args(["audit", "verify"])
        .arg(dir.join("missing"))
        .assert()
        .code(3);
}

// --- v2 allowlists (rotation format) --------------------------------------

fn v2_doc(
    dir: &TempDir,
    seed: u8,
    trusted_seed: u8,
    seq: u64,
) -> (std::path::PathBuf, std::path::PathBuf) {
    use ed25519_dalek::{Signer, SigningKey};
    use pos_gate::allowlist_v2::*;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
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
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id: id,
                public_key_hex: pk,
                valid_from: 0,
                valid_until: now + 86400,
                retired: false,
            }],
        },
        entries: vec![V2Entry {
            name: "ripgrep".into(),
            version: None,
            sha256: "a".repeat(64),
        }],
        signature_hex: String::new(),
    };
    d.signature_hex = hex::encode(sk.sign(&canonical_payload_bytes(&d).unwrap()).to_bytes());
    let tsk = SigningKey::from_bytes(&[trusted_seed; 32]);
    let tpk = hex::encode(tsk.verifying_key().to_bytes());
    let kr = format!(
        r#"{{"keys":[{{"key_id":"{}","public_key_hex":"{}"}}]}}"#,
        derive_key_id(&tpk),
        tpk
    );
    (
        write(dir, "v2.json", &serde_json::to_string(&d).unwrap()),
        write(dir, "kr2.json", &kr),
    )
}

#[test]
fn v2_verify_install_and_rollback() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = v2_doc(&dir, 5, 5, 3);
    bin()
        .args([
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(0);
    let state = dir.path().join("state.json");
    let a = |c: &str| {
        vec![
            c.to_string(),
            "ripgrep".into(),
            "--allowlist".into(),
            al.to_str().unwrap().into(),
            "--keyring".into(),
            kr.to_str().unwrap().into(),
            "--state".into(),
            state.to_str().unwrap().into(),
        ]
    };
    bin().args(a("install")).assert().code(0);
    // older sequence is rejected after the state was recorded
    let (al2, _) = v2_doc(&dir, 5, 5, 2);
    bin()
        .args([
            "verify",
            al2.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    // package not in allowlist
    bin()
        .args([
            "install",
            "nmap",
            "--dry-run",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(3);
}

#[test]
fn v2_self_signed_document_is_rejected_when_signer_not_trusted() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = v2_doc(&dir, 5, 6, 1); // signed by key 5, trusted ring holds key 6
    bin()
        .args([
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    bin()
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}

#[test]
fn keygen_refuses_to_overwrite_existing_keys() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("k");
    bin()
        .args(["keygen", "--out", out.to_str().unwrap()])
        .assert()
        .code(0);
    let before = fs::read_to_string(out.join("private-key.json")).unwrap();
    bin()
        .args(["keygen", "--out", out.to_str().unwrap()])
        .assert()
        .code(2);
    assert_eq!(
        before,
        fs::read_to_string(out.join("private-key.json")).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = fs::metadata(out.join("private-key.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            m & 0o077,
            0,
            "private key must not be group/world accessible"
        );
    }
}

#[test]
fn v2_real_install_requires_state() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = v2_doc(&dir, 5, 5, 3);
    bin()
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(4);
    bin()
        .args([
            "install",
            "ripgrep",
            "--dry-run",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(0);
}

// --- extra pinning tests (round 15) ---------------------------------------

#[test]
fn install_rejects_bad_package_identifiers_with_exit_4() {
    let dir = TempDir::new().unwrap();
    let (kr, al) = signed(
        &dir,
        1,
        4_000_000_000,
        r#"[{"name":"ripgrep","version":"14"}]"#,
    );
    for bad in ["", "-evil", "a/b", "a b", "a;b", "$(x)", "a\\b"] {
        bin()
            .args([
                "install",
                bad,
                "--dry-run",
                "--allowlist",
                al.to_str().unwrap(),
                "--keyring",
                kr.to_str().unwrap(),
            ])
            .assert()
            .code(4);
    }
}

#[test]
fn allowlist_checked_against_a_different_keyring_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (_kr, al) = signed(
        &dir,
        1,
        4_000_000_000,
        r#"[{"name":"ripgrep","version":"14"}]"#,
    );
    let other = dir.path().join("other");
    bin()
        .args(["keygen", "--out", other.to_str().unwrap()])
        .assert()
        .code(0);
    bin()
        .args([
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            other.join("keyring.json").to_str().unwrap(),
        ])
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
    bin()
        .args(["audit", "tail", "-n", "1"])
        .arg(&f)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("GateDenied"))
        .stdout(predicate::str::contains("GateAllowed").not());
    let before = fs::read_to_string(&f).unwrap();
    let after = before.replace("gate_denied", "gate_allowed");
    assert_ne!(before, after, "tamper must change the file");
    fs::write(&f, after).unwrap();
    bin().args(["audit", "verify"]).arg(&f).assert().code(2);
}

// --- legacy text-v1: runtime rejection and offline migration ---------------

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Writes a signed legacy text-v1 file using the library (the CLI cannot sign v1 any more).
fn legacy_v1(dir: &TempDir, expires: u64) -> (std::path::PathBuf, std::path::PathBuf) {
    use ed25519_dalek::SigningKey;
    use pos_gate::allowlist::{AllowlistDoc, PackageEntry};
    let sk = SigningKey::from_bytes(&[21u8; 32]);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let kid = pos_gate::allowlist_v2::derive_key_id(&pk);
    let mut d = AllowlistDoc {
        signed_by: kid.clone(),
        signature_hex: String::new(),
        issued_at: 1,
        expires_at: expires,
        packages: vec![PackageEntry {
            name: "ripgrep".into(),
            version: "14".into(),
        }],
    };
    d.sign(&sk);
    let kr = format!(r#"{{"keys":[{{"key_id":"{kid}","public_key_hex":"{pk}"}}]}}"#);
    (
        write(dir, "legacy.json", &serde_json::to_string(&d).unwrap()),
        write(dir, "legacy-kr.json", &kr),
    )
}

#[test]
fn legacy_v1_is_rejected_at_runtime_by_verify_and_install() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = legacy_v1(&dir, 4_000_000_000);
    bin()
        .args([
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    bin()
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .code(2);
}

#[test]
fn unknown_or_json_v1_versions_are_rejected_at_runtime() {
    let dir = TempDir::new().unwrap();
    let (_al, kr) = legacy_v1(&dir, 4_000_000_000);
    for (i, body) in [
        r#"{"version":3}"#,
        r#"{"version":1,"issued_at":1,"expires_at":9,"key_id":"k","entries":[],"signature":"00"}"#,
    ]
    .iter()
    .enumerate()
    {
        let f = write(&dir, &format!("odd{i}.json"), body);
        bin()
            .args([
                "verify",
                f.to_str().unwrap(),
                "--keyring",
                kr.to_str().unwrap(),
            ])
            .assert()
            .code(2);
    }
}

#[test]
fn migrate_produces_unsigned_v2_that_fails_until_signed() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = legacy_v1(&dir, 4_000_000_000);
    let map = write(&dir, "map.json", &format!(r#"{{"ripgrep@14":"{HASH}"}}"#));
    let out = dir.path().join("migrated.json");
    bin()
        .args([
            "allowlist-migrate",
            "--from-v1",
            al.to_str().unwrap(),
            "--trusted-key",
            kr.to_str().unwrap(),
            "--sha256-map",
            map.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("UNSIGNED"));
    let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(v["version"], 2);
    assert_eq!(v["sequence"], 0);
    assert_eq!(v["signature_hex"], "");
    // Unsigned: verify must fail.
    bin()
        .args([
            "verify",
            out.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    // No overwrite.
    bin()
        .args([
            "allowlist-migrate",
            "--from-v1",
            al.to_str().unwrap(),
            "--trusted-key",
            kr.to_str().unwrap(),
            "--sha256-map",
            map.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn migrate_fails_when_a_hash_is_missing_and_lists_it() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = legacy_v1(&dir, 4_000_000_000);
    let map = write(&dir, "map.json", "{}");
    let out = dir.path().join("migrated.json");
    bin()
        .args([
            "allowlist-migrate",
            "--from-v1",
            al.to_str().unwrap(),
            "--trusted-key",
            kr.to_str().unwrap(),
            "--sha256-map",
            map.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("ripgrep@14"));
    assert!(!out.exists(), "no partial output");
}

#[test]
fn migrate_requires_sha256_map_flag_and_trusted_key() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = legacy_v1(&dir, 4_000_000_000);
    let out = dir.path().join("m.json");
    bin()
        .args([
            "allowlist-migrate",
            "--from-v1",
            al.to_str().unwrap(),
            "--trusted-key",
            kr.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(4);
    // A keyring that does not hold the signer is rejected (the document's own data is never trusted).
    let other = dir.path().join("other");
    bin()
        .args(["keygen", "--out", other.to_str().unwrap()])
        .assert()
        .code(0);
    let map = write(&dir, "map.json", &format!(r#"{{"ripgrep@14":"{HASH}"}}"#));
    bin()
        .args([
            "allowlist-migrate",
            "--from-v1",
            al.to_str().unwrap(),
            "--trusted-key",
            other.join("keyring.json").to_str().unwrap(),
            "--sha256-map",
            map.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    assert!(!out.exists());
}

#[test]
fn sign_refuses_a_key_that_does_not_match_signed_by_and_does_not_overwrite() {
    let dir = TempDir::new().unwrap();
    let (kr, al) = signed(
        &dir,
        1,
        4_000_000_000,
        r#"[{"name":"ripgrep","version":"14"}]"#,
    );
    let _ = kr;
    let other = dir.path().join("other");
    bin()
        .args(["keygen", "--out", other.to_str().unwrap()])
        .assert()
        .code(0);
    let out = dir.path().join("resigned.json");
    bin()
        .args([
            "sign",
            al.to_str().unwrap(),
            "--private-key",
            other.join("private-key.json").to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    assert!(!out.exists());
    // Existing output is not overwritten.
    let keys = dir.path().join("keys");
    bin()
        .args([
            "sign",
            al.to_str().unwrap(),
            "--private-key",
            keys.join("private-key.json").to_str().unwrap(),
            "--out",
            al.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}
// The refused locations are Linux system paths; Windows resolves
// them under the current drive and fails differently, so unix only.
#[cfg(unix)]
#[test]
fn migrate_refuses_installed_allowlist_locations_even_if_the_file_does_not_exist() {
    let dir = TempDir::new().unwrap();
    let (al, kr) = legacy_v1(&dir, 4_000_000_000);
    let map = write(&dir, "map.json", &format!(r#"{{"ripgrep@14":"{HASH}"}}"#));
    for out in [
        "/etc/passaura/allowlist.json",
        "/var/lib/passaura/allowlist.json",
        "/usr/share/passaura/allowlist.json",
        "/tmp/zz/../../etc/passaura/allowlist.json",
    ] {
        bin()
            .args([
                "allowlist-migrate",
                "--from-v1",
                al.to_str().unwrap(),
                "--trusted-key",
                kr.to_str().unwrap(),
                "--sha256-map",
                map.to_str().unwrap(),
                "--out",
                out,
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("protected"));
        assert!(
            !std::path::Path::new(out).exists(),
            "{out} must not have been created"
        );
    }
    // The input file itself is never a valid output.
    bin()
        .args([
            "allowlist-migrate",
            "--from-v1",
            al.to_str().unwrap(),
            "--trusted-key",
            kr.to_str().unwrap(),
            "--sha256-map",
            map.to_str().unwrap(),
            "--out",
            al.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}

/// Self-signed v2 document whose own keyring vouches for itself.
fn self_signed_v2(dir: &TempDir, seed: u8) -> std::path::PathBuf {
    use ed25519_dalek::{Signer, SigningKey};
    use pos_gate::allowlist_v2::*;
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let id = derive_key_id(&pk);
    let mut d = V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence: 1,
        issued_at: 1,
        expires_at: 4_000_000_000,
        signed_by: id.clone(),
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id: id,
                public_key_hex: pk,
                valid_from: 0,
                valid_until: 4_000_000_000,
                retired: false,
            }],
        },
        entries: vec![V2Entry {
            name: "ripgrep".into(),
            version: None,
            sha256: "a".repeat(64),
        }],
        signature_hex: String::new(),
    };
    d.signature_hex = hex::encode(sk.sign(&canonical_payload_bytes(&d).unwrap()).to_bytes());
    write(dir, "selfsigned.json", &serde_json::to_string(&d).unwrap())
}

#[test]
fn a_documents_own_keyring_cannot_establish_trust_in_verify_or_install() {
    let dir = TempDir::new().unwrap();
    let al = self_signed_v2(&dir, 31);
    // (a) trusted keyring is empty.
    let empty = write(&dir, "empty.json", r#"{"keys":[]}"#);
    for args in [
        vec![
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            empty.to_str().unwrap(),
        ],
        vec![
            "install",
            "ripgrep",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            empty.to_str().unwrap(),
            "--dry-run",
        ],
    ] {
        bin()
            .args(&args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("not in the trusted keyring"));
    }
    // (b) trusted keyring has the same key_id but a different public key.
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&al).unwrap()).unwrap();
    let kid = doc["signed_by"].as_str().unwrap();
    let other_pk = "bb".repeat(32);
    let spoof = write(
        &dir,
        "spoof.json",
        &format!(r#"{{"keys":[{{"key_id":"{kid}","public_key_hex":"{other_pk}"}}]}}"#),
    );
    bin()
        .args([
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            spoof.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    // (c) a keyring that really holds the key accepts it, so the failures above are about trust, not the document.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let good = write(
        &dir,
        "good.json",
        &format!(r#"{{"keys":[{{"key_id":"{kid}","public_key_hex":"{pk}"}}]}}"#),
    );
    bin()
        .args([
            "verify",
            al.to_str().unwrap(),
            "--keyring",
            good.to_str().unwrap(),
        ])
        .assert()
        .code(0);
}

// --- exact-file install and recovery (SAFE paths only) --------------------
// No test here may reach the real runner: every case below fails or finishes
// before any command is built (dry-run, usage errors, nothing to recover,
// lock held). Install/retry/abandon flows run with a fake runner in
// src/main.rs unit tests.

const DEB: &[u8] = b"pretend this is a .deb";

fn deb_sha() -> String {
    // sha256 of DEB computed with the system tool-free path: use the CLI-independent
    // sha2 crate.
    use sha2::{Digest, Sha256};
    hex_lower(&Sha256::digest(DEB))
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn pkg_setup(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let (kr, al) = signed_sha(
        dir,
        1,
        4_000_000_000,
        r#"[{"name":"ripgrep","version":"14"}]"#,
        &deb_sha(),
    );
    let deb = write(dir, "p.deb", std::str::from_utf8(DEB).unwrap());
    (kr, al, deb)
}

#[test]
fn package_file_dry_run_checks_hash_and_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let (kr, al, deb) = pkg_setup(&dir);
    let state = dir.path().join("state.json");
    let audit = dir.path().join("audit.log");
    bin()
        .args([
            "install",
            "ripgrep",
            "--dry-run",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--package-file",
            deb.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("nothing was written"));
    for n in [
        "state.json",
        "audit.log",
        "state.json.lock",
        "state.json.install-journal",
        "state.json.stage",
    ] {
        assert!(
            !dir.path().join(n).exists(),
            "{n} must not be created by dry-run"
        );
    }
}

#[test]
fn package_file_dry_run_hash_mismatch_is_exit_2() {
    let dir = TempDir::new().unwrap();
    let (kr, al, deb) = pkg_setup(&dir);
    fs::write(&deb, b"tampered").unwrap();
    bin()
        .args([
            "install",
            "ripgrep",
            "--dry-run",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--package-file",
            deb.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("mismatch"));
}

#[test]
fn package_file_dry_run_not_allowed_is_exit_3() {
    let dir = TempDir::new().unwrap();
    let (kr, al, deb) = pkg_setup(&dir);
    bin()
        .args([
            "install",
            "nmap",
            "--dry-run",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--package-file",
            deb.to_str().unwrap(),
        ])
        .assert()
        .code(3);
}

#[test]
fn recover_flag_has_no_default_and_needs_state_and_audit() {
    let dir = TempDir::new().unwrap();
    let (kr, al, _deb) = pkg_setup(&dir);
    let base = |extra: &[&str]| {
        let mut v = vec![
            "install",
            "ripgrep",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
        ];
        v.extend_from_slice(extra);
        v.into_iter().map(String::from).collect::<Vec<_>>()
    };
    bin().args(base(&["--recover"])).assert().code(4);
    bin().args(base(&["--recover", "maybe"])).assert().code(4);
    bin().args(base(&["--recover", "abandon"])).assert().code(4);
    bin()
        .args(base(&[
            "--recover",
            "retry",
            "--state",
            dir.path().join("s.json").to_str().unwrap(),
        ]))
        .assert()
        .code(4);
    // A real package-file install also needs both paths.
    bin()
        .args(base(&[
            "--package-file",
            dir.path().join("p.deb").to_str().unwrap(),
        ]))
        .assert()
        .code(4);
    assert!(!dir.path().join("s.json").exists());
}

#[test]
fn recover_without_a_journal_is_exit_2_and_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let (kr, al, _deb) = pkg_setup(&dir);
    let state = dir.path().join("state.json");
    let audit = dir.path().join("audit.log");
    for mode in ["retry", "abandon"] {
        bin()
            .args([
                "install",
                "ripgrep",
                "--allowlist",
                al.to_str().unwrap(),
                "--keyring",
                kr.to_str().unwrap(),
                "--state",
                state.to_str().unwrap(),
                "--audit-log",
                audit.to_str().unwrap(),
                "--recover",
                mode,
            ])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("no unresolved"));
    }
    assert!(!audit.exists());
}

#[test]
fn legacy_dry_run_with_state_does_not_create_the_state_file() {
    let dir = TempDir::new().unwrap();
    let (kr, al) = signed(
        &dir,
        1,
        4_000_000_000,
        r#"[{"name":"ripgrep","version":"14"}]"#,
    );
    let state = dir.path().join("state.json");
    bin()
        .args([
            "install",
            "ripgrep",
            "--dry-run",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
        ])
        .assert()
        .code(0);
    assert!(!state.exists());
    assert!(!dir.path().join("state.json.lock").exists());
}

#[test]
fn legacy_state_write_is_refused_while_another_process_holds_the_lock() {
    let dir = TempDir::new().unwrap();
    let (kr, al) = signed(
        &dir,
        1,
        4_000_000_000,
        r#"[{"name":"ripgrep","version":"14"}]"#,
    );
    let state = dir.path().join("state.json");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.path().join("state.json.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    bin()
        .args([
            "install",
            "ripgrep",
            "--allowlist",
            al.to_str().unwrap(),
            "--keyring",
            kr.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
        ])
        .assert()
        .code(2);
    assert!(!state.exists(), "state must not be written while locked");
    drop(lock);
}

// ---- update subcommand (binary level). Dry-run only: a real run would
// execute dpkg on the host, so the install path itself stays in the unit
// tests with a fake runner. ----

use ed25519_dalek::Signer;
use sha2::Digest as _;

/// Builds a transport dir with `stable.json` (signed envelope), `p.deb` and
/// `p.allowlist.json`, plus an update-keys file. Returns (dir paths as Vec).
fn update_env(dir: &TempDir, wrong_sig: bool) -> Vec<std::path::PathBuf> {
    let tdir = dir.path().join("transport");
    let ustate = dir.path().join("ustate");
    fs::create_dir_all(&tdir).unwrap();
    fs::create_dir_all(&ustate).unwrap();
    let deb = b"pretend deb bytes";
    let al = b"{\"pretend\":\"allowlist\"}";
    fs::write(tdir.join("p.deb"), deb).unwrap();
    fs::write(tdir.join("p.allowlist.json"), al).unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let uk = serde_json::json!({"keys":[{
        "key_id": "k1",
        "public_key_hex": hex::encode(sk.verifying_key().to_bytes()),
        "valid_from": 0,
        "valid_until": now + 86_400,
        "retired": false
    }]});
    let uk_path = write(dir, "update-keys.json", &uk.to_string());
    let sha = |b: &[u8]| hex::encode(sha2::Sha256::digest(b));
    let m = pos_update::Manifest {
        format: pos_update::FORMAT.into(),
        channel: "stable".into(),
        sequence: 1,
        issued_at: now - 10,
        expires_at: now + 3600,
        artifacts: vec![
            pos_update::Artifact {
                name: "p.deb".into(),
                version: "1".into(),
                sha256: sha(deb),
                size: deb.len() as u64,
            },
            pos_update::Artifact {
                name: "p.allowlist.json".into(),
                version: "1".into(),
                sha256: sha(al),
                size: al.len() as u64,
            },
        ],
    };
    let bytes = pos_update::signed_bytes(&m).unwrap();
    let signer = if wrong_sig {
        ed25519_dalek::SigningKey::from_bytes(&[6u8; 32])
    } else {
        sk
    };
    let env = pos_update::Envelope {
        manifest: m,
        signatures: vec![pos_update::SignatureEntry {
            key_id: "k1".into(),
            sig_hex: hex::encode(signer.sign(&bytes).to_bytes()),
        }],
    };
    fs::write(tdir.join("stable.json"), serde_json::to_vec(&env).unwrap()).unwrap();
    let kr = write(dir, "kr.json", "{\"keys\":[]}");
    vec![
        tdir,
        uk_path,
        kr,
        dir.path().join("state.json"),
        dir.path().join("audit.log"),
        ustate,
    ]
}

fn update_args<'a>(paths: &'a [std::path::PathBuf], extra: &'a [&'a str]) -> Vec<String> {
    let mut v = vec![
        "update".to_string(),
        "--channel".into(),
        "stable".into(),
        "--transport-dir".into(),
        paths[0].to_str().unwrap().into(),
        "--update-keys".into(),
        paths[1].to_str().unwrap().into(),
        "--threshold".into(),
        "1".into(),
        "--keyring".into(),
        paths[2].to_str().unwrap().into(),
        "--state".into(),
        paths[3].to_str().unwrap().into(),
        "--audit-log".into(),
        paths[4].to_str().unwrap().into(),
        "--update-state-dir".into(),
        paths[5].to_str().unwrap().into(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

#[test]
fn update_dry_run_prints_plan_and_persists_nothing() {
    let dir = TempDir::new().unwrap();
    let paths = update_env(&dir, false);
    bin()
        .args(update_args(&paths, &["--dry-run"]))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("would install"))
        .stdout(predicate::str::contains("p.deb"))
        .stdout(predicate::str::contains("no state was persisted"));
    assert!(!dir.path().join("state.json").exists());
}

#[test]
fn update_wrong_signature_is_exit2() {
    let dir = TempDir::new().unwrap();
    let paths = update_env(&dir, true);
    bin()
        .args(update_args(&paths, &["--dry-run"]))
        .assert()
        .code(2);
    assert!(!dir.path().join("state.json").exists());
}

#[test]
fn update_threshold_above_key_count_is_exit4() {
    let dir = TempDir::new().unwrap();
    let paths = update_env(&dir, false);
    let mut a = update_args(&paths, &["--dry-run"]);
    let i = a.iter().position(|s| s == "--threshold").unwrap();
    a[i + 1] = "5".into();
    bin().args(a).assert().code(4);
}

#[test]
fn update_missing_envelope_is_exit2() {
    let dir = TempDir::new().unwrap();
    let paths = update_env(&dir, false);
    fs::remove_file(paths[0].join("stable.json")).unwrap();
    bin()
        .args(update_args(&paths, &["--dry-run"]))
        .assert()
        .code(2);
}

// --- store pre-review checks (review-check) --------------------------------
// Store-side tooling: reads only the submitted .deb file, never a runner or
// the network. Exit 0 pass, 2 check failure, 4 usage error.

/// A minimal real .deb (ar of debian-binary + control.tar + data.tar.xz),
/// modeled on the review_check_tests fixture in src/main.rs.
fn review_deb(package: &str, version: &str, scripts: &[(&str, &str)]) -> Vec<u8> {
    fn tar_header(name: &str, size: usize) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{:011o}\0", size).as_bytes());
        h[156] = b'0';
        h
    }
    let control = format!("Package: {package}\nVersion: {version}\nArchitecture: all\n");
    let mut tar = Vec::new();
    let push = |tar: &mut Vec<u8>, name: &str, data: &[u8]| {
        tar.extend_from_slice(&tar_header(name, data.len()));
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    };
    push(&mut tar, "./control", control.as_bytes());
    for (n, body) in scripts {
        push(&mut tar, &format!("./{n}"), body.as_bytes());
    }
    tar.resize(tar.len() + 1024, 0);
    let member = |name: &str, data: &[u8]| {
        let mut v = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            format!("{name}/"),
            0,
            0,
            0,
            "100644",
            data.len()
        )
        .into_bytes();
        v.extend_from_slice(data);
        if data.len() % 2 == 1 {
            v.push(b'\n');
        }
        v
    };
    let mut deb = b"!<arch>\n".to_vec();
    deb.extend(member("debian-binary", b"2.0\n"));
    deb.extend(member("control.tar", &tar));
    deb.extend(member("data.tar.xz", b"placeholder"));
    deb
}

fn review_args(
    deb: &std::path::Path,
    sha256: &str,
    name: &str,
    version: Option<&str>,
) -> Vec<String> {
    let mut a = vec![
        "review-check".to_string(),
        "--deb".to_string(),
        deb.to_str().unwrap().to_string(),
        "--sha256".to_string(),
        sha256.to_string(),
        "--name".to_string(),
        name.to_string(),
    ];
    if let Some(v) = version {
        a.push("--version".to_string());
        a.push(v.to_string());
    }
    a
}

#[test]
fn review_check_missing_file_is_exit4() {
    let dir = TempDir::new().unwrap();
    bin()
        .args(review_args(
            &dir.path().join("nope.deb"),
            &"a".repeat(64),
            "hello-app",
            None,
        ))
        .assert()
        .code(4);
}

#[test]
fn review_check_unsafe_name_is_exit2() {
    let dir = TempDir::new().unwrap();
    let deb = dir.path().join("p.deb");
    fs::write(&deb, DEB).unwrap();
    bin()
        .args(review_args(&deb, &deb_sha(), "bad;name", None))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("safe-name"));
}

#[test]
fn review_check_uppercase_hash_is_exit2() {
    let dir = TempDir::new().unwrap();
    let deb = dir.path().join("p.deb");
    fs::write(&deb, DEB).unwrap();
    bin()
        .args(review_args(
            &deb,
            &deb_sha().to_uppercase(),
            "hello-app",
            None,
        ))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("64 lowercase hex"));
}

#[test]
fn review_check_hash_mismatch_is_exit2() {
    let dir = TempDir::new().unwrap();
    let deb = dir.path().join("p.deb");
    fs::write(&deb, DEB).unwrap();
    bin()
        .args(review_args(&deb, &"b".repeat(64), "hello-app", None))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("hash mismatch"));
}

#[test]
fn review_check_clean_pass_is_exit0() {
    let dir = TempDir::new().unwrap();
    let bytes = review_deb(
        "hello-app",
        "1.0",
        &[("postinst", "#!/bin/sh\nset -e\nldconfig\n")],
    );
    let deb = dir.path().join("p.deb");
    fs::write(&deb, &bytes).unwrap();
    bin()
        .args(review_args(
            &deb,
            &hex_lower(&sha2_digest(&bytes)),
            "hello-app",
            Some("1.0"),
        ))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("review-check passed"))
        .stdout(predicate::str::contains("1 maintainer script(s) scanned"));
}

#[test]
fn review_check_warn_only_is_exit0() {
    let dir = TempDir::new().unwrap();
    let bytes = review_deb(
        "doc-app",
        "1.0",
        &[("postinst", "#!/bin/sh\necho see https://x.example/docs\n")],
    );
    let deb = dir.path().join("p.deb");
    fs::write(&deb, &bytes).unwrap();
    bin()
        .args(review_args(
            &deb,
            &hex_lower(&sha2_digest(&bytes)),
            "doc-app",
            None,
        ))
        .assert()
        .code(0)
        .stdout(predicate::str::contains("WARN:"))
        .stdout(predicate::str::contains("review-check passed"));
}

#[test]
fn review_check_fail_finding_is_exit2() {
    let dir = TempDir::new().unwrap();
    let bytes = review_deb(
        "evil-app",
        "1.0",
        &[("postinst", "#!/bin/sh\nmkfs.ext4 /dev/sda1\n")],
    );
    let deb = dir.path().join("p.deb");
    fs::write(&deb, &bytes).unwrap();
    bin()
        .args(review_args(
            &deb,
            &hex_lower(&sha2_digest(&bytes)),
            "evil-app",
            None,
        ))
        .assert()
        .code(2)
        .stdout(predicate::str::contains("FAIL:"))
        .stderr(predicate::str::contains("review-check FAILED"));
}

/// sha256 of arbitrary bytes through the test-only sha2 dev-dependency.
fn sha2_digest(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}
