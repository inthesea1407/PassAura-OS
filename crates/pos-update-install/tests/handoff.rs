//! Adapter tests over a fake backend. The real dpkg backend is not exercised
//! here; pos-install's own suite covers the pipeline against fakes too.

use ed25519_dalek::{Signer, SigningKey};
use pos_gate::allowlist::{KeyEntry, Keyring};
use pos_gate::allowlist_v2::{
    canonical_payload_bytes, derive_key_id, V2Allowlist, V2Entry, V2Key, V2Keyring,
};
use pos_gate::linux_backend::{
    InstallMode, InstallReport, PackageBackend, PackageBackendError, PlannedCommand,
};
use pos_gate::rollback::{RollbackStore, StdFileOps};
use pos_install::pipeline::InstallPaths;
use pos_update::flow::{Handoff, StagedFile, StagedUpdate};
use pos_update::{AcceptedState, Artifact, Manifest, Verified};
use pos_update_install::{InstallHandoff, ALLOWLIST_SUFFIX};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOW: i64 = 1_700_000_100;
const ISSUED: i64 = 1_700_000_000;
const PKG: &str = "ripgrep";
const PKG2: &str = "fd";
const CONTENT: &[u8] = b"pretend this is a .deb";
const CONTENT2: &[u8] = b"pretend this is another .deb";

#[derive(Clone, Default)]
struct Fake {
    runs: Arc<AtomicUsize>,
    seen_paths: Arc<Mutex<Vec<PathBuf>>>,
}

impl Fake {
    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

impl PackageBackend for Fake {
    fn install(
        &mut self,
        _p: &str,
        _d: &V2Allowlist,
        _t: &Keyring,
        _n: i64,
        _s: Option<(u64, &str)>,
        _m: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        panic!("the by-name path must not be used by the adapter");
    }

    fn install_staged_file(
        &mut self,
        _package: &str,
        staged: &Path,
        _doc: &V2Allowlist,
        _trusted: &Keyring,
        _now: i64,
        _stored: Option<(u64, &str)>,
        _mode: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        assert!(
            staged.is_file(),
            "staged file must exist when the command runs"
        );
        self.seen_paths.lock().unwrap().push(staged.to_path_buf());
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(InstallReport {
            command: PlannedCommand {
                program: "dpkg".into(),
                args: vec![],
            },
            executed: true,
        })
    }
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn keyring_for(sk: &SigningKey) -> Keyring {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    Keyring {
        keys: vec![KeyEntry {
            key_id: derive_key_id(&pk),
            public_key_hex: pk,
        }],
    }
}

fn doc_with(sk: &SigningKey, seq: u64, entries: Vec<V2Entry>) -> V2Allowlist {
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let key_id = derive_key_id(&pk);
    let mut doc = V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence: seq,
        issued_at: ISSUED,
        expires_at: ISSUED + 86_400,
        signed_by: key_id.clone(),
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id,
                public_key_hex: pk,
                valid_from: 0,
                valid_until: ISSUED + 86_400,
                retired: false,
            }],
        },
        entries,
        signature_hex: String::new(),
    };
    let payload = canonical_payload_bytes(&doc).unwrap();
    doc.signature_hex = hex::encode(sk.sign(&payload).to_bytes());
    doc
}

fn doc_for(sk: &SigningKey, seq: u64, package: &str, content: &[u8]) -> V2Allowlist {
    doc_with(
        sk,
        seq,
        vec![V2Entry {
            name: package.into(),
            version: Some("1.0.0".into()),
            sha256: sha256_hex(content),
        }],
    )
}

fn verified_stub() -> Verified {
    Verified {
        manifest: Manifest {
            format: "pos-update-manifest-v1".into(),
            channel: "stable".into(),
            sequence: 7,
            issued_at: ISSUED as u64,
            expires_at: (ISSUED + 86_400) as u64,
            artifacts: vec![],
        },
        state: AcceptedState {
            channel: "stable".into(),
            sequence: 7,
            digest: [0u8; 32],
        },
        idempotent: false,
    }
}

struct Env {
    _dir: tempfile::TempDir,
    stage_dir: PathBuf,
    paths: InstallPaths,
    fake: Fake,
    sk: SigningKey,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let stage_dir = dir.path().join("update-stage");
        std::fs::create_dir(&stage_dir).unwrap();
        let mut paths = InstallPaths::new(
            dir.path().join("state.json"),
            dir.path().join("audit.jsonl"),
        );
        paths.lock_timeout = Duration::from_millis(300);
        Env {
            _dir: dir,
            stage_dir,
            paths,
            fake: Fake::default(),
            sk: SigningKey::from_bytes(&[7u8; 32]),
        }
    }

    /// Stages one `X.deb` plus its signed `X.allowlist.json`.
    fn stage_deb(&self, base: &str, package: &str, content: &[u8], seq: u64) -> StagedUpdate {
        std::fs::write(self.stage_dir.join(format!("{base}.deb")), content).unwrap();
        let doc = doc_for(&self.sk, seq, package, content);
        std::fs::write(
            self.stage_dir.join(format!("{base}{ALLOWLIST_SUFFIX}")),
            serde_json::to_vec(&doc).unwrap(),
        )
        .unwrap();
        StagedUpdate {
            dir: self.stage_dir.clone(),
            files: vec![
                StagedFile {
                    name: format!("{base}.deb"),
                    sha256: sha256_hex(content),
                    size: content.len() as u64,
                },
                StagedFile {
                    name: format!("{base}{ALLOWLIST_SUFFIX}"),
                    sha256: String::new(),
                    size: 0,
                },
            ],
        }
    }

    fn handoff(&self) -> InstallHandoff<Fake, StdFileOps> {
        InstallHandoff::new(
            self.paths.clone(),
            self.fake.clone(),
            StdFileOps,
            keyring_for(&self.sk),
            NOW,
        )
    }

    fn stored_seq(&self) -> Option<u64> {
        RollbackStore::read_state_readonly(&self.paths.state)
            .unwrap()
            .map(|r| r.last_seq)
    }
}

#[test]
fn staged_deb_with_signed_allowlist_installs() {
    let env = Env::new();
    let staged = env.stage_deb("ripgrep-14.1.0", PKG, CONTENT, 3);
    let v = verified_stub();
    env.handoff().handoff(&v, &staged).unwrap();
    assert_eq!(env.fake.runs(), 1);
    let seen = env.fake.seen_paths.lock().unwrap();
    let mut want = env.paths.state.clone().into_os_string();
    want.push(".stage");
    assert!(seen[0].starts_with(PathBuf::from(want)), "{seen:?}");
    assert_eq!(env.stored_seq(), Some(3));
}

#[test]
fn deb_without_allowlist_fails_closed_and_runs_nothing() {
    let env = Env::new();
    std::fs::write(env.stage_dir.join("lonely.deb"), CONTENT).unwrap();
    let staged = StagedUpdate {
        dir: env.stage_dir.clone(),
        files: vec![StagedFile {
            name: "lonely.deb".into(),
            sha256: sha256_hex(CONTENT),
            size: CONTENT.len() as u64,
        }],
    };
    let v = verified_stub();
    let e = env.handoff().handoff(&v, &staged).unwrap_err();
    assert!(e.0.contains(ALLOWLIST_SUFFIX), "{e}");
    assert_eq!(env.fake.runs(), 0);
    assert_eq!(env.stored_seq(), None);
}

#[test]
fn allowlist_entry_for_other_bytes_fails_closed() {
    let env = Env::new();
    // The staged deb is CONTENT, but the signed entry names a different hash.
    let mut staged = env.stage_deb("ripgrep-14.1.0", PKG, CONTENT, 3);
    let doc = doc_with(
        &env.sk,
        3,
        vec![V2Entry {
            name: PKG.into(),
            version: Some("1.0.0".into()),
            sha256: sha256_hex(b"different bytes"),
        }],
    );
    std::fs::write(
        env.stage_dir
            .join(format!("ripgrep-14.1.0{ALLOWLIST_SUFFIX}")),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    let v = verified_stub();
    let e = env.handoff().handoff(&v, &staged).unwrap_err();
    assert!(e.0.contains("no entry matches"), "{e}");
    assert_eq!(env.fake.runs(), 0);
    staged.files.clear();
}

#[test]
fn untrusted_signer_fails_closed() {
    let env = Env::new();
    let staged = env.stage_deb("ripgrep-14.1.0", PKG, CONTENT, 3);
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let mut h = env.handoff();
    h.trusted = keyring_for(&other); // adapter trusts a key that did not sign
    let v = verified_stub();
    let e = h.handoff(&v, &staged).unwrap_err();
    assert!(e.0.contains("install failed"), "{e}");
    assert_eq!(env.fake.runs(), 0);
    assert_eq!(env.stored_seq(), None);
}

#[test]
fn manifest_without_debs_is_a_noop() {
    let env = Env::new();
    let staged = StagedUpdate {
        dir: env.stage_dir.clone(),
        files: vec![StagedFile {
            name: "notes.txt".into(),
            sha256: sha256_hex(b"notes"),
            size: 5,
        }],
    };
    let v = verified_stub();
    env.handoff().handoff(&v, &staged).unwrap();
    assert_eq!(env.fake.runs(), 0);
}

#[test]
fn two_debs_install_in_manifest_order() {
    let env = Env::new();
    let a = env.stage_deb("a", PKG, CONTENT, 3);
    // stage the second pair into the same dir by hand (stage_deb builds one pair)
    std::fs::write(env.stage_dir.join("b.deb"), CONTENT2).unwrap();
    let doc2 = doc_for(&env.sk, 4, PKG2, CONTENT2);
    std::fs::write(
        env.stage_dir.join(format!("b{ALLOWLIST_SUFFIX}")),
        serde_json::to_vec(&doc2).unwrap(),
    )
    .unwrap();
    let mut files = a.files;
    files.push(StagedFile {
        name: "b.deb".into(),
        sha256: sha256_hex(CONTENT2),
        size: CONTENT2.len() as u64,
    });
    files.push(StagedFile {
        name: format!("b{ALLOWLIST_SUFFIX}"),
        sha256: String::new(),
        size: 0,
    });
    let staged = StagedUpdate {
        dir: env.stage_dir.clone(),
        files,
    };
    let v = verified_stub();
    env.handoff().handoff(&v, &staged).unwrap();
    assert_eq!(env.fake.runs(), 2);
    assert_eq!(env.stored_seq(), Some(4));
}

#[test]
fn artifact_type_is_checked_by_suffix_not_version_field() {
    // `Artifact.version` is opaque; the adapter keys on the file name only.
    let env = Env::new();
    let staged = env.stage_deb("ripgrep-14.1.0", PKG, CONTENT, 3);
    let v = verified_stub();
    env.handoff().handoff(&v, &staged).unwrap();
    let _ = Artifact {
        name: "x".into(),
        version: "opaque, never parsed".into(),
        sha256: "0".repeat(64),
        size: 0,
    };
}
