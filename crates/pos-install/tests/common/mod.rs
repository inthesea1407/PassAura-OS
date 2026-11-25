#![allow(dead_code)]
use ed25519_dalek::{Signer, SigningKey};
use pos_core::audit::{AuditEvent, AuditLog, FixedClock};
use pos_gate::allowlist::{KeyEntry, Keyring};
use pos_gate::allowlist_v2::{
    canonical_payload_bytes, derive_key_id, V2Allowlist, V2Entry, V2Key, V2Keyring,
};
use pos_gate::linux_backend::{
    InstallMode, InstallReport, PackageBackend, PackageBackendError, PlannedCommand,
};
use pos_gate::rollback::{RollbackStore, StdFileOps};
use pos_install::pipeline::{InstallPaths, LocalFileFetcher, Pipeline};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const NOW: i64 = 1_700_000_100;
pub const ISSUED: i64 = 1_700_000_000;
pub const PKG: &str = "ripgrep";
pub const CONTENT: &[u8] = b"pretend this is a .deb";

#[derive(Clone, Default)]
pub struct Fake {
    pub runs: Arc<AtomicUsize>,
    pub fail: Arc<Mutex<bool>>,
    /// When set, the failure carries this (code, message) instead of exit 1.
    #[allow(clippy::type_complexity)]
    pub fail_as: Arc<Mutex<Option<(Option<i32>, String)>>>,
    pub seen_paths: Arc<Mutex<Vec<PathBuf>>>,
}

impl Fake {
    pub fn runs(&self) -> usize {
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
        panic!("the by-name path must not be used by pos-install");
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
        if let Some((code, message)) = self.fail_as.lock().unwrap().clone() {
            if code.is_none() && message == "NOT_STARTED" {
                return Err(PackageBackendError::RunnerNotStarted {
                    program: "dpkg".into(),
                    message: "spawn failed".into(),
                });
            }
            return Err(PackageBackendError::RunnerFailure {
                program: "dpkg".into(),
                code,
                message,
            });
        }
        if *self.fail.lock().unwrap() {
            return Err(PackageBackendError::RunnerFailure {
                program: "dpkg".into(),
                code: Some(1),
                message: "fake failure".into(),
            });
        }
        Ok(InstallReport {
            command: PlannedCommand {
                program: "dpkg".into(),
                args: vec![],
            },
            executed: true,
        })
    }
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

pub fn trusted() -> Keyring {
    let sk = signing_key();
    let pk = hex::encode(sk.verifying_key().to_bytes());
    Keyring {
        keys: vec![KeyEntry {
            key_id: derive_key_id(&pk),
            public_key_hex: pk,
        }],
    }
}

pub fn doc_with(seq: u64, entries: Vec<V2Entry>) -> V2Allowlist {
    let sk = signing_key();
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
    sign(&mut doc);
    doc
}

pub fn sign(doc: &mut V2Allowlist) {
    let payload = canonical_payload_bytes(doc).unwrap();
    doc.signature_hex = hex::encode(signing_key().sign(&payload).to_bytes());
}

pub fn good_doc(seq: u64) -> V2Allowlist {
    doc_with(
        seq,
        vec![V2Entry {
            name: PKG.into(),
            version: Some("14.1.0".into()),
            sha256: sha256_hex(CONTENT),
        }],
    )
}

pub struct Env {
    pub dir: tempfile::TempDir,
    pub paths: InstallPaths,
    pub source: PathBuf,
    pub fake: Fake,
}

pub type P = Pipeline<Fake, LocalFileFetcher, StdFileOps>;

impl Env {
    pub fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("src.deb");
        std::fs::write(&source, CONTENT).unwrap();
        let mut paths = InstallPaths::new(
            dir.path().join("state.json"),
            dir.path().join("audit.jsonl"),
        );
        paths.lock_timeout = Duration::from_millis(300);
        Env {
            dir,
            paths,
            source,
            fake: Fake::default(),
        }
    }

    /// A fresh pipeline over the same files and the same fake system, as if
    /// the process had restarted.
    pub fn pipeline(&self) -> P {
        Pipeline::new(
            self.paths.clone(),
            self.fake.clone(),
            LocalFileFetcher {
                path: self.source.clone(),
            },
            StdFileOps,
        )
    }

    pub fn stored_seq(&self) -> Option<u64> {
        RollbackStore::read_state_readonly(&self.paths.state)
            .unwrap()
            .map(|r| r.last_seq)
    }

    pub fn state_digest(&self) -> Option<String> {
        RollbackStore::read_state_readonly(&self.paths.state)
            .unwrap()
            .map(|r| r.last_digest_hex)
    }

    pub fn audit_events(&self) -> Vec<AuditEvent> {
        if !self.paths.audit.exists() {
            return vec![];
        }
        AuditLog::load_from_file(&self.paths.audit, FixedClock(0))
            .expect("audit chain verifies")
            .records()
            .iter()
            .map(|r| r.event)
            .collect()
    }

    pub fn count(&self, e: AuditEvent) -> usize {
        self.audit_events().iter().filter(|x| **x == e).count()
    }

    pub fn journal_exists(&self) -> bool {
        pos_install::journal::Journal::for_state(&self.paths.state).exists()
    }

    pub fn stage_list(&self) -> Vec<String> {
        pos_install::stage::Stager::for_state(&self.paths.state).list()
    }
}

pub fn req<'a>(doc: &'a V2Allowlist, trusted: &'a Keyring) -> pos_install::Request<'a> {
    pos_install::Request {
        package: PKG,
        doc,
        trusted,
        now: NOW,
    }
}

/// Collects every fault label a clean run hits.
pub fn record_labels(env: &Env) -> Vec<String> {
    let labels = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = labels.clone();
    let mut p = env.pipeline();
    p.set_fault(move |label| {
        l2.lock().unwrap().push(label.to_string());
        false
    });
    let doc = good_doc(3);
    let t = trusted();
    p.install(&req(&doc, &t)).expect("clean run");
    let v = labels.lock().unwrap().clone();
    v
}

/// Crash at the n-th (1-based) hit.
pub fn crash_at(p: &mut P, n: usize) {
    let c = Arc::new(AtomicUsize::new(0));
    p.set_fault(move |_| c.fetch_add(1, Ordering::SeqCst) + 1 == n);
}
