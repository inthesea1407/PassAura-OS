//! Needs feature `fault-injection` (which turns on the writer's test hook). Injected failures and simulated
//! crash points of the real atomic writer; this is not a power-loss test.
use pos_update::file_state::*;
use pos_update::flow::StateStore;
use pos_update::AcceptedState;
use pos_vault_store::{HookAction, WriteStep};
use std::io::ErrorKind;
use std::time::Duration;

fn st(seq: u64) -> AcceptedState {
    AcceptedState {
        channel: "stable".into(),
        sequence: seq,
        digest: [seq as u8; 32],
    }
}
const T: Duration = Duration::from_millis(50);
const STEPS: [WriteStep; 6] = [
    WriteStep::AfterTmpCreate,
    WriteStep::AfterWrite,
    WriteStep::AfterSync,
    WriteStep::BeforeRename,
    WriteStep::AfterRename,
    WriteStep::AfterDirSync,
];

fn before_rename(s: WriteStep) -> bool {
    !matches!(s, WriteStep::AfterRename | WriteStep::AfterDirSync)
}

#[test]
fn injected_failure_at_each_step_keeps_a_consistent_state() {
    for step in STEPS {
        let d = tempfile::tempdir().unwrap();
        let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
        s.store(&st(1)).unwrap();
        s.set_fault_hook(Box::new(move |x| {
            if x == step {
                HookAction::Fail(ErrorKind::PermissionDenied)
            } else {
                HookAction::Continue
            }
        }));
        let e = s.store(&st(2)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{step:?}");
        // Never a mix: old state before the rename, new state after it.
        let want = if before_rename(step) { st(1) } else { st(2) };
        assert_eq!(s.load("stable").unwrap(), Some(want), "{step:?}");
        assert!(
            s.list_orphan_temps().unwrap().is_empty(),
            "{step:?}: failed write cleans its own temp file"
        );
    }
}

#[test]
fn simulated_crash_at_each_step_leaves_old_or_new_state_and_never_deletes_orphans() {
    for step in STEPS {
        let d = tempfile::tempdir().unwrap();
        {
            let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
            s.store(&st(1)).unwrap();
            s.set_fault_hook(Box::new(move |x| {
                if x == step {
                    HookAction::Crash
                } else {
                    HookAction::Continue
                }
            }));
            assert!(s.store(&st(2)).is_err(), "{step:?}");
        } // the "process" ends: the lock is released
        let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
        let want = if before_rename(step) { st(1) } else { st(2) };
        assert_eq!(s.load("stable").unwrap(), Some(want), "{step:?}");
        let orphans = s.list_orphan_temps().unwrap();
        assert_eq!(
            orphans.len(),
            usize::from(before_rename(step)),
            "{step:?}: temp file left by the crash, listed only"
        );
        // The next write works and the orphan is still there (nothing is deleted automatically).
        s.set_fault_hook(Box::new(|_| HookAction::Continue));
        s.store(&st(3)).unwrap();
        assert_eq!(s.load("stable").unwrap(), Some(st(3)));
        assert_eq!(s.list_orphan_temps().unwrap().len(), orphans.len());
    }
}

// ---- whole flow: crash while persisting the state, then replay ----

use ed25519_dalek::{Signer, SigningKey};
use pos_update::flow::*;
use pos_update::*;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

const NOW: u64 = 1_000_000;
const PAYLOAD: &[u8] = b"payload bytes";

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn tkeys() -> Vec<TrustedKey> {
    [("a", 1u8), ("b", 2u8)]
        .iter()
        .map(|(id, s)| TrustedKey {
            key_id: (*id).into(),
            public_key: sk(*s).verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: u64::MAX,
            retired: false,
        })
        .collect()
}
fn envelope(seq: u64) -> Vec<u8> {
    let m = Manifest {
        format: FORMAT.into(),
        channel: "stable".into(),
        sequence: seq,
        issued_at: NOW - 10,
        expires_at: NOW + 1000,
        artifacts: vec![Artifact {
            name: "a.bin".into(),
            version: "v".into(),
            sha256: hex::encode(Sha256::digest(PAYLOAD)),
            size: PAYLOAD.len() as u64,
        }],
    };
    let msg = signed_bytes(&m).unwrap();
    let signatures = [("a", 1u8), ("b", 2u8)]
        .iter()
        .map(|(id, s)| SignatureEntry {
            key_id: (*id).into(),
            sig_hex: hex::encode(sk(*s).sign(&msg).to_bytes()),
        })
        .collect();
    serde_json::to_vec(&Envelope {
        manifest: m,
        signatures,
    })
    .unwrap()
}
struct Tr(Vec<u8>);
impl Transport for Tr {
    fn fetch_manifest(&mut self, _: &str) -> std::io::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
    fn fetch_artifact<'a>(
        &'a mut self,
        _: &str,
        _: &Artifact,
    ) -> std::io::Result<Box<dyn Read + 'a>> {
        Ok(Box::new(Cursor::new(PAYLOAD.to_vec())))
    }
}
#[derive(Default)]
struct H(Vec<u64>);
impl Handoff for H {
    fn handoff(&mut self, v: &Verified, s: &StagedUpdate) -> Result<(), HandoffError> {
        assert_eq!(std::fs::read(s.dir.join("a.bin")).unwrap(), PAYLOAD);
        self.0.push(v.state.sequence);
        Ok(())
    }
}

#[test]
fn crash_during_state_persist_then_replay_ends_in_the_same_state() {
    for step in STEPS {
        let d = tempfile::tempdir().unwrap();
        let stage = d.path().join("stage");
        let keys = tkeys();
        let pol = VerifyPolicy::new(&keys, 2, NOW, "stable");
        let mut h = H::default();
        {
            let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
            s.store(&AcceptedState {
                channel: "stable".into(),
                sequence: 1,
                digest: [1; 32],
            })
            .unwrap();
            s.set_fault_hook(Box::new(move |x| {
                if x == step {
                    HookAction::Crash
                } else {
                    HookAction::Continue
                }
            }));
            let r = run_update(
                "stable",
                &pol,
                &mut Tr(envelope(2)),
                &mut s,
                &mut h,
                &stage,
                &Options::default(),
            );
            assert!(matches!(r, Err(FlowError::State(_))), "{step:?}: {r:?}");
        }
        assert_eq!(
            h.0,
            vec![2],
            "{step:?}: handoff ran before the persist crashed"
        );
        let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
        let r = run_update(
            "stable",
            &pol,
            &mut Tr(envelope(2)),
            &mut s,
            &mut h,
            &stage,
            &Options::default(),
        )
        .unwrap();
        if before_rename(step) {
            // Old state on disk: the handoff is replayed (idempotent contract) and the state advances.
            assert!(
                matches!(r, Outcome::Applied { sequence: 2, .. }),
                "{step:?}: {r:?}"
            );
            assert_eq!(h.0, vec![2, 2]);
        } else {
            // The new state was already durable: nothing is handed off again.
            assert_eq!(r, Outcome::AlreadyCurrent { sequence: 2 }, "{step:?}");
            assert_eq!(h.0, vec![2]);
        }
        assert_eq!(s.load("stable").unwrap().unwrap().sequence, 2);
    }
}
