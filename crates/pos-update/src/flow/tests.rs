use super::*;
use crate::{signed_bytes, Envelope, Manifest, SignatureEntry, TrustedKey, FORMAT};
use ed25519_dalek::{Signer, SigningKey};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::rc::Rc;

const NOW: u64 = 1_000_000;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn keys() -> Vec<TrustedKey> {
    [("a", 1u8), ("b", 2u8)]
        .iter()
        .map(|(id, seed)| TrustedKey {
            key_id: (*id).into(),
            public_key: sk(*seed).verifying_key().to_bytes(),
            valid_from: 0,
            valid_until: u64::MAX,
            retired: false,
        })
        .collect()
}
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn manifest(channel: &str, seq: u64, payloads: &[(&str, &[u8])]) -> Manifest {
    Manifest {
        format: FORMAT.into(),
        channel: channel.into(),
        sequence: seq,
        issued_at: NOW - 10,
        expires_at: NOW + 1000,
        artifacts: payloads
            .iter()
            .map(|(n, b)| Artifact {
                name: (*n).into(),
                version: "v".into(),
                sha256: sha(b),
                size: b.len() as u64,
            })
            .collect(),
    }
}
fn sign(m: &Manifest) -> Vec<u8> {
    let msg = signed_bytes(m).unwrap();
    let signatures = [("a", 1u8), ("b", 2u8)]
        .iter()
        .map(|(id, seed)| SignatureEntry {
            key_id: (*id).into(),
            sig_hex: hex::encode(sk(*seed).sign(&msg).to_bytes()),
        })
        .collect();
    serde_json::to_vec(&Envelope {
        manifest: m.clone(),
        signatures,
    })
    .unwrap()
}

type HandoffCall = (u64, [u8; 32], Vec<StagedFile>, Vec<Vec<u8>>);
#[derive(Default)]
struct FakeT {
    manifest: Vec<u8>,
    payloads: BTreeMap<String, Vec<u8>>,
    manifest_fetches: usize,
    artifact_fetches: usize,
    bytes_read: Rc<Cell<u64>>,
}
struct Counting<R> {
    inner: R,
    n: Rc<Cell<u64>>,
}
impl<R: Read> Read for Counting<R> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(b)?;
        self.n.set(self.n.get() + k as u64);
        Ok(k)
    }
}
impl Transport for FakeT {
    fn fetch_manifest(&mut self, _c: &str) -> io::Result<Vec<u8>> {
        self.manifest_fetches += 1;
        Ok(self.manifest.clone())
    }
    fn fetch_artifact<'a>(&'a mut self, _c: &str, a: &Artifact) -> io::Result<Box<dyn Read + 'a>> {
        self.artifact_fetches += 1;
        let b = self
            .payloads
            .get(&a.name)
            .cloned()
            .ok_or(io::ErrorKind::NotFound)?;
        Ok(Box::new(Counting {
            inner: Cursor::new(b),
            n: self.bytes_read.clone(),
        }))
    }
}

#[derive(Default)]
struct FakeS {
    st: Option<AcceptedState>,
    fail_store: bool,
}
impl StateStore for FakeS {
    fn load(&mut self, c: &str) -> io::Result<Option<AcceptedState>> {
        Ok(self.st.clone().filter(|s| s.channel == c))
    }
    fn store(&mut self, s: &AcceptedState) -> io::Result<()> {
        if self.fail_store {
            return Err(io::ErrorKind::Other.into());
        }
        self.st = Some(s.clone());
        Ok(())
    }
}

#[derive(Default)]
struct RecH {
    calls: Vec<HandoffCall>,
    fail: bool,
    #[cfg(unix)]
    dir_modes: Vec<u32>,
    #[cfg(unix)]
    file_modes: Vec<u32>,
}
impl Handoff for RecH {
    fn handoff(&mut self, v: &Verified, s: &StagedUpdate) -> Result<(), HandoffError> {
        let contents = s
            .files
            .iter()
            .map(|f| fs::read(s.dir.join(&f.name)).unwrap())
            .collect();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.dir_modes
                .push(fs::metadata(&s.dir).unwrap().permissions().mode() & 0o777);
            for f in &s.files {
                self.file_modes.push(
                    fs::metadata(s.dir.join(&f.name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                );
            }
        }
        self.calls
            .push((v.state.sequence, v.state.digest, s.files.clone(), contents));
        if self.fail {
            return Err(HandoffError("no".into()));
        }
        Ok(())
    }
}

struct Env {
    root: tempfile::TempDir,
    t: FakeT,
    s: FakeS,
    h: RecH,
    keys: Vec<TrustedKey>,
}
impl Env {
    fn new(channel: &str, seq: u64, payloads: &[(&str, &[u8])]) -> Env {
        let mut e = Env {
            root: tempfile::tempdir().unwrap(),
            t: FakeT::default(),
            s: FakeS::default(),
            h: RecH::default(),
            keys: keys(),
        };
        e.publish(channel, seq, payloads);
        e
    }
    fn publish(&mut self, channel: &str, seq: u64, payloads: &[(&str, &[u8])]) {
        self.t.manifest = sign(&manifest(channel, seq, payloads));
        self.t.payloads = payloads
            .iter()
            .map(|(n, b)| ((*n).to_string(), b.to_vec()))
            .collect();
    }
    fn stage_root(&self) -> PathBuf {
        self.root.path().join("stage")
    }
    fn run(&mut self, channel: &str) -> Result<Outcome, FlowError> {
        self.run_with(channel, Stager::new(&self.stage_root()))
    }
    fn run_with(&mut self, channel: &str, st: Stager) -> Result<Outcome, FlowError> {
        let pol = VerifyPolicy::new(&self.keys, 2, NOW, channel);
        run_with_stager(
            channel,
            &pol,
            &mut self.t,
            &mut self.s,
            &mut self.h,
            st,
            &Options::default(),
        )
    }
    fn stage_entries(&self) -> Vec<String> {
        match fs::read_dir(self.stage_root()) {
            Ok(r) => r
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => vec![],
        }
    }
}

const P1: &[u8] = b"first payload";
const P2: &[u8] = b"second payload, a bit longer";

#[test]
fn happy_path_stages_verified_bytes_hands_off_once_persists_and_cleans_up() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1), ("b.bin", P2)]);
    let out = e.run("stable").unwrap();
    assert_eq!(
        out,
        Outcome::Applied {
            sequence: 5,
            cleanup_complete: true
        }
    );
    assert_eq!(e.h.calls.len(), 1);
    let (seq, _, files, contents) = &e.h.calls[0];
    assert_eq!(*seq, 5);
    assert_eq!(
        files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        ["a.bin", "b.bin"]
    );
    assert_eq!(contents, &vec![P1.to_vec(), P2.to_vec()]);
    assert_eq!(files[0].sha256, sha(P1));
    assert_eq!(e.s.st.as_ref().unwrap().sequence, 5);
    assert!(
        e.stage_entries().is_empty(),
        "stage root and directory were created by this run, so both are removed"
    );
    #[cfg(unix)]
    {
        assert_eq!(e.h.dir_modes, vec![0o700]);
        assert!(
            !e.h.file_modes.is_empty() && e.h.file_modes.iter().all(|m| *m == 0o600),
            "{:?}",
            e.h.file_modes
        );
    }
}

#[test]
fn same_manifest_again_is_already_current_without_fetch_or_handoff() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    e.run("stable").unwrap();
    let (mf, af) = (e.t.manifest_fetches, e.t.artifact_fetches);
    assert_eq!(
        e.run("stable").unwrap(),
        Outcome::AlreadyCurrent { sequence: 5 }
    );
    assert_eq!(e.t.manifest_fetches, mf + 1);
    assert_eq!(e.t.artifact_fetches, af, "no payload fetch");
    assert_eq!(e.h.calls.len(), 1, "no second handoff");
}

#[test]
fn verify_failures_stage_nothing_and_change_nothing() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    e.run("stable").unwrap();
    // rollback
    e.publish("stable", 4, &[("a.bin", P1)]);
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Verify(UpdateError::Rollback)
    );
    // fork: same sequence, different content
    e.publish("stable", 5, &[("a.bin", P2)]);
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Verify(UpdateError::Fork)
    );
    // wrong channel inside the manifest
    e.publish("beta", 9, &[("a.bin", P1)]);
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Verify(UpdateError::WrongChannel)
    );
    // bad signature
    let mut bad = sign(&manifest("stable", 6, &[("a.bin", P1)]));
    let i = bad.iter().position(|b| *b == b'a').unwrap();
    bad[i] = b'b';
    e.t.manifest = bad;
    assert!(matches!(e.run("stable").unwrap_err(), FlowError::Verify(_)));
    assert_eq!(e.h.calls.len(), 1);
    assert_eq!(e.s.st.as_ref().unwrap().sequence, 5);
    assert!(e.stage_entries().is_empty());
}

#[test]
fn channel_arguments_are_checked() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    assert_eq!(e.run("../x").unwrap_err(), FlowError::BadChannel);
    let pol = VerifyPolicy::new(&e.keys, 2, NOW, "beta");
    let root = e.stage_root();
    let r = run_with_stager(
        "stable",
        &pol,
        &mut e.t,
        &mut e.s,
        &mut e.h,
        Stager::new(&root),
        &Options::default(),
    );
    assert_eq!(r.unwrap_err(), FlowError::ChannelMismatch);
    assert_eq!(e.t.manifest_fetches, 0);
}

#[test]
fn state_is_per_channel() {
    let mut e = Env::new("stable", 50, &[("a.bin", P1)]);
    e.run("stable").unwrap();
    // A lower sequence on another channel is fine: stable's state is not used for beta.
    e.publish("beta", 1, &[("a.bin", P1)]);
    assert_eq!(
        e.run("beta").unwrap(),
        Outcome::Applied {
            sequence: 1,
            cleanup_complete: true
        }
    );
}

#[test]
fn handoff_failure_leaves_state_unchanged_and_cleans_stage() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    e.h.fail = true;
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Handoff(HandoffError("no".into()))
    );
    assert!(e.s.st.is_none());
    assert!(e.stage_entries().is_empty());
}

/// Crash window between handoff and persist: the handoff already ran, the state was not saved. A rerun
/// replays the same manifest, so the handoff runs again with the same verified data and staged bytes, and
/// the end state equals an uninterrupted run. This is the idempotent-replay contract.
#[test]
fn persist_failure_after_handoff_replays_handoff_with_identical_input() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1), ("b.bin", P2)]);
    e.s.fail_store = true;
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::State(io::ErrorKind::Other)
    );
    assert!(e.s.st.is_none());
    assert_eq!(e.h.calls.len(), 1);
    assert!(e.stage_entries().is_empty());
    e.s.fail_store = false;
    assert_eq!(
        e.run("stable").unwrap(),
        Outcome::Applied {
            sequence: 5,
            cleanup_complete: true
        }
    );
    assert_eq!(e.h.calls.len(), 2);
    assert_eq!(
        e.h.calls[0], e.h.calls[1],
        "same sequence, digest, staged files and bytes"
    );
    assert_eq!(e.s.st.as_ref().unwrap().digest, e.h.calls[0].1);
    // A non-idempotent handoff would be called a second time here; the third run proves it is skipped.
    assert_eq!(
        e.run("stable").unwrap(),
        Outcome::AlreadyCurrent { sequence: 5 }
    );
    assert_eq!(e.h.calls.len(), 2);
}

#[test]
fn stage_faults_at_every_step_leave_nothing_and_do_not_hand_off() {
    for step in [
        StageStep::AfterTmpCreate,
        StageStep::AfterWrite,
        StageStep::AfterVerify,
        StageStep::BeforeRename,
        StageStep::AfterRename,
    ] {
        for target in ["a.bin", "b.bin"] {
            let mut e = Env::new("stable", 5, &[("a.bin", P1), ("b.bin", P2)]);
            let mut st = Stager::new(&e.stage_root());
            st.hook = Some(Box::new(move |s, n| {
                if s == step && n == target {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(())
                }
            }));
            let err = e.run_with("stable", st).unwrap_err();
            assert_eq!(
                err,
                FlowError::Stage(StageError::Io(io::ErrorKind::PermissionDenied)),
                "{step:?} {target}"
            );
            assert!(e.h.calls.is_empty(), "{step:?} {target}");
            assert!(e.s.st.is_none());
            assert!(
                e.stage_entries().is_empty(),
                "{step:?} {target}: leftovers {:?}",
                e.stage_entries()
            );
            // A clean rerun on the same root works.
            assert_eq!(
                e.run("stable").unwrap(),
                Outcome::Applied {
                    sequence: 5,
                    cleanup_complete: true
                }
            );
        }
    }
}

/// Simulated crash: leftovers of an earlier run are present when the next run starts.
#[test]
fn leftovers_of_a_crashed_run_are_reused_when_valid_and_never_deleted() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1), ("b.bin", P2)]);
    // First run fails persisting, so we can learn the directory name from the handoff.
    e.s.fail_store = true;
    let _ = e.run("stable");
    let dir = {
        let (seq, digest, ..) = &e.h.calls[0];
        e.stage_root().join(format!(
            "{}.{}.{}",
            channel_key("stable").unwrap(),
            seq,
            hex::encode(&digest[..8])
        ))
    };
    // Simulate the crash: root, directory, one valid payload and a stray temp file remain.
    make_private_dir(&e.stage_root()).unwrap();
    make_private_dir(&dir).unwrap();
    fs::write(dir.join("a.bin"), P1).unwrap();
    fs::write(dir.join(".stage-tmp-999-0"), b"partial").unwrap();
    e.s.fail_store = false;
    let out = e.run("stable").unwrap();
    assert_eq!(
        out,
        Outcome::Applied {
            sequence: 5,
            cleanup_complete: false
        }
    );
    assert!(
        dir.join(".stage-tmp-999-0").exists(),
        "foreign temp file must not be deleted"
    );
    assert!(
        dir.join("a.bin").exists(),
        "reused payload is left in place"
    );
    assert!(
        !dir.join("b.bin").exists(),
        "payload fetched by this run is removed"
    );
}

#[test]
fn different_file_under_a_final_name_is_a_conflict_and_is_untouched() {
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    e.s.fail_store = true;
    let _ = e.run("stable");
    let (seq, digest) = (e.h.calls[0].0, e.h.calls[0].1);
    let dir = e.stage_root().join(format!(
        "{}.{}.{}",
        channel_key("stable").unwrap(),
        seq,
        hex::encode(&digest[..8])
    ));
    make_private_dir(&e.stage_root()).unwrap();
    make_private_dir(&dir).unwrap();
    fs::write(dir.join("a.bin"), b"someone else's file").unwrap();
    e.s.fail_store = false;
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Stage(StageError::Conflict("a.bin".into()))
    );
    assert_eq!(fs::read(dir.join("a.bin")).unwrap(), b"someone else's file");
    assert!(e.s.st.is_none());
}

#[test]
fn size_hash_and_total_caps_are_enforced_while_streaming() {
    // Longer than declared: stop at size + 1 bytes.
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    e.t.payloads.insert("a.bin".into(), vec![7u8; 10_000_000]);
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Stage(StageError::TooLong("a.bin".into()))
    );
    assert!(
        e.t.bytes_read.get() <= P1.len() as u64 + 1 + 64 * 1024,
        "read {} bytes",
        e.t.bytes_read.get()
    );
    assert!(e.stage_entries().is_empty());
    // Shorter than declared.
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    e.t.payloads.insert("a.bin".into(), P1[..3].to_vec());
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Stage(StageError::TooShort("a.bin".into()))
    );
    // Same size, wrong bytes.
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    let mut wrong = P1.to_vec();
    wrong[0] ^= 1;
    e.t.payloads.insert("a.bin".into(), wrong);
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Stage(StageError::HashMismatch("a.bin".into()))
    );
    assert!(e.stage_entries().is_empty());
    assert!(e.h.calls.is_empty());
    // Declared total above the cap: refused before any payload fetch.
    let mut e = Env::new("stable", 5, &[("a.bin", P1), ("b.bin", P2)]);
    let pol = VerifyPolicy::new(&e.keys, 2, NOW, "stable");
    let root = e.stage_root();
    let opts = Options {
        max_total_bytes: (P1.len() + P2.len() - 1) as u64,
    };
    let r = run_with_stager(
        "stable",
        &pol,
        &mut e.t,
        &mut e.s,
        &mut e.h,
        Stager::new(&root),
        &opts,
    );
    assert_eq!(
        r.unwrap_err(),
        FlowError::Stage(StageError::TotalCapExceeded)
    );
    assert_eq!(e.t.artifact_fetches, 0);
    assert!(e.stage_entries().is_empty());
    // Exactly at the cap is accepted.
    let opts = Options {
        max_total_bytes: (P1.len() + P2.len()) as u64,
    };
    let r = run_with_stager(
        "stable",
        &pol,
        &mut e.t,
        &mut e.s,
        &mut e.h,
        Stager::new(&root),
        &opts,
    );
    assert!(r.is_ok());
}

#[cfg(unix)]
#[test]
fn stage_root_symlink_or_open_permissions_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let mut e = Env::new("stable", 5, &[("a.bin", P1)]);
    let real = e.root.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, e.stage_root()).unwrap();
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Stage(StageError::Symlink)
    );
    fs::remove_file(e.stage_root()).unwrap();
    fs::create_dir(e.stage_root()).unwrap();
    fs::set_permissions(e.stage_root(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        e.run("stable").unwrap_err(),
        FlowError::Stage(StageError::RootNotPrivate)
    );
    assert!(e.h.calls.is_empty());
}

#[test]
fn channel_key_is_injective_and_portable() {
    assert_eq!(channel_key("stable").unwrap(), "ch-stable");
    assert_eq!(channel_key("Stable").unwrap(), "ch-%53table");
    assert_eq!(channel_key("a.b").unwrap(), "ch-a%2Eb");
    assert_ne!(
        channel_key("Stable").unwrap(),
        channel_key("stable").unwrap()
    );
    assert_eq!(channel_key("a%2Eb").unwrap_err(), FlowError::BadChannel);
    for bad in ["", ".x", "a/b", "a\\b", "..", "x y", &"a".repeat(65)] {
        assert_eq!(
            channel_key(bad).unwrap_err(),
            FlowError::BadChannel,
            "{bad:?}"
        );
    }
    // Worst case length stays below common NAME_MAX (255) with the stage suffix.
    let worst = channel_key(&"A".repeat(64)).unwrap();
    assert!(worst.len() + 1 + 20 + 1 + 16 < 255);
    // Distinct sampled channels give distinct keys.
    let names = ["a", "A", "a.", "a-", "a_", "a.A", "A.a", "ab", "a.b", "a-b"];
    let keys: BTreeSet<_> = names
        .iter()
        .map(|n| channel_key(n).unwrap().to_lowercase())
        .collect();
    assert_eq!(
        keys.len(),
        names.len(),
        "keys must stay distinct even when case-folded"
    );
}
