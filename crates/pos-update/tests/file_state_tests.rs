use pos_update::file_state::*;
use pos_update::flow::StateStore;
use pos_update::AcceptedState;
use std::io::ErrorKind;
use std::time::Duration;

fn st(channel: &str, seq: u64, d: u8) -> AcceptedState {
    AcceptedState { channel: channel.into(), sequence: seq, digest: [d; 32] }
}
const T: Duration = Duration::from_millis(50);

#[test]
fn load_none_then_store_and_reload() {
    let d = tempfile::tempdir().unwrap();
    let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
    assert_eq!(s.load("stable").unwrap(), None);
    s.store(&st("stable", 7, 9)).unwrap();
    assert_eq!(s.load("stable").unwrap(), Some(st("stable", 7, 9)));
    drop(s);
    let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
    assert_eq!(s.load("stable").unwrap(), Some(st("stable", 7, 9)));
    assert!(s.list_orphan_temps().unwrap().is_empty());
}

#[test]
fn lock_is_exclusive_bounded_and_released_on_drop() {
    let d = tempfile::tempdir().unwrap();
    let a = FileStateStore::acquire(d.path(), "stable", T).unwrap();
    let t0 = std::time::Instant::now();
    match FileStateStore::acquire(d.path(), "stable", T) {
        Err(FileStateError::Held { waited, .. }) => assert!(waited >= T),
        other => panic!("expected Held, got {:?}", other.map(|_| ())),
    }
    assert!(t0.elapsed() < Duration::from_secs(5), "wait is bounded");
    // A different channel is independent.
    let _b = FileStateStore::acquire(d.path(), "beta", T).unwrap();
    drop(a);
    assert!(FileStateStore::acquire(d.path(), "stable", T).is_ok());
}

#[test]
fn leftover_lock_file_with_no_holder_does_not_block() {
    let d = tempfile::tempdir().unwrap();
    drop(FileStateStore::acquire(d.path(), "stable", T).unwrap());
    assert!(d.path().join("ch-stable.lock").exists(), "lock file is never deleted");
    assert!(FileStateStore::acquire(d.path(), "stable", T).is_ok());
}

#[test]
fn channels_with_case_or_dots_never_share_files() {
    let d = tempfile::tempdir().unwrap();
    let mut a = FileStateStore::acquire(d.path(), "Stable", T).unwrap();
    let mut b = FileStateStore::acquire(d.path(), "stable", T).unwrap();
    a.store(&st("Stable", 1, 1)).unwrap();
    assert_eq!(b.load("stable").unwrap(), None);
    assert_ne!(a.state_path(), b.state_path());
    assert!(FileStateStore::acquire(d.path(), "../x", T).is_err());
}

#[test]
fn wrong_channel_calls_and_foreign_or_corrupt_files_are_rejected() {
    let d = tempfile::tempdir().unwrap();
    let mut s = FileStateStore::acquire(d.path(), "stable", T).unwrap();
    assert_eq!(s.load("beta").unwrap_err().kind(), ErrorKind::InvalidInput);
    assert_eq!(s.store(&st("beta", 1, 1)).unwrap_err().kind(), ErrorKind::InvalidInput);
    let p = s.state_path();
    for bad in [
        &b"garbage"[..],
        b"pos-update-state-v1\nchannel=stable\nsequence=1\ndigest=00\n",
        b"pos-update-state-v1\nchannel=beta\nsequence=1\ndigest=0000000000000000000000000000000000000000000000000000000000000000\n",
        b"pos-update-state-v1\nchannel=stable\nsequence=+1\ndigest=0000000000000000000000000000000000000000000000000000000000000000\n",
        b"pos-update-state-v1\nchannel=stable\nsequence=1\ndigest=0000000000000000000000000000000000000000000000000000000000000000\nextra\n",
    ] {
        std::fs::write(&p, bad).unwrap();
        assert_eq!(s.load("stable").unwrap_err().kind(), ErrorKind::InvalidData);
    }
    std::fs::write(&p, vec![b'x'; 4096]).unwrap();
    assert_eq!(s.load("stable").unwrap_err().kind(), ErrorKind::InvalidData);
}
