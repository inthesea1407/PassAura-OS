mod common;
use common::*;
use pos_core::audit::AuditEvent;
use pos_gate::rollback::RollbackStore;
use pos_install::pipeline::{InstallError, Outcome, RecoveryStatus};

#[test]
fn happy_path_commits_in_order_and_leaves_no_residue() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let out = env.pipeline().install(&req(&doc, &t)).unwrap();
    assert_eq!(out, Outcome::Committed { sequence: 3 });
    assert_eq!(env.fake.runs(), 1);
    assert_eq!(env.stored_seq(), Some(3));
    assert_eq!(env.audit_events(), vec![AuditEvent::InstallCommitted]);
    assert!(!env.journal_exists());
    assert!(env.stage_list().is_empty());
}

#[test]
fn staged_file_has_the_signed_bytes_and_private_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    let doc = good_doc(1);
    let t = trusted();
    // Run with a crash right after the command so the stage still exists.
    let labels = record_labels(&Env::new());
    let n = labels.iter().position(|l| l == "command:ran").unwrap() + 1;
    let mut p = env.pipeline();
    crash_at(&mut p, n);
    assert!(matches!(p.install(&req(&doc, &t)), Err(InstallError::Crashed(_))));
    let dir = pos_install::stage::Stager::for_state(&env.paths.state);
    let mode = std::fs::metadata(dir.dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let names = dir.list();
    assert_eq!(names.len(), 1);
    assert_eq!(std::fs::read(dir.dir().join(&names[0])).unwrap(), CONTENT);
    let fmode = std::fs::metadata(dir.dir().join(&names[0])).unwrap().permissions().mode() & 0o777;
    assert_eq!(fmode, 0o600);
}

#[test]
fn hash_mismatch_is_distinct_and_leaves_no_stage_and_no_command() {
    let env = Env::new();
    std::fs::write(&env.source, b"tampered").unwrap();
    let doc = good_doc(3);
    let t = trusted();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::HashMismatch { .. }), "{err}");
    assert_eq!(env.fake.runs(), 0);
    assert!(env.stage_list().is_empty());
    assert_eq!(env.stored_seq(), None);
    assert!(!env.journal_exists());
    assert_eq!(env.audit_events(), vec![AuditEvent::InstallHashMismatch]);
}

#[test]
fn failed_install_does_not_advance_the_sequence() {
    let env = Env::new();
    *env.fake.fail.lock().unwrap() = true;
    let doc = good_doc(4);
    let t = trusted();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Backend(_)), "{err}");
    assert_eq!(env.fake.runs(), 1);
    assert_eq!(env.stored_seq(), None);
    assert_eq!(env.audit_events(), vec![AuditEvent::InstallFailed]);
    assert!(!env.journal_exists());
    assert!(env.stage_list().is_empty());
    // A later good run still works.
    *env.fake.fail.lock().unwrap() = false;
    env.pipeline().install(&req(&doc, &t)).unwrap();
    assert_eq!(env.stored_seq(), Some(4));
}

#[test]
fn rejected_requests_run_nothing_stage_nothing_and_audit_a_denial() {
    let t = trusted();
    let cases: Vec<(&str, Box<dyn Fn(&Env) -> (pos_gate::allowlist_v2::V2Allowlist, pos_gate::allowlist::Keyring, i64, &'static str)>)> = vec![
        ("unsigned", Box::new(|_| { let mut d = good_doc(3); d.signature_hex = String::new(); (d, trusted(), NOW, PKG) })),
        ("expired", Box::new(|_| (good_doc(3), trusted(), ISSUED + 999_999, PKG))),
        ("untrusted", Box::new(|_| (good_doc(3), pos_gate::allowlist::Keyring { keys: vec![] }, NOW, PKG))),
        ("lower sequence", Box::new(|e| {
            let mut s = RollbackStore::open(&e.paths.state).unwrap();
            s.accept_and_persist(9, &"b".repeat(64), Some(1)).unwrap();
            (good_doc(3), trusted(), NOW, PKG)
        })),
        ("missing package", Box::new(|_| (good_doc(3), trusted(), NOW, "not-listed"))),
        ("traversal", Box::new(|_| (good_doc(3), trusted(), NOW, "../etc/passwd"))),
        ("leading dash", Box::new(|_| (good_doc(3), trusted(), NOW, "-evil"))),
        ("space", Box::new(|_| (good_doc(3), trusted(), NOW, "a b"))),
        ("empty", Box::new(|_| (good_doc(3), trusted(), NOW, ""))),
    ];
    let _ = t;
    for (name, build) in cases {
        let env = Env::new();
        let (doc, tr, now, pkg) = build(&env);
        let r = pos_install::Request { package: pkg, doc: &doc, trusted: &tr, now };
        let before = env.stored_seq();
        let err = env.pipeline().install(&r).unwrap_err();
        assert!(
            matches!(err, InstallError::Verification(_) | InstallError::NotAllowed | InstallError::InvalidPackageName),
            "{name}: {err}"
        );
        assert_eq!(env.fake.runs(), 0, "{name}");
        assert!(env.stage_list().is_empty(), "{name}");
        assert!(!env.journal_exists(), "{name}");
        assert_eq!(env.stored_seq(), before, "{name}");
        assert_eq!(env.audit_events(), vec![AuditEvent::GateDenied], "{name}");
    }
}

#[test]
fn bad_digest_in_the_signed_entry_is_rejected_before_staging() {
    let env = Env::new();
    let doc = doc_with(1, vec![pos_gate::allowlist_v2::V2Entry { name: PKG.into(), version: None, sha256: "zz".into() }]);
    let t = trusted();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::InvalidEntry(_)), "{err}");
    assert_eq!(env.fake.runs(), 0);
}

#[test]
fn running_the_same_document_twice_is_safe_and_keeps_the_sequence() {
    let env = Env::new();
    let doc = good_doc(5);
    let t = trusted();
    env.pipeline().install(&req(&doc, &t)).unwrap();
    let digest = env.state_digest();
    env.pipeline().install(&req(&doc, &t)).unwrap();
    assert_eq!(env.stored_seq(), Some(5));
    assert_eq!(env.state_digest(), digest);
    assert_eq!(env.fake.runs(), 2);
    assert_eq!(env.count(AuditEvent::InstallCommitted), 2);
    // A lower sequence afterwards is refused.
    let old = good_doc(4);
    assert!(env.pipeline().install(&req(&old, &t)).is_err());
    assert_eq!(env.fake.runs(), 2);
}

#[test]
fn every_crash_point_recovers_to_a_defined_state() {
    let labels = record_labels(&Env::new());
    assert!(labels.len() >= 15, "expected many fault points, got {labels:?}");
    let t = trusted();
    let doc = good_doc(3);
    let mut seen_indeterminate = 0;
    let mut seen_committed = 0;
    let mut seen_failed = 0;
    for n in 1..=labels.len() {
        let env = Env::new();
        let mut p = env.pipeline();
        crash_at(&mut p, n);
        let res = p.install(&req(&doc, &t));
        let label = &labels[n - 1];
        assert!(matches!(res, Err(InstallError::Crashed(_))), "n={n} {label}: {res:?}");
        let runs_at_crash = env.fake.runs();
        // "Restart": a new pipeline recovers under the lock.
        let status = env.pipeline().recover().unwrap_or_else(|e| panic!("n={n} {label}: {e}"));
        // Recovery never runs the install command.
        assert_eq!(env.fake.runs(), runs_at_crash, "n={n} {label}: recovery ran the command");
        match status {
            RecoveryStatus::ClosedCommitted => {
                seen_committed += 1;
                assert_eq!(env.fake.runs(), 1, "n={n} {label}");
                assert_eq!(env.stored_seq(), Some(3), "n={n} {label}");
                assert_eq!(env.count(AuditEvent::InstallCommitted), 1, "n={n} {label}");
                assert!(!env.journal_exists(), "n={n} {label}");
                assert!(env.stage_list().is_empty(), "n={n} {label}");
            }
            RecoveryStatus::ClosedFailed => {
                seen_failed += 1;
                assert_eq!(env.fake.runs(), 0, "n={n} {label}");
                assert_eq!(env.stored_seq(), None, "n={n} {label}: sequence advanced without an install");
                assert_eq!(env.count(AuditEvent::InstallCommitted), 0, "n={n} {label}");
                assert!(!env.journal_exists(), "n={n} {label}");
                assert!(env.stage_list().is_empty(), "n={n} {label}");
            }
            RecoveryStatus::Indeterminate { .. } => {
                seen_indeterminate += 1;
                assert_eq!(env.stored_seq(), None, "n={n} {label}: sequence advanced on unknown outcome");
                assert!(env.journal_exists(), "n={n} {label}");
                assert_eq!(env.count(AuditEvent::InstallIndeterminate), 1, "n={n} {label}");
                assert_eq!(env.count(AuditEvent::InstallCommitted), 0, "n={n} {label}");
                // Installs stay blocked, and recovery again does not duplicate the audit.
                let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
                assert!(matches!(err, InstallError::Blocked(RecoveryStatus::Indeterminate { .. })), "n={n} {label}: {err}");
                assert_eq!(env.fake.runs(), runs_at_crash, "n={n} {label}");
                assert_eq!(env.count(AuditEvent::InstallIndeterminate), 1, "n={n} {label}");
            }
            other => panic!("n={n} {label}: unexpected {other:?}"),
        }
        // Whatever happened, the sequence never advances without a command run.
        if env.stored_seq().is_some() {
            assert!(env.fake.runs() >= 1, "n={n} {label}");
        }
        assert!(env.count(AuditEvent::InstallCommitted) <= 1, "n={n} {label}: duplicate committed audit");
    }
    assert!(seen_indeterminate >= 2, "install_started and command:ran must both be indeterminate");
    assert!(seen_committed >= 6);
    assert!(seen_failed >= 4);
}

#[test]
fn retry_after_indeterminate_is_explicit_and_commits() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let labels = record_labels(&Env::new());
    let n = labels.iter().position(|l| l == "command:ran").unwrap() + 1;
    let mut p = env.pipeline();
    crash_at(&mut p, n);
    let _ = p.install(&req(&doc, &t));
    assert_eq!(env.fake.runs(), 1);
    // Plain install is blocked; no automatic re-run.
    assert!(matches!(env.pipeline().install(&req(&doc, &t)), Err(InstallError::Blocked(_))));
    assert_eq!(env.fake.runs(), 1);
    // A different document is refused as a retry.
    let other = good_doc(4);
    let err = env.pipeline().retry(&req(&other, &t)).unwrap_err();
    assert!(matches!(err, InstallError::RetryRefused(_)), "{err}");
    assert_eq!(env.fake.runs(), 1);
    // Same document: runs the command again, then commits.
    let out = env.pipeline().retry(&req(&doc, &t)).unwrap();
    assert_eq!(out, Outcome::Committed { sequence: 3 });
    assert_eq!(env.fake.runs(), 2);
    assert_eq!(env.stored_seq(), Some(3));
    assert_eq!(env.count(AuditEvent::InstallRetried), 1);
    assert_eq!(env.count(AuditEvent::InstallCommitted), 1);
    assert!(!env.journal_exists());
    assert!(env.stage_list().is_empty());
}

#[test]
fn retry_with_a_changed_staged_file_is_refused() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let labels = record_labels(&Env::new());
    let n = labels.iter().position(|l| l == "command:ran").unwrap() + 1;
    let mut p = env.pipeline();
    crash_at(&mut p, n);
    let _ = p.install(&req(&doc, &t));
    let stage = pos_install::stage::Stager::for_state(&env.paths.state);
    let name = stage.list().remove(0);
    std::fs::write(stage.dir().join(&name), b"changed after staging").unwrap();
    let err = env.pipeline().retry(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::HashMismatch { .. }), "{err}");
    assert_eq!(env.fake.runs(), 1);
    assert_eq!(env.stored_seq(), None);
    assert!(env.journal_exists());
}

#[test]
fn abandon_clears_the_block_without_advancing_or_undoing() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let labels = record_labels(&Env::new());
    let n = labels.iter().position(|l| l == "command:ran").unwrap() + 1;
    let mut p = env.pipeline();
    crash_at(&mut p, n);
    let _ = p.install(&req(&doc, &t));
    env.pipeline().abandon().unwrap();
    assert_eq!(env.stored_seq(), None);
    assert!(!env.journal_exists());
    assert!(env.stage_list().is_empty());
    assert_eq!(env.count(AuditEvent::InstallAbandoned), 1);
    // Abandon with nothing unresolved is an error, not a silent success.
    assert!(matches!(env.pipeline().abandon(), Err(InstallError::NothingToRecover)));
    // A fresh install works again.
    env.pipeline().install(&req(&doc, &t)).unwrap();
    assert_eq!(env.stored_seq(), Some(3));
}

#[test]
fn a_crash_during_abandon_never_drops_the_block_and_abandon_can_be_resumed() {
    let doc = good_doc(3);
    let t = trusted();
    // Count the fault points that abandon itself hits.
    let probe = Env::new();
    let labels = record_labels(&Env::new());
    let cmd = labels.iter().position(|l| l == "command:ran").unwrap() + 1;
    let mut p = probe.pipeline();
    crash_at(&mut p, cmd);
    let _ = p.install(&req(&doc, &t));
    let hits = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let h2 = hits.clone();
    let mut pa = probe.pipeline();
    pa.set_fault(move |_| { *h2.lock().unwrap() += 1; false });
    pa.abandon().unwrap();
    let total = *hits.lock().unwrap();
    assert!(total >= 4, "abandon should hit several fault points, got {total}");

    for n in 1..=total {
        let env = Env::new();
        let mut p = env.pipeline();
        crash_at(&mut p, cmd);
        let _ = p.install(&req(&doc, &t));
        let mut pa = env.pipeline();
        crash_at(&mut pa, n);
        assert!(matches!(pa.abandon(), Err(InstallError::Crashed(_))), "n={n}");
        // Recovery either resumes the abandon the operator already made
        // durable, or (if abandon_requested was not durable yet) the attempt
        // is still unresolved and installs stay blocked.
        match env.pipeline().recover().unwrap() {
            RecoveryStatus::ClosedAbandoned => {}
            RecoveryStatus::Indeterminate { .. } => {
                let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
                assert!(matches!(err, InstallError::Blocked(_)), "n={n}: {err}");
                assert!(env.journal_exists(), "n={n}");
            }
            other => panic!("n={n}: unexpected {other:?}"),
        }
        // Resume: abandon (or it was already completed by recovery).
        let _ = env.pipeline().abandon();
        assert!(!env.journal_exists(), "n={n}");
        assert_eq!(env.stored_seq(), None, "n={n}");
        assert!(env.stage_list().is_empty(), "n={n}");
        assert_eq!(env.count(AuditEvent::InstallAbandoned), 1, "n={n}: audit must be exactly once");
    }
}

#[test]
fn a_held_lock_fails_fast_before_any_command() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let guard = pos_install::lock::StateLock::acquire(&env.paths.state, std::time::Duration::from_secs(1)).unwrap();
    let start = std::time::Instant::now();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Lock(_)), "{err}");
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(env.fake.runs(), 0);
    assert!(!env.journal_exists());
    drop(guard);
    env.pipeline().install(&req(&doc, &t)).unwrap();
}

#[test]
fn a_leftover_lockfile_with_no_holder_does_not_block() {
    let env = Env::new();
    std::fs::write(pos_install::lock::lock_path(&env.paths.state), b"stale").unwrap();
    let doc = good_doc(3);
    let t = trusted();
    env.pipeline().install(&req(&doc, &t)).unwrap();
}

#[test]
fn two_concurrent_installs_of_one_document_both_complete_serially() {
    let env = std::sync::Arc::new(Env::new());
    let doc = good_doc(3);
    let t = trusted();
    let mut handles = vec![];
    for _ in 0..2 {
        let env = env.clone();
        let doc = doc.clone();
        let t = t.clone();
        handles.push(std::thread::spawn(move || {
            let mut p = env.pipeline();
            p.install(&req(&doc, &t)).is_ok()
        }));
    }
    let ok: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(ok.iter().all(|x| *x), "{ok:?}");
    assert_eq!(env.stored_seq(), Some(3));
    assert_eq!(env.fake.runs(), 2);
    assert!(!env.journal_exists());
}

#[test]
fn dry_run_writes_nothing_and_does_not_create_the_lockfile() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let before: Vec<_> = std::fs::read_dir(env.dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    let rep = env.pipeline().dry_run(&req(&doc, &t)).unwrap();
    assert_eq!(rep.sequence, 3);
    let after: Vec<_> = std::fs::read_dir(env.dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(before, after);
    assert!(!pos_install::lock::lock_path(&env.paths.state).exists());
    assert_eq!(env.fake.runs(), 0);
    // A bad hash is reported by the dry run too.
    std::fs::write(&env.source, b"other").unwrap();
    assert!(matches!(env.pipeline().dry_run(&req(&doc, &t)), Err(InstallError::HashMismatch { .. })));
}

#[test]
fn symlinked_or_loose_stage_directory_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let stage = pos_install::stage::Stager::for_state(&env.paths.state);
    let elsewhere = env.dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, stage.dir()).unwrap();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Stage(_)), "{err}");
    assert_eq!(env.fake.runs(), 0);
    assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    assert_eq!(env.stored_seq(), None);
    std::fs::remove_file(stage.dir()).unwrap();
    std::fs::create_dir(stage.dir()).unwrap();
    std::fs::set_permissions(stage.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Stage(_)), "{err}");
    assert_eq!(env.fake.runs(), 0);
}

#[test]
fn symlinked_package_source_is_refused() {
    let env = Env::new();
    let link = env.dir.path().join("link.deb");
    std::os::unix::fs::symlink(&env.source, &link).unwrap();
    let doc = good_doc(3);
    let t = trusted();
    let mut p = pos_install::Pipeline::new(
        env.paths.clone(),
        env.fake.clone(),
        pos_install::LocalFileFetcher { path: link },
        pos_gate::rollback::StdFileOps,
    );
    let err = p.install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Fetch(_)), "{err}");
    assert_eq!(env.fake.runs(), 0);
    assert_eq!(env.stored_seq(), None);
}

#[test]
fn a_crash_during_retry_keeps_protection_or_completes_without_duplicates() {
    let doc = good_doc(3);
    let t = trusted();
    let labels = record_labels(&Env::new());
    let cmd = labels.iter().position(|l| l == "command:ran").unwrap() + 1;
    let make = || {
        let env = Env::new();
        let mut p = env.pipeline();
        crash_at(&mut p, cmd);
        let _ = p.install(&req(&doc, &t));
        env
    };
    // Number of fault points a retry hits.
    let probe = make();
    let hits = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let h2 = hits.clone();
    let mut p = probe.pipeline();
    p.set_fault(move |_| { *h2.lock().unwrap() += 1; false });
    p.retry(&req(&doc, &t)).unwrap();
    let total = *hits.lock().unwrap();
    assert!(total >= 10, "{total}");
    for n in 1..=total {
        let env = make();
        let mut p = env.pipeline();
        crash_at(&mut p, n);
        assert!(matches!(p.retry(&req(&doc, &t)), Err(InstallError::Crashed(_))), "n={n}");
        let runs = env.fake.runs();
        let status = env.pipeline().recover().unwrap_or_else(|e| panic!("n={n}: {e}"));
        assert_eq!(env.fake.runs(), runs, "n={n}: recovery re-ran the command");
        match status {
            RecoveryStatus::Indeterminate { .. } => {
                assert_eq!(env.stored_seq(), None, "n={n}");
                assert!(env.journal_exists(), "n={n}");
                // Still resolvable: retry again completes.
                env.pipeline().retry(&req(&doc, &t)).unwrap_or_else(|e| panic!("n={n}: {e}"));
                assert_eq!(env.stored_seq(), Some(3), "n={n}");
            }
            RecoveryStatus::ClosedCommitted => {
                assert_eq!(env.stored_seq(), Some(3), "n={n}");
                assert_eq!(env.fake.runs(), 2, "n={n}");
            }
            other => panic!("n={n}: unexpected {other:?}"),
        }
        assert_eq!(env.count(AuditEvent::InstallCommitted), 1, "n={n}");
        // One record for the first attempt; a second only if the retry attempt's
        // own outcome was left unknown by the crash (a new attempt, a new record).
        assert!((1..=2).contains(&env.count(AuditEvent::InstallIndeterminate)), "n={n}");
        assert!(env.count(AuditEvent::InstallRetried) <= 2, "n={n}");
        assert!(!env.journal_exists(), "n={n}");
        assert!(env.stage_list().is_empty(), "n={n}");
    }
}

#[test]
fn a_corrupt_journal_blocks_before_any_command() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    let j = pos_install::journal::Journal::for_state(&env.paths.state);
    std::fs::write(j.path(), b"{\"attempt\":\"a1\",\"step\":\"verif").unwrap();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Journal(_)), "{err}");
    assert_eq!(env.fake.runs(), 0);
    assert_eq!(env.stored_seq(), None);
}

#[test]
fn corrupt_rollback_state_blocks_before_any_command() {
    let env = Env::new();
    let doc = good_doc(3);
    let t = trusted();
    std::fs::write(&env.paths.state, b"").unwrap();
    assert!(env.pipeline().install(&req(&doc, &t)).is_err());
    std::fs::write(&env.paths.state, b"garbage").unwrap();
    assert!(env.pipeline().install(&req(&doc, &t)).is_err());
    std::fs::write(&env.paths.state, b"{\"last_seq\":").unwrap();
    assert!(env.pipeline().install(&req(&doc, &t)).is_err());
    assert_eq!(env.fake.runs(), 0);
}

fn fail_as(env: &Env, code: Option<i32>, msg: &str) {
    *env.fake.fail_as.lock().unwrap() = Some((code, msg.to_string()));
}

#[test]
fn proven_not_started_is_a_definite_failure_and_closes_cleanly() {
    let env = Env::new();
    fail_as(&env, None, "NOT_STARTED");
    let doc = good_doc(3);
    let t = trusted();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Backend(_)), "{err}");
    assert_eq!(env.stored_seq(), None);
    assert!(!env.journal_exists());
    assert_eq!(env.audit_events(), vec![AuditEvent::InstallFailed]);
}

#[test]
fn nonzero_exit_fails_closed_without_advancing_and_never_blocks_a_new_run() {
    let env = Env::new();
    fail_as(&env, Some(100), "dpkg: error processing package");
    let doc = good_doc(3);
    let t = trusted();
    let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
    assert!(matches!(err, InstallError::Backend(_)), "{err}");
    assert_eq!(env.stored_seq(), None);
    assert!(!env.journal_exists());
    assert_eq!(env.count(AuditEvent::InstallFailed), 1);
    *env.fake.fail_as.lock().unwrap() = None;
    env.pipeline().install(&req(&doc, &t)).unwrap();
    assert_eq!(env.stored_seq(), Some(3));
}

#[test]
fn unknown_runner_failure_after_spawn_stays_indeterminate_and_blocks() {
    for msg in ["wait failed: interrupted", "killed by signal", "not started: imitation from child output"] {
        let env = Env::new();
        fail_as(&env, None, msg);
        let doc = good_doc(3);
        let t = trusted();
        let err = env.pipeline().install(&req(&doc, &t)).unwrap_err();
        assert!(matches!(err, InstallError::Blocked(RecoveryStatus::Indeterminate { .. })), "{msg}: {err}");
        assert_eq!(env.stored_seq(), None, "{msg}");
        assert!(env.journal_exists(), "{msg}");
        assert_eq!(env.count(AuditEvent::InstallIndeterminate), 1, "{msg}");
        assert_eq!(env.count(AuditEvent::InstallFailed), 0, "{msg}");
        *env.fake.fail_as.lock().unwrap() = None;
        // No automatic re-run; an explicit retry is the only way forward.
        assert!(matches!(env.pipeline().install(&req(&doc, &t)), Err(InstallError::Blocked(_))));
        assert_eq!(env.fake.runs(), 1);
        assert_eq!(env.count(AuditEvent::InstallIndeterminate), 1, "{msg}: no duplicate audit");
        env.pipeline().retry(&req(&doc, &t)).unwrap();
        assert_eq!(env.stored_seq(), Some(3));
    }
}
