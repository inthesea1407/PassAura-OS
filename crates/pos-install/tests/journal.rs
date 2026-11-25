use pos_install::journal::{fold, parse, Journal, JournalError};

const BEGUN: &str = r#"{"attempt":"a1","step":"begun","package":"p","sequence":1,"digest":"d","sha256":"s","source":"x","parent":null}"#;

fn lines(ls: &[&str]) -> Vec<u8> {
    let mut s = ls.join("\n");
    s.push('\n');
    s.into_bytes()
}

fn is_corrupt<T: std::fmt::Debug>(r: Result<T, JournalError>) -> bool {
    matches!(r, Err(JournalError::Corrupt(_)))
}

#[test]
fn a_valid_journal_folds() {
    let b = lines(&[
        BEGUN,
        r#"{"attempt":"a1","step":"verified"}"#,
        r#"{"attempt":"a1","step":"fetched"}"#,
    ]);
    let a = fold(&parse(&b).unwrap()).unwrap();
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].rank, 2);
}

#[test]
fn truncated_last_line_is_rejected() {
    let mut b = lines(&[BEGUN, r#"{"attempt":"a1","step":"verified"}"#]);
    b.truncate(b.len() - 6);
    assert!(is_corrupt(parse(&b)));
    // Cut in the middle of the first line too.
    assert!(is_corrupt(parse(&BEGUN.as_bytes()[..30])));
}

#[test]
fn garbage_and_wrong_shapes_are_rejected() {
    assert!(is_corrupt(parse(b"not json at all\n")));
    assert!(is_corrupt(parse(&[0xff, 0xfe, b'\n'])));
    assert!(is_corrupt(parse(b"{\"attempt\":\"a1\"}\n")));
    assert!(is_corrupt(parse(
        b"{\"attempt\":\"a1\",\"step\":\"warp_drive\"}\n"
    )));
    assert!(is_corrupt(parse(b"\n")));
    assert!(is_corrupt(parse(b"[]\n")));
}

#[test]
fn duplicate_skipped_and_out_of_order_steps_are_rejected() {
    let v = r#"{"attempt":"a1","step":"verified"}"#;
    let f = r#"{"attempt":"a1","step":"fetched"}"#;
    let s = r#"{"attempt":"a1","step":"staged","file":"x.deb"}"#;
    let st = r#"{"attempt":"a1","step":"install_started"}"#;
    assert!(is_corrupt(fold(&parse(&lines(&[BEGUN, v, v])).unwrap()))); // duplicate
    assert!(is_corrupt(fold(&parse(&lines(&[BEGUN, f])).unwrap()))); // skipped
    assert!(is_corrupt(fold(&parse(&lines(&[BEGUN, v, s])).unwrap()))); // skipped
    assert!(is_corrupt(fold(
        &parse(&lines(&[BEGUN, v, f, st])).unwrap()
    ))); // skipped staged
    assert!(is_corrupt(fold(&parse(&lines(&[v])).unwrap()))); // before begun
    assert!(is_corrupt(fold(&parse(&lines(&[BEGUN, BEGUN])).unwrap()))); // duplicate attempt
    assert!(is_corrupt(fold(
        &parse(&lines(&[BEGUN, r#"{"attempt":"a1","step":"installed"}"#])).unwrap()
    )));
    assert!(is_corrupt(fold(
        &parse(&lines(&[
            BEGUN,
            r#"{"attempt":"a1","step":"audit_written","seq":1}"#
        ]))
        .unwrap()
    )));
    assert!(is_corrupt(fold(
        &parse(&lines(&[
            BEGUN,
            v,
            f,
            r#"{"attempt":"a1","step":"staged","file":"../x.deb"}"#
        ]))
        .unwrap()
    )));
}

#[test]
fn a_zero_length_journal_means_no_journal() {
    assert!(parse(b"").unwrap().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::for_state(&dir.path().join("s.json"));
    std::fs::write(j.path(), b"").unwrap();
    assert!(j.load().unwrap().is_empty());
}

#[test]
fn append_refuses_an_illegal_step_and_leaves_the_file_unchanged() {
    use pos_install::journal::{Entry, Step};
    let dir = tempfile::tempdir().unwrap();
    let j = Journal::for_state(&dir.path().join("s.json"));
    let e = |s| Entry {
        attempt: "a1".into(),
        step: s,
    };
    j.append(&e(Step::Begun {
        package: "p".into(),
        sequence: 1,
        digest: "d".into(),
        sha256: "s".into(),
        source: "x".into(),
        parent: None,
    }))
    .unwrap();
    let before = std::fs::read(j.path()).unwrap();
    assert!(j.append(&e(Step::Installed)).is_err());
    assert!(j.append(&e(Step::Fetched)).is_err());
    assert_eq!(std::fs::read(j.path()).unwrap(), before);
    j.append(&e(Step::Verified)).unwrap();
    assert!(j.append(&e(Step::Verified)).is_err());
}
