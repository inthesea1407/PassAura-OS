use super::*;
use std::io::Cursor;

fn tar_with(name: &str, content: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut v = h.to_vec();
    v.extend_from_slice(content);
    v.resize(v.len().div_ceil(512) * 512, 0);
    v.extend_from_slice(&[0u8; 1024]);
    v
}

fn member(name: &str, data: &[u8]) -> Vec<u8> {
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
    assert_eq!(v.len(), 60);
    v.extend_from_slice(data);
    if data.len() % 2 == 1 {
        v.push(b'\n');
    }
    v
}

fn deb(control_member: &str, control_tar: &[u8]) -> Vec<u8> {
    let mut v = b"!<arch>\n".to_vec();
    v.extend(member("debian-binary", b"2.0\n"));
    v.extend(member(control_member, control_tar));
    v.extend(member("data.tar.xz", &[1, 2, 3]));
    v
}

const CTRL: &[u8] =
    b"Package: curl\nVersion: 7.88.1-10\nArchitecture: amd64\nDescription: x\n more\n";

fn plain() -> Vec<u8> {
    deb("control.tar", &tar_with("./control", CTRL))
}

fn id(b: &[u8]) -> Result<DebIdentity, DebError> {
    read_identity(&mut Cursor::new(b.to_vec()))
}

#[test]
fn reads_plain_control_tar() {
    let i = id(&plain()).unwrap();
    assert_eq!(i.package, "curl");
    assert_eq!(i.version, "7.88.1-10");
    assert_eq!(i.architecture.as_deref(), Some("amd64"));
}

#[test]
fn reads_gzip_control_tar() {
    use flate2::{write::GzEncoder, Compression};
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(&tar_with("control", CTRL)).unwrap();
    let gz = e.finish().unwrap();
    assert_eq!(id(&deb("control.tar.gz", &gz)).unwrap().package, "curl");
}

#[test]
fn xz_and_zstd_real_streams_decode() {
    // Streams produced by the system tools when available (CI runners have xz and zstd).
    for (tool, member_name) in [("xz", "control.tar.xz"), ("zstd", "control.tar.zst")] {
        let tar = tar_with("./control", CTRL);
        let mut child = match std::process::Command::new(tool)
            .arg("-c")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                // Locally a tool may be missing; CI must have both, so a missing tool fails there.
                assert!(
                    std::env::var_os("CI").is_none(),
                    "{tool} missing in CI: {e}"
                );
                continue;
            }
        };
        let mut stdin = child.stdin.take().unwrap();
        let t = tar.clone();
        let w = std::thread::spawn(move || stdin.write_all(&t));
        let out = child.wait_with_output().unwrap();
        w.join().unwrap().unwrap();
        assert!(out.status.success());
        assert_eq!(
            id(&deb(member_name, &out.stdout)).unwrap().version,
            "7.88.1-10",
            "{tool}"
        );
    }
}

#[test]
fn check_requires_name_and_optional_version() {
    let i = id(&plain()).unwrap();
    assert!(check_identity(&i, "curl", None).is_ok());
    assert!(check_identity(&i, "curl", Some("7.88.1-10")).is_ok());
    assert!(matches!(
        check_identity(&i, "wget", None),
        Err(DebError::NameMismatch { .. })
    ));
    assert!(matches!(
        check_identity(&i, "curl", Some("7.88.1-11")),
        Err(DebError::VersionMismatch { .. })
    ));
    // exact comparison: case and whitespace matter
    assert!(matches!(
        check_identity(&i, "Curl", None),
        Err(DebError::NameMismatch { .. })
    ));
}

#[test]
fn duplicate_and_missing_fields_are_refused() {
    let dup = deb(
        "control.tar",
        &tar_with("./control", b"Package: curl\nPackage: wget\nVersion: 1\n"),
    );
    assert_eq!(id(&dup), Err(DebError::DuplicateField("Package")));
    let dupv = deb(
        "control.tar",
        &tar_with("./control", b"Package: curl\nVersion: 1\nVersion: 2\n"),
    );
    assert_eq!(id(&dupv), Err(DebError::DuplicateField("Version")));
    let nov = deb("control.tar", &tar_with("./control", b"Package: curl\n"));
    assert_eq!(id(&nov), Err(DebError::MissingField("Version")));
    let empty = deb(
        "control.tar",
        &tar_with("./control", b"Package:\nVersion: 1\n"),
    );
    assert_eq!(id(&empty), Err(DebError::MissingField("Package")));
}

#[test]
fn a_package_field_after_the_paragraph_does_not_count() {
    let c = b"Package: curl\nVersion: 1\n\nPackage: evil\n";
    assert_eq!(
        id(&deb("control.tar", &tar_with("./control", c)))
            .unwrap()
            .package,
        "curl"
    );
}

#[test]
fn folded_line_cannot_smuggle_a_field() {
    let c = b"Description: a\n Package: evil\nPackage: curl\nVersion: 1\n";
    assert_eq!(
        id(&deb("control.tar", &tar_with("./control", c)))
            .unwrap()
            .package,
        "curl"
    );
}

#[test]
fn structural_errors_fail_closed() {
    assert_eq!(id(b""), Err(DebError::NotAnArArchive));
    assert_eq!(id(b"not a deb at all"), Err(DebError::NotAnArArchive));
    let mut no_control = b"!<arch>\n".to_vec();
    no_control.extend(member("debian-binary", b"2.0\n"));
    assert_eq!(id(&no_control), Err(DebError::NoControlMember));
    assert_eq!(
        id(&deb("control.tar.bz2", b"x")),
        Err(DebError::UnsupportedCompression)
    );
    assert_eq!(
        id(&deb("control.tar.gz", b"not gzip")),
        Err(DebError::BadCompressedData)
    );
    assert_eq!(
        id(&deb("control.tar", &tar_with("other", CTRL))),
        Err(DebError::NoControlFile)
    );
    let mut trunc = plain();
    trunc.truncate(trunc.len() - 80);
    assert!(id(&trunc).is_err());
}

#[test]
fn size_caps_are_enforced() {
    let big = vec![b'a'; (MAX_CONTROL_FILE + 1) as usize];
    let mut c = b"Package: curl\nVersion: 1\nX: ".to_vec();
    c.extend(big);
    assert_eq!(
        id(&deb("control.tar", &tar_with("./control", &c))),
        Err(DebError::ControlTooLarge)
    );
    // a bomb: gzip of far more than the output cap
    use flate2::{write::GzEncoder, Compression};
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    e.write_all(&vec![0u8; (MAX_CONTROL_TAR as usize) + 4096])
        .unwrap();
    let gz = e.finish().unwrap();
    assert!(gz.len() < 100_000);
    assert_eq!(
        id(&deb("control.tar.gz", &gz)),
        Err(DebError::BadCompressedData)
    );
}

#[test]
fn check_staged_deb_reads_a_file() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("a.deb");
    std::fs::write(&p, plain()).unwrap();
    assert!(check_staged_deb(&p, "curl", Some("7.88.1-10")).is_ok());
    assert!(matches!(
        check_staged_deb(&p, "wget", None),
        Err(DebError::NameMismatch { .. })
    ));
    assert!(matches!(
        check_staged_deb(&d.path().join("missing.deb"), "curl", None),
        Err(DebError::Io(_))
    ));
}
