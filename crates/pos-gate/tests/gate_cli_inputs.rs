use std::process::Command;

fn gate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pos-gate"))
}

#[test]
fn missing_file_list_fails_closed() {
    let out = gate().args(["somepkg", "/nonexistent/files-list"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_desktop_entry_fails_closed() {
    let dir = std::env::temp_dir().join(format!("pos-gate-in-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("files");
    std::fs::write(&list, "/usr/bin/harmless\n").unwrap();
    let out = gate().arg("somepkg").arg(&list).arg("/nonexistent/x.desktop").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn readable_inputs_for_harmless_package_allow() {
    let dir = std::env::temp_dir().join(format!("pos-gate-ok-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("files");
    std::fs::write(&list, "/usr/bin/harmless\n").unwrap();
    let out = gate().arg("harmless").arg(&list).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}
