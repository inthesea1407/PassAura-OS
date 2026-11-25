mod common;
use common::*;
use pos_gate::linux_backend::{
    AptDpkgBackend, CommandOutput, CommandRunner, FlatpakBackend, InstallMode, PackageBackend,
    PackageBackendError,
};
use std::path::Path;

/// A real (minimal) .deb whose control data matches the allowlist entry, in a temp dir.
fn staged_deb(entry_version: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("a.deb");
    std::fs::write(
        &p,
        pos_gate::deb_identity::build_minimal_deb(PKG, entry_version),
    )
    .unwrap();
    (d, p)
}

#[derive(Default)]
struct Rec {
    calls: Vec<(String, Vec<String>)>,
}
impl CommandRunner for Rec {
    fn run(&mut self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
        self.calls.push((program.to_string(), args.to_vec()));
        Ok(CommandOutput {
            success: true,
            code: Some(0),
            message: String::new(),
        })
    }
}

#[test]
fn dpkg_exact_file_command_is_fixed_and_absolute() {
    let doc = good_doc(1);
    let t = trusted();
    let mut b = AptDpkgBackend::new(Rec::default());
    let (_d, deb) = staged_deb("14.1.0");
    let r = b
        .install_staged_file(PKG, &deb, &doc, &t, NOW, None, InstallMode::Apply)
        .unwrap();
    assert!(r.executed);
    assert_eq!(
        b.runner().calls,
        vec![(
            "dpkg".to_string(),
            vec![
                "-i".to_string(),
                "--".to_string(),
                deb.to_str().unwrap().to_string()
            ]
        )]
    );
}

#[test]
fn dpkg_exact_file_refuses_relative_unlisted_bad_name_and_bad_signature() {
    let doc = good_doc(1);
    let t = trusted();
    let mut b = AptDpkgBackend::new(Rec::default());
    assert_eq!(
        b.install_staged_file(
            PKG,
            Path::new("rel/a.deb"),
            &doc,
            &t,
            NOW,
            None,
            InstallMode::Apply
        )
        .unwrap_err(),
        PackageBackendError::InvalidStagedPath
    );
    assert_eq!(
        b.install_staged_file(
            "other",
            Path::new("/s/a.deb"),
            &doc,
            &t,
            NOW,
            None,
            InstallMode::Apply
        )
        .unwrap_err(),
        PackageBackendError::PackageNotAllowed
    );
    assert_eq!(
        b.install_staged_file(
            "-x",
            Path::new("/s/a.deb"),
            &doc,
            &t,
            NOW,
            None,
            InstallMode::Apply
        )
        .unwrap_err(),
        PackageBackendError::InvalidPackageName
    );
    let mut bad = good_doc(1);
    bad.signature_hex = String::new();
    assert!(matches!(
        b.install_staged_file(
            PKG,
            Path::new("/s/a.deb"),
            &bad,
            &t,
            NOW,
            None,
            InstallMode::Apply
        ),
        Err(PackageBackendError::AllowlistVerification(_))
    ));
    assert!(b.runner().calls.is_empty());
}

#[test]
fn dry_run_builds_but_does_not_run_and_flatpak_is_unsupported() {
    let doc = good_doc(1);
    let t = trusted();
    let mut b = AptDpkgBackend::new(Rec::default());
    let (_d, deb) = staged_deb("14.1.0");
    let r = b
        .install_staged_file(PKG, &deb, &doc, &t, NOW, None, InstallMode::DryRun)
        .unwrap();
    assert!(!r.executed);
    assert!(b.runner().calls.is_empty());
    let mut f = FlatpakBackend::new(Rec::default(), "flathub").unwrap();
    assert_eq!(
        f.install_staged_file(
            "org.app.X",
            Path::new("/s/a.deb"),
            &doc,
            &t,
            NOW,
            None,
            InstallMode::Apply
        )
        .unwrap_err(),
        PackageBackendError::ExactFileUnsupported
    );
}

#[test]
fn the_by_name_path_is_unchanged() {
    let doc = good_doc(1);
    let t = trusted();
    let mut b = AptDpkgBackend::new(Rec::default());
    b.install(PKG, &doc, &t, NOW, None, InstallMode::Apply)
        .unwrap();
    assert_eq!(
        b.runner().calls[0],
        (
            "apt-get".to_string(),
            ["install", "--no-install-recommends", "-y", "--", PKG]
                .map(String::from)
                .to_vec()
        )
    );
}
