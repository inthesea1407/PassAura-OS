use ed25519_dalek::SigningKey;

use pos_gate::allowlist::{AllowlistDoc, KeyEntry, Keyring, PackageEntry};
use pos_gate::linux_backend::{
    AptDpkgBackend, CommandOutput, CommandRunner, FlatpakBackend,
    InstallMode, PackageBackend, PackageBackendError, PlannedCommand,
};

struct FakeRunner {
    calls: Vec<PlannedCommand>,
    result: Result<CommandOutput, String>,
}

impl FakeRunner {
    fn successful() -> Self {
        Self {
            calls: Vec::new(),
            result: Ok(CommandOutput {
                success: true,
                code: Some(0),
                message: String::new(),
            }),
        }
    }

    fn failing() -> Self {
        Self {
            calls: Vec::new(),
            result: Ok(CommandOutput {
                success: false,
                code: Some(42),
                message: "simulated failure".into(),
            }),
        }
    }
}

impl CommandRunner for FakeRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
    ) -> Result<CommandOutput, String> {
        self.calls.push(PlannedCommand {
            program: program.into(),
            args: args.to_vec(),
        });

        self.result.clone()
    }
}

struct SignedFixture {
    doc: AllowlistDoc,
    keys: Keyring,
}

fn fixture() -> SignedFixture {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let mut doc = AllowlistDoc {
        signed_by: "test-key".into(),
        signature_hex: String::new(),
        issued_at: 100,
        expires_at: 500,
        packages: vec![
            PackageEntry { name: "curl".into(), version: "8".into() },
            PackageEntry { name: "org.example.App".into(), version: "1".into() },
        ],
    };
    doc.sign(&key);
    SignedFixture {
        doc,
        keys: Keyring {
            keys: vec![KeyEntry {
                key_id: "test-key".into(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            }],
        },
    }
}

#[test]
fn apt_allowed_install_uses_exact_argv() {
    let fixture = fixture();
    let runner = FakeRunner::successful();
    let mut backend = AptDpkgBackend::new(runner);

    let report = backend
        .install(
            "curl",
            &fixture.doc,
            &fixture.keys,
            200,
            InstallMode::Apply,
        )
        .unwrap();

    assert!(report.executed);
    assert_eq!(
        report.command,
        PlannedCommand {
            program: "apt-get".into(),
            args: vec![
                "install".into(),
                "--no-install-recommends".into(),
                "-y".into(),
                "--".into(),
                "curl".into(),
            ],
        }
    );

    assert_eq!(backend.runner().calls, vec![report.command]);
}

#[test]
fn flatpak_allowed_install_uses_exact_argv() {
    let fixture = fixture();
    let runner = FakeRunner::successful();
    let mut backend = FlatpakBackend::new(runner, "flathub").unwrap();

    let report = backend
        .install(
            "org.example.App",
            &fixture.doc,
            &fixture.keys,
            200,
            InstallMode::Apply,
        )
        .unwrap();

    assert!(report.executed);
    assert_eq!(
        report.command,
        PlannedCommand {
            program: "flatpak".into(),
            args: vec![
                "install".into(),
                "--noninteractive".into(),
                "--".into(),
                "flathub".into(),
                "org.example.App".into(),
            ],
        }
    );

    assert_eq!(backend.runner().calls, vec![report.command]);
}

#[test]
fn disallowed_package_runs_zero_commands() {
    let fixture = fixture();
    let runner = FakeRunner::successful();
    let mut backend = AptDpkgBackend::new(runner);

    let result = backend.install(
        "not-allowlisted",
        &fixture.doc,
        &fixture.keys,
        200,
        InstallMode::Apply,
    );

    assert_eq!(result, Err(PackageBackendError::PackageNotAllowed));
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn apt_injection_attempts_are_rejected_before_execution() {
    let fixture = fixture();

    let attempts = [
        "curl; malicious",
        "curl\nmalicious",
        "curl with spaces",
        "-curl",
        "../curl",
        "dir/curl",
        "dir\\curl",
        "curl&&malicious",
        "curl|malicious",
        "curl$(malicious)",
    ];

    for attempt in attempts {
        let runner = FakeRunner::successful();
        let mut backend = AptDpkgBackend::new(runner);

        let result = backend.install(
            attempt,
            &fixture.doc,
            &fixture.keys,
            200,
            InstallMode::Apply,
        );

        assert_eq!(
            result,
            Err(PackageBackendError::InvalidPackageName),
            "attempt: {attempt:?}"
        );
        assert!(backend.runner().calls.is_empty());
    }
}

#[test]
fn flatpak_invalid_remote_rejected_at_construction() {
    assert!(FlatpakBackend::new(FakeRunner::successful(), "-bad").is_err());
    assert!(FlatpakBackend::new(FakeRunner::successful(), "bad remote").is_err());
    assert!(FlatpakBackend::new(FakeRunner::successful(), "remote;bad").is_err());
}

#[test]
fn flatpak_invalid_app_id_rejected_before_execution() {
    let fixture = fixture();

    let attempts = [
        "not-an-app-id",
        "org.example.App;evil",
        "org.example.App with spaces",
        "-org.example.App",
        "org/example/App",
        "org..example.App",
    ];

    for attempt in attempts {
        let runner = FakeRunner::successful();
        let mut backend = FlatpakBackend::new(runner, "flathub").unwrap();

        let result = backend.install(
            attempt,
            &fixture.doc,
            &fixture.keys,
            200,
            InstallMode::Apply,
        );

        assert_eq!(
            result,
            Err(PackageBackendError::InvalidFlatpakAppId),
            "attempt: {attempt:?}"
        );
        assert!(backend.runner().calls.is_empty());
    }
}

#[test]
fn expired_allowlist_rejected_before_execution() {
    let fixture = fixture();
    let runner = FakeRunner::successful();
    let mut backend = AptDpkgBackend::new(runner);

    let result = backend.install(
        "curl",
        &fixture.doc,
        &fixture.keys,
        500,
        InstallMode::Apply,
    );

    assert!(matches!(
        result,
        Err(PackageBackendError::AllowlistVerification(_))
    ));
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn unsigned_allowlist_rejected_before_execution() {
    let fixture = fixture();
    let mut unsigned = fixture.doc.clone();
    unsigned.signature_hex = String::new();

    let runner = FakeRunner::successful();
    let mut backend = AptDpkgBackend::new(runner);

    let result = backend.install(
        "curl",
        &unsigned,
        &fixture.keys,
        200,
        InstallMode::Apply,
    );

    assert!(matches!(
        result,
        Err(PackageBackendError::AllowlistVerification(_))
    ));
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn runner_failure_surfaces_typed_error() {
    let fixture = fixture();
    let runner = FakeRunner::failing();
    let mut backend = AptDpkgBackend::new(runner);

    let result = backend.install(
        "curl",
        &fixture.doc,
        &fixture.keys,
        200,
        InstallMode::Apply,
    );

    assert!(matches!(
        result,
        Err(PackageBackendError::RunnerFailure {
            code: Some(42),
            ..
        })
    ));

    assert_eq!(backend.runner().calls.len(), 1);
}

#[test]
fn dry_run_builds_command_without_running_it() {
    let fixture = fixture();
    let runner = FakeRunner::successful();
    let mut backend = AptDpkgBackend::new(runner);

    let report = backend
        .install(
            "curl",
            &fixture.doc,
            &fixture.keys,
            200,
            InstallMode::DryRun,
        )
        .unwrap();

    assert!(!report.executed);
    assert_eq!(report.command.program, "apt-get");
    assert_eq!(report.command.args.last().unwrap(), "curl");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn flatpak_dry_run_does_not_execute() {
    let fixture = fixture();
    let runner = FakeRunner::successful();
    let mut backend = FlatpakBackend::new(runner, "flathub").unwrap();

    let report = backend
        .install(
            "org.example.App",
            &fixture.doc,
            &fixture.keys,
            200,
            InstallMode::DryRun,
        )
        .unwrap();

    assert!(!report.executed);
    assert_eq!(report.command.program, "flatpak");
    assert!(backend.runner().calls.is_empty());
}
