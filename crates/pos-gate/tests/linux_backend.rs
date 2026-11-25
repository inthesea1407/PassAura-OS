use ed25519_dalek::SigningKey;

use ed25519_dalek::Signer;
use pos_gate::allowlist::{KeyEntry, Keyring};
use pos_gate::allowlist_v2::{
    canonical_digest_hex, canonical_payload_bytes, derive_key_id, V2Allowlist, V2Entry, V2Key,
    V2Keyring,
};
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
    doc: V2Allowlist,
    keys: Keyring,
}

const SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn fixture() -> SignedFixture {
    fixture_with_sequence(1)
}

fn fixture_with_sequence(sequence: u64) -> SignedFixture {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pk_hex = hex::encode(key.verifying_key().to_bytes());
    let key_id = derive_key_id(&pk_hex);
    let mut doc = V2Allowlist {
        format: "passaura-allowlist".into(),
        version: 2,
        sequence,
        issued_at: 100,
        expires_at: 500,
        signed_by: key_id.clone(),
        keyring: V2Keyring {
            keys: vec![V2Key {
                key_id: key_id.clone(),
                public_key_hex: pk_hex.clone(),
                valid_from: 0,
                valid_until: 1000,
                retired: false,
            }],
        },
        entries: vec![
            V2Entry { name: "curl".into(), version: Some("8".into()), sha256: SHA.into() },
            V2Entry { name: "org.example.App".into(), version: Some("1".into()), sha256: SHA.into() },
        ],
        signature_hex: String::new(),
    };
    let payload = canonical_payload_bytes(&doc).unwrap();
    doc.signature_hex = hex::encode(key.sign(&payload).to_bytes());
    SignedFixture {
        doc,
        keys: Keyring { keys: vec![KeyEntry { key_id, public_key_hex: pk_hex }] },
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
            None,
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
            None,
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
        None,
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
            None,
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
            None,
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
        None,
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
        None,
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
        None,
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
            None,
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
            None,
            InstallMode::DryRun,
        )
        .unwrap();

    assert!(!report.executed);
    assert_eq!(report.command.program, "flatpak");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn flatpak_runner_failure_surfaces_typed_error() {
    let fixture = fixture();
    let mut backend = FlatpakBackend::new(FakeRunner::failing(), "flathub").unwrap();
    let result = backend.install("org.example.App", &fixture.doc, &fixture.keys, 200, None, InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::RunnerFailure { code: Some(42), .. })));
    assert_eq!(backend.runner().calls.len(), 1);
    assert_eq!(backend.runner().calls[0].program, "flatpak");
}

#[test]
fn runner_spawn_error_is_an_error_not_success() {
    let fixture = fixture();
    let mut runner = FakeRunner::successful();
    runner.result = Err("no such program".into());
    let mut backend = AptDpkgBackend::new(runner);
    let result = backend.install("curl", &fixture.doc, &fixture.keys, 200, None, InstallMode::Apply);
    assert!(result.is_err());
    assert_eq!(backend.runner().calls.len(), 1);
}

#[test]
fn verification_failure_wins_over_not_allowed() {
    // Expired document AND a package that is not listed: verification is reported.
    let fixture = fixture();
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    let result = backend.install("definitely-not-listed", &fixture.doc, &fixture.keys, 10_000_000, None, InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::AllowlistVerification(_))), "{result:?}");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn dry_run_succeeds_even_if_runner_would_fail() {
    let fixture = fixture();
    let mut backend = AptDpkgBackend::new(FakeRunner::failing());
    let report = backend.install("curl", &fixture.doc, &fixture.keys, 200, None, InstallMode::DryRun).unwrap();
    assert!(!report.executed);
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn v1_shaped_document_cannot_reach_the_backend() {
    // The backend only takes V2Allowlist: a v2 doc relabelled version 1 is rejected.
    let fixture = fixture();
    let mut relabelled = fixture.doc.clone();
    relabelled.version = 1;
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    let result = backend.install("curl", &relabelled, &fixture.keys, 200, None, InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::AllowlistVerification(_))), "{result:?}");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn untrusted_signer_is_rejected_before_execution() {
    let fixture = fixture();
    let empty = Keyring { keys: vec![] };
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    let result = backend.install("curl", &fixture.doc, &empty, 200, None, InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::AllowlistVerification(_))), "{result:?}");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn tampered_entries_fail_signature_before_execution() {
    let fixture = fixture();
    let mut tampered = fixture.doc.clone();
    tampered.entries.push(V2Entry { name: "evil".into(), version: None, sha256: SHA.into() });
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    let result = backend.install("evil", &tampered, &fixture.keys, 200, None, InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::AllowlistVerification(_))), "{result:?}");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn downgrade_against_stored_sequence_is_rejected() {
    let older = fixture_with_sequence(2);
    let digest = canonical_digest_hex(&older.doc).unwrap();
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    let result = backend.install("curl", &older.doc, &older.keys, 200, Some((3, &digest)), InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::AllowlistVerification(_))), "{result:?}");
    assert!(backend.runner().calls.is_empty());
}

#[test]
fn same_sequence_with_different_digest_is_rejected_and_same_digest_accepted() {
    let f = fixture_with_sequence(2);
    let digest = canonical_digest_hex(&f.doc).unwrap();
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    assert!(backend.install("curl", &f.doc, &f.keys, 200, Some((2, &digest)), InstallMode::DryRun).is_ok());
    let other = "ff".repeat(32);
    let r = backend.install("curl", &f.doc, &f.keys, 200, Some((2, &other)), InstallMode::DryRun);
    assert!(matches!(r, Err(PackageBackendError::AllowlistVerification(_))), "{r:?}");
}

#[test]
fn trusted_key_with_same_id_but_different_public_key_is_rejected() {
    let fixture = fixture();
    let spoofed = Keyring {
        keys: vec![KeyEntry {
            key_id: fixture.keys.keys[0].key_id.clone(),
            public_key_hex: "bb".repeat(32),
        }],
    };
    let mut backend = AptDpkgBackend::new(FakeRunner::successful());
    let result = backend.install("curl", &fixture.doc, &spoofed, 200, None, InstallMode::Apply);
    assert!(matches!(result, Err(PackageBackendError::AllowlistVerification(_))), "{result:?}");
    assert!(backend.runner().calls.is_empty());
}
