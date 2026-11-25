use crate::allowlist::Keyring;
use crate::allowlist_v2::{verify_v2_trusted, V2Allowlist, V2Error};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Apply,
    DryRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageBackendError {
    InvalidPackageName,
    InvalidFlatpakRemote,
    InvalidFlatpakAppId,
    AllowlistVerification(V2Error),
    PackageNotAllowed,
    RunnerFailure {
        program: String,
        code: Option<i32>,
        message: String,
    },
    /// Exact-file path only: the runner itself reported (through its own `Err`
    /// control flow, never through child output) that the program was never
    /// started. Nothing ran.
    RunnerNotStarted {
        program: String,
        message: String,
    },
    /// This backend cannot install an exact staged file.
    ExactFileUnsupported,
    /// The staged file path is not an absolute, plain path.
    InvalidStagedPath,
    /// The staged `.deb` does not carry the allowlisted package identity (name, and version when the
    /// entry names one), or its control data could not be read.
    StagedIdentity(crate::deb_identity::DebError),
}

impl fmt::Display for PackageBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPackageName => f.write_str("invalid package name"),
            Self::InvalidFlatpakRemote => f.write_str("invalid Flatpak remote"),
            Self::InvalidFlatpakAppId => f.write_str("invalid Flatpak application ID"),
            Self::AllowlistVerification(e) => {
                write!(f, "allowlist verification failed: {e}")
            }
            Self::PackageNotAllowed => f.write_str("package is not allowlisted"),
            Self::ExactFileUnsupported => {
                f.write_str("this backend cannot install an exact staged file")
            }
            Self::InvalidStagedPath => f.write_str("invalid staged file path"),
            Self::StagedIdentity(e) => write!(f, "staged file identity check failed: {e}"),
            Self::RunnerNotStarted { program, message } => {
                write!(f, "command was not started: {program}: {message}")
            }
            Self::RunnerFailure {
                program,
                code,
                message,
            } => write!(
                f,
                "command runner failed: {} (exit {:?}): {}",
                program, code, message
            ),
        }
    }
}

impl std::error::Error for PackageBackendError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub message: String,
}

/// A runner that PROVES the program was never started (spawn failed before
/// exec) returns `Err` with a message starting with this prefix; the exact-file
/// path then yields `RunnerNotStarted`. Any other `Err` (wait/read/interrupt
/// after spawn) or a signal-killed process (`success == false`, `code == None`)
/// is an unknown outcome, even if its text imitates the prefix.
pub const RUNNER_NOT_STARTED_PREFIX: &str = "not started: ";

/// Executes one program with argv. Implementations must not invoke a shell.
pub trait CommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<CommandOutput, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub command: PlannedCommand,
    pub executed: bool,
}

pub trait PackageBackend {
    fn install(
        &mut self,
        package: &str,
        doc: &V2Allowlist,
        trusted: &Keyring,
        now: i64,
        stored: Option<(u64, &str)>,
        mode: InstallMode,
    ) -> Result<InstallReport, PackageBackendError>;

    /// Install the exact file at `staged` (already hash-checked by the
    /// caller against the signed entry). Additive: the by-name `install`
    /// above is unchanged. Backends that cannot do this keep the default.
    #[allow(clippy::too_many_arguments)]
    fn install_staged_file(
        &mut self,
        _package: &str,
        _staged: &std::path::Path,
        _doc: &V2Allowlist,
        _trusted: &Keyring,
        _now: i64,
        _stored: Option<(u64, &str)>,
        _mode: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        Err(PackageBackendError::ExactFileUnsupported)
    }
}

struct VerifiedAllowlist<'a> {
    doc: &'a V2Allowlist,
}

impl<'a> VerifiedAllowlist<'a> {
    fn new(
        doc: &'a V2Allowlist,
        trusted: &Keyring,
        now: i64,
        stored: Option<(u64, &str)>,
    ) -> Result<Self, PackageBackendError> {
        // Signature over the canonical bytes, then key validity, then
        // sequence/digest against `stored`. Only v2 documents get here.
        verify_v2_trusted(doc, trusted, now, stored)
            .map_err(PackageBackendError::AllowlistVerification)?;

        Ok(Self { doc })
    }

    fn contains(&self, package: &str) -> bool {
        self.doc.entries.iter().any(|entry| entry.name == package)
    }

    /// Some entry of that name must match the staged deb's name and version (an entry without a version
    /// accepts any version of that name). Returns the first mismatch when none does.
    fn check_staged_identity(
        &self,
        package: &str,
        staged: &std::path::Path,
    ) -> Result<(), PackageBackendError> {
        let mut file = std::fs::File::open(staged)
            .map_err(|e| PackageBackendError::StagedIdentity(e.into()))?;
        let id = crate::deb_identity::read_identity(&mut file)
            .map_err(PackageBackendError::StagedIdentity)?;
        let mut first_err = None;
        for entry in self.doc.entries.iter().filter(|e| e.name == package) {
            match crate::deb_identity::check_identity(&id, &entry.name, entry.version.as_deref()) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(PackageBackendError::StagedIdentity(first_err.unwrap_or(
            crate::deb_identity::DebError::NameMismatch {
                expected: package.to_string(),
                found: id.package,
            },
        )))
    }
}

/// Conservative package-name validator shared by apt and Flatpak.
/// Rejects leading dashes, whitespace, shell metacharacters,
/// path separators, and names outside the allowed character set.
pub fn valid_package_name(package: &str) -> bool {
    if package.is_empty()
        || package.len() > 256
        || package.starts_with('-')
        || package.contains('/')
        || package.contains('\\')
        || package.chars().any(char::is_whitespace)
    {
        return false;
    }

    package
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '_' | '-'))
}

/// Flatpak remotes: ASCII alphanumeric, underscore, or hyphen.
/// Length is bounded and the value cannot begin with a dash.
pub fn valid_flatpak_remote(remote: &str) -> bool {
    !remote.is_empty()
        && remote.len() <= 64
        && !remote.starts_with('-')
        && remote
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// Flatpak application IDs:
/// reverse-domain-style segments, with each segment starting
/// with an ASCII letter and containing letters, digits or hyphens.
/// At least two segments are required.
pub fn valid_flatpak_app_id(app_id: &str) -> bool {
    if app_id.is_empty() || app_id.len() > 255 {
        return false;
    }

    let segments: Vec<&str> = app_id.split('.').collect();

    if segments.len() < 2 {
        return false;
    }

    segments.iter().all(|segment| {
        !segment.is_empty()
            && segment.len() <= 63
            && segment.as_bytes()[0].is_ascii_alphabetic()
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

fn run_command<R: CommandRunner>(
    runner: &mut R,
    command: PlannedCommand,
    mode: InstallMode,
) -> Result<InstallReport, PackageBackendError> {
    run_command_ex(runner, command, mode, false)
}

/// `typed_not_started`: a runner `Err` whose message starts with
/// `RUNNER_NOT_STARTED_PREFIX` becomes `RunnerNotStarted`. Only the runner's
/// own `Err` return can do this; text inside a finished command's output
/// (`CommandOutput.message`) never can.
fn run_command_ex<R: CommandRunner>(
    runner: &mut R,
    command: PlannedCommand,
    mode: InstallMode,
    typed_not_started: bool,
) -> Result<InstallReport, PackageBackendError> {
    if mode == InstallMode::DryRun {
        return Ok(InstallReport {
            command,
            executed: false,
        });
    }

    let output = runner
        .run(&command.program, &command.args)
        .map_err(|message| {
            if typed_not_started && message.starts_with(RUNNER_NOT_STARTED_PREFIX) {
                PackageBackendError::RunnerNotStarted {
                    program: command.program.clone(),
                    message,
                }
            } else {
                PackageBackendError::RunnerFailure {
                    program: command.program.clone(),
                    code: None,
                    message,
                }
            }
        })?;

    if !output.success {
        return Err(PackageBackendError::RunnerFailure {
            program: command.program.clone(),
            code: output.code,
            message: output.message,
        });
    }

    Ok(InstallReport {
        command,
        executed: true,
    })
}

pub struct AptDpkgBackend<R> {
    runner: R,
}

impl<R: CommandRunner> AptDpkgBackend<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    pub fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }

    pub fn into_runner(self) -> R {
        self.runner
    }
}

impl<R: CommandRunner> PackageBackend for AptDpkgBackend<R> {
    fn install(
        &mut self,
        package: &str,
        doc: &V2Allowlist,
        trusted: &Keyring,
        now: i64,
        stored: Option<(u64, &str)>,
        mode: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        // Validate untrusted input before verification or execution.
        if !valid_package_name(package) {
            return Err(PackageBackendError::InvalidPackageName);
        }

        // Signature, time, key trust, and package authorization are
        // checked before a command can be built or executed.
        let verified = VerifiedAllowlist::new(doc, trusted, now, stored)?;

        if !verified.contains(package) {
            return Err(PackageBackendError::PackageNotAllowed);
        }

        let command = PlannedCommand {
            program: "apt-get".into(),
            args: vec![
                "install".into(),
                "--no-install-recommends".into(),
                "-y".into(),
                "--".into(),
                package.into(),
            ],
        };

        run_command(&mut self.runner, command, mode)
    }

    fn install_staged_file(
        &mut self,
        package: &str,
        staged: &std::path::Path,
        doc: &V2Allowlist,
        trusted: &Keyring,
        now: i64,
        stored: Option<(u64, &str)>,
        mode: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        if !valid_package_name(package) {
            return Err(PackageBackendError::InvalidPackageName);
        }
        let verified = VerifiedAllowlist::new(doc, trusted, now, stored)?;
        if !verified.contains(package) {
            return Err(PackageBackendError::PackageNotAllowed);
        }
        // Absolute path only, so it can never be read as an option, and the
        // `--` separator is passed as well. Non-UTF-8 paths are refused.
        let path = staged
            .to_str()
            .ok_or(PackageBackendError::InvalidStagedPath)?;
        if !staged.is_absolute() || path.contains('\0') {
            return Err(PackageBackendError::InvalidStagedPath);
        }
        // Identity binding (added after the hash check, before dpkg can run): the file's own control data
        // must name the allowlisted package, and the entry's version when it has one.
        verified.check_staged_identity(package, staged)?;
        let command = PlannedCommand {
            program: "dpkg".into(),
            args: vec!["-i".into(), "--".into(), path.into()],
        };
        run_command_ex(&mut self.runner, command, mode, true)
    }
}

pub struct FlatpakBackend<R> {
    runner: R,
    remote: String,
}

impl<R: CommandRunner> FlatpakBackend<R> {
    pub fn new(runner: R, remote: impl Into<String>) -> Result<Self, PackageBackendError> {
        let remote = remote.into();

        if !valid_flatpak_remote(&remote) {
            return Err(PackageBackendError::InvalidFlatpakRemote);
        }

        Ok(Self { runner, remote })
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    pub fn runner_mut(&mut self) -> &mut R {
        &mut self.runner
    }

    pub fn into_runner(self) -> R {
        self.runner
    }

    pub fn remote(&self) -> &str {
        &self.remote
    }
}

impl<R: CommandRunner> PackageBackend for FlatpakBackend<R> {
    fn install(
        &mut self,
        package: &str,
        doc: &V2Allowlist,
        trusted: &Keyring,
        now: i64,
        stored: Option<(u64, &str)>,
        mode: InstallMode,
    ) -> Result<InstallReport, PackageBackendError> {
        if !valid_flatpak_app_id(package) {
            return Err(PackageBackendError::InvalidFlatpakAppId);
        }

        let verified = VerifiedAllowlist::new(doc, trusted, now, stored)?;

        if !verified.contains(package) {
            return Err(PackageBackendError::PackageNotAllowed);
        }

        let command = PlannedCommand {
            program: "flatpak".into(),
            args: vec![
                "install".into(),
                "--noninteractive".into(),
                "--".into(),
                self.remote.clone(),
                package.into(),
            ],
        };

        run_command(&mut self.runner, command, mode)
    }
}
