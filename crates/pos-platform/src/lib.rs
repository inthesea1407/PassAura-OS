#![forbid(unsafe_code)]

//! PassAura OS platform policy abstraction.
//!
//! This crate generates platform policy requests and performs read-only
//! hardening checks through injectable CommandRunner and Fs interfaces.
//! It does NOT claim to enforce OS-wide credential-manager restrictions.

use std::collections::BTreeSet;
use std::fmt;

// -----------------------------------------------------------------------------
// Shared types
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    Io(String),
    Command(String),
    InvalidPackageId(String),
    InvalidPolicy(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "filesystem error: {msg}"),
            Self::Command(msg) => write!(f, "command error: {msg}"),
            Self::InvalidPackageId(id) => write!(f, "invalid package id: {id}"),
            Self::InvalidPolicy(msg) => write!(f, "invalid policy: {msg}"),
        }
    }
}

impl std::error::Error for BackendError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardeningCheck {
    pub name: String,
    pub status: CheckStatus,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HardeningReport {
    pub checks: Vec<HardeningCheck>,
}

impl HardeningReport {
    pub fn add(
        &mut self,
        name: impl Into<String>,
        status: CheckStatus,
        details: impl Into<String>,
    ) {
        self.checks.push(HardeningCheck {
            name: name.into(),
            status,
            details: details.into(),
        });
    }

    pub fn passed(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == CheckStatus::Pass)
            .count()
    }

    pub fn failed(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == CheckStatus::Fail)
            .count()
    }

    pub fn unknown(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| check.status == CheckStatus::Unknown)
            .count()
    }

    /// A report is complete only if every check passed.
    pub fn is_fully_hardened(&self) -> bool {
        !self.checks.is_empty() && self.failed() == 0 && self.unknown() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CredentialManagerPolicy {
    pub allowed_packages: BTreeSet<String>,
}

impl CredentialManagerPolicy {
    pub fn new<I, S>(packages: I) -> Result<Self, BackendError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut allowed_packages = BTreeSet::new();

        for package in packages {
            let package = package.into();
            validate_package_id(&package)?;
            allowed_packages.insert(package);
        }

        Ok(Self { allowed_packages })
    }

    pub fn is_approved(&self, package: &str) -> bool {
        self.allowed_packages.contains(package)
    }
}

fn validate_package_id(package: &str) -> Result<(), BackendError> {
    if package.is_empty()
        || package.len() > 255
        || package.starts_with('.')
        || package.ends_with('.')
        || package.contains("..")
        || !package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' )
    {
        return Err(BackendError::InvalidPackageId(package.to_owned()));
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Injectable system interfaces
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<CommandOutput, BackendError>;
}

pub trait Fs {
    fn read(&self, path: &str) -> Result<String, BackendError>;
    fn write(&self, path: &str, contents: &str) -> Result<(), BackendError>;
    fn exists(&self, path: &str) -> bool;
}

pub trait PlatformBackend {
    fn set_allowed_credential_managers(
        &mut self,
        packages: &[String],
    ) -> Result<(), BackendError>;

    fn is_credential_manager_approved(&self, package: &str) -> bool;

    fn hardening_status(&self) -> HardeningReport;
}

// -----------------------------------------------------------------------------
// Linux
// -----------------------------------------------------------------------------

pub const LINUX_POLICY_PATH: &str =
    "/etc/pos/credential-manager-allowlist";

pub const LINUX_APT_HOOK_PATH: &str =
    "/etc/apt/apt.conf.d/90-pos-package-gate";

pub const LINUX_SYSCTL_PATH: &str =
    "/etc/sysctl.d/90-pos-hardening.conf";

pub const LINUX_APPARMOR_PROFILE_PATH: &str =
    "/etc/apparmor.d/pos-credential-manager-gate";

pub const LINUX_APT_HOOK: &str = r#"
DPkg::Pre-Install-Pkgs {
    "/usr/local/libexec/pos-package-gate";
};
"#;

pub const LINUX_SYSCTL_POLICY: &str = r#"
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
"#;

pub const LINUX_APPARMOR_PROFILE: &str = r#"
#include <tunables/global>

profile pos-credential-manager-gate flags=(enforce) {
    # This profile is a scaffold. It does not independently
    # enforce desktop credential-manager package restrictions.
}
"#;

pub struct LinuxBackend<R: CommandRunner, F: Fs> {
    runner: R,
    fs: F,
    policy: CredentialManagerPolicy,
}

impl<R: CommandRunner, F: Fs> LinuxBackend<R, F> {
    pub fn new(runner: R, fs: F) -> Self {
        Self {
            runner,
            fs,
            policy: CredentialManagerPolicy::default(),
        }
    }

    pub fn policy_file_contents(&self) -> String {
        let mut output = String::new();

        for package in &self.policy.allowed_packages {
            output.push_str(package);
            output.push('\n');
        }

        output
    }

    /// Produces configuration data for review.
    /// No privileged commands are run and no files are written.
    pub fn dry_run_files(&self) -> Vec<(String, String)> {
        vec![
            (
                LINUX_POLICY_PATH.to_owned(),
                self.policy_file_contents(),
            ),
            (
                LINUX_APT_HOOK_PATH.to_owned(),
                LINUX_APT_HOOK.to_owned(),
            ),
            (
                LINUX_SYSCTL_PATH.to_owned(),
                LINUX_SYSCTL_POLICY.to_owned(),
            ),
            (
                LINUX_APPARMOR_PROFILE_PATH.to_owned(),
                LINUX_APPARMOR_PROFILE.to_owned(),
            ),
        ]
    }

    fn check_command(
        &self,
        name: &str,
        program: &str,
        args: &[&str],
        expected: &str,
    ) -> HardeningCheck {
        match self.runner.run(program, args) {
            Ok(output) if output.success && output.stdout.contains(expected) => {
                HardeningCheck {
                    name: name.to_owned(),
                    status: CheckStatus::Pass,
                    details: output.stdout,
                }
            }
            Ok(output) => HardeningCheck {
                name: name.to_owned(),
                status: CheckStatus::Fail,
                details: if output.stderr.is_empty() {
                    output.stdout
                } else {
                    output.stderr
                },
            },
            Err(error) => HardeningCheck {
                name: name.to_owned(),
                status: CheckStatus::Unknown,
                details: error.to_string(),
            },
        }
    }

    fn check_file(
        &self,
        name: &str,
        path: &str,
        expected: &str,
    ) -> HardeningCheck {
        match self.fs.read(path) {
            Ok(contents) if contents.contains(expected) => HardeningCheck {
                name: name.to_owned(),
                status: CheckStatus::Pass,
                details: format!("{path}: expected setting found"),
            },
            Ok(_) => HardeningCheck {
                name: name.to_owned(),
                status: CheckStatus::Fail,
                details: format!("{path}: expected setting missing"),
            },
            Err(error) => HardeningCheck {
                name: name.to_owned(),
                status: CheckStatus::Unknown,
                details: error.to_string(),
            },
        }
    }
}

impl<R: CommandRunner, F: Fs> PlatformBackend for LinuxBackend<R, F> {
    fn set_allowed_credential_managers(
        &mut self,
        packages: &[String],
    ) -> Result<(), BackendError> {
        let policy = CredentialManagerPolicy::new(packages.iter().cloned())?;
        self.policy = policy;

        // Intentional dry-run: policy is held in memory and can be exported
        // via dry_run_files(). No system files are changed here.
        Ok(())
    }

    fn is_credential_manager_approved(&self, package: &str) -> bool {
        self.policy.is_approved(package)
    }

    fn hardening_status(&self) -> HardeningReport {
        let mut report = HardeningReport::default();

        report.checks.push(self.check_file(
            "sysctl_kernel_dmesg_restrict",
            LINUX_SYSCTL_PATH,
            "kernel.dmesg_restrict = 1",
        ));

        report.checks.push(self.check_file(
            "sysctl_kernel_kptr_restrict",
            LINUX_SYSCTL_PATH,
            "kernel.kptr_restrict = 2",
        ));

        report.checks.push(self.check_command(
            "apparmor_loaded",
            "aa-status",
            &[],
            "apparmor",
        ));

        report.checks.push(self.check_command(
            "apt_package_gate_hook",
            "apt-config",
            &["dump"],
            "90-pos-package-gate",
        ));

        report
    }
}

// -----------------------------------------------------------------------------
// Windows
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryValue {
    pub key: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowsPolicyPlan {
    pub applocker_xml: String,
    pub wdac_policy_notes: String,
    pub registry_values: Vec<RegistryValue>,
}

#[allow(dead_code)] // scaffold: fields are used once the backend is wired
pub struct WindowsBackend<R: CommandRunner, F: Fs> {
    runner: R,
    fs: F,
    policy: CredentialManagerPolicy,
}

impl<R: CommandRunner, F: Fs> WindowsBackend<R, F> {
    pub fn new(runner: R, fs: F) -> Self {
        Self {
            runner,
            fs,
            policy: CredentialManagerPolicy::default(),
        }
    }

    pub fn dry_run_policy(&self) -> WindowsPolicyPlan {
        let mut rules = String::new();

        for package in &self.policy.allowed_packages {
            rules.push_str(&format!(
                "<FilePathRule Id=\"{}\" Name=\"Allow {}\" \
                 Description=\"POS generated allow rule\" \
                 UserOrGroupSid=\"S-1-1-0\" Action=\"Allow\">\
                 <Conditions><FilePathCondition Path=\"*\\{}\\*\" />\
                 </Conditions></FilePathRule>\n",
                xml_escape(package),
                xml_escape(package),
                xml_escape(package),
            ));
        }

        let applocker_xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <AppLockerPolicy Version=\"1\">\
            <RuleCollection Type=\"Exe\" EnforcementMode=\"AuditOnly\">\
            {}\
            </RuleCollection></AppLockerPolicy>",
            rules
        );

        WindowsPolicyPlan {
            applocker_xml,
            wdac_policy_notes: String::from(
                "WDAC requires policy signing/deployment and platform validation. \
                 This crate only emits a plan; no policy is activated.",
            ),
            registry_values: vec![
                RegistryValue {
                    key: String::from(
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\\
                         DeviceGuard",
                    ),
                    name: String::from("EnableVirtualizationBasedSecurity"),
                    value: String::from("1"),
                },
                RegistryValue {
                    key: String::from(
                        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\\
                         DeviceGuard",
                    ),
                    name: String::from("RequirePlatformSecurityFeatures"),
                    value: String::from("1"),
                },
            ],
        }
    }
}

fn xml_escape(value: &str) -> String {
    value.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl<R: CommandRunner, F: Fs> PlatformBackend for WindowsBackend<R, F> {
    fn set_allowed_credential_managers(
        &mut self,
        packages: &[String],
    ) -> Result<(), BackendError> {
        self.policy = CredentialManagerPolicy::new(packages.iter().cloned())?;
        Ok(())
    }

    fn is_credential_manager_approved(&self, package: &str) -> bool {
        self.policy.is_approved(package)
    }

    fn hardening_status(&self) -> HardeningReport {
        let mut report = HardeningReport::default();

        report.add(
            "applocker_policy",
            CheckStatus::Unknown,
            "Policy generation is dry-run only; live AppLocker state is not queried.",
        );

        report.add(
            "wdac_policy",
            CheckStatus::Unknown,
            "WDAC policy is generated as guidance only; no policy is deployed.",
        );

        report.add(
            "registry_hardening",
            CheckStatus::Unknown,
            "Registry values are data only; no registry changes are made.",
        );

        report
    }
}

// -----------------------------------------------------------------------------
// Android
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AndroidPolicyRequest {
    pub allowed_packages: Vec<String>,
    pub request_type: String,
    pub enforcement_scope: String,
}

#[allow(dead_code)] // scaffold: fields are used once the backend is wired
pub struct AndroidBackend<R: CommandRunner, F: Fs> {
    runner: R,
    fs: F,
    policy: CredentialManagerPolicy,
}

impl<R: CommandRunner, F: Fs> AndroidBackend<R, F> {
    pub fn new(runner: R, fs: F) -> Self {
        Self {
            runner,
            fs,
            policy: CredentialManagerPolicy::default(),
        }
    }

    pub fn policy_request(&self) -> AndroidPolicyRequest {
        AndroidPolicyRequest {
            allowed_packages: self.policy.allowed_packages.iter().cloned().collect(),
            request_type: String::from("credential_manager_allowlist"),
            enforcement_scope: String::from(
                "device_owner_app_or_system_integration_required",
            ),
        }
    }

    pub fn policy_request_json(&self) -> String {
        let request = self.policy_request();
        let packages = request
            .allowed_packages
            .iter()
            .map(|package| format!("\"{}\"", json_escape(package)))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{{\"request_type\":\"{}\",\
            \"enforcement_scope\":\"{}\",\
            \"allowed_packages\":[{}]}}",
            json_escape(&request.request_type),
            json_escape(&request.enforcement_scope),
            packages
        )
    }
}

impl<R: CommandRunner, F: Fs> PlatformBackend for AndroidBackend<R, F> {
    fn set_allowed_credential_managers(
        &mut self,
        packages: &[String],
    ) -> Result<(), BackendError> {
        self.policy = CredentialManagerPolicy::new(packages.iter().cloned())?;
        Ok(())
    }

    fn is_credential_manager_approved(&self, package: &str) -> bool {
        self.policy.is_approved(package)
    }

    fn hardening_status(&self) -> HardeningReport {
        let mut report = HardeningReport::default();

        report.add(
            "device_owner_policy",
            CheckStatus::Unknown,
            "Requires Kotlin device-owner integration and platform validation.",
        );

        report.add(
            "credential_manager_policy",
            CheckStatus::Unknown,
            "Request generation does not prove that Android applied the policy.",
        );

        report.add(
            "hardware_backed_security",
            CheckStatus::Unknown,
            "Not assessed by this platform abstraction.",
        );

        report
    }
}

// -----------------------------------------------------------------------------
// JSON escaping
// -----------------------------------------------------------------------------

fn json_escape(value: &str) -> String {
    let mut output = String::new();

    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }

    output
}

// -----------------------------------------------------------------------------
// Tests (fakes only; no real OS calls)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeRunner {
        responses: RefCell<HashMap<String, CommandOutput>>,
        failures: RefCell<HashMap<String, String>>,
    }

    impl FakeRunner {
        fn set_response(&self, command: &str, output: CommandOutput) {
            self.responses.borrow_mut().insert(command.to_owned(), output);
        }

        fn set_failure(&self, command: &str, message: &str) {
            self.failures
                .borrow_mut()
                .insert(command.to_owned(), message.to_owned());
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            _args: &[&str],
        ) -> Result<CommandOutput, BackendError> {
            if let Some(message) = self.failures.borrow().get(program) {
                return Err(BackendError::Command(message.clone()));
            }

            self.responses
                .borrow()
                .get(program)
                .cloned()
                .unwrap_or(CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: format!("{program} not configured"),
                })
                .pipe(Ok)
        }
    }

    trait Pipe: Sized {
        fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
            f(self)
        }
    }

    impl<T> Pipe for T {}

    #[derive(Default)]
    struct FakeFs {
        files: RefCell<HashMap<String, String>>,
        errors: RefCell<HashMap<String, String>>,
    }

    impl FakeFs {
        fn put(&self, path: &str, contents: &str) {
            self.files
                .borrow_mut()
                .insert(path.to_owned(), contents.to_owned());
        }

        fn fail_read(&self, path: &str, message: &str) {
            self.errors
                .borrow_mut()
                .insert(path.to_owned(), message.to_owned());
        }
    }

    impl Fs for FakeFs {
        fn read(&self, path: &str) -> Result<String, BackendError> {
            if let Some(message) = self.errors.borrow().get(path) {
                return Err(BackendError::Io(message.clone()));
            }

            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| BackendError::Io(format!("{path} not found")))
        }

        fn write(&self, path: &str, contents: &str) -> Result<(), BackendError> {
            self.files
                .borrow_mut()
                .insert(path.to_owned(), contents.to_owned());
            Ok(())
        }

        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }
    }

    fn ok_output(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    fn fail_output(stderr: &str) -> CommandOutput {
        CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }

    fn packages() -> Vec<String> {
        vec![String::from("com.inthesea.passaura")]
    }

    // 1
    #[test]
    fn policy_accepts_valid_package() {
        assert!(CredentialManagerPolicy::new(packages()).is_ok());
    }

    // 2
    #[test]
    fn policy_rejects_empty_package() {
        assert!(CredentialManagerPolicy::new([""]).is_err());
    }

    // 3
    #[test]
    fn policy_rejects_leading_dot() {
        assert!(CredentialManagerPolicy::new([".bad"]).is_err());
    }

    // 4
    #[test]
    fn policy_rejects_trailing_dot() {
        assert!(CredentialManagerPolicy::new(["bad."]).is_err());
    }

    // 5
    #[test]
    fn policy_rejects_double_dot() {
        assert!(CredentialManagerPolicy::new(["bad..name"]).is_err());
    }

    // 6
    #[test]
    fn policy_rejects_slash() {
        assert!(CredentialManagerPolicy::new(["bad/name"]).is_err());
    }

    // 7
    #[test]
    fn policy_rejects_package_over_255_chars() {
        assert!(CredentialManagerPolicy::new([format!("a{}", "b".repeat(255))]).is_err());
    }

    // 8
    #[test]
    fn policy_deduplicates_packages() {
        let policy = CredentialManagerPolicy::new(["app.one", "app.one"]).unwrap();
        assert_eq!(policy.allowed_packages.len(), 1);
    }

    // 9
    #[test]
    fn policy_is_exact_match() {
        let policy = CredentialManagerPolicy::new(["app.one"]).unwrap();
        assert!(policy.is_approved("app.one"));
        assert!(!policy.is_approved("app.one.extra"));
    }

    // 10
    #[test]
    fn policy_empty_denies_all() {
        let policy = CredentialManagerPolicy::default();
        assert!(!policy.is_approved("anything"));
    }

    // 11
    #[test]
    fn linux_set_policy_updates_allowlist() {
        let mut backend = LinuxBackend::new(FakeRunner::default(), FakeFs::default());
        backend.set_allowed_credential_managers(&packages()).unwrap();
        assert!(backend.is_credential_manager_approved("com.inthesea.passaura"));
    }

    // 12
    #[test]
    fn linux_policy_file_is_sorted_and_stable() {
        let mut backend = LinuxBackend::new(FakeRunner::default(), FakeFs::default());
        backend
            .set_allowed_credential_managers(&["z.app".into(), "a.app".into()])
            .unwrap();
        assert_eq!(backend.policy_file_contents(), "a.app\nz.app\n");
    }

    // 13
    #[test]
    fn linux_dry_run_contains_four_files() {
        let backend = LinuxBackend::new(FakeRunner::default(), FakeFs::default());
        assert_eq!(backend.dry_run_files().len(), 4);
    }

    // 14
    #[test]
    fn linux_dry_run_contains_apt_hook() {
        let backend = LinuxBackend::new(FakeRunner::default(), FakeFs::default());
        let files = backend.dry_run_files();
        assert!(files.iter().any(|(_, content)| content.contains("DPkg")));
    }

    // 15
    #[test]
    fn linux_dry_run_contains_sysctl() {
        let backend = LinuxBackend::new(FakeRunner::default(), FakeFs::default());
        let files = backend.dry_run_files();
        assert!(files.iter().any(|(_, content)| content.contains("kptr_restrict")));
    }

    // 16
    #[test]
    fn linux_dry_run_contains_apparmor() {
        let backend = LinuxBackend::new(FakeRunner::default(), FakeFs::default());
        let files = backend.dry_run_files();
        assert!(files.iter().any(|(path, _)| path.contains("apparmor")));
    }

    // 17
    #[test]
    fn linux_sysctl_passes_when_values_exist() {
        let fs = FakeFs::default();
        fs.put(
            LINUX_SYSCTL_PATH,
            "kernel.dmesg_restrict = 1\nkernel.kptr_restrict = 2\n",
        );
        let backend = LinuxBackend::new(FakeRunner::default(), fs);
        let report = backend.hardening_status();
        assert_eq!(report.passed(), 2);
    }

    // 18
    #[test]
    fn linux_sysctl_fails_when_values_missing() {
        let fs = FakeFs::default();
        fs.put(LINUX_SYSCTL_PATH, "kernel.dmesg_restrict = 0\n");
        let backend = LinuxBackend::new(FakeRunner::default(), fs);
        let report = backend.hardening_status();
        let sysctl_failed = report
            .checks
            .iter()
            .filter(|c| c.name.starts_with("sysctl") && c.status == CheckStatus::Fail)
            .count();
        assert_eq!(sysctl_failed, 2);
    }

    // 19
    #[test]
    fn linux_sysctl_unknown_on_fs_error() {
        let fs = FakeFs::default();
        fs.fail_read(LINUX_SYSCTL_PATH, "permission denied");
        let backend = LinuxBackend::new(FakeRunner::default(), fs);
        let report = backend.hardening_status();
        assert_eq!(report.unknown(), 2);
    }

    // 20
    #[test]
    fn linux_apparmor_passes_with_expected_output() {
        let runner = FakeRunner::default();
        runner.set_response("aa-status", ok_output("apparmor is enabled"));
        let backend = LinuxBackend::new(runner, FakeFs::default());
        let report = backend.hardening_status();
        assert!(report.checks.iter().any(|check| {
            check.name == "apparmor_loaded" && check.status == CheckStatus::Pass
        }));
    }

    // 21
    #[test]
    fn linux_apparmor_unknown_on_command_error() {
        let runner = FakeRunner::default();
        runner.set_failure("aa-status", "command unavailable");
        let backend = LinuxBackend::new(runner, FakeFs::default());
        let report = backend.hardening_status();
        assert!(report.checks.iter().any(|check| {
            check.name == "apparmor_loaded" && check.status == CheckStatus::Unknown
        }));
    }

    // 22
    #[test]
    fn linux_apt_hook_check_fails_when_not_found() {
        let runner = FakeRunner::default();
        runner.set_response("apt-config", fail_output("hook not found"));
        let backend = LinuxBackend::new(runner, FakeFs::default());
        let report = backend.hardening_status();
        assert!(report.checks.iter().any(|check| {
            check.name == "apt_package_gate_hook" && check.status == CheckStatus::Fail
        }));
    }

    // 23
    #[test]
    fn windows_policy_is_audit_only() {
        let mut backend = WindowsBackend::new(FakeRunner::default(), FakeFs::default());
        backend.set_allowed_credential_managers(&packages()).unwrap();
        let plan = backend.dry_run_policy();
        assert!(plan.applocker_xml.contains("AuditOnly"));
    }

    // 24
    #[test]
    fn windows_policy_includes_allowed_package() {
        let mut backend = WindowsBackend::new(FakeRunner::default(), FakeFs::default());
        backend.set_allowed_credential_managers(&packages()).unwrap();
        assert!(backend.dry_run_policy().applocker_xml.contains("com.inthesea.passaura"));
    }

    // 25
    #[test]
    fn windows_policy_escapes_xml() {
        let mut backend = WindowsBackend::new(FakeRunner::default(), FakeFs::default());
        backend
            .set_allowed_credential_managers(&["safe.app".into()])
            .unwrap();
        assert!(backend.dry_run_policy().applocker_xml.contains("safe.app"));
        assert_eq!(xml_escape("a&b<c"), "a&amp;b&lt;c");
    }

    // 26
    #[test]
    fn windows_plan_has_registry_values() {
        let backend = WindowsBackend::new(FakeRunner::default(), FakeFs::default());
        assert_eq!(backend.dry_run_policy().registry_values.len(), 2);
    }

    // 27
    #[test]
    fn windows_status_is_unknown_without_live_enforcement() {
        let backend = WindowsBackend::new(FakeRunner::default(), FakeFs::default());
        assert_eq!(backend.hardening_status().unknown(), 3);
    }

    // 28
    #[test]
    fn android_policy_request_contains_package() {
        let mut backend = AndroidBackend::new(FakeRunner::default(), FakeFs::default());
        backend.set_allowed_credential_managers(&packages()).unwrap();
        assert_eq!(
            backend.policy_request().allowed_packages,
            packages()
        );
    }

    // 29
    #[test]
    fn android_json_has_request_type() {
        let backend = AndroidBackend::new(FakeRunner::default(), FakeFs::default());
        assert!(backend.policy_request_json().contains("credential_manager_allowlist"));
    }

    // 30
    #[test]
    fn android_json_escapes_quotes() {
        let mut backend = AndroidBackend::new(FakeRunner::default(), FakeFs::default());
        backend
            .set_allowed_credential_managers(&["app.safe".into()])
            .unwrap();
        assert!(backend.policy_request_json().contains("app.safe"));
        assert_eq!(json_escape("a\"b"), "a\\\"b");
    }

    // 31
    #[test]
    fn android_status_is_unknown_without_device_owner() {
        let backend = AndroidBackend::new(FakeRunner::default(), FakeFs::default());
        assert_eq!(backend.hardening_status().unknown(), 3);
    }

    // 32
    #[test]
    fn report_is_not_hardened_when_unknown_exists() {
        let backend = AndroidBackend::new(FakeRunner::default(), FakeFs::default());
        assert!(!backend.hardening_status().is_fully_hardened());
    }

    // 33
    #[test]
    fn report_counts_statuses() {
        let mut report = HardeningReport::default();
        report.add("pass", CheckStatus::Pass, "ok");
        report.add("fail", CheckStatus::Fail, "bad");
        report.add("unknown", CheckStatus::Unknown, "not checked");
        assert_eq!(report.passed(), 1);
        assert_eq!(report.failed(), 1);
        assert_eq!(report.unknown(), 1);
    }

    // 34
    #[test]
    fn report_empty_is_not_hardened() {
        assert!(!HardeningReport::default().is_fully_hardened());
    }

    // 35
    #[test]
    fn report_all_passed_is_hardened() {
        let mut report = HardeningReport::default();
        report.add("a", CheckStatus::Pass, "ok");
        assert!(report.is_fully_hardened());
    }
}
pub mod windows;
