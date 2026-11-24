//! Observes a package's real contents (file list, desktop entries) instead
//! of trusting what it declares, then asks pos-core::blocking for a verdict.
//! This is real enforcement when run as an install-time hook (see
//! enforcement/apt-hook). It is user-space only: a root user can bypass it,
//! and it only sees packages installed through the hooked package manager.

pub mod allowlist;
pub mod rollback;
pub use allowlist::{is_allowed, verify_allowlist, AllowlistDoc, GateError, Keyring};

use pos_core::blocking::{enforce, Capability, Operation, Verdict};

#[derive(Debug, Default)]
pub struct PackageFacts {
    pub name: String,
    /// Absolute paths the package installs.
    pub files: Vec<String>,
    /// Text of any .desktop files the package installs.
    pub desktop_entries: Vec<String>,
}

const NATIVE_MESSAGING_DIRS: &[&str] = &[
    "/usr/lib/mozilla/native-messaging-hosts/",
    "/usr/lib64/mozilla/native-messaging-hosts/",
    "/etc/opt/chrome/native-messaging-hosts/",
    "/etc/chromium/native-messaging-hosts/",
    "/usr/lib/chromium/native-messaging-hosts/",
    "/etc/opt/edge/native-messaging-hosts/",
];

const PM_WORDS: &[&str] = &["password manager", "password vault", "passwords", "autofill", "credential vault", "keepass", "passkey"];

/// Known password-manager package names (a seed list; observation below is
/// what catches renamed ones).
const KNOWN: &[&str] = &[
    "keepassxc", "keepass2", "bitwarden", "1password", "lastpass", "dashlane",
    "enpass", "nordpass", "proton-pass", "buttercup", "gopass", "pass", "passwordsafe",
];

pub fn observe(f: &PackageFacts) -> Vec<Capability> {
    let mut caps = vec![];
    let lname = f.name.to_lowercase();
    if KNOWN.iter().any(|k| lname == *k || lname.starts_with(&format!("{k}-"))) {
        caps.push(Capability::PasswordVaultStore);
    }
    if f.files.iter().any(|p| NATIVE_MESSAGING_DIRS.iter().any(|d| p.starts_with(d))) {
        // Browser native-messaging hosts are how desktop password managers
        // reach browser autofill.
        caps.push(Capability::AutofillProvider);
    }
    for d in &f.desktop_entries {
        let l = d.to_lowercase();
        let relevant = l.lines().filter(|x| {
            x.starts_with("keywords") || x.starts_with("comment") || x.starts_with("genericname") || x.starts_with("categories")
        });
        if relevant.clone().any(|x| PM_WORDS.iter().any(|w| x.contains(w))) {
            caps.push(Capability::PasswordVaultStore);
        }
    }
    caps
}

/// `licensed` = active PassAura Premium membership on this device.
pub fn verdict(f: &PackageFacts, licensed: bool) -> Verdict {
    enforce(&f.name, &observe(f), licensed, Operation::Install)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(name: &str, files: &[&str], desk: &[&str]) -> PackageFacts {
        PackageFacts { name: name.into(), files: files.iter().map(|s| s.to_string()).collect(), desktop_entries: desk.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn known_manager_blocked() {
        assert!(matches!(verdict(&facts("keepassxc", &[], &[]), true), Verdict::Block(_)));
    }

    #[test]
    fn renamed_manager_caught_by_native_messaging_host() {
        let f = facts("totally-innocent", &["/usr/lib/mozilla/native-messaging-hosts/x.json"], &[]);
        assert!(matches!(verdict(&f, true), Verdict::Block(_)));
    }

    #[test]
    fn renamed_manager_caught_by_desktop_entry() {
        let d = "[Desktop Entry]\nName=Notes+\nKeywords=vault;Password Manager;\n";
        assert!(matches!(verdict(&facts("notes-plus", &[], &[d]), true), Verdict::Block(_)));
    }

    #[test]
    fn ordinary_package_allowed() {
        let d = "[Desktop Entry]\nName=Calc\nCategories=Utility;\n";
        assert_eq!(verdict(&facts("gnome-calculator", &["/usr/bin/gnome-calculator"], &[d]), false), Verdict::Allow);
    }

    #[test]
    fn passaura_allowed_only_when_licensed() {
        let f = facts("passaura.premium", &["/usr/lib/mozilla/native-messaging-hosts/passaura.json"], &[]);
        assert_eq!(verdict(&f, true), Verdict::Allow);
        assert!(matches!(verdict(&f, false), Verdict::Block(_)));
    }
}
