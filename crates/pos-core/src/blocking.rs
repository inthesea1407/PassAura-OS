//! Technical blocking of non-PassAura password managers.
//!
//! TRUST BOUNDARY: `caps` here must be the capabilities OBSERVED by the OS
//! (from the installer's analysis of the real package manifest/components,
//! and from the platform's actual service registrations at runtime), never
//! self-declared by the app. This module is only the decision logic. The
//! enforcement itself belongs in the OS (installer, autofill/credential
//! service selection, accessibility grants, SELinux) and is not built yet.
//! Classification is by declared capability, not by app name, so renaming an
//! app does not bypass it. Limits: an app that hides these capabilities
//! (for example a web page or an app that scrapes the screen without
//! declaring anything) needs runtime detection too, and forks of this code
//! can remove the block.

use crate::{category_allowed, AppCategory, PASSWORD_MANAGER_ID};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    AutofillProvider,       // Android AutofillService / credential provider
    CredentialProvider,     // passkey / credential manager provider
    AccessibilityAutofill,  // accessibility service reading password fields
    PasswordVaultStore,     // declares a password vault / import-export of logins
    Camera,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Install,
    Launch,
    BecomeAutofillProvider,
    BecomeCredentialProvider,
    ReadPasswordFields,
    ImportExportLogins,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block(&'static str),
}

pub fn classify(caps: &[Capability]) -> AppCategory {
    // Exhaustive on purpose: adding a Capability forces a decision here.
    let pm = caps.iter().any(|c| match c {
        Capability::AutofillProvider
        | Capability::CredentialProvider
        | Capability::AccessibilityAutofill
        | Capability::PasswordVaultStore => true,
        Capability::Camera | Capability::Network => false,
    });
    if pm { AppCategory::PasswordManager } else { AppCategory::Other }
}

/// Decide an operation for an app. Every password-manager-class app other
/// than the licensed PassAura one is blocked from every operation.
#[must_use]
pub fn enforce(app_id: &str, caps: &[Capability], licensed: bool, _op: Operation) -> Verdict {
    match classify(caps) {
        AppCategory::PasswordManager => {
            // Pin the id here too, so loosening category_allowed later cannot
            // let another vault through by accident.
            if app_id == PASSWORD_MANAGER_ID
                && licensed
                && category_allowed(AppCategory::PasswordManager, app_id, licensed)
            {
                Verdict::Allow
            } else if app_id == PASSWORD_MANAGER_ID {
                Verdict::Block("PassAura Premium requires active membership")
            } else {
                Verdict::Block("only PassAura Premium is allowed as password manager")
            }
        }
        _ => Verdict::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Capability::*;

    #[test]
    fn other_managers_blocked_on_every_operation() {
        for op in [
            Operation::Install,
            Operation::Launch,
            Operation::BecomeAutofillProvider,
            Operation::BecomeCredentialProvider,
            Operation::ReadPasswordFields,
            Operation::ImportExportLogins,
        ] {
            assert!(matches!(enforce("com.other.vault", &[AutofillProvider], true, op), Verdict::Block(_)));
        }
    }

    #[test]
    fn renaming_does_not_bypass() {
        assert!(matches!(enforce("passaura.premium.fake", &[CredentialProvider], true, Operation::Install), Verdict::Block(_)));
    }

    #[test]
    fn accessibility_autofill_counts_as_password_manager() {
        assert_eq!(classify(&[AccessibilityAutofill, Network]), AppCategory::PasswordManager);
    }

    #[test]
    fn passaura_allowed_only_when_licensed() {
        assert_eq!(enforce(PASSWORD_MANAGER_ID, &[AutofillProvider], true, Operation::Launch), Verdict::Allow);
        assert!(matches!(enforce(PASSWORD_MANAGER_ID, &[AutofillProvider], false, Operation::Launch), Verdict::Block(_)));
    }

    #[test]
    fn ordinary_apps_unaffected() {
        assert_eq!(enforce("com.game", &[Camera, Network], false, Operation::Install), Verdict::Allow);
    }
}
