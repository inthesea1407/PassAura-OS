//! iOS-style closed install model, decision logic only.
//! An app installs only if (1) its package signature was verified by the
//! platform against the store key (`store_signed`, set by the verifier, not
//! by the app), (2) every entitlement it asks for is one the store review
//! approved for its developer, and (3) restricted entitlements (credential
//! provider, autofill, accessibility) are held only by the PassAura team.
//! Real signature verification and the secure boot chain are NOT built here.

pub const PASSAURA_TEAM: &str = "team.passaura";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entitlement {
    Network,
    Camera,
    CredentialProvider,   // restricted
    AutofillProvider,     // restricted
    AccessibilityControl, // restricted
}

impl Entitlement {
    pub fn restricted(self) -> bool {
        matches!(
            self,
            Entitlement::CredentialProvider
                | Entitlement::AutofillProvider
                | Entitlement::AccessibilityControl
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallVerdict {
    Install,
    Reject(&'static str),
}

pub struct Manifest<'a> {
    pub team: &'a str,
    pub requested: &'a [Entitlement],
    /// Entitlements store review approved for this team.
    pub approved: &'a [Entitlement],
    pub store_signed: bool,
    pub sideloaded: bool,
}

pub fn install_decision(m: &Manifest) -> InstallVerdict {
    if m.sideloaded {
        return InstallVerdict::Reject("sideloading is not allowed");
    }
    if !m.store_signed {
        return InstallVerdict::Reject("not signed by the store");
    }
    for e in m.requested {
        if !m.approved.contains(e) {
            return InstallVerdict::Reject("entitlement not approved by review");
        }
        if e.restricted() && m.team != PASSAURA_TEAM {
            return InstallVerdict::Reject("restricted entitlement is reserved for PassAura");
        }
    }
    InstallVerdict::Install
}

#[cfg(test)]
mod tests {
    use super::*;
    use Entitlement::*;

    fn m<'a>(
        team: &'a str,
        req: &'a [Entitlement],
        appr: &'a [Entitlement],
        signed: bool,
        side: bool,
    ) -> Manifest<'a> {
        Manifest {
            team,
            requested: req,
            approved: appr,
            store_signed: signed,
            sideloaded: side,
        }
    }

    #[test]
    fn sideload_and_unsigned_rejected() {
        assert!(matches!(
            install_decision(&m("t", &[Network], &[Network], true, true)),
            InstallVerdict::Reject(_)
        ));
        assert!(matches!(
            install_decision(&m("t", &[Network], &[Network], false, false)),
            InstallVerdict::Reject(_)
        ));
    }

    #[test]
    fn unapproved_entitlement_rejected() {
        assert!(matches!(
            install_decision(&m("t", &[Camera], &[Network], true, false)),
            InstallVerdict::Reject(_)
        ));
    }

    #[test]
    fn restricted_only_for_passaura_even_if_approved() {
        assert!(matches!(
            install_decision(&m(
                "evil",
                &[CredentialProvider],
                &[CredentialProvider],
                true,
                false
            )),
            InstallVerdict::Reject(_)
        ));
        assert_eq!(
            install_decision(&m(
                PASSAURA_TEAM,
                &[CredentialProvider, AutofillProvider],
                &[CredentialProvider, AutofillProvider],
                true,
                false
            )),
            InstallVerdict::Install
        );
    }

    #[test]
    fn ordinary_app_installs() {
        assert_eq!(
            install_decision(&m("t", &[Network, Camera], &[Network, Camera], true, false)),
            InstallVerdict::Install
        );
    }
}
