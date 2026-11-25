//! PassAura OS security core.
//!
//! Deny-by-default: an action is allowed only if an unexpired, unrevoked
//! grant matches the subject, the resource and the action. An explicit
//! deny rule always wins over any grant.

pub mod admin;
pub mod audit;
pub mod blocking;
pub mod device;
pub mod entitlements;
pub mod fawry;
pub mod invite;
pub mod policy;

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Read,
    Write,
    Execute,
    Network,
    Camera,
    Microphone,
    Location,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    UnknownSubject,
    NotAuthenticated,
    NoGrant,
    Revoked,
    Expired,
    ExplicitDeny,
}

/// Resource path such as "app/notes/data". A grant on "app/notes" covers
/// "app/notes/data" but not "app/notes2".
fn covers(grant: &str, resource: &str) -> bool {
    grant == "*"
        || resource == grant
        || (resource.starts_with(grant) && resource.as_bytes().get(grant.len()) == Some(&b'/'))
}

#[derive(Debug, Clone)]
struct Grant {
    resource: String,
    action: Action,
    expires_at: Option<u64>,
    revoked: bool,
}

#[derive(Debug, Clone)]
struct Subject {
    authenticated: bool,
    grants: Vec<Grant>,
    denies: Vec<(String, Action)>,
}

/// Policy schema version. Bump when decision semantics change.
pub const POLICY_VERSION: u32 = 1;

/// One audit record. Holds identifiers only: never tokens or secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub policy_version: u32,
    pub subject: String,
    pub resource: String,
    pub action: Action,
    pub at: u64,
    pub decision: Decision,
}

#[derive(Debug, Default)]
pub struct PolicyEngine {
    subjects: HashMap<SubjectId, Subject>,
    log: Vec<AuditRecord>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, id: &str) -> SubjectId {
        let sid = SubjectId(id.to_string());
        self.subjects.entry(sid.clone()).or_insert(Subject {
            authenticated: false,
            grants: vec![],
            denies: vec![],
        });
        sid
    }

    pub fn set_authenticated(&mut self, id: &SubjectId, ok: bool) -> bool {
        match self.subjects.get_mut(id) {
            Some(s) => {
                s.authenticated = ok;
                true
            }
            None => false,
        }
    }

    pub fn grant(
        &mut self,
        id: &SubjectId,
        resource: &str,
        action: Action,
        expires_at: Option<u64>,
    ) -> bool {
        match self.subjects.get_mut(id) {
            Some(s) => {
                s.grants.push(Grant {
                    resource: resource.into(),
                    action,
                    expires_at,
                    revoked: false,
                });
                true
            }
            None => false,
        }
    }

    pub fn deny(&mut self, id: &SubjectId, resource: &str, action: Action) -> bool {
        match self.subjects.get_mut(id) {
            Some(s) => {
                s.denies.push((resource.into(), action));
                true
            }
            None => false,
        }
    }

    /// Revoke every matching grant. Returns how many were revoked.
    pub fn revoke(&mut self, id: &SubjectId, resource: &str, action: Action) -> usize {
        let mut n = 0;
        if let Some(s) = self.subjects.get_mut(id) {
            for g in s
                .grants
                .iter_mut()
                .filter(|g| g.resource == resource && g.action == action && !g.revoked)
            {
                g.revoked = true;
                n += 1;
            }
        }
        n
    }

    /// Like `check`, and records the decision in the audit log.
    pub fn check_logged(
        &mut self,
        id: &SubjectId,
        resource: &str,
        action: Action,
        now: u64,
    ) -> Decision {
        let decision = self.check(id, resource, action, now);
        self.log.push(AuditRecord {
            policy_version: POLICY_VERSION,
            subject: id.0.clone(),
            resource: resource.into(),
            action,
            at: now,
            decision: decision.clone(),
        });
        decision
    }

    pub fn audit_log(&self) -> &[AuditRecord] {
        &self.log
    }

    /// `now` is seconds since epoch, passed in so decisions are testable.
    pub fn check(&self, id: &SubjectId, resource: &str, action: Action, now: u64) -> Decision {
        let Some(s) = self.subjects.get(id) else {
            return Decision::Deny(DenyReason::UnknownSubject);
        };
        if !s.authenticated {
            return Decision::Deny(DenyReason::NotAuthenticated);
        }
        if s.denies
            .iter()
            .any(|(r, a)| *a == action && covers(r, resource))
        {
            return Decision::Deny(DenyReason::ExplicitDeny);
        }
        let mut reason = DenyReason::NoGrant;
        for g in s
            .grants
            .iter()
            .filter(|g| g.action == action && covers(&g.resource, resource))
        {
            if g.revoked {
                reason = DenyReason::Revoked;
            } else if g.expires_at.is_some_and(|t| now >= t) {
                reason = DenyReason::Expired;
            } else {
                return Decision::Allow;
            }
        }
        Decision::Deny(reason)
    }
}

/// Product rules fixed by the owner.
/// 1. No ads anywhere in the system.
/// 2. Only PassAura Premium may act as the password manager.
pub const ADS_ALLOWED: bool = false;
pub const PASSWORD_MANAGER_ID: &str = "passaura.premium";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCategory {
    PasswordManager,
    Ads,
    Other,
}

/// Deny-by-default system policy for app categories.
/// `licensed` is whether the user has an active PassAura Premium license.
pub fn category_allowed(category: AppCategory, app_id: &str, licensed: bool) -> bool {
    match category {
        AppCategory::Ads => ADS_ALLOWED,
        AppCategory::PasswordManager => app_id == PASSWORD_MANAGER_ID && licensed,
        AppCategory::Other => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (PolicyEngine, SubjectId) {
        let mut e = PolicyEngine::new();
        let s = e.register("app.notes");
        e.set_authenticated(&s, true);
        (e, s)
    }

    #[test]
    fn no_ads_ever() {
        assert!(!category_allowed(AppCategory::Ads, "any", true));
    }

    #[test]
    fn only_premium_password_manager() {
        assert!(category_allowed(
            AppCategory::PasswordManager,
            PASSWORD_MANAGER_ID,
            true
        ));
        assert!(!category_allowed(
            AppCategory::PasswordManager,
            PASSWORD_MANAGER_ID,
            false
        ));
        assert!(!category_allowed(
            AppCategory::PasswordManager,
            "other.manager",
            true
        ));
    }

    #[test]
    fn denies_by_default() {
        let (e, s) = setup();
        assert_eq!(
            e.check(&s, "app/notes", Action::Read, 0),
            Decision::Deny(DenyReason::NoGrant)
        );
    }

    #[test]
    fn unknown_subject_denied() {
        let e = PolicyEngine::new();
        assert_eq!(
            e.check(&SubjectId("x".into()), "a", Action::Read, 0),
            Decision::Deny(DenyReason::UnknownSubject)
        );
    }

    #[test]
    fn unauthenticated_denied_even_with_grant() {
        let (mut e, s) = setup();
        e.grant(&s, "app/notes", Action::Read, None);
        e.set_authenticated(&s, false);
        assert_eq!(
            e.check(&s, "app/notes", Action::Read, 0),
            Decision::Deny(DenyReason::NotAuthenticated)
        );
    }

    #[test]
    fn grant_allows_child_not_sibling() {
        let (mut e, s) = setup();
        e.grant(&s, "app/notes", Action::Read, None);
        assert_eq!(
            e.check(&s, "app/notes/data", Action::Read, 0),
            Decision::Allow
        );
        assert_eq!(
            e.check(&s, "app/notes2", Action::Read, 0),
            Decision::Deny(DenyReason::NoGrant)
        );
        assert_eq!(
            e.check(&s, "app/notes/data", Action::Write, 0),
            Decision::Deny(DenyReason::NoGrant)
        );
    }

    #[test]
    fn expiry_enforced() {
        let (mut e, s) = setup();
        e.grant(&s, "cam", Action::Camera, Some(100));
        assert_eq!(e.check(&s, "cam", Action::Camera, 99), Decision::Allow);
        assert_eq!(
            e.check(&s, "cam", Action::Camera, 100),
            Decision::Deny(DenyReason::Expired)
        );
    }

    #[test]
    fn revoke_removes_access() {
        let (mut e, s) = setup();
        e.grant(&s, "net", Action::Network, None);
        assert_eq!(e.revoke(&s, "net", Action::Network), 1);
        assert_eq!(
            e.check(&s, "net", Action::Network, 0),
            Decision::Deny(DenyReason::Revoked)
        );
    }

    #[test]
    fn explicit_deny_beats_grant() {
        let (mut e, s) = setup();
        e.grant(&s, "*", Action::Read, None);
        e.deny(&s, "secrets", Action::Read);
        assert_eq!(
            e.check(&s, "secrets/key", Action::Read, 0),
            Decision::Deny(DenyReason::ExplicitDeny)
        );
        assert_eq!(e.check(&s, "other", Action::Read, 0), Decision::Allow);
    }

    #[test]
    fn audit_log_records_allow_and_deny() {
        let (mut e, s) = setup();
        e.grant(&s, "a", Action::Read, None);
        e.check_logged(&s, "a", Action::Read, 5);
        e.check_logged(&s, "b", Action::Read, 6);
        let l = e.audit_log();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].decision, Decision::Allow);
        assert_eq!(l[1].decision, Decision::Deny(DenyReason::NoGrant));
        assert_eq!(l[0].policy_version, POLICY_VERSION);
    }

    #[test]
    fn empty_resource_and_wildcard_boundaries() {
        let (mut e, s) = setup();
        e.grant(&s, "app", Action::Read, None);
        assert_eq!(
            e.check(&s, "", Action::Read, 0),
            Decision::Deny(DenyReason::NoGrant)
        );
        assert_eq!(e.check(&s, "app/", Action::Read, 0), Decision::Allow);
        assert_eq!(
            e.check(&s, "ap", Action::Read, 0),
            Decision::Deny(DenyReason::NoGrant)
        );
    }

    #[test]
    fn regrant_after_revoke_allows() {
        let (mut e, s) = setup();
        e.grant(&s, "net", Action::Network, None);
        e.revoke(&s, "net", Action::Network);
        e.grant(&s, "net", Action::Network, None);
        assert_eq!(e.check(&s, "net", Action::Network, 0), Decision::Allow);
    }
}
