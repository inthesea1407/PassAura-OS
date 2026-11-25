//! Owner admin controls: access mode, pausing invites, revoking members.
//! Every admin action needs an `AdminToken` (checked by the caller against
//! an owner-held credential) and is written to the admin audit log.

use crate::invite::{InviteBook, InviteError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Free, invite based (current decision).
    FreeInvite,
    /// Paid: joining needs a payment proof; invites do not grant access.
    Paid,
    /// Nobody new joins.
    Closed,
}

/// Who must pay once Paid mode is on. The owner decides later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaidScope {
    /// Only people who join after the switch pay. Existing members stay free.
    NewOnly,
    /// Everyone pays, existing members included (after the switch).
    Everyone,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdminError {
    NotOwner,
    Denied(&'static str),
    Invite(InviteError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminEvent {
    ModeChanged(AccessMode),
    PaidScopeChanged(PaidScope),
    IssuancePaused(bool),
    RedemptionPaused(bool),
    MemberRevoked(String),
}

/// Proof that the caller is the owner. Constructed only by the code that
/// verifies the owner credential (hardware key / passkey), never by apps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,   // everything
    Support, // revoke members only
}

pub const REAUTH_WINDOW: u64 = 300;

pub struct AdminToken {
    role: Role,
    authed_at: u64,
}

impl AdminToken {
    /// Called only by the code that has verified a strong credential
    /// (passkey / hardware key) for this session.
    pub fn verified(role: Role, authed_at: u64) -> Self {
        AdminToken { role, authed_at }
    }
    pub fn verified_owner(authed_at: u64) -> Self {
        Self::verified(Role::Owner, authed_at)
    }
    fn fresh(&self, now: u64) -> bool {
        now >= self.authed_at && now - self.authed_at <= REAUTH_WINDOW
    }
}

pub struct AccessControl {
    pub mode: AccessMode,
    pub paid_scope: PaidScope,
    paid: std::collections::HashSet<String>,
    pub issuance_paused: bool,
    pub redemption_paused: bool,
    pub book: InviteBook,
    pub events: Vec<AdminEvent>,
}

impl AccessControl {
    pub fn new(book: InviteBook) -> Self {
        Self { mode: AccessMode::FreeInvite, paid_scope: PaidScope::NewOnly, paid: Default::default(), issuance_paused: false, redemption_paused: false, book, events: vec![] }
    }

    // ---- admin actions ----
    // Role separation: Owner does everything, Support only revokes.
    // Every action needs a fresh re-authentication (REAUTH_WINDOW).
    fn authorize(t: &AdminToken, now: u64, owner_only: bool) -> Result<(), AdminError> {
        if owner_only && t.role != Role::Owner {
            return Err(AdminError::NotOwner);
        }
        if !t.fresh(now) {
            return Err(AdminError::Denied("re-authentication required"));
        }
        Ok(())
    }

    pub fn set_mode(&mut self, t: &AdminToken, now: u64, m: AccessMode) -> Result<(), AdminError> {
        Self::authorize(t, now, true)?;
        self.mode = m;
        self.events.push(AdminEvent::ModeChanged(m));
        Ok(())
    }
    pub fn set_paid_scope(&mut self, t: &AdminToken, now: u64, sc: PaidScope) -> Result<(), AdminError> {
        Self::authorize(t, now, true)?;
        self.paid_scope = sc;
        self.events.push(AdminEvent::PaidScopeChanged(sc));
        Ok(())
    }

    /// Record a verified payment (payment checked out of band).
    pub fn mark_paid(&mut self, id: &str) {
        if self.book.is_member(id) {
            self.paid.insert(id.into());
        }
    }

    pub fn pause_issuance(&mut self, t: &AdminToken, now: u64, p: bool) -> Result<(), AdminError> {
        Self::authorize(t, now, true)?;
        self.issuance_paused = p;
        self.events.push(AdminEvent::IssuancePaused(p));
        Ok(())
    }
    pub fn pause_redemption(&mut self, t: &AdminToken, now: u64, p: bool) -> Result<(), AdminError> {
        Self::authorize(t, now, true)?;
        self.redemption_paused = p;
        self.events.push(AdminEvent::RedemptionPaused(p));
        Ok(())
    }
    pub fn revoke(&mut self, t: &AdminToken, now: u64, id: &str) -> Result<bool, AdminError> {
        Self::authorize(t, now, false)?;
        let ok = self.book.revoke_member(id);
        if ok {
            self.events.push(AdminEvent::MemberRevoked(id.into()));
        }
        Ok(ok)
    }

    // ---- member-facing actions, gated by the admin switches ----
    pub fn issue(&mut self, inviter: &str, code: &str) -> Result<(), AdminError> {
        if self.mode != AccessMode::FreeInvite {
            return Err(AdminError::Denied("invites only work in free-invite mode"));
        }
        if self.issuance_paused {
            return Err(AdminError::Denied("invite issuance is paused"));
        }
        if !self.book.is_active(inviter) {
            return Err(AdminError::Denied("inviter is not an active member"));
        }
        self.book.issue(inviter, code).map_err(AdminError::Invite)
    }

    pub fn redeem(&mut self, code: &str, device: &str) -> Result<(), AdminError> {
        if self.mode != AccessMode::FreeInvite {
            return Err(AdminError::Denied("invites only work in free-invite mode"));
        }
        if self.redemption_paused {
            return Err(AdminError::Denied("invite redemption is paused"));
        }
        self.book.redeem(code, device).map_err(AdminError::Invite)
    }

    /// Paid mode join: the caller has verified payment out of band.
    pub fn join_paid(&mut self, device: &str, payment_verified: bool) -> Result<(), AdminError> {
        if self.mode != AccessMode::Paid {
            return Err(AdminError::Denied("paid join only in paid mode"));
        }
        if !payment_verified {
            return Err(AdminError::Denied("payment not verified"));
        }
        self.book.add_seed_member(device);
        self.paid.insert(device.into());
        Ok(())
    }

    /// Access rules:
    /// - not active (revoked/unknown): no access
    /// - FreeInvite or Closed: active members keep access
    /// - Paid + NewOnly: everyone already in keeps access, new joiners paid
    /// - Paid + Everyone: only members with a recorded payment have access
    ///
    /// Vault export is separate and never depends on this.
    pub fn has_access(&self, id: &str) -> bool {
        if !self.book.is_active(id) {
            return false;
        }
        match (self.mode, self.paid_scope) {
            (AccessMode::Paid, PaidScope::Everyone) => self.paid.contains(id),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl() -> AccessControl {
        let mut b = InviteBook::new();
        b.add_seed_member("owner-seed");
        AccessControl::new(b)
    }

    #[test]
    fn pause_issuance_and_redemption() {
        let t = AdminToken::verified_owner(0);
        let mut c = ctl();
        c.pause_issuance(&t, 1, true).unwrap();
        assert!(matches!(c.issue("owner-seed", "a"), Err(AdminError::Denied(_))));
        c.pause_issuance(&t, 1, false).unwrap();
        c.issue("owner-seed", "a").unwrap();
        c.pause_redemption(&t, 1, true).unwrap();
        assert!(matches!(c.redeem("a", "d"), Err(AdminError::Denied(_))));
        c.pause_redemption(&t, 1, false).unwrap();
        assert!(c.redeem("a", "d").is_ok());
    }

    #[test]
    fn paid_mode_disables_invites_but_keeps_members() {
        let t = AdminToken::verified_owner(0);
        let mut c = ctl();
        c.set_mode(&t, 1, AccessMode::Paid).unwrap();
        assert!(matches!(c.issue("owner-seed", "a"), Err(AdminError::Denied(_))));
        assert!(c.has_access("owner-seed"));
        assert!(c.join_paid("new", false).is_err());
        assert!(c.join_paid("new", true).is_ok());
        assert!(c.has_access("new"));
    }

    #[test]
    fn support_cannot_change_mode_stale_session_rejected() {
        let mut c = ctl();
        let support = AdminToken::verified(Role::Support, 0);
        assert_eq!(c.set_mode(&support, 1, AccessMode::Closed), Err(AdminError::NotOwner));
        assert_eq!(c.revoke(&support, 1, "owner-seed"), Ok(true));
        let owner = AdminToken::verified_owner(0);
        assert!(matches!(c.set_mode(&owner, REAUTH_WINDOW + 1, AccessMode::Paid), Err(AdminError::Denied(_))));
        assert_eq!(c.mode, AccessMode::FreeInvite);
    }

    #[test]
    fn paid_everyone_vs_new_only() {
        let t = AdminToken::verified_owner(0);
        // New only (default): existing member stays free.
        let mut c = ctl();
        c.set_mode(&t, 1, AccessMode::Paid).unwrap();
        assert!(c.has_access("owner-seed"));
        // Everyone: existing member loses access until paid, export stays.
        c.set_paid_scope(&t, 1, PaidScope::Everyone).unwrap();
        assert!(!c.has_access("owner-seed"));
        assert!(c.book.can_export_vault("owner-seed"));
        c.mark_paid("owner-seed");
        assert!(c.has_access("owner-seed"));
        // Switching back restores free access for the unpaid.
        let mut d = ctl();
        d.set_mode(&t, 1, AccessMode::Paid).unwrap();
        d.set_paid_scope(&t, 1, PaidScope::Everyone).unwrap();
        d.set_mode(&t, 1, AccessMode::FreeInvite).unwrap();
        assert!(d.has_access("owner-seed"));
    }

    #[test]
    fn closed_mode_blocks_all_new_joins() {
        let t = AdminToken::verified_owner(0);
        let mut c = ctl();
        c.set_mode(&t, 1, AccessMode::Closed).unwrap();
        assert!(c.join_paid("n", true).is_err());
        assert!(c.issue("owner-seed", "a").is_err());
    }

    #[test]
    fn revoke_removes_access_logs_event_and_blocks_issuing() {
        let t = AdminToken::verified_owner(0);
        let mut c = ctl();
        assert_eq!(c.revoke(&t, 1, "owner-seed"), Ok(true));
        assert!(!c.has_access("owner-seed"));
        assert!(c.issue("owner-seed", "a").is_err());
        assert_eq!(c.events, vec![AdminEvent::MemberRevoked("owner-seed".into())]);
    }
}
