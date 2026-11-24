//! Invite-code access. Single-use codes, two invites per member.
//! Codes are supplied by the caller: production must generate them with a
//! cryptographically secure RNG (at least 128 bits) and store only hashes.

use std::collections::HashMap;

pub const INVITES_PER_MEMBER: usize = 2;
pub const SEED_CAP: usize = 1000;

#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    UnknownInviter,
    QuotaExhausted,
    DuplicateCode,
    UnknownCode,
    AlreadyRedeemed,
    AlreadyMember,
    SeedClosed,
    InviterRevoked,
}

#[derive(Debug)]
struct Invite {
    inviter: String,
    redeemed_by: Option<String>,
}

#[derive(Debug, Default)]
pub struct InviteBook {
    members: HashMap<String, usize>, // member -> invites issued so far
    invites: HashMap<String, Invite>,
    seeds: Vec<String>, // registration order
    revoked: std::collections::HashSet<String>,
}

impl InviteBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Founder/seed member, outside the invite chain.
    pub fn add_seed_member(&mut self, id: &str) {
        self.members.entry(id.into()).or_insert(0);
    }

    /// Open registration: the first SEED_CAP registrants join without a
    /// code and get their own invites. After that, registration is refused
    /// and only `redeem` can add members.
    pub fn register_seed(&mut self, id: &str) -> Result<usize, InviteError> {
        // Idempotent: a retry by the same id returns its existing seed
        // number and never grants a second set of invites.
        if let Some(n) = self.seed_number(id) {
            return Ok(n);
        }
        if self.members.contains_key(id) {
            return Err(InviteError::AlreadyMember);
        }
        if self.seeds.len() >= SEED_CAP {
            return Err(InviteError::SeedClosed);
        }
        self.members.insert(id.into(), 0);
        self.seeds.push(id.into());
        Ok(self.seeds.len()) // seed number, 1-based
    }

    pub fn seed_number(&self, id: &str) -> Option<usize> {
        self.seeds.iter().position(|s| s == id).map(|i| i + 1)
    }

    /// Membership never expires. Only the owner revokes. Revoking also
    /// voids the member's unredeemed invites. The slot is not reused.
    pub fn revoke_member(&mut self, id: &str) -> bool {
        if !self.members.contains_key(id) || !self.revoked.insert(id.into()) {
            return false;
        }
        self.invites.retain(|_, i| !(i.inviter == id && i.redeemed_by.is_none()));
        true
    }

    /// Active = member and not revoked. Premium features need this.
    pub fn is_active(&self, id: &str) -> bool {
        self.members.contains_key(id) && !self.revoked.contains(id)
    }

    /// Vault keys and export never depend on membership, payment or mode.
    pub fn can_export_vault(&self, _id: &str) -> bool {
        true
    }

    /// Exporting one's own data is allowed for every member, revoked or not.
    pub fn can_export(&self, id: &str) -> bool {
        self.members.contains_key(id)
    }

    pub fn is_member(&self, id: &str) -> bool {
        self.members.contains_key(id)
    }

    pub fn issue(&mut self, inviter: &str, code: &str) -> Result<(), InviteError> {
        let used = *self.members.get(inviter).ok_or(InviteError::UnknownInviter)?;
        // A revoked member must not keep growing the network.
        if self.revoked.contains(inviter) {
            return Err(InviteError::InviterRevoked);
        }
        if used >= INVITES_PER_MEMBER {
            return Err(InviteError::QuotaExhausted);
        }
        if self.invites.contains_key(code) {
            return Err(InviteError::DuplicateCode);
        }
        self.invites.insert(code.into(), Invite { inviter: inviter.into(), redeemed_by: None });
        *self.members.get_mut(inviter).unwrap() += 1;
        Ok(())
    }

    /// Redeem once. The new member gets their own two invites.
    pub fn redeem(&mut self, code: &str, new_member: &str) -> Result<(), InviteError> {
        if self.members.contains_key(new_member) {
            return Err(InviteError::AlreadyMember);
        }
        let inv = self.invites.get_mut(code).ok_or(InviteError::UnknownCode)?;
        if inv.redeemed_by.is_some() {
            return Err(InviteError::AlreadyRedeemed);
        }
        inv.redeemed_by = Some(new_member.into());
        self.members.insert(new_member.into(), 0);
        Ok(())
    }

    pub fn remaining(&self, member: &str) -> Option<usize> {
        self.members.get(member).map(|u| INVITES_PER_MEMBER - u)
    }

    pub fn inviter_of(&self, member: &str) -> Option<&str> {
        self.invites
            .values()
            .find(|i| i.redeemed_by.as_deref() == Some(member))
            .map(|i| i.inviter.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_invites_each_single_use() {
        let mut b = InviteBook::new();
        b.add_seed_member("founder");
        assert_eq!(b.issue("founder", "c1"), Ok(()));
        assert_eq!(b.issue("founder", "c2"), Ok(()));
        assert_eq!(b.issue("founder", "c3"), Err(InviteError::QuotaExhausted));
        assert_eq!(b.redeem("c1", "alice"), Ok(()));
        assert_eq!(b.redeem("c1", "bob"), Err(InviteError::AlreadyRedeemed));
        assert_eq!(b.remaining("alice"), Some(2));
        assert_eq!(b.inviter_of("alice"), Some("founder"));
    }

    #[test]
    fn seed_cap_then_invite_only() {
        let mut b = InviteBook::new();
        for i in 1..=SEED_CAP {
            assert_eq!(b.register_seed(&format!("u{i}")), Ok(i));
        }
        assert_eq!(b.register_seed("late"), Err(InviteError::SeedClosed));
        assert_eq!(b.seed_number("u1"), Some(1));
        assert_eq!(b.seed_number("u1000"), Some(1000));
        assert_eq!(b.remaining("u5"), Some(2));
        b.issue("u5", "code").unwrap();
        assert_eq!(b.redeem("code", "late"), Ok(()));
        assert_eq!(b.register_seed("u1"), Ok(1)); // idempotent retry
        assert_eq!(b.remaining("u1"), Some(2)); // no second grant of invites
    }

    #[test]
    fn revoke_only_by_owner_call_voids_pending_invites_keeps_export() {
        let mut b = InviteBook::new();
        b.add_seed_member("f");
        b.issue("f", "c1").unwrap();
        assert!(b.is_active("f"));
        assert!(b.revoke_member("f"));
        assert!(!b.revoke_member("f"));
        assert!(!b.is_active("f"));
        assert!(b.can_export("f"));
        assert_eq!(b.redeem("c1", "x"), Err(InviteError::UnknownCode));
        assert!(!b.can_export("stranger"));
    }

    #[test]
    fn vault_export_never_depends_on_membership() {
        let b = InviteBook::new();
        assert!(b.can_export_vault("anyone"));
    }

    #[test]
    fn strangers_cannot_issue_or_redeem_unknown() {
        let mut b = InviteBook::new();
        assert_eq!(b.issue("nobody", "x"), Err(InviteError::UnknownInviter));
        assert_eq!(b.redeem("x", "a"), Err(InviteError::UnknownCode));
    }

    #[test]
    fn duplicate_code_and_existing_member_rejected() {
        let mut b = InviteBook::new();
        b.add_seed_member("f");
        b.add_seed_member("g");
        b.issue("f", "c").unwrap();
        assert_eq!(b.issue("g", "c"), Err(InviteError::DuplicateCode));
        assert_eq!(b.redeem("c", "g"), Err(InviteError::AlreadyMember));
    }
}

#[cfg(test)]
mod revoked_inviter_tests {
    use super::*;

    #[test]
    fn revoked_member_cannot_issue_invites() {
        let mut b = InviteBook::new();
        b.add_seed_member("a");
        assert!(b.revoke_member("a"));
        assert_eq!(b.issue("a", "code-1"), Err(InviteError::InviterRevoked));
        assert_eq!(b.redeem("code-1", "x"), Err(InviteError::UnknownCode));
    }
}
