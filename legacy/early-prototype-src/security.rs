#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    ReadVault,
    WriteVault,
    ExportData,
    ImportData,
    ManageSettings,
    NetworkAccess,
    InstallExtension,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ReadVault,
    WriteVault,
    ExportData,
    ImportData,
    ManageSettings,
    NetworkRequest,
    InstallExtension,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    DenyAuthenticationRequired,
    DenyCapabilityMissing,
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityContext {
    pub authenticated: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    allowed: Vec<Capability>,
    require_authentication: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            require_authentication: true,
        }
    }
}

impl SecurityPolicy {
    pub fn new(require_authentication: bool) -> Self {
        Self {
            allowed: Vec::new(),
            require_authentication,
        }
    }

    pub fn grant(&mut self, capability: Capability) {
        if !self.allowed.contains(&capability) {
            self.allowed.push(capability);
        }
    }

    pub fn revoke(&mut self, capability: Capability) {
        self.allowed.retain(|item| *item != capability);
    }

    pub fn has_capability(&self, capability: Capability) -> bool {
        self.allowed.contains(&capability)
    }

    pub fn evaluate(&self, action: Action, context: SecurityContext) -> Decision {
        if self.require_authentication && !context.authenticated {
            return Decision::DenyAuthenticationRequired;
        }

        let required = match action {
            Action::ReadVault => Capability::ReadVault,
            Action::WriteVault => Capability::WriteVault,
            Action::ExportData => Capability::ExportData,
            Action::ImportData => Capability::ImportData,
            Action::ManageSettings => Capability::ManageSettings,
            Action::NetworkRequest => Capability::NetworkAccess,
            Action::InstallExtension => Capability::InstallExtension,
        };

        if self.has_capability(required) {
            Decision::Allow
        } else {
            Decision::DenyCapabilityMissing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_by_default() {
        let policy = SecurityPolicy::default();
        let context = SecurityContext {
            authenticated: true,
        };

        assert_eq!(
            policy.evaluate(Action::ReadVault, context),
            Decision::DenyCapabilityMissing
        );
    }

    #[test]
    fn allow_granted_capability() {
        let mut policy = SecurityPolicy::default();
        policy.grant(Capability::ReadVault);

        let context = SecurityContext {
            authenticated: true,
        };

        assert_eq!(policy.evaluate(Action::ReadVault, context), Decision::Allow);
    }

    #[test]
    fn require_authentication() {
        let mut policy = SecurityPolicy::default();
        policy.grant(Capability::ReadVault);

        let context = SecurityContext {
            authenticated: false,
        };

        assert_eq!(
            policy.evaluate(Action::ReadVault, context),
            Decision::DenyAuthenticationRequired
        );
    }

    #[test]
    fn revoke_capability() {
        let mut policy = SecurityPolicy::default();
        policy.grant(Capability::WriteVault);
        policy.revoke(Capability::WriteVault);

        let context = SecurityContext {
            authenticated: true,
        };

        assert_eq!(
            policy.evaluate(Action::WriteVault, context),
            Decision::DenyCapabilityMissing
        );
    }
}
