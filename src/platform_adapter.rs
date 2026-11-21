use crate::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformFeature {
    CorePolicy,
    SecureStorage,
    NativeAutofill,
    SystemWideControls,
    ApplicationManagement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationStatus {
    CoreAvailable,
    NativeIntegrationPending,
}

pub trait PlatformAdapter {
    fn platform(&self) -> Platform;

    fn supports(&self, feature: PlatformFeature) -> bool;

    fn integration_status(&self) -> IntegrationStatus;
}

pub struct AndroidAdapter;

impl PlatformAdapter for AndroidAdapter {
    fn platform(&self) -> Platform {
        Platform::Android
    }

    fn supports(&self, feature: PlatformFeature) -> bool {
        matches!(feature, PlatformFeature::CorePolicy)
    }

    fn integration_status(&self) -> IntegrationStatus {
        IntegrationStatus::NativeIntegrationPending
    }
}

pub struct WindowsAdapter;

impl PlatformAdapter for WindowsAdapter {
    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn supports(&self, feature: PlatformFeature) -> bool {
        matches!(feature, PlatformFeature::CorePolicy)
    }

    fn integration_status(&self) -> IntegrationStatus {
        IntegrationStatus::NativeIntegrationPending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_adapter_identifies_platform() {
        let adapter = AndroidAdapter;
        assert!(matches!(adapter.platform(), Platform::Android));
    }

    #[test]
    fn windows_adapter_identifies_platform() {
        let adapter = WindowsAdapter;
        assert!(matches!(adapter.platform(), Platform::Windows));
    }

    #[test]
    fn core_policy_is_available() {
        let android = AndroidAdapter;
        let windows = WindowsAdapter;

        assert!(android.supports(PlatformFeature::CorePolicy));
        assert!(windows.supports(PlatformFeature::CorePolicy));
    }

    #[test]
    fn native_features_are_not_claimed_as_available() {
        let android = AndroidAdapter;
        let windows = WindowsAdapter;

        assert!(!android.supports(PlatformFeature::SecureStorage));
        assert!(!windows.supports(PlatformFeature::SecureStorage));

        assert_eq!(
            android.integration_status(),
            IntegrationStatus::NativeIntegrationPending
        );

        assert_eq!(
            windows.integration_status(),
            IntegrationStatus::NativeIntegrationPending
        );
    }
}
