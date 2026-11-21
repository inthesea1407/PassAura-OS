pub const POS_NAME: &str = "PassAura OS";
pub const POS_CORE_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Android,
    Windows,
    Linux,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    Arm64,
    X86_64,
    X86,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemInfo {
    pub platform: Platform,
    pub architecture: Architecture,
}

pub fn detect_system() -> SystemInfo {
    let platform = if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else {
        Platform::Unknown
    };

    let architecture = if cfg!(target_arch = "aarch64") {
        Architecture::Arm64
    } else if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else if cfg!(target_arch = "x86") {
        Architecture::X86
    } else {
        Architecture::Unknown
    };

    SystemInfo {
        platform,
        architecture,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity() {
        assert_eq!(POS_NAME, "PassAura OS");
        assert_eq!(POS_CORE_VERSION, "0.1.0");
    }

    #[test]
    fn test_detect_system() {
        let info = detect_system();
        assert_ne!(info.platform, Platform::Unknown);
        assert_ne!(info.architecture, Architecture::Unknown);
    }

    #[test]
    fn test_android_arm64() {
        if cfg!(target_os = "android") && cfg!(target_arch = "aarch64") {
            let info = detect_system();
            assert_eq!(info.platform, Platform::Android);
            assert_eq!(info.architecture, Architecture::Arm64);
        }
    }
}
pub mod platform_adapter;
pub mod security;
