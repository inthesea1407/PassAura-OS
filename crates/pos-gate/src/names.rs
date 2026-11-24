use std::fmt;

/// Maximum allowed length for a package identifier (`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$`).
pub const MAX_PACKAGE_NAME_LEN: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong(usize),
    InvalidStartChar(char),
    InvalidChar(char),
    PathTraversal,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Empty => write!(f, "package name must not be empty"),
            NameError::TooLong(len) => {
                write!(f, "package name length {len} exceeds maximum {MAX_PACKAGE_NAME_LEN}")
            }
            NameError::InvalidStartChar(c) => {
                write!(f, "package name must start with ASCII alphanumeric, got {c:?}")
            }
            NameError::InvalidChar(c) => {
                write!(f, "package name contains disallowed character {c:?}")
            }
            NameError::PathTraversal => {
                write!(f, "package name contains path traversal or separator")
            }
        }
    }
}

impl std::error::Error for NameError {}

/// Validates a package name against `^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$`
/// and explicitly rejects shell metacharacters, leading dashes, and path separators.
pub fn validate_package_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_PACKAGE_NAME_LEN {
        return Err(NameError::TooLong(name.len()));
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(NameError::PathTraversal);
    }

    let mut chars = name.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return Err(NameError::Empty),
    };

    if !first.is_ascii_alphanumeric() {
        if first == '-' {
            return Err(NameError::InvalidStartChar(first));
        }
        return Err(NameError::InvalidStartChar(first));
    }

    for c in chars {
        if !c.is_ascii_alphanumeric() && !matches!(c, '.' | '+' | '_' | '-') {
            return Err(NameError::InvalidChar(c));
        }
    }

    Ok(())
}

/// Convenience boolean wrapper around [`validate_package_name`].
pub fn is_valid_package_name(name: &str) -> bool {
    validate_package_name(name).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_package_names() {
        for valid in [
            "ripgrep",
            "fd-find",
            "libssl3",
            "g++",
            "python3.12",
            "pkg_name-1.0+pos",
            &"a".repeat(MAX_PACKAGE_NAME_LEN),
        ] {
            assert!(
                validate_package_name(valid).is_ok(),
                "expected valid package name: {valid}"
            );
            assert!(is_valid_package_name(valid));
        }
    }

    #[test]
    fn rejects_empty_and_overlong_names() {
        assert_eq!(validate_package_name(""), Err(NameError::Empty));
        let too_long = "a".repeat(MAX_PACKAGE_NAME_LEN + 1);
        assert_eq!(
            validate_package_name(&too_long),
            Err(NameError::TooLong(MAX_PACKAGE_NAME_LEN + 1))
        );
    }

    #[test]
    fn rejects_leading_dash_and_non_alnum_start() {
        assert!(matches!(
            validate_package_name("-ripgrep"),
            Err(NameError::InvalidStartChar('-'))
        ));
        assert!(matches!(
            validate_package_name(".hidden"),
            Err(NameError::InvalidStartChar('.'))
        ));
        assert!(matches!(
            validate_package_name("_pkg"),
            Err(NameError::InvalidStartChar('_'))
        ));
    }

    #[test]
    fn rejects_path_separators_and_traversal() {
        assert_eq!(
            validate_package_name("../etc/passwd"),
            Err(NameError::PathTraversal)
        );
        assert_eq!(
            validate_package_name("dir/pkg"),
            Err(NameError::PathTraversal)
        );
        assert_eq!(
            validate_package_name("dir\\pkg"),
            Err(NameError::PathTraversal)
        );
        assert_eq!(
            validate_package_name("pkg..name"),
            Err(NameError::PathTraversal)
        );
    }

    #[test]
    fn rejects_shell_metacharacters_and_whitespace() {
        for bad in [
            "pkg;id",
            "pkg$(whoami)",
            "pkg`id`",
            "pkg|cat",
            "pkg&bg",
            "pkg name",
            "pkg\nline",
            "pkg\0nul",
        ] {
            assert!(
                validate_package_name(bad).is_err(),
                "expected shell/control input to be rejected: {bad:?}"
            );
        }
    }
}
