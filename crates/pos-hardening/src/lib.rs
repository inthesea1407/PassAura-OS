//! Audit a kernel .config against a profile of `OPTION=y|n` lines.
//! A missing option counts as disabled ("is not set").

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub option: String,
    pub expected: char,
    pub actual: char,
}

fn parse_config(cfg: &str) -> std::collections::HashMap<String, char> {
    let mut m = std::collections::HashMap::new();
    for line in cfg.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if k.starts_with("CONFIG_") {
                // `m` (loadable module) is neither built in nor disabled.
                let v = v.split('#').next().unwrap_or("").trim().trim_matches('"');
                m.insert(k.trim().to_string(), match v { "y" => 'y', "m" => 'm', _ => 'n' });
            }
        }
    }
    m
}

/// Returns every profile line the config violates. Empty means compliant.
pub fn audit(config: &str, profile: &str) -> Vec<Finding> {
    let cfg = parse_config(config);
    let mut out = vec![];
    for line in profile.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((opt, exp)) = line.split_once('=') {
            let expected = exp.chars().next().unwrap_or('y');
            let actual = *cfg.get(opt).unwrap_or(&'n');
            if actual != expected {
                out.push(Finding { option: opt.into(), expected, actual });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    const P: &str = "CONFIG_A=y\nCONFIG_B=n\n";
    #[test]
    fn module_counts_as_neither_enabled_nor_disabled() {
        let f = audit("CONFIG_A=m\nCONFIG_B=m\n", P);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].actual, 'm');
    }

    #[test]
    fn trailing_comment_is_ignored() {
        assert!(audit("CONFIG_A=y # note\n", "CONFIG_A=y\n").is_empty());
    }

    #[test]
    fn compliant() {
        assert!(audit("CONFIG_A=y\n# CONFIG_B is not set\n", P).is_empty());
    }
    #[test]
    fn missing_required_and_enabled_forbidden() {
        let f = audit("CONFIG_B=y\n", P);
        assert_eq!(f.len(), 2);
    }
    #[test]
    fn shipped_profile_parses_and_flags_empty_config() {
        let p = include_str!("../../../profiles/linux-kernel-hardening.txt");
        let f = audit("", p);
        assert!(f.iter().any(|x| x.option == "CONFIG_STRICT_KERNEL_RWX"));
        assert!(!f.iter().any(|x| x.option == "CONFIG_DEVMEM")); // absent == disabled, ok
    }
}
