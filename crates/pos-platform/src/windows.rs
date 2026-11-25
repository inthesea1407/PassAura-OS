use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageAllowlistEntry {
    pub name: String,
    pub publisher: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleCollection {
    Exe,
    Msi,
    Script,
    PackagedApp,
}

impl RuleCollection {
    fn xml_name(self) -> &'static str {
        match self {
            Self::Exe => "Exe",
            Self::Msi => "Msi",
            Self::Script => "Script",
            Self::PackagedApp => "Appx",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

const ADMIN_SID: &str = "S-1-5-32-544";

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_entries(entries: &[PackageAllowlistEntry]) -> Result<(), PolicyError> {
    for entry in entries {
        if entry.name.trim().is_empty() {
            return Err(PolicyError("empty package name".into()));
        }
        if entry.publisher.trim().is_empty() {
            return Err(PolicyError("empty publisher".into()));
        }
        if !valid_sha256(&entry.sha256) {
            return Err(PolicyError(format!("invalid SHA-256 for {}", entry.name)));
        }
    }
    Ok(())
}

/// XML 1.0 attribute escaping. Disallowed control characters are
/// replaced rather than emitted into the document.
pub fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());

    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' => out.push('\u{FFFD}'),
            _ => out.push(ch),
        }
    }

    out
}

/// Converts 32-byte SHA-256 hex to Base64 for AppLocker FileHash data.
fn hex_sha256_to_base64(hex: &str) -> Result<String, PolicyError> {
    if !valid_sha256(hex) {
        return Err(PolicyError("invalid SHA-256".into()));
    }

    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| PolicyError("invalid SHA-256".into()))?;

    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);

        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);

        if chunk.len() > 1 {
            out.push(TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(TABLE[(c & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }

    Ok(out)
}

fn admin_allow_rule(collection: RuleCollection) -> String {
    format!(
        r#"<Rule Id="POS-ADMIN-{}" Name="Administrators exception" Description="Allow local administrators" UserOrGroupSid="{}" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></Rule>"#,
        collection.xml_name(),
        ADMIN_SID
    )
}

fn hash_rule(
    collection: RuleCollection,
    index: usize,
    entry: &PackageAllowlistEntry,
) -> Result<String, PolicyError> {
    let base64_hash = hex_sha256_to_base64(&entry.sha256)?;

    Ok(format!(
        r#"<FileHashRule Id="POS-{}-HASH-{}" Name="{}" Description="POS SHA256 allowlist rule" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FileHashCondition><FileHash Type="SHA256" Data="{}" SourceFileName="{}" SourceFileLength="0"/></FileHashCondition></Conditions></FileHashRule>"#,
        collection.xml_name(),
        index,
        xml_escape(&entry.name),
        base64_hash,
        xml_escape(&entry.name)
    ))
}

fn packaged_app_rule(index: usize, entry: &PackageAllowlistEntry) -> String {
    format!(
        r#"<Rule Id="POS-APPX-{}" Name="{}" Description="POS packaged-app publisher allowlist" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><PublisherCondition PublisherName="{}" ProductName="{}" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></PublisherCondition></Conditions></Rule>"#,
        index,
        xml_escape(&entry.name),
        xml_escape(&entry.publisher),
        xml_escape(&entry.name)
    )
}

/// Creates deterministic AppLocker XML from a package allowlist.
///
/// Entries are sorted by (name, publisher, hash).
/// Unmatched applications are denied by AppLocker default behavior
/// because no broad non-admin Allow rules are generated.
pub fn generate_applocker_xml(entries: &[PackageAllowlistEntry]) -> Result<String, PolicyError> {
    validate_entries(entries)?;

    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| {
        (&a.name, &a.publisher, &a.sha256).cmp(&(&b.name, &b.publisher, &b.sha256))
    });

    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><AppLockerPolicy Version="1">"#);

    for collection in [
        RuleCollection::Exe,
        RuleCollection::Msi,
        RuleCollection::Script,
        RuleCollection::PackagedApp,
    ] {
        xml.push_str(&format!(
            r#"<RuleCollection Type="{}" EnforcementMode="Enabled"><Rules>"#,
            collection.xml_name()
        ));

        xml.push_str(&admin_allow_rule(collection));

        if collection == RuleCollection::PackagedApp {
            for (i, entry) in sorted.iter().enumerate() {
                xml.push_str(&packaged_app_rule(i, entry));
            }
        } else {
            for (i, entry) in sorted.iter().enumerate() {
                xml.push_str(&hash_rule(collection, i, entry)?);
            }
        }

        xml.push_str("</Rules><RuleCollectionExtensions><Threshold></Threshold><Redstone></Redstone></RuleCollectionExtensions></RuleCollection>");
    }

    xml.push_str("</AppLockerPolicy>");
    Ok(xml)
}

// ---------------------------------------------------------------------
// Credential-manager allowlist policy writer
// ---------------------------------------------------------------------

pub const CREDENTIAL_POLICY_PATH: &str = r"Software\Policies\PassAuraOS\CredentialManager";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryChange {
    pub path: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryWriteError(pub String);

impl std::fmt::Display for RegistryWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RegistryWriteError {}

/// Implemented by the platform-specific registry backend.
/// Tests can use a fake implementation.
pub trait RegistryWriter {
    fn write_string(
        &mut self,
        path: &str,
        name: &str,
        value: &str,
    ) -> Result<(), RegistryWriteError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    DryRun,
    Apply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteReport {
    pub planned: Vec<RegistryChange>,
    pub applied: bool,
}

fn build_credential_changes(allowlist: &[String]) -> Result<Vec<RegistryChange>, PolicyError> {
    let mut values = BTreeSet::new();

    for name in allowlist {
        let trimmed = name.trim();

        if trimmed.is_empty() {
            return Err(PolicyError("empty credential allowlist entry".into()));
        }

        if trimmed.chars().any(|c| c.is_control()) {
            return Err(PolicyError(
                "control character in credential allowlist entry".into(),
            ));
        }

        values.insert(trimmed.to_string());
    }

    Ok(values
        .into_iter()
        .enumerate()
        .map(|(index, value)| RegistryChange {
            path: CREDENTIAL_POLICY_PATH.to_string(),
            name: format!("AllowedCredential{:04}", index),
            value,
        })
        .collect())
}

/// DryRun returns the planned changes without invoking the writer.
/// Apply invokes the injected writer and returns the same plan.
pub fn write_credential_allowlist<W: RegistryWriter>(
    allowlist: &[String],
    mode: WriteMode,
    writer: &mut W,
) -> Result<WriteReport, RegistryWriteError> {
    let planned =
        build_credential_changes(allowlist).map_err(|e| RegistryWriteError(e.to_string()))?;

    if mode == WriteMode::DryRun {
        return Ok(WriteReport {
            planned,
            applied: false,
        });
    }

    for change in &planned {
        writer.write_string(&change.path, &change.name, &change.value)?;
    }

    Ok(WriteReport {
        planned,
        applied: true,
    })
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, publisher: &str, hash: &str) -> PackageAllowlistEntry {
        PackageAllowlistEntry {
            name: name.into(),
            publisher: publisher.into(),
            sha256: hash.into(),
        }
    }

    fn sample_entries() -> Vec<PackageAllowlistEntry> {
        vec![
            entry(
                "Beta",
                "Publisher B",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            entry(
                "Alpha",
                "Publisher A",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ]
    }

    /// Lightweight XML balance and entity check without an external parser.
    fn hand_check_xml(xml: &str) -> bool {
        let mut stack: Vec<String> = Vec::new();
        let mut pos = 0;

        while let Some(start_rel) = xml[pos..].find('<') {
            let start = pos + start_rel;
            let Some(end_rel) = xml[start..].find('>') else {
                return false;
            };
            let end = start + end_rel;
            let tag = &xml[start + 1..end];

            if tag.starts_with('?') || tag.starts_with('!') {
                pos = end + 1;
                continue;
            }

            let closing = tag.starts_with('/');
            let self_closing = tag.ends_with('/');
            let raw = tag.trim_start_matches('/').trim_end_matches('/');
            let name = raw.split_whitespace().next().unwrap_or("");

            if name.is_empty() {
                return false;
            }

            if closing {
                if stack.pop().as_deref() != Some(name) {
                    return false;
                }
            } else if !self_closing {
                stack.push(name.to_string());
            }

            pos = end + 1;
        }

        if !stack.is_empty() {
            return false;
        }

        // Only the five predefined XML entities are accepted.
        let mut rest = xml;
        while let Some(i) = rest.find('&') {
            rest = &rest[i + 1..];
            let Some(end) = rest.find(';') else {
                return false;
            };
            let entity = &rest[..end];
            if !matches!(entity, "amp" | "lt" | "gt" | "quot" | "apos") {
                return false;
            }
            rest = &rest[end + 1..];
        }

        true
    }

    #[test]
    fn xml_output_is_balanced_and_entities_valid() {
        let xml = generate_applocker_xml(&sample_entries()).unwrap();
        assert!(hand_check_xml(&xml));
        assert!(xml.starts_with("<?xml"));
        assert!(xml.ends_with("</AppLockerPolicy>"));
    }

    #[test]
    fn adversarial_values_are_escaped() {
        let malicious = entry(
            r#"A&<"'>"#,
            r#"P&<"'>"#,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );

        let xml = generate_applocker_xml(&[malicious]).unwrap();

        assert!(xml.contains("A&amp;&lt;&quot;&apos;"));
        assert!(xml.contains("P&amp;&lt;&quot;&apos;"));
        assert!(!xml.contains(r#"Name="A&<"#));
        assert!(hand_check_xml(&xml));
    }

    #[test]
    fn deterministic_ordering() {
        let a = generate_applocker_xml(&sample_entries()).unwrap();
        let mut reversed = sample_entries();
        reversed.reverse();
        let b = generate_applocker_xml(&reversed).unwrap();

        assert_eq!(a, b);
        assert!(a.find("Alpha").unwrap() < a.find("Beta").unwrap());
    }

    #[test]
    fn invalid_hash_rejected() {
        let bad = entry("App", "Publisher", "not-a-hash");
        assert!(generate_applocker_xml(&[bad]).is_err());
    }

    #[derive(Default)]
    struct FakeRegistry {
        writes: Vec<RegistryChange>,
    }

    impl RegistryWriter for FakeRegistry {
        fn write_string(
            &mut self,
            path: &str,
            name: &str,
            value: &str,
        ) -> Result<(), RegistryWriteError> {
            self.writes.push(RegistryChange {
                path: path.into(),
                name: name.into(),
                value: value.into(),
            });
            Ok(())
        }
    }

    #[test]
    fn dry_run_never_calls_registry_writer() {
        let allowlist = vec!["VaultA".into(), "VaultB".into()];
        let mut fake = FakeRegistry::default();

        let report = write_credential_allowlist(&allowlist, WriteMode::DryRun, &mut fake).unwrap();

        assert!(!report.applied);
        assert_eq!(report.planned.len(), 2);
        assert!(fake.writes.is_empty());
    }

    #[test]
    fn apply_calls_fake_writer() {
        let allowlist = vec!["VaultB".into(), "VaultA".into()];
        let mut fake = FakeRegistry::default();

        let report = write_credential_allowlist(&allowlist, WriteMode::Apply, &mut fake).unwrap();

        assert!(report.applied);
        assert_eq!(fake.writes, report.planned);
        assert_eq!(fake.writes.len(), 2);
    }

    #[test]
    fn registry_plan_is_sorted_and_deduplicated() {
        let allowlist = vec!["VaultB".into(), "VaultA".into(), "VaultB".into()];
        let mut fake = FakeRegistry::default();

        let report = write_credential_allowlist(&allowlist, WriteMode::DryRun, &mut fake).unwrap();

        assert_eq!(report.planned.len(), 2);
        assert_eq!(report.planned[0].value, "VaultA");
        assert_eq!(report.planned[1].value, "VaultB");
    }

    #[test]
    fn registry_rejects_control_characters() {
        let allowlist = vec!["Vault\nInjected".into()];
        let mut fake = FakeRegistry::default();

        assert!(write_credential_allowlist(&allowlist, WriteMode::DryRun, &mut fake).is_err());

        assert!(fake.writes.is_empty());
    }

    #[test]
    fn base64_hash_conversion_has_expected_length() {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(hex_sha256_to_base64(hash).unwrap().len(), 44);
    }
}
