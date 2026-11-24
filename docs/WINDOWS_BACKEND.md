
# PassAura OS — Windows Backend

## Scope

The Windows backend provides:

- Deterministic AppLocker XML generation.
- EXE, MSI, Script, and packaged-app rule collections.
- Administrator exception rules.
- Allowlist validation.
- XML escaping for adversarial input.
- Credential-manager registry change planning.
- A dry-run mode that does not invoke the registry writer.
- A `RegistryWriter` trait so the actual Windows registry implementation
  can be isolated from policy generation and tested with a fake.

This is a policy generator, not an enforcement mechanism.

## AppLocker generation

`generate_applocker_xml()` accepts `PackageAllowlistEntry` values containing:

- `name`
- `publisher`
- `sha256`

The generated output has four enabled collections:

| Collection | Rule type |
|---|---|
| Exe | File hash |
| Msi | File hash |
| Script | File hash |
| Appx | Publisher rule |

An administrator exception is generated in each collection.

Entries are sorted deterministically before generation. XML values are
escaped, and invalid SHA-256 strings are rejected.

AppLocker normally denies files that are not covered by an applicable
allow rule once the corresponding collection is configured as an
allowlist. The generated XML does not claim that Windows has imported,
activated, or enforced the policy.

### Important limitations

The current allowlist input does not include file length, which is
normally required for AppLocker file-hash rules. The generator currently
uses a placeholder length of zero.

Consequently, the generated file must not be considered a production-ready
or verified AppLocker policy.

Before production use:

1. Verify the generated policy against the Windows AppLocker schema.
2. Replace the placeholder hash metadata with verified file metadata.
3. Validate rule IDs against Windows policy requirements.
4. Test policy import and enforcement in an isolated Windows environment.
5. Verify each rule collection and administrator exception.
6. Test policy behavior when an allowlisted application is updated.

This code does not generate a complete WDAC policy. WDAC uses a different
policy format and deployment/enforcement pipeline.

## Credential-manager registry changes

`write_credential_allowlist()` generates a deterministic plan.

The default policy path is:

`Software\Policies\PassAuraOS\CredentialManager`
