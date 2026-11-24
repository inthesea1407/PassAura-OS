# POS Platform Abstraction

`pos-platform` is the cross-platform policy layer for PassAura OS.

## Scope

This crate provides:

- A shared `PlatformBackend` interface.
- Credential-manager allowlist validation and lookup.
- Named hardening checks with `Pass`, `Fail`, or `Unknown`.
- Linux policy configuration output.
- Windows AppLocker/WDAC policy planning data.
- Android policy request JSON for a Kotlin integration.
- Injectable `CommandRunner` and `Fs` interfaces.

The crate is intentionally dependency-free.

## Credential manager allowlist

The policy is an exact-match allowlist.

Package identifiers are validated before they are accepted. Duplicate entries are
removed, and an empty allowlist denies all package IDs through the local gate.

`is_credential_manager_approved()` is a policy decision only. It does not block
software installation or execution on the host OS.

## Linux

`LinuxBackend::dry_run_files()` produces configuration files for:

- APT package-gate hook
- Sysctl hardening
- AppArmor profile scaffold
- POS credential-manager allowlist

The output is data for review. The backend does not write to `/etc`, install
hooks, change sysctl values, reload AppArmor, or run privileged commands.

Hardening checks are read-only and use injected interfaces:

- sysctl configuration file contents
- `aa-status`
- `apt-config dump`

A successful configuration check does not prove that a setting is active in the
running kernel. Configuration and runtime state should be verified separately.

The generated APT hook is not an enforcement mechanism until an executable
package-gate implementation is installed, tested, and connected to the hook.

## Windows

`WindowsBackend::dry_run_policy()` produces:

- AppLocker XML (AuditOnly)
- WDAC implementation notes
- Registry value plan

No registry values are written and no policy is deployed.

AppLocker and WDAC rules need platform-specific validation. The generated
policy is a starting point, not a complete credential-manager restriction
system. In particular, matching a package identifier to an executable path is
not a reliable identity mechanism.

## Android

`AndroidBackend::policy_request_json()` emits a request that can be consumed by
the Kotlin layer.

The request includes:

- Request type
- Enforcement scope
- Allowed package identifiers

Android application-level policy is not equivalent to system-wide enforcement.
Device-owner APIs, system integration, supported OS versions, and OEM behavior
must be verified independently.

## Hardening status

Each hardening check contains:

- Name
- Status
- Details

Status meanings:

- `Pass`: the check's expected condition was observed.
- `Fail`: the check was evaluated and its expected condition was not observed.
- `Unknown`: the check could not be evaluated or enforcement cannot be confirmed.

`HardeningReport::is_fully_hardened()` returns true only if the report is
non-empty and all checks are `Pass`.

This is a narrow report. It does not represent a complete security audit.

## Test strategy

Unit tests use fake command and filesystem implementations. They do not execute
real host commands or write to real system files.

## Build integration

The repository workspace currently lists its members explicitly. This crate is
not automatically included in the workspace test command until
`crates/pos-platform` is added to the root `Cargo.toml`.

Root workspace configuration is intentionally not changed in this task.

Suggested standalone checks after adding the files:

```bash
cargo test --manifest-path crates/pos-platform/Cargo.toml
cargo clippy --manifest-path crates/pos-platform/Cargo.toml --all-targets
```

After workspace integration:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Security limitations

- No OS enforcement is installed by this crate.
- No administrator privileges are used.
- No system policy is changed.
- No hardware attestation is performed.
- No security guarantee is made from a generated policy alone.
- Credential-manager allowlisting at the application layer can be bypassed
  outside the trusted POS enforcement boundary.

4. نتائج التنفيذ

لم يتم تنفيذ الاختبارات؛ هذه الملفات مسودة تنفيذ وليست تغييرات تم التحقق منها داخل المستودع.

البند

	

النتيجة




Crate مستقل

	

مكتوب




PlatformBackend

	

مكتوب




Linux / Windows / Android

	

واجهات أولية مكتوبة




CommandRunner وFs

	

قابلان للحقن




Fake tests

	

35 اختبارًا مكتوبًا




Dependencies

	

صفر




MIT

	

محدد




ملفات خارج النطاق

	

لم أعدلها




Root Cargo.toml

	

لم ألمسه




cargo test

	

لم أشغّله




cargo clippy

	

لم أشغّله




GitHub commit

	

لم يتم — رفضت صلاحيات GitHub إنشاء الفرع

نقطة تحتاج إصلاح قبل اعتبارها جاهزة

فحص APT في النسخة أعلاه يبحث عن 90-pos-package-gate داخل مخرجات apt-config dump، بينما الاسم الموجود في ملف الـhook لا يضمن ظهور هذا النص في المخرجات. يجب تصحيح شرط الفحص ليتحقق من الأمر أو إعداد الـhook الحقيقي، وإلا سيعطي Fail غير دقيق.

كذلك، الـWindows backend والـAndroid backend في هذه النسخة ينتجان خطط سياسات فقط؛ لا يوجد enforcement فعلي. وLinux لديه إعدادات hardening مقترحة، وليس gate مكتملًا.
