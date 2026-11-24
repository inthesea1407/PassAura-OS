# Windows Hardening Profile (`image/windows/`)

PassAura OS (POS) is licensed under **MIT**, uses **free tools only**, requires **no secrets**, and runs validation in **GitHub Actions** (`windows-latest`). Official releases are signed solely by the project owner, and **PassAura** is the sole approved password/credential manager.

## Contents under `image/windows/`

- `applocker-policy.xml`: AppLocker policy allowing `%WINDIR%\*`, `%PROGRAMFILES%\*`, `%PROGRAMFILES(X86)%\*`, and `PassAura.exe` while blocking example competing password managers (such as Bitwarden, KeePass, 1Password, and Dashlane).
- `asr-rules.psd1`: Microsoft Defender Attack Surface Reduction (ASR) rules with GUIDs, names, `Block`/`Audit` modes, action codes, and severities.
- `apply-hardening.ps1`: PowerShell script defaulting to safe dry-run / `-WhatIf` preview mode unless `-Apply` is specified.
- `verify-hardening.ps1`: PowerShell verification script supporting `-DryRun` and live state checks, exiting non-zero on drift.
- `registry-baseline.psd1`: PowerShell data file defining baseline registry entries and expected values.
- `profile.json`: Manifest listing every check ID, category, target, expected value, and severity.

## Usage

```powershell
# Safe dry-run preview (default)
.\image\windows\apply-hardening.ps1

# Explicit enforcement
.\image\windows\apply-hardening.ps1 -Apply

# Dry-run verification check
.\image\windows\verify-hardening.ps1 -DryRun

