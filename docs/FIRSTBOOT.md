# PassAura OS — Linux First Boot

## Purpose

The first-boot service displays a simple checklist and verifies the
integrity of the installed `pos-cli` binary.

It is intentionally offline and does not install software, modify
security policy, enroll membership, or contact remote services.

## Files

```text
image/linux/firstboot/
├── pos-firstboot.sh
├── pos-firstboot.service
└── test.sh
```

## Installation layout

The image is expected to install:

```text
/usr/bin/pos-firstboot.sh
/usr/bin/pos-cli
/usr/share/passaura/SHA256SUMS
```

The first-boot script is installed at:

```text
/usr/bin/pos-firstboot.sh
```

The service runs it once using systemd's `ConditionFirstBoot=yes`.

## Checklist behavior

The script displays a plain text checklist:

- Review system installation.
- Confirm PassAura OS installation.
- Verify `pos-cli` integrity.
- Review security policy.
- Complete initial setup.

The checklist is informational. It does not claim that policy,
enforcement, secure boot, hardware attestation, or membership has
already been verified.

## Integrity verification

The installed binary:

```text
/usr/bin/pos-cli
```

is compared with the `pos-cli` entry in:

```text
/usr/share/passaura/SHA256SUMS
```

The manifest entry must contain exactly one checksum for `pos-cli`.

If the binary is missing, not executable, the manifest is missing,
the checksum entry is malformed or duplicated, or the hash does not
match, the script exits unsuccessfully.

No fallback download is attempted.

## Service hardening

The systemd service includes:

- `ConditionFirstBoot=yes`
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- `PrivateTmp=yes`
- `ProtectHome=yes`
- Kernel and control-group protection settings.
- Restricted namespaces.
- Read-only filesystem access by default.

The service is a read-only checklist and integrity check.

## Manual execution

```bash
sudo /usr/bin/pos-firstboot.sh
```

Running it manually does not reset the first-boot state.

## Tests

Run:

```bash
sh image/linux/firstboot/test.sh
```

The test creates a temporary filesystem layout and a fake CLI binary.

It verifies:

1. A valid checksum is accepted.
2. A modified binary is rejected.
3. A malformed checksum manifest is rejected.
4. A missing binary is rejected.

The tests do not modify the real system or invoke package managers.

## Security limitations

This checksum check is an integrity consistency check, not a full
signature verification mechanism.

If an attacker can replace both the binary and the checksum manifest,
the check alone cannot detect the replacement.

For stronger trust, the release checksum manifest must be authenticated
using the independent offline release-signing process described in
`docs/RELEASE.md`.

This service does not prove that the installed operating system is
secure or that PassAura OS enforcement is working.

POSIX portability correction

The initial drafts used dirname --/cd --, which are not guaranteed by strict POSIX. Use the corrected versions below for the two scripts instead of the earlier drafts.

Corrected image/linux/firstboot/pos-firstboot.sh
Bash

#!/bin/sh
set -eu

POS_ROOT="${POS_ROOT:-}"
CLI="${POS_ROOT}/usr/bin/pos-cli"
MANIFEST="${POS_ROOT}/usr/share/passaura/SHA256SUMS"

fail() {
    printf '\nERROR: %s\n' "$1" >&2
    exit 1
}

printf '%s\n' '========================================'
printf '%s\n' '        PassAura OS First Boot'
printf '%s\n' '========================================'
printf '%s\n' ''
printf '%s\n' '[ ] Review system installation'
printf '%s\n' '[ ] Confirm PassAura OS installation'
printf '%s\n' '[ ] Verify pos-cli integrity'
printf '%s\n' '[ ] Review security policy'
printf '%s\n' '[ ] Complete initial setup'
printf '%s\n' ''

command -v sha256sum >/dev/null 2>&1 ||
    fail "sha256sum is not installed."

command -v awk >/dev/null 2>&1 ||
    fail "awk is not installed."

[ -f "$CLI" ] && [ -x "$CLI" ] ||
    fail "Installed pos-cli is missing or not executable."

[ -f "$MANIFEST" ] ||
    fail "SHA256SUMS is missing."

EXPECTED_HASH=$(
    awk '
        $2 == "pos-cli" || $2 == "*pos-cli" {
            if (length($1) != 64 || $1 !~ /^[[:xdigit:]]+$/)
                invalid = 1
            else {
                hash = $1
                count++
            }
        }
        END {
            if (invalid || count != 1)
                exit 1
            print hash
        }
    ' "$MANIFEST"
) || fail "Missing, duplicate, or invalid pos-cli checksum entry."

[ "${#EXPECTED_HASH}" -eq 64 ] ||
    fail "Invalid checksum length."

case "$EXPECTED_HASH" in
    *[!0123456789abcdefABCDEF]*)
        fail "Invalid checksum characters."
        ;;
esac

ACTUAL_HASH=$(
    sha256sum "$CLI" | awk '{print $1}'
) || fail "Failed to calculate pos-cli checksum."

[ "$ACTUAL_HASH" = "$EXPECTED_HASH" ] ||
    fail "pos-cli checksum verification failed."

printf '%s\n' '[OK] Installed pos-cli checksum verified.'
printf '%s\n' ''
printf '%s\n' 'Checklist is ready.'
printf '%s\n' 'No packages were installed and no network access was attempted.'
printf '%s\n' ''

Corrected image/linux/firstboot/test.sh
Bash

#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
FIRSTBOOT="$SCRIPT_DIR/pos-firstboot.sh"

command -v sha256sum >/dev/null 2>&1 || {
    echo "FAIL: sha256sum is required." >&2
    exit 1
}

TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT HUP INT TERM

ROOT="$TMPDIR_TEST/root"
CLI="$ROOT/usr/bin/pos-cli"
MANIFEST_DIR="$ROOT/usr/share/passaura"
MANIFEST="$MANIFEST_DIR/SHA256SUMS"

mkdir -p "$ROOT/usr/bin" "$MANIFEST_DIR"

# Fake CLI binary: no real POS operations are performed.
cat > "$CLI" <<'MOCK'
#!/bin/sh
exit 0
MOCK

chmod +x "$CLI"

HASH=$(sha256sum "$CLI" | awk '{print $1}')
printf '%s  pos-cli\n' "$HASH" > "$MANIFEST"

echo "Test 1: valid checksum"
POS_ROOT="$ROOT" "$FIRSTBOOT" >/dev/null
echo "PASS"

echo "Test 2: corrupted binary"
printf '%s\n' 'corrupted' >> "$CLI"

if POS_ROOT="$ROOT" "$FIRSTBOOT" >/dev/null 2>&1; then
    echo "FAIL: corrupted binary was accepted." >&2
    exit 1
fi
echo "PASS"

echo "Test 3: missing checksum entry"
printf '%s\n' 'invalid manifest' > "$MANIFEST"

if POS_ROOT="$ROOT" "$FIRSTBOOT" >/dev/null 2>&1; then
    echo "FAIL: invalid manifest was accepted." >&2
    exit 1
fi
echo "PASS"

echo "Test 4: missing CLI"
rm -f "$CLI"
HASH=$(printf '%s' 'missing' | sha256sum | awk '{print $1}')
printf '%s  pos-cli\n' "$HASH" > "$MANIFEST"

if POS_ROOT="$ROOT" "$FIRSTBOOT" >/dev/null 2>&1; then
    echo "FAIL: missing CLI was accepted." >&2
    exit 1
fi
echo "PASS"

echo "All first-boot tests passed."

Validation report

Functional shell tests passed

4/4 temporary-directory tests passed using a mock CLI.

Check

	

Status

Valid binary accepted

	

Passed

Corrupted binary rejected

	

Passed

Invalid checksum manifest rejected

	

Passed

Missing CLI rejected

	

Passed

Real POS CLI tested

	

No

ShellCheck

	

Unavailable

systemd service tested on image

	

No

Important remaining issue

The checksum manifest only establishes that the binary matches the checksum file. If an attacker can replace both files, this check will not detect it. The stronger next step is verifying an independently trusted release signature before first boot, rather than treating the local checksum manifest as a trust anchor.

No repository files were modified. All four requested files are provided above; no continuation prompt is needed.
