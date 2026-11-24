
#!/bin/sh
set -eu

# POS First-Boot Checklist
# Offline only. No downloads, installs, or policy changes.

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

# The verification tools are mandatory. Missing tools must fail closed.
command -v sha256sum >/dev/null 2>&1 ||
    fail "sha256sum is not installed."

command -v awk >/dev/null 2>&1 ||
    fail "awk is not installed."

[ -f "$CLI" ] && [ -x "$CLI" ] ||
    fail "Installed pos-cli is missing or not executable."

[ -f "$MANIFEST" ] ||
    fail "SHA256SUMS is missing."

# Extract exactly one checksum entry for the installed CLI.
# Expected manifest format:
# <64 hexadecimal characters><whitespace><optional *><pos-cli>
EXPECTED_HASH=$(
    awk '
        /^[[:xdigit:]]{64}[[:space:]]+\*?pos-cli$/ {
            hash = substr($0, 1, 64)
            count++
        }
        END {
            if (count != 1)
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
