#!/usr/bin/env bash
set -euo pipefail

# PassAura OS (POS) - Package Gate Hook (MIT)
# Enforces PassAura as the sole approved password/credential manager and
# blocks known competing password manager packages.

BLOCKED_REGEX='^(bitwarden|keepass(xc|2)?|1password|dashlane|lastpass|roboform|enpass|buttercup|padloc)(-|$|[^a-zA-Z0-9])'

check_pkg_name() {
    local pkg="$1"
    if [[ -z "$pkg" ]]; then
        return 0
    fi
    if [[ "$pkg" == "passaura" || "$pkg" == "passaura-cli" || "$pkg" == "passaura-pos" ]]; then
        return 0
    fi
    if [[ "$pkg" =~ $BLOCKED_REGEX ]]; then
        echo "[PASSAURA-GATE] BLOCKED competing password/credential manager package: '$pkg'" >&2
        echo "[PASSAURA-GATE] PassAura is the sole approved password/credential manager in POS." >&2
        exit 1
    fi
}

if [[ "$#" -gt 0 ]]; then
    for arg in "$@"; do
        case "$arg" in
            -*|/*) ;;
            *) check_pkg_name "$arg" ;;
        esac
    done
fi

if [[ ! -t 0 ]]; then
    while IFS= read -r line; do
        pkg_field="$(printf '%s\n' "$line" | awk -F'\t' '{print $1}' | cut -d':' -f1)"
        check_pkg_name "$pkg_field"
    done
fi

exit 0
