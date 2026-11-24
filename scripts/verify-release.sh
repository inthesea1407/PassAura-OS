#!/usr/bin/env bash
set -euo pipefail

# PassAura OS release verification.
# Trust anchor: a pinned minisign public key shipped in the trusted image.

readonly DEFAULT_PUBLIC_KEY="/usr/share/pos/release.pub"
readonly DEFAULT_MANIFEST="SHA256SUMS"
readonly DEFAULT_SIGNATURE="SHA256SUMS.minisig"

release_dir="${POS_RELEASE_DIR:-.}"
manifest="${POS_RELEASE_MANIFEST:-${release_dir}/${DEFAULT_MANIFEST}}"
signature="${POS_RELEASE_SIGNATURE:-${release_dir}/${DEFAULT_SIGNATURE}}"
public_key="${POS_RELEASE_PUBLIC_KEY:-${DEFAULT_PUBLIC_KEY}}"

fail() {
    printf 'verify-release: ERROR: %s\n' "$*" >&2
    exit 1
}

info() {
    printf 'verify-release: %s\n' "$*"
}

command -v minisign >/dev/null 2>&1 ||
    fail "minisign is required but was not found in PATH"

[[ -f "$manifest" ]] ||
    fail "manifest not found: $manifest"

[[ -f "$signature" ]] ||
    fail "detached signature not found: $signature"

[[ -f "$public_key" ]] ||
    fail "trusted public key not found: $public_key"

# Authenticate the manifest BEFORE parsing or trusting any hashes.
if ! minisign -Vm "$manifest" -x "$signature" -p "$public_key"; then
    fail "manifest signature verification failed"
fi

info "manifest signature is valid"

# Verify manifest entries only after signature validation.
# Supported format: sha256sum-compatible entries.
# Reject absolute paths and traversal paths.
entries=0

while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip blank lines and comments.
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    # sha256sum-compatible: HASH [space(s)] [*]FILENAME
    if [[ "$line" =~ ^([a-fA-F0-9]{64})[[:space:]]+[*]?(.+)$ ]]; then
        expected="${BASH_REMATCH[1],,}"
        filename="${BASH_REMATCH[2]}"

        # Manifest entries must be local, simple filenames.
        [[ -n "$filename" ]] ||
            fail "empty filename in manifest"

        [[ "$filename" != */* ]] ||
            fail "subdirectories are not permitted in manifest entries: $filename"

        [[ "$filename" != "." && "$filename" != ".." ]] ||
            fail "invalid filename in manifest: $filename"

        [[ "$filename" != *".."* ]] ||
            fail "filename contains forbidden traversal sequence: $filename"

        [[ "$filename" != /* ]] ||
            fail "absolute paths are not permitted: $filename"

        [[ "$filename" != "$DEFAULT_MANIFEST" ]] ||
            fail "manifest must not list itself"

        [[ "$filename" != "$DEFAULT_SIGNATURE" ]] ||
            fail "signature must not be listed as an artifact"

        artifact="${release_dir}/${filename}"

        [[ -f "$artifact" ]] ||
            fail "artifact missing: $filename"

        actual="$(sha256sum -- "$artifact")"
        actual="${actual%% *}"
        actual="${actual,,}"

        [[ "$actual" == "$expected" ]] ||
            fail "SHA-256 mismatch: $filename"

        info "verified: $filename"
        entries=$((entries + 1))
    else
        fail "invalid manifest entry"
    fi
done < "$manifest"

(( entries > 0 )) ||
    fail "manifest contains no artifact entries"

info "release verification successful ($entries artifact(s))"
