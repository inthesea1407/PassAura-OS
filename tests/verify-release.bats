#!/usr/bin/env bats

setup() {
    TEST_ROOT="$(mktemp -d)"
    RELEASE_DIR="$TEST_ROOT/release"
    BIN_DIR="$TEST_ROOT/bin"

    mkdir -p "$RELEASE_DIR" "$BIN_DIR"

    VERIFY_SCRIPT="${BATS_TEST_DIRNAME}/../scripts/verify-release.sh"

    export POS_RELEASE_DIR="$RELEASE_DIR"
    export POS_RELEASE_MANIFEST="$RELEASE_DIR/SHA256SUMS"
    export POS_RELEASE_SIGNATURE="$RELEASE_DIR/SHA256SUMS.minisig"
    export POS_RELEASE_PUBLIC_KEY="$TEST_ROOT/test.pub"

    printf 'mock public key\n' > "$POS_RELEASE_PUBLIC_KEY"

    # Test-only mock. It does not perform cryptography.
    cat > "$BIN_DIR/minisign" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

signature=""

while (($#)); do
    case "$1" in
        -x)
            signature="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

[[ -f "$signature" ]] || exit 1
grep -qx 'VALID' "$signature" || exit 1
exit 0
MOCK

    chmod +x "$BIN_DIR/minisign"
    export PATH="$BIN_DIR:$PATH"
}

teardown() {
    rm -rf "$TEST_ROOT"
}

create_valid_release() {
    printf 'release artifact\n' > "$RELEASE_DIR/example.bin"

    (
        cd "$RELEASE_DIR"
        sha256sum example.bin > SHA256SUMS
    )

    printf 'VALID\n' > "$POS_RELEASE_SIGNATURE"
}

@test "accepts valid signature and matching artifact hash" {
    create_valid_release

    run "$VERIFY_SCRIPT"

    [ "$status" -eq 0 ]
    [[ "$output" == *"manifest signature is valid"* ]]
    [[ "$output" == *"release verification successful"* ]]
}

@test "rejects missing detached signature" {
    create_valid_release
    rm "$POS_RELEASE_SIGNATURE"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"detached signature not found"* ]]
}

@test "rejects invalid signature before trusting manifest" {
    create_valid_release
    printf 'INVALID\n' > "$POS_RELEASE_SIGNATURE"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"manifest signature verification failed"* ]]
}

@test "rejects artifact hash mismatch" {
    create_valid_release
    printf 'modified artifact\n' > "$RELEASE_DIR/example.bin"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"SHA-256 mismatch"* ]]
}

@test "rejects missing artifact" {
    create_valid_release
    rm "$RELEASE_DIR/example.bin"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"artifact missing"* ]]
}

@test "rejects traversal entries in manifest" {
    create_valid_release

    printf '%s  ../outside.bin\n' \
        "$(printf '0%.0s' {1..64})" > "$POS_RELEASE_MANIFEST"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"subdirectories are not permitted"* ]]
}

@test "rejects empty manifest" {
    create_valid_release
    : > "$POS_RELEASE_MANIFEST"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"manifest contains no artifact entries"* ]]
}

@test "rejects malformed manifest entry" {
    create_valid_release
    printf 'not-a-valid-hash  example.bin\n' > "$POS_RELEASE_MANIFEST"

    run "$VERIFY_SCRIPT"

    [ "$status" -ne 0 ]
    [[ "$output" == *"invalid manifest entry"* ]]
}
