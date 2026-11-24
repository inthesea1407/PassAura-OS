
#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FIRSTBOOT="$SCRIPT_DIR/pos-firstboot.sh"

command -v sha256sum >/dev/null 2>&1 || {
    echo "SKIP: sha256sum is required." >&2
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
