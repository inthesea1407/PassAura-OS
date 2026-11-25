#!/usr/bin/env bats
# apt-hook.sh with mock dpkg-deb and pos-gate on PATH: tests the hook's own logic only.

setup() {
  D="$(mktemp -d)"
  mkdir -p "$D/bin"
  printf '%s\n' '#!/bin/sh' \
    'case "$1" in' \
    '  -f) echo "${MOCK_PKG:-harmless}" ;;' \
    '  -c) echo "-rwxr-xr-x root/root 1 2024-01-01 00:00 ./usr/bin/x" ;;' \
    '  -x) mkdir -p "$3" ;;' \
    'esac' > "$D/bin/dpkg-deb"
  printf '%s\n' '#!/bin/sh' \
    '[ "$1" = "badpkg" ] && exit 1' \
    'exit 0' > "$D/bin/pos-gate"
  chmod +x "$D/bin/dpkg-deb" "$D/bin/pos-gate"
  touch "$D/ok.deb"
  export PATH="$D/bin:$PATH"
  HOOK="$BATS_TEST_DIRNAME/../enforcement/apt-hook.sh"
}

teardown() { rm -rf "$D"; }

feed() { printf '%s\n' "$@" | sh "$HOOK"; }

@test "protocol lines without a .deb path are ignored" {
  run feed "VERSION 3" "APT::Architecture=amd64" ""
  [ "$status" -eq 0 ]
}

@test "readable harmless .deb is allowed" {
  run feed "harmless - 1.0 < 1.0 = $D/ok.deb"
  [ "$status" -eq 0 ]
}

@test "named but missing .deb fails closed" {
  run feed "harmless - 1.0 < 1.0 = $D/missing.deb"
  [ "$status" -ne 0 ]
}

@test "a missing .deb does not hide a later block, and vice versa" {
  run feed "x - 1 < 1 = $D/ok.deb" "y - 1 < 1 = $D/missing.deb"
  [ "$status" -ne 0 ]
}

@test "gate verdict block is propagated" {
  MOCK_PKG=badpkg run feed "badpkg - 1.0 < 1.0 = $D/ok.deb"
  [ "$status" -ne 0 ]
}

@test "path with spaces is read whole and checked" {
  mkdir -p "$D/my dir"; touch "$D/my dir/a b.deb"
  run feed "harmless - 1.0 < 1.0 = $D/my dir/a b.deb"
  [ "$status" -eq 0 ]
  MOCK_PKG=badpkg run feed "badpkg - 1.0 < 1.0 = $D/my dir/a b.deb"
  [ "$status" -ne 0 ]
}

@test "ambiguous line with text after the .deb fails closed" {
  run feed "harmless - 1.0 < 1.0 = $D/ok.deb $D/other.deb extra"
  [ "$status" -ne 0 ]
}
