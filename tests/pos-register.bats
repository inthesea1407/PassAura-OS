#!/usr/bin/env bats
# image/bin/pos-register stub: local file handling only (no network exists in it).

setup() {
  D="$(mktemp -d)"
  export PASSAURA_INVITE_FILE="$D/invite.code"
  export PASSAURA_STATE_DIR="$D/state"
  BIN="$BATS_TEST_DIRNAME/../image/bin/pos-register"
}

@test "defers without an invite file and writes no record" {
  run "$BIN"
  [ "$status" -eq 0 ]
  [ ! -e "$D/state/registration.json" ]
}

@test "an invite file with only comments fails" {
  printf '# nothing\n\n' > "$PASSAURA_INVITE_FILE"
  run "$BIN"
  [ "$status" -eq 1 ]
  [ ! -e "$D/state/registration.json" ]
}

@test "records a hash, mode 600, no plaintext code, and clears the invite file" {
  printf '# c\nABCD-1234\n' > "$PASSAURA_INVITE_FILE"
  run "$BIN"
  [ "$status" -eq 0 ]
  [ "$(stat -c %a "$D/state/registration.json")" = "600" ]
  ! grep -q 'ABCD-1234' "$D/state/registration.json"
  grep -q '"invite_sha256": "[0-9a-f]\{64\}"' "$D/state/registration.json"
  [ ! -s "$PASSAURA_INVITE_FILE" ]
  [ -z "$(ls -A "$D/state" | grep '^\.registration')" ]
}
