# Update channel manifest verification (`pos-update`)

Status: engineering draft, not reviewed or audited. **TUF-inspired, not TUF.**
This document makes no security guarantee. It describes what the code checks.

## Scope

`crates/pos-update` is a library of pure functions that verify one signed
release manifest. It does no file, network or clock I/O, holds no keys, signs
nothing, and is not wired to any installer, downloader or `release.yml`.
The caller passes the bytes, the trusted keys, the threshold, `now` and the
previously accepted state, and persists the returned state itself.
It does not depend on `pos-gate`.

## Units

All times are `u64` whole seconds since the Unix epoch. `skew_secs` and
`max_validity` are whole seconds. Additions and subtractions are checked; an
overflow is rejected, never wrapped.

## Envelope and signed bytes

```
{"manifest":{...},"signatures":[{"key_id":"..","sig_hex":".."}]}
```

Manifest fields: `format` (must be `pos-update-manifest-v1`), `channel`,
`sequence`, `issued_at`, `expires_at`, `artifacts[]` of
`{name, version, sha256, size}`. `version` is an opaque label: it is never
parsed or compared. The threshold is not in the manifest.

Signed bytes = `pos-update-manifest-v1` + LF + compact, sorted-key JSON of the
`manifest` object only (signatures excluded). Unknown fields, duplicate keys
and trailing data are rejected. `sha256` and `sig_hex` must be lowercase hex.
Artifact names are unique and non-empty. Envelopes over 1 MiB are rejected
before parsing.

## Verification order

size, parse, manifest fields, key set and threshold, time, signatures, then
rollback state. Any failure returns one error from a closed enum that carries
no input data; there is no partial result.

## Signers and threshold

- The trusted key set and threshold `k` come from the caller, never from the
  manifest. `1 <= k <= number of distinct keys`.
- The key set is rejected if it has a duplicate `key_id`, a duplicate public
  key, an empty id, or `valid_from > valid_until`.
- A signer counts only if its `key_id` is in the set, it is not retired, and
  `valid_from <= now < valid_until`. Unknown, retired and out-of-window
  entries are ignored.
- Two entries with the same `key_id` make the manifest invalid.
- An invalid signature from a counted (trusted, active) key rejects the whole
  manifest, even when the threshold is otherwise met.
- Signatures use Ed25519 `verify_strict`.
- Key validity is checked against `now`, not `issued_at`. A manifest signed
  while a key was valid stops verifying after that key's `valid_until` (or once
  it is retired). Plan manifest lifetimes and key lifetimes together.
- A bad signature from a known key that is retired or out of window is ignored
  (the entry is not counted). A bad signature from an active, in-window key
  rejects the whole manifest.
- `k = 1` is allowed but weak: one compromised key can forge a manifest.
- Key rotation and key-set updates are out of scope.
- `k = 1` is weaker than a threshold of several independent signers.
- Signers written in other languages must reproduce the signed bytes exactly:
  the `serde_json` compact output with sorted keys, no whitespace, and
  `serde_json` string escaping.

## Channel and state

`VerifyPolicy::new` requires `expected_channel`. Channels and artifact names
are 1 to 64 / 1 to 128 bytes of ASCII letters, digits, `.`, `_`, `-`, with no
leading dot (so never `.` or `..`). At most 1024 artifacts and 256 signature
entries. `version` is a free label limited only by the 1 MiB envelope cap.

- A manifest for another channel fails with `WrongChannel` right after
  parsing and field checks, before any signature work, even if validly signed.
- An invalid `expected_channel` fails with `BadPolicyChannel`.
- `AcceptedState` carries its `channel`. The caller keeps one state per channel
  and passes `None` for a channel it has not seen. State for another channel
  is not ignored: it fails with `StateChannelMismatch`, so it can neither
  constrain nor silently reset another channel.

## Time

`now` is supplied by the caller. The device clock is not trusted and there is
no trusted-time source, so expiry and freeze protection are only as good as
the caller's `now`. A caller whose clock is rolled back can be made to accept
an expired manifest.

- `issued_at > now + skew_secs` is rejected (default skew 0).
- `now >= expires_at` is rejected.
- `issued_at >= expires_at` is rejected as inconsistent.
- `max_validity` caps `expires_at - issued_at`. Default 90 days. It is
  disabled only by explicitly choosing `MaxValidity::Disabled`.

## Rollback state

The caller stores `AcceptedState {sequence, digest}` (digest is SHA-256 of the
signed bytes) after an accepted manifest. Against a previous state:

- lower sequence: `Rollback`
- equal sequence, different digest: `Fork`
- equal sequence, same digest: accepted as idempotent
- higher sequence: accepted

Limits: if the caller loses or deletes the state, the counter resets. There is
no per-artifact downgrade protection: a higher `sequence` may carry a
lower-labelled artifact. There is no locking or persistence in this crate.

## Non-goals

No key holding or signing tooling, no TUF roles, delegation, snapshot or
targets metadata, no transport or download, no installer wiring, no
`release.yml` changes, no trusted time, no key rotation, no multi-device state.
A valid signature does not show an artifact is safe; artifact hashes must be
checked separately.

## Choices for review

1. Key windows are evaluated at `now`.
2. A manifest needs at least one artifact; artifact and channel names are limited as above.
3. Signed-bytes digest uses the prefix too, so it differs from a plain
   manifest hash.
4. (Superseded by the peer's review: the channel is now checked here.)

## Tested on

Linux, Rust 1.100.0 only. Windows and other platforms are untested.
