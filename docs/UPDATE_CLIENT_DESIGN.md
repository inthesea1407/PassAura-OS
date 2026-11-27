# Update client design (`pos-cli update`, not built yet)

Status: implemented as `pos-cli update` (see CLI.md). Everything it
wires together is CI-tested only and unaudited; the real dpkg backend has
never run.

## Purpose

One operator command that checks a channel, and when the channel advanced:
verifies the signed manifest, fetches and stages the payloads, installs the
ones that are `.deb` packages through the install pipeline, and persists the
new channel state. Every piece already exists; this note is the wiring plan.

## Pieces (all merged)

- `pos_update::flow::run_update` - fetch manifest, verify (threshold Ed25519,
  expiry, per-channel rollback state), fetch and stage payloads with hashes
  re-checked, hand off, persist state. Idempotent: a manifest equal to the
  persisted state does nothing (`Outcome::AlreadyCurrent`).
- `pos_update::flow::Transport` - the caller's fetcher (manifest + artifacts).
- `pos_update::flow::StateStore` - the caller's persistence; a file-backed
  implementation exists behind `pos-update/file-state`.
- `pos_update_install::InstallHandoff` - installs each staged `X.deb` whose
  paired signed `X.allowlist.json` authorizes it, through the unchanged
  pos-install pipeline (see UPDATE_INSTALL_HANDOFF.md).

## Command shape (draft)

```
pos-cli update --channel stable \
  --transport dir:/srv/pos-updates \        # local dir first; HTTPS later
  --update-keys update-keys.json \          # threshold key set for manifests
  --threshold 2 \
  --install-keys install-keys.json \        # keyring for allowlists
  --install-state /var/lib/pos/install-state.json \
  --audit /var/log/pos/audit.jsonl
```

Two distinct key sets on purpose: the update keys authorize what may be
fetched and staged, the install keys authorize what may be installed. A
compromise of the update channel alone cannot install anything the install
keyring did not sign for (UPDATE_INSTALL_HANDOFF.md).

## Decisions still open

- Transport: the local-directory transport is what exists (fits the offline
  posture; netpolicy allow-lists are unverified on real traffic, so HTTPS
  fetch is a later step and needs its own review: TLS roots, timeouts, size
  caps, and the netpolicy rules that permit it).
- Backend: the Linux build wires the real apt/dpkg backend; until it has run
  on hardware, builds keep a dry-run default and the command prints what it
  would install.
- Operator recovery: when the install pipeline blocks indeterminate, the
  command reports the attempt and points at the existing
  `pos-cli install --recover retry|abandon` path; it never auto-retries.
- Scheduling: manual first. Any timer/cron integration is a separate
  decision, and background self-updates are out of scope until the signed
  release process exists (releases are unsigned today).
