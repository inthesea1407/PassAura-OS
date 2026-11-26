# Update-to-install handoff (`pos-update-install`)

Status: engineering draft, CI-tested only, not audited. The real dpkg backend
has never run; adapter tests use a fake backend, like pos-install's own suite.

## What it does

`pos-update-install` is the glue between the update flow (`pos-update`) and
the install transaction (`pos-install`). It implements
`pos_update::flow::Handoff`: after the update flow has verified a signed
manifest (threshold Ed25519, rollback state, time window) and staged the
payload bytes on disk with their hashes re-checked, the adapter installs the
staged `.deb` artifacts through the unchanged pos-install pipeline.

## Release convention (what a manifest must carry)

An artifact `X.deb` is installed only when the same manifest also carries
`X.allowlist.json`: a signed v2 allowlist (see `ALLOWLIST_FORMAT.md`) whose
entries include one whose SHA-256 equals the staged `X.deb` bytes. The entry's
`name` is the package passed to the installer; its `version`, when present, is
bound to the deb's control data by the real backend's identity check.

The adapter deliberately adds **no second root of trust**:

- The update manifest authorizes fetching and staging only.
- The signed allowlist alone authorizes the install. The pipeline re-verifies
  its signature, keyring, time window and rollback sequence, re-hashes the
  staged bytes against the signed entry, stages them privately, and the real
  backend verifies the allowlist once more before `dpkg` runs.
- A `.deb` with no paired allowlist fails closed before anything runs. An
  allowlist signed by a key the device does not trust fails closed. An
  allowlist whose entries do not cover the staged bytes fails closed.
- A manifest with no `.deb` artifacts is a no-op.

Release tooling therefore signs, per package, both the update manifest and
the per-package allowlist. Those keys and ceremonies are the owner's and live
outside this repo.

## Failure model

Installs run in manifest order; the first failure stops the handoff and the
update flow reports `FlowError::Handoff`. Each package install is its own
pos-install attempt with the full journal/recovery machinery (see
`INSTALL_PIPELINE.md`): a crash mid-install leaves a blocked, indeterminate
attempt that only an explicit operator recovery (`--recover retry|abandon`)
resolves. The adapter never retries on its own.

The rollback sequences of the update channel (manifest sequence, persisted by
the caller of the update flow) and of each allowlist (persisted by
pos-install) are independent and advance independently.

## Limits

- No hardware runs, no audit, no security-level claims.
- `now` is fixed at adapter construction; every allowlist time check of one
  handoff uses it.
- Multiple `.deb` artifacts sharing one paired allowlist name cannot exist
  (manifest artifact names are unique), so each package carries its own
  allowlist with its own sequence.
- The adapter parses each `X.allowlist.json` from the staged bytes; a
  malformed document fails the handoff before verification even starts.
