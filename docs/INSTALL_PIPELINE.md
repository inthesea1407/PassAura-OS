# Install pipeline (`pos-install`)

Status: review draft. Tested on Linux only, with Rust 1.100.0. Minimum Rust is
**1.89** (`File::try_lock`), set in `crates/pos-install/Cargo.toml` (`rust-version`). Windows is not
supported or tested. This document makes no security-audit or certification claim.

## What it does

Installs one **local** `.deb` file for a package named in a signed allowlist:

1. Verify the allowlist (signature, time window, trusted key, rollback state).
2. Read the local file (a symlink is refused). Its SHA-256 must equal the signed entry. The signed
   name, version and sha256 bind the accepted bytes. No network is used anywhere.
3. Copy the bytes into a stage directory and re-check them there.
4. Run `dpkg -i -- <absolute staged path>`.
5. Persist the allowlist sequence in the rollback state, then commit, then write the audit record.

The by-name path (`apt-get install`) is unchanged. Flatpak does not support exact-file install and
returns `ExactFileUnsupported`.

Files, all next to the rollback state file `S`: `S.lock` (lock), `S.install-journal`, `S.stage/`.

## Journal and state machine

Each journal line is one JSON record, synced before the next step. Per attempt:

`begun -> verified -> fetched -> staged -> install_started -> installed -> seq_persisted -> committed -> audit_intent -> audit_written`

Terminal marks: `failed`, `aborted`, `abandon_requested`, `abandoned`. `install_started` is written and
synced **before** the command runs, `installed` only after it reported success. Order after the
command: installed, then seq_persisted, then committed, then audit.

A retry is a new attempt chained to the previous one (`parent`).

## Recovery table (what happens when a run starts and finds a journal)

| Journal ends at | Meaning | Recovery action |
|---|---|---|
| nothing / empty file | no attempt | clean |
| begun .. staged | command never started | audit `InstallFailed`, remove stage, close |
| `install_started` | command may or may not have run | audit `InstallIndeterminate`, **block**. Operator must choose `--recover retry` or `--recover abandon` |
| `installed`, `seq_persisted`, `committed` | command succeeded | roll forward: persist sequence if needed, commit, audit. If the stored sequence moved on, the attempt is `Superseded` and blocked (abandon only) |
| `failed` | definite failure | audit (if not yet written), remove stage, close |
| `abandon_requested` | abandon was interrupted | finish abandon |
| a retry attempt that stopped before its command | retry never ran | audit, mark aborted, fall back to the attempt it retried |

Recovery runs under the lock at the start of every install, retry and abandon.

## What the install command outcome means

| Result | Journal / sequence | Notes |
|---|---|---|
| exit code 0 | continues to commit | |
| non-zero exit from `dpkg` | attempt `failed`, audited `InstallFailed`, sequence **not** advanced, journal closed | `dpkg` can leave **partial side effects** (unpacked or half-configured package, maintainer script effects). Before running again, check `dpkg --audit` and `dpkg -l <package>`. A fresh install or `--recover retry` repeats those scripts |
| runner proved the program never started (spawn failed) | `failed`, audited `InstallFailed` | nothing ran |
| anything else: wait/read failure after spawn, killed by a signal, interruption | stays at `install_started`, audited `InstallIndeterminate`, **blocked** | outcome unknown. Never reported as a failure |

Only the runner's own `Err` return can prove non-start (message prefix `RUNNER_NOT_STARTED_PREFIX`,
mapped to `PackageBackendError::RunnerNotStarted` on the exact-file path only). Text inside a finished
command's output can never do that. The `CommandRunner` trait still returns `Result<_, String>`, so the
proof is a convention between the real runner and the backend, not a typed value from the trait.

## Operator recovery: `--recover retry|abandon` (no default)

- **retry**: runs the install command again for the **same** package and the **same** signed document,
  after fully re-verifying it and re-checking the staged bytes. It is **not idempotent**: package
  maintainer scripts and other side effects can run twice. The CLI prints a warning, and it never runs
  automatically. A different document is a new install: abandon first.
- **abandon**: writes `abandon_requested`, then the audit record `InstallAbandoned`, then removes the
  stage, then writes `abandoned`, then deletes the journal and syncs the directory. Abandon itself
  never changes the rollback sequence and undoes nothing that may already be installed. It does NOT
  say the sequence is unchanged relative to the original attempt: for a `Superseded` attempt the stored
  sequence had already moved on (and the package may be installed), so check both by hand. It needs neither allowlist
  nor keyring. A crash before the final delete keeps the block; run it again.

## Torn or corrupt journal: fails closed

A last line without its trailing newline, a non-UTF-8 file, or a broken step order is `Corrupt`.
Every command (install, retry, abandon, dry-run) then refuses and changes nothing. A zero-length journal
counts as no journal.

**Do not delete the journal.** A torn tail can be a partial `install_started`, and deleting or truncating
the file would let recovery treat a possibly-started install as "never started". There is **no CLI repair
route in this version.** What an operator can do:

1. Copy the journal and the stage directory somewhere safe, and keep the copy.
2. Read the file. If the last (torn) line could be a prefix of `install_started` or any later step, assume the
   install may have started.
3. Check the system by hand (`dpkg --audit`, `dpkg -l <package>`, dpkg log).
4. Escalate to the maintainers. An explicit repair step is proposed separately and is not part of this change.

Unfulfilled guarantee: a torn journal cannot be resolved with `--recover abandon` or `retry`.

## Locking

`S.lock` is locked with advisory `File::try_lock` and a bounded wait (5 s). A stale lock file with no OS
lock does not block. The lock is **cooperative**: it only protects against other processes that also use
it (this pipeline and `pos-cli install` with `--state`). A program that edits the state file directly is not
stopped.

Dry-run is lock-free and read-only: it never creates the state file, the lock file, the journal or the
stage. What it reads (state, journal, stage) is advisory and can change at any moment while another
process works.

## CLI paths

| Command | Behavior |
|---|---|
| `install P --allowlist A --keyring K --dry-run [--state S]` | verify only. No state file is created |
| same plus `--package-file F` | verify and check F against the signed sha256. Nothing is written |
| `install P ... --state S` (no `--package-file`) | legacy: records the sequence under the lock and prints "installer not wired". Installs nothing |
| `install P ... --state S --audit-log L --package-file F` | the pipeline above |
| `... --recover retry --state S --audit-log L` | retry (warns) |
| `... --recover abandon --state S --audit-log L` | abandon |

Exit codes: 0 ok, 2 failure (verification, hash, lock, command, blocked), 3 not allowed, 4 usage.

The real runner (`ProcessRunner` in `pos-cli`) allows only `/usr/bin/apt-get` and `/usr/bin/dpkg`, no shell,
no stdin, fixed `PATH`. It has **never been run by a test and has not been system-tested.** All tests use
fake runners.

## Audit additions

Six new audit event kinds: `InstallHashMismatch`, `InstallFailed`, `InstallCommitted`,
`InstallIndeterminate`, `InstallRetried`, `InstallAbandoned`. The canonical hash format and existing test
vectors are unchanged. **Old readers that do not know these kinds will fail to parse an audit log
that contains them.** Audit writes are at-least-once; recovery dedups by the exact planned record.
`InstallIndeterminate` can appear twice for one install when a retry itself ends unknown.

## Limits

- Idempotent recovery and at-least-once audit are claimed only for the crash points the fault-injection
  tests cover (a crash after each journal write, around the command, the state write and each audit write).
  There is **no exactly-once claim** beyond those local crash points.
- Nothing here undoes an install.
- Not covered: power loss with a lying disk, other filesystems' fsync quirks, hostile local users, the
  state file being deleted, Windows, system tests of `apt-get`/`dpkg`, cargo-deny.
