## `FileOps` Seam in `crates/pos-gate/src/rollback.rs`

To test crash/failure behavior deterministically without privileged OS fault injection:
- `pub trait FileOps` abstracts `rename_replace`, `fsync_file`, and `fsync_dir`.
- `StdFileOps` is the production implementation:
  - On Unix, `rename_replace` calls `std::fs::rename` and `fsync_dir` opens and syncs the parent directory.
  - On Windows (`#[cfg(windows)]`), `rename_replace` retries transient access-denied errors (`io::ErrorKind::PermissionDenied` or raw OS code `5`, `ERROR_ACCESS_DENIED`) with backoff before surfacing an error, avoiding a delete-before-rename window where a crash could leave the target file missing.
- In unit tests (`#[cfg(test)]`), `FakeFileOps` simulates mid-write crashes before `rename_replace` and transient rename failures to verify:
  1. A crash between write/fsync and rename leaves previously persisted state (`last_seq`, `last_digest_hex`) intact both in memory and on disk.
  2. Retrying after transient rename failures commits the candidate sequence and digest cleanly.
  3. The monotonic sequence counter never moves backwards (`DowngradeRejected`), and equal sequences with differing digests are rejected (`DigestMismatch`).

## Status & Verification Scope

نواة أمنية وأدوات نموذجية مختبَرة في CI والمحاكيات، ولا يوجد إصدار مختبَر على عتاد أو مدقَّق خارجيًا بعد.
