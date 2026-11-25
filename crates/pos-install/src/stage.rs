//! Private staging directory: mode 0700, files created with `create_new`
//! (never follows or overwrites an existing path), symlinks refused.
//!
//! Limit: a root attacker, or a racing process of the same user that already
//! owns the directory, is not defended against; this uses only std (no
//! `openat`/`O_NOFOLLOW`), so checks are `symlink_metadata` before use.

use pos_gate::rollback::FileOps;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageError(pub String);

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "staging error: {}", self.0)
    }
}
impl std::error::Error for StageError {}

impl From<io::Error> for StageError {
    fn from(e: io::Error) -> Self {
        StageError(e.to_string())
    }
}

/// A staged file name must be a plain file name ending in `.deb`.
pub fn valid_stage_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name.ends_with(".deb")
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[derive(Debug, Clone)]
pub struct Stager {
    dir: PathBuf,
}

impl Stager {
    /// `<state path>.stage`
    pub fn for_state(state_path: &Path) -> Stager {
        let mut s = state_path.as_os_str().to_owned();
        s.push(".stage");
        Stager { dir: PathBuf::from(s) }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn file_path(&self, name: &str) -> Result<PathBuf, StageError> {
        if !valid_stage_name(name) {
            return Err(StageError(format!("invalid staged file name {name:?}")));
        }
        Ok(self.dir.join(name))
    }

    /// Create the directory (0700) or validate an existing one: it must be a
    /// real directory (not a symlink) with no group/other access.
    pub fn ensure_dir(&self) -> Result<(), StageError> {
        match fs::symlink_metadata(&self.dir) {
            Ok(md) => self.check_dir(&md),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut b = DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                }
                b.create(&self.dir)?;
                let md = fs::symlink_metadata(&self.dir)?;
                self.check_dir(&md)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn check_dir(&self, md: &fs::Metadata) -> Result<(), StageError> {
        if md.file_type().is_symlink() {
            return Err(StageError("stage directory is a symlink".into()));
        }
        if !md.is_dir() {
            return Err(StageError("stage path is not a directory".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if md.permissions().mode() & 0o077 != 0 {
                return Err(StageError("stage directory is not private (needs 0700)".into()));
            }
        }
        Ok(())
    }

    /// Write a new staged file. Fails if the name already exists.
    pub fn write_new<O: FileOps>(
        &self,
        name: &str,
        bytes: &[u8],
        ops: &O,
    ) -> Result<PathBuf, StageError> {
        let path = self.file_path(name)?;
        self.ensure_dir()?;
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let res: Result<(), StageError> = (|| {
            let mut f = opts.open(&path)?;
            f.write_all(bytes)?;
            ops.fsync_file(&f)?;
            drop(f);
            ops.fsync_dir(&self.dir)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = fs::remove_file(&path);
        }
        res.map(|_| path)
    }

    /// Read a staged file after checking it is a regular file, not a symlink.
    pub fn read_checked(&self, name: &str) -> Result<Vec<u8>, StageError> {
        let path = self.file_path(name)?;
        let md = fs::symlink_metadata(&path)?;
        if !md.file_type().is_file() {
            return Err(StageError("staged path is not a regular file".into()));
        }
        Ok(fs::read(&path)?)
    }

    /// Remove a staged file. Missing is fine. A symlink or non-file is refused.
    pub fn remove(&self, name: &str) -> Result<(), StageError> {
        let path = self.file_path(name)?;
        match fs::symlink_metadata(&path) {
            Ok(md) if md.file_type().is_file() => Ok(fs::remove_file(&path)?),
            Ok(_) => Err(StageError("refusing to remove a non-regular staged path".into())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Names of the entries currently in the stage directory (for tests and
    /// diagnostics). Empty if the directory does not exist.
    pub fn list(&self) -> Vec<String> {
        match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}
