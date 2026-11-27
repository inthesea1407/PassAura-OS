//! Package identity of a staged `.deb`, read from the file itself.
//!
//! The allowlist binds a package NAME (and optionally a VERSION) to a sha256. The install path used to
//! check only that hash. This module reads the `control` file inside the `.deb` and lets the caller
//! require that the file's own `Package` equals the allowlisted name and, when the entry has a version,
//! that `Version` equals it exactly. It is a consistency check on a file whose hash already matched the
//! signed entry; it is not a signature check and not a security boundary on its own.
//!
//! Reading is bounded: the ar members are walked with seeks (payload members are skipped, never read),
//! the control archive is capped before and after decompression, and the control file is capped. Control
//! archives may be plain, gzip, xz or zstd (all pure Rust). Anything else, a missing control file, a
//! duplicated `Package` or `Version` field or malformed input is an error (fail closed).
//!
//! Limits: the `Architecture` field is read but not bound (entries carry none). Version comparison is exact
//! string equality, not dpkg ordering. The file is read here and read again by `dpkg`, so a writer of the
//! staging directory could swap it in between (the staging directory is private, mode 0700). xz and zstd
//! decoders allocate their declared dictionary/window (zstd is capped at 100 MiB by the decoder); the
//! input and output caps below bound everything else.

use std::fmt;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

/// Largest compressed control member accepted.
pub const MAX_CONTROL_MEMBER: u64 = 1 << 20;
/// Largest decompressed control archive accepted.
pub const MAX_CONTROL_TAR: u64 = 4 << 20;
/// Largest `control` file accepted.
pub const MAX_CONTROL_FILE: u64 = 64 << 10;
/// Most ar members walked before giving up.
const MAX_MEMBERS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebIdentity {
    pub package: String,
    pub version: String,
    pub architecture: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebError {
    Io(io::ErrorKind),
    NotAnArArchive,
    BadMember,
    NoControlMember,
    ControlTooLarge,
    UnsupportedCompression,
    BadCompressedData,
    BadTar,
    NoControlFile,
    BadControl,
    MissingField(&'static str),
    DuplicateField(&'static str),
    NameMismatch { expected: String, found: String },
    VersionMismatch { expected: String, found: String },
}

impl fmt::Display for DebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DebError::NameMismatch { expected, found } => {
                write!(
                    f,
                    "deb Package is {found:?}, allowlist entry is {expected:?}"
                )
            }
            DebError::VersionMismatch { expected, found } => {
                write!(
                    f,
                    "deb Version is {found:?}, allowlist entry is {expected:?}"
                )
            }
            other => write!(f, "deb identity error: {other:?}"),
        }
    }
}
impl std::error::Error for DebError {}

impl From<io::Error> for DebError {
    fn from(e: io::Error) -> Self {
        DebError::Io(e.kind())
    }
}

/// Fails once more than `limit` bytes were written.
struct CapWriter {
    buf: Vec<u8>,
    limit: u64,
}

impl Write for CapWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if (self.buf.len() as u64).saturating_add(data.len() as u64) > self.limit {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "output cap"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_decimal(field: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(field).ok()?.trim_end_matches(' ');
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn decompress(name: &str, data: &[u8]) -> Result<Vec<u8>, DebError> {
    let mut out = CapWriter {
        buf: Vec::new(),
        limit: MAX_CONTROL_TAR,
    };
    match name {
        "control.tar" => {
            if data.len() as u64 > MAX_CONTROL_TAR {
                return Err(DebError::ControlTooLarge);
            }
            return Ok(data.to_vec());
        }
        "control.tar.gz" => {
            let mut d = flate2::read::GzDecoder::new(data);
            io::copy(&mut d.by_ref().take(MAX_CONTROL_TAR + 1), &mut out)
                .map_err(|_| DebError::BadCompressedData)?;
        }
        "control.tar.xz" => {
            let mut r = BufReader::new(data);
            lzma_rs::xz_decompress(&mut r, &mut out).map_err(|_| DebError::BadCompressedData)?;
        }
        "control.tar.zst" => {
            let mut d = ruzstd::decoding::StreamingDecoder::new(data)
                .map_err(|_| DebError::BadCompressedData)?;
            io::copy(&mut d.by_ref().take(MAX_CONTROL_TAR + 1), &mut out)
                .map_err(|_| DebError::BadCompressedData)?;
        }
        _ => return Err(DebError::UnsupportedCompression),
    }
    Ok(out.buf)
}

/// One ustar member: name, typeflag, and content range (start, end).
type TarMember<'a> = (&'a [u8], u8, usize, usize);

/// Walks the members of a ustar archive, yielding (name, typeflag, content
/// start, content end) for each. Members are skipped by size, never read.
/// Same bounds and malformed-input behavior as the original control_from_tar.
fn walk_tar(tar: &[u8], f: &mut dyn FnMut(TarMember<'_>)) -> Result<(), DebError> {
    let mut pos = 0usize;
    while pos + 512 <= tar.len() {
        let h = &tar[pos..pos + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let name_end = h[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = &h[..name_end];
        let size_txt = std::str::from_utf8(&h[124..136]).map_err(|_| DebError::BadTar)?;
        let size_txt = size_txt.trim_matches(|c| c == '\0' || c == ' ');
        let size = u64::from_str_radix(size_txt, 8).map_err(|_| DebError::BadTar)?;
        let typeflag = h[156];
        let start = pos + 512;
        let end = start
            .checked_add(usize::try_from(size).map_err(|_| DebError::BadTar)?)
            .ok_or(DebError::BadTar)?;
        if end > tar.len() {
            return Err(DebError::BadTar);
        }
        f((name, typeflag, start, end));
        let padded = (end - start).div_ceil(512) * 512;
        pos = start.checked_add(padded).ok_or(DebError::BadTar)?;
    }
    Ok(())
}

/// First `control` file of a ustar archive (`./control` or `control`).
fn control_from_tar(tar: &[u8]) -> Result<&[u8], DebError> {
    let mut found: Option<(usize, usize)> = None;
    let mut too_large = false;
    walk_tar(tar, &mut |(name, typeflag, start, end)| {
        if found.is_some() || too_large {
            return;
        }
        if (name == b"./control" || name == b"control") && (typeflag == b'0' || typeflag == 0) {
            if (end - start) as u64 > MAX_CONTROL_FILE {
                too_large = true;
            } else {
                found = Some((start, end));
            }
        }
    })?;
    if too_large {
        return Err(DebError::ControlTooLarge);
    }
    let (start, end) = found.ok_or(DebError::NoControlFile)?;
    Ok(&tar[start..end])
}

/// Maintainer script names collected from a control archive.
pub const MAINTAINER_SCRIPTS: [&str; 5] = ["preinst", "postinst", "prerm", "postrm", "config"];

/// One maintainer script found in the control archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlScript {
    /// Bare name: one of MAINTAINER_SCRIPTS.
    pub name: String,
    /// Raw body, capped at MAX_CONTROL_FILE.
    pub body: Vec<u8>,
}

/// The control file's identity plus the package's maintainer scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlContents {
    pub identity: DebIdentity,
    pub scripts: Vec<ControlScript>,
}

/// Parses the fields we need. A folded (indented) line belongs to the field above. Duplicated `Package`
/// or `Version` fields are refused, so there is never a "which one counts" question.
pub fn parse_control(bytes: &[u8]) -> Result<DebIdentity, DebError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DebError::BadControl)?;
    let (mut package, mut version, mut arch) = (None, None, None);
    let mut in_field = false;
    for line in text.split('\n') {
        if line.is_empty() {
            break; // a blank line ends the paragraph
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if !in_field {
                return Err(DebError::BadControl);
            }
            continue;
        }
        let (k, v) = line.split_once(':').ok_or(DebError::BadControl)?;
        in_field = true;
        let v = v.trim().to_string();
        match k {
            "Package" => {
                if package.replace(v).is_some() {
                    return Err(DebError::DuplicateField("Package"));
                }
            }
            "Version" => {
                if version.replace(v).is_some() {
                    return Err(DebError::DuplicateField("Version"));
                }
            }
            "Architecture" => {
                arch = Some(v);
            }
            _ => {}
        }
    }
    let package = package
        .filter(|s| !s.is_empty())
        .ok_or(DebError::MissingField("Package"))?;
    let version = version
        .filter(|s| !s.is_empty())
        .ok_or(DebError::MissingField("Version"))?;
    Ok(DebIdentity {
        package,
        version,
        architecture: arch,
    })
}

/// Locates and decompresses the control member of a `.deb`. Shared by
/// read_identity and read_control_contents; bounds identical for both.
fn read_control_tar<R: Read + Seek>(r: &mut R) -> Result<Vec<u8>, DebError> {
    let total = r.seek(SeekFrom::End(0))?;
    r.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)
        .map_err(|_| DebError::NotAnArArchive)?;
    if &magic != b"!<arch>\n" {
        return Err(DebError::NotAnArArchive);
    }
    let mut pos = 8u64;
    for _ in 0..MAX_MEMBERS {
        if pos + 60 > total {
            break;
        }
        let mut h = [0u8; 60];
        r.read_exact(&mut h).map_err(|_| DebError::BadMember)?;
        if &h[58..60] != b"`\n" {
            return Err(DebError::BadMember);
        }
        let name = std::str::from_utf8(&h[..16])
            .map_err(|_| DebError::BadMember)?
            .trim_end_matches(' ');
        let name = name.trim_end_matches('/');
        let size = parse_decimal(&h[48..58]).ok_or(DebError::BadMember)?;
        let data_start = pos + 60;
        if data_start.checked_add(size).ok_or(DebError::BadMember)? > total {
            return Err(DebError::BadMember);
        }
        if name.starts_with("control.tar") {
            if size > MAX_CONTROL_MEMBER {
                return Err(DebError::ControlTooLarge);
            }
            let mut data = vec![0u8; size as usize];
            r.read_exact(&mut data).map_err(|_| DebError::BadMember)?;
            return decompress(name, &data);
        }
        pos = data_start + size + (size & 1);
        r.seek(SeekFrom::Start(pos))?;
    }
    Err(DebError::NoControlMember)
}

/// Reads the identity from a `.deb`.
pub fn read_identity<R: Read + Seek>(r: &mut R) -> Result<DebIdentity, DebError> {
    let tar = read_control_tar(r)?;
    parse_control(control_from_tar(&tar)?)
}

/// Reads the identity and the maintainer scripts (preinst, postinst, prerm,
/// postrm, config; first occurrence of each wins, each capped at
/// MAX_CONTROL_FILE) from a `.deb`. Same bounds and failure behavior as
/// read_identity. This is a consistency and inspection read on a file whose
/// hash the caller has already checked; it is not a signature check.
pub fn read_control_contents<R: Read + Seek>(r: &mut R) -> Result<ControlContents, DebError> {
    let tar = read_control_tar(r)?;
    let mut control: Option<(usize, usize)> = None;
    let mut scripts: Vec<(String, usize, usize)> = Vec::new();
    let mut too_large = false;
    walk_tar(&tar, &mut |(name, typeflag, start, end)| {
        if typeflag != b'0' && typeflag != 0 {
            return;
        }
        let bare = name.strip_prefix(b"./").unwrap_or(name);
        if bare == b"control" {
            if control.is_none() {
                if (end - start) as u64 > MAX_CONTROL_FILE {
                    too_large = true;
                } else {
                    control = Some((start, end));
                }
            }
            return;
        }
        if let Ok(script) = std::str::from_utf8(bare) {
            if MAINTAINER_SCRIPTS.contains(&script) && !scripts.iter().any(|(n, _, _)| n == script)
            {
                if (end - start) as u64 > MAX_CONTROL_FILE {
                    too_large = true;
                } else {
                    scripts.push((script.to_string(), start, end));
                }
            }
        }
    })?;
    if too_large {
        return Err(DebError::ControlTooLarge);
    }
    let (cs, ce) = control.ok_or(DebError::NoControlFile)?;
    let identity = parse_control(&tar[cs..ce])?;
    let scripts = scripts
        .into_iter()
        .map(|(name, s, e)| ControlScript {
            name,
            body: tar[s..e].to_vec(),
        })
        .collect();
    Ok(ControlContents { identity, scripts })
}

/// The deb must be exactly the allowlisted package: same name, and the same version when the entry names one.
pub fn check_identity(id: &DebIdentity, name: &str, version: Option<&str>) -> Result<(), DebError> {
    if id.package != name {
        return Err(DebError::NameMismatch {
            expected: name.to_string(),
            found: id.package.clone(),
        });
    }
    if let Some(v) = version {
        if id.version != v {
            return Err(DebError::VersionMismatch {
                expected: v.to_string(),
                found: id.version.clone(),
            });
        }
    }
    Ok(())
}

/// Reads `path` and applies `check_identity`.
pub fn check_staged_deb(
    path: &std::path::Path,
    name: &str,
    version: Option<&str>,
) -> Result<DebIdentity, DebError> {
    let mut f = std::fs::File::open(path)?;
    let id = read_identity(&mut f)?;
    check_identity(&id, name, version)?;
    Ok(id)
}

/// Builds a minimal `.deb` (ar archive with an uncompressed control archive) naming `package` and
/// `version`. For tests of code that stages a `.deb`; the payload is a placeholder, not installable.
pub fn build_minimal_deb(package: &str, version: &str) -> Vec<u8> {
    let control = format!("Package: {package}\nVersion: {version}\nArchitecture: all\n");
    let mut h = [0u8; 512];
    h[..9].copy_from_slice(b"./control");
    h[100..108].copy_from_slice(b"0000644\0");
    h[124..136].copy_from_slice(format!("{:011o}\0", control.len()).as_bytes());
    h[156] = b'0';
    let mut tar = h.to_vec();
    tar.extend_from_slice(control.as_bytes());
    tar.resize(tar.len().div_ceil(512) * 512 + 1024, 0);
    let member = |name: &str, data: &[u8]| {
        let mut v = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            format!("{name}/"),
            0,
            0,
            0,
            "100644",
            data.len()
        )
        .into_bytes();
        v.extend_from_slice(data);
        if data.len() % 2 == 1 {
            v.push(b'\n');
        }
        v
    };
    let mut deb = b"!<arch>\n".to_vec();
    deb.extend(member("debian-binary", b"2.0\n"));
    deb.extend(member("control.tar", &tar));
    deb.extend(member("data.tar.xz", b"placeholder"));
    deb
}

#[cfg(test)]
mod tests;
