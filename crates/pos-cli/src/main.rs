// pos-cli — PassAura OS command-line tool.
//
// Subcommands:
//   verify  <allowlist.json> --keyring <keyring.json>      (v2 only)
//   install <package> --allowlist <file> --dry-run          (v2 only)
//   sign    <unsigned v2 allowlist> --private-key <file> --out <file>
//   allowlist-migrate --from-v1 <text-v1 file> --trusted-key <keyring.json>
//                     --sha256-map <map.json> --out <new file>   (offline, one way)
//   keygen  --out <dir>
//
// Exit codes: 0 ok, 2 verification failed, 3 not allowed, 4 usage.
// No panics on malformed input: every fallible path returns a Result and is
// mapped to an exit code. clap handles usage errors (exit 4 via try_parse).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use pos_gate::Keyring;

#[derive(Parser)]
#[command(
    name = "pos-cli",
    about = "PassAura OS: verify signed allowlists and gate package installs",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Check the hash chain. Exit 0 ok, 2 tampered/corrupt, 3 unreadable.
    Verify { file: PathBuf },
    /// Print the last N records (default 10).
    Tail {
        file: PathBuf,
        #[arg(short = 'n', default_value_t = 10)]
        n: usize,
    },
}

fn cmd_audit(action: AuditCmd) -> ExitCode {
    use pos_core::audit::{AuditLog, SystemClock};
    let (file, tail) = match &action {
        AuditCmd::Verify { file } => (file, None),
        AuditCmd::Tail { file, n } => (file, Some(*n)),
    };
    let log = match AuditLog::load_from_file(file, SystemClock) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            eprintln!("audit log INVALID: {e}");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", file.display());
            return ExitCode::from(3);
        }
    };
    match tail {
        None => {
            println!("audit chain OK: {} records (head {})", log.records().len(), log.head_hash());
            println!("note: a hash chain cannot show that the newest records were not removed.");
        }
        Some(n) => {
            let r = log.records();
            for rec in &r[r.len().saturating_sub(n.max(1))..] {
                println!("{} {} {:?} {}", rec.seq, rec.timestamp, rec.event, rec.hash);
            }
        }
    }
    ExitCode::SUCCESS
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify an allowlist against a keyring.
    Verify {
        /// Path to allowlist.json
        allowlist: PathBuf,
        /// Path to keyring.json
        #[arg(long)]
        keyring: PathBuf,
        /// Rollback state file (v2 allowlists only); rejects older sequences.
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Check whether a package is allowed, and optionally dry-run install.
    Install {
        /// Package name (e.g. "ripgrep")
        package: String,
        /// Path to allowlist.json
        #[arg(long)]
        allowlist: PathBuf,
        /// Path to keyring.json (the allowlist signature is verified first)
        #[arg(long)]
        keyring: PathBuf,
        /// Show what would happen without installing.
        #[arg(long)]
        dry_run: bool,
        /// Rollback state file (v2 allowlists only); updated after a real install.
        #[arg(long)]
        state: Option<PathBuf>,
    },
    /// Convert a legacy text-v1 allowlist to an UNSIGNED v2 document (offline, one way).
    ///
    /// The v1 signature is verified with the old rules against --trusted-key
    /// (never a key from the document). The operator supplies the sha256 of every
    /// entry in --sha256-map (JSON object "name@version" -> hex); only the format
    /// is checked, not that it matches the real application file. The output
    /// has sequence 0 and fails verification until signed with `sign`.
    AllowlistMigrate {
        /// Legacy text-v1 allowlist file
        #[arg(long)]
        from_v1: PathBuf,
        /// Trusted keyring.json (the signer must be in it)
        #[arg(long)]
        trusted_key: PathBuf,
        /// JSON object mapping name@version to sha256 (lowercase hex)
        #[arg(long)]
        sha256_map: PathBuf,
        /// New output file; an existing file is never overwritten
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign an UNSIGNED v2 allowlist (signature_hex is overwritten; the key must match signed_by).
    Sign {
        /// Path to the allowlist.json to sign
        allowlist: PathBuf,
        /// Path to private-key.json written by keygen
        #[arg(long)]
        private_key: PathBuf,
        /// Output path for the signed allowlist
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify or show an audit log (JSON lines, hash-chained).
    Audit {
        #[command(subcommand)]
        action: AuditCmd,
    },
    /// Generate a fresh ed25519 keypair into a directory.
    Keygen {
        /// Output directory (created if missing).
        #[arg(long)]
        out: PathBuf,
    },
}

fn now_secs() -> u64 {
    // Fail-closed: if the clock is before the epoch, return 0. An allowlist
    // with issued_at > 0 will then be rejected as not-yet-valid, which is the
    // safe direction.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_json(path: &PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))
}

/// Parses and verifies a v2 allowlist against the trusted keyring (and optional
/// rollback state). v1 and unknown versions are rejected here.
fn check_v2(
    bytes: &[u8],
    trusted: &Keyring,
    state: Option<&PathBuf>,
) -> Result<pos_gate::allowlist_v2::V2Allowlist, String> {
    use pos_gate::allowlist_v2::{canonical_digest_hex, parse_v2, verify_v2_trusted};
    let doc = parse_v2(bytes).map_err(|e| format!("invalid allowlist: {e}"))?;
    let store = match state {
        Some(p) => Some(pos_gate::rollback::RollbackStore::open(p).map_err(|e| e.to_string())?),
        None => None,
    };
    let digest = canonical_digest_hex(&doc).map_err(|e| e.to_string())?;
    let stored = store.as_ref().filter(|s| s.last_seq() > 0).map(|s| (s.last_seq(), s.last_digest_hex().to_string()));
    verify_v2_trusted(&doc, trusted, now_secs() as i64, stored.as_ref().map(|(a, b)| (*a, b.as_str()))).map_err(|e| e.to_string())?;
    if let Some(s) = &store {
        s.check_candidate(doc.sequence, &digest).map_err(|e| e.to_string())?;
    }
    Ok(doc)
}

fn cmd_verify(allowlist: PathBuf, keyring: PathBuf, state: Option<PathBuf>) -> ExitCode {
    let keyring_bytes = match read_json(&keyring) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let allowlist_bytes = match read_json(&allowlist) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let kr = match Keyring::from_json(&keyring_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: invalid keyring: {e}");
            return ExitCode::from(2);
        }
    };
    match check_v2(&allowlist_bytes, &kr, state.as_ref()) {
        Ok(d) => {
            println!("ok: v2 allowlist verified (sequence {})", d.sequence);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("verification failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_install(package: String, allowlist: PathBuf, keyring: PathBuf, dry_run: bool, state: Option<PathBuf>) -> ExitCode {
    if package.is_empty()
        || package.starts_with('-')
        || !package.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | ':'))
    {
        eprintln!("invalid package identifier: {package}");
        return ExitCode::from(4);
    }
    let bytes = match read_json(&allowlist) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    // Reject unreadable / non-v2 input before looking at the keyring.
    if let Err(e) = pos_gate::allowlist_v2::parse_v2(&bytes) {
        eprintln!("error: invalid allowlist: {e}");
        return ExitCode::from(2);
    }
    let kr = match read_json(&keyring).and_then(|b| Keyring::from_json(&b).map_err(|e| e.to_string())) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: invalid keyring: {e}");
            return ExitCode::from(2);
        }
    };
    let doc = match check_v2(&bytes, &kr, state.as_ref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("verification failed: {e}");
            return ExitCode::from(2);
        }
    };
    if !dry_run && state.is_none() {
        eprintln!("error: installing requires --state so the rollback sequence is recorded");
        return ExitCode::from(4);
    }
    if !doc.entries.iter().any(|e| e.name == package) {
        eprintln!("not allowed: {package} is not in the allowlist");
        return ExitCode::from(3);
    }

    if dry_run {
        println!("dry-run: would install {package} (allowed)");
    } else {
        if let Some(sp) = &state {
            let digest = pos_gate::allowlist_v2::canonical_digest_hex(&doc).unwrap_or_default();
            let r = pos_gate::rollback::RollbackStore::open(sp)
                .and_then(|mut st| st.accept_and_persist(doc.sequence, &digest, Some(now_secs() as i64)));
            if let Err(e) = r {
                eprintln!("error: cannot record rollback state: {e}");
                return ExitCode::from(2);
            }
        }
        // The real installer is out of scope; this prints intent only. The
        // state file records that intent and is NOT rollback protection: it can
        // be deleted (which resets the counter), has no inter-process lock, and
        // no installer is connected to it.
        println!("install: {package} is allowed (installer not wired in this build)");
    }
    ExitCode::SUCCESS
}

fn cmd_sign(allowlist: PathBuf, private_key: PathBuf, out: PathBuf) -> ExitCode {
    use ed25519_dalek::{Signer, SigningKey};
    let run = || -> Result<(), String> {
        let mut doc = pos_gate::allowlist_v2::parse_v2(&read_json(&allowlist)?).map_err(|e| e.to_string())?;
        let pk: serde_json::Value = serde_json::from_slice(&read_json(&private_key)?).map_err(|e| e.to_string())?;
        let hexs = pk.get("private_key_hex").and_then(|v| v.as_str()).ok_or("private_key_hex missing")?;
        let bytes: [u8; 32] = hex::decode(hexs).map_err(|e| e.to_string())?.try_into().map_err(|_| "private key must be 32 bytes")?;
        let sk = SigningKey::from_bytes(&bytes);
        // The key must be the signed_by ring member, or the result could never verify.
        let signer = doc.keyring.keys.iter().find(|k| k.key_id == doc.signed_by).ok_or("signed_by is not in the document keyring")?;
        if signer.public_key_hex != hex::encode(sk.verifying_key().to_bytes()) {
            return Err("private key does not match the signed_by key in the document".into());
        }
        let payload = pos_gate::allowlist_v2::canonical_payload_bytes(&doc).map_err(|e| e.to_string())?;
        doc.signature_hex = hex::encode(sk.sign(&payload).to_bytes());
        write_new_file(&out, &serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?)
    };
    match run() {
        Ok(()) => {
            println!("wrote {}", out.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Creates a NEW file; an existing path (or a symlink to one) is never overwritten.
fn write_new_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

/// System directories where an installed PassAura allowlist or state could live.
/// The migration command refuses to write anywhere under them, whether or not the
/// target file exists yet. (The repo defines no single "installed allowlist path",
/// so this is a deny list of its system directories.)
const PROTECTED_DIRS: &[&str] = &[
    "/etc/passaura",
    "/var/lib/passaura",
    "/usr/share/passaura",
    "/usr/lib/passaura",
    "/usr/local/share/passaura",
    "/usr/local/lib/passaura",
];

/// Lexically normalizes an absolute path (removes `.` and `..`) without touching the disk.
fn normalize_abs(p: &std::path::Path) -> Result<PathBuf, String> {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// Decides whether `out` may be created as a NEW output file for `allowlist-migrate`.
/// Refuses: any path under a protected system directory (checked before the file or
/// directory has to exist, on the lexical path and again after resolving symlinks in
/// the parent), any existing path, and any of the command's own input files.
fn check_new_output(out: &std::path::Path, inputs: &[&std::path::Path]) -> Result<(), String> {
    let lexical = normalize_abs(out)?;
    let protected = |p: &std::path::Path| PROTECTED_DIRS.iter().any(|d| p.starts_with(d));
    if protected(&lexical) {
        return Err(format!("{} is in a protected PassAura system directory; choose another output path", out.display()));
    }
    let parent = lexical.parent().ok_or("output path has no parent directory")?;
    let name = lexical.file_name().ok_or("output path has no file name")?;
    let resolved_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("output directory {} is not usable: {e}", parent.display()))?;
    let resolved = resolved_parent.join(name);
    let canon_protected: Vec<PathBuf> = PROTECTED_DIRS.iter().filter_map(|d| std::fs::canonicalize(d).ok()).collect();
    if protected(&resolved) || canon_protected.iter().any(|d| resolved.starts_with(d)) {
        return Err(format!("{} resolves into a protected PassAura system directory", out.display()));
    }
    if std::fs::symlink_metadata(&lexical).is_ok() {
        return Err(format!("{} already exists; refusing to overwrite", out.display()));
    }
    for i in inputs {
        if let Ok(ci) = std::fs::canonicalize(i) {
            if ci == resolved {
                return Err("output path is the same as an input file".into());
            }
        }
    }
    Ok(())
}

fn cmd_migrate(from_v1: PathBuf, trusted_key: PathBuf, sha256_map: PathBuf, out: PathBuf) -> ExitCode {
    let run = || -> Result<usize, String> {
        // Check the destination first so a bad --out never leads to a read or a write.
        check_new_output(&out, &[from_v1.as_path(), trusted_key.as_path(), sha256_map.as_path()])?;
        let bytes = read_json(&from_v1)?;
        let kr = Keyring::from_json(&read_json(&trusted_key)?).map_err(|e| format!("invalid keyring: {e}"))?;
        let hashes = pos_gate::migrate::parse_sha256_map(&read_json(&sha256_map)?).map_err(|e| e.to_string())?;
        check_new_output(&out, &[from_v1.as_path(), trusted_key.as_path(), sha256_map.as_path()])?;
        let v2 = pos_gate::migrate::migrate_text_v1(&bytes, &kr, &hashes, now_secs()).map_err(|e| e.to_string())?;
        write_new_file(&out, &serde_json::to_vec_pretty(&v2).map_err(|e| e.to_string())?)?;
        Ok(v2.entries.len())
    };
    match run() {
        Ok(n) => {
            println!("wrote {} ({n} entries, UNSIGNED v2, sequence 0)", out.display());
            println!("note: hashes came from the operator's map; only their format was checked.");
            println!("next: review times/key window, then run `pos-cli sign` before use.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("migration failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_keygen(out: PathBuf) -> ExitCode {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    if let Err(e) = std::fs::create_dir_all(&out) {
        eprintln!("error: cannot create {}: {e}", out.display());
        return ExitCode::from(2);
    }

    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();

    let private_hex = hex::encode(signing.to_bytes());
    let public_hex = hex::encode(verifying.to_bytes());
    let key_id = format!("ed25519:{}", public_hex.get(..16).unwrap_or(&public_hex));

    let keyring = serde_json::json!({
        "keys": [ { "key_id": key_id, "public_key_hex": public_hex } ]
    });
    let private = serde_json::json!({
        "key_id": key_id,
        "private_key_hex": private_hex,
        "warning": "KEEP THIS FILE SECRET. It can sign allowlists."
    });

    let keyring_path = out.join("keyring.json");
    let private_path = out.join("private-key.json");

    // Never overwrite existing keys: a rerun must not destroy a private key.
    for p in [&keyring_path, &private_path] {
        if p.exists() {
            eprintln!("error: {} already exists; refusing to overwrite", p.display());
            return ExitCode::from(2);
        }
    }
    fn write_new(path: &std::path::Path, bytes: &[u8], secret: bool) -> std::io::Result<()> {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600); // private from the first byte, no chmod window
        }
        let _ = secret;
        o.open(path)?.write_all(bytes)
    }
    if let Err(e) = write_new(&keyring_path, &serde_json::to_vec_pretty(&keyring).unwrap_or_default(), false) {
        eprintln!("error: cannot write {}: {e}", keyring_path.display());
        return ExitCode::from(2);
    }
    if let Err(e) = write_new(&private_path, &serde_json::to_vec_pretty(&private).unwrap_or_default(), true) {
        eprintln!("error: cannot write {}: {e}", private_path.display());
        return ExitCode::from(2);
    }

    println!("wrote {}", keyring_path.display());
    println!("wrote {} (keep secret)", private_path.display());
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    // try_parse returns Err for usage errors; clap prints and we map to 4.
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap already prints help/version to stdout for --help/--version;
            // for genuine usage errors it prints to stderr. Map both to 4
            // except --help/--version, which clap marks with use_stderr()=false.
            let usage = e.use_stderr();
            let _ = e.print();
            return if usage { ExitCode::from(4) } else { ExitCode::SUCCESS };
        }
    };

    match cli.cmd {
        Cmd::Verify { allowlist, keyring, state } => cmd_verify(allowlist, keyring, state),
        Cmd::Install { package, allowlist, keyring, dry_run, state } => cmd_install(package, allowlist, keyring, dry_run, state),
        Cmd::AllowlistMigrate { from_v1, trusted_key, sha256_map, out } => cmd_migrate(from_v1, trusted_key, sha256_map, out),
        Cmd::Sign { allowlist, private_key, out } => cmd_sign(allowlist, private_key, out),
        Cmd::Keygen { out } => cmd_keygen(out),
        Cmd::Audit { action } => cmd_audit(action),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn protected_dirs_are_refused_even_when_nothing_exists_there() {
        for p in [
            "/etc/passaura/allowlist.json",
            "/var/lib/passaura/allowlist.json",
            "/usr/share/passaura/new.json",
            "/etc/passaura/sub/dir/new.json",
            "/tmp/x/../../etc/passaura/allowlist.json",
        ] {
            let e = check_new_output(Path::new(p), &[]).unwrap_err();
            assert!(e.contains("protected"), "{p}: {e}");
        }
    }

    #[test]
    fn normal_new_path_is_allowed_and_existing_or_input_paths_are_not() {
        let dir = std::env::temp_dir().join(format!("pos-cli-out-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fresh = dir.join("new.json");
        assert!(check_new_output(&fresh, &[]).is_ok());
        std::fs::write(&fresh, b"x").unwrap();
        assert!(check_new_output(&fresh, &[]).unwrap_err().contains("already exists"));
        assert!(check_new_output(&dir.join("missing-dir/new.json"), &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
