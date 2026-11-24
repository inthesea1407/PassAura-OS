// pos-cli — PassAura OS command-line tool.
//
// Subcommands:
//   verify  <allowlist.json> --keyring <keyring.json>
//   install <package> --allowlist <file> --dry-run
//   keygen  --out <dir>
//
// Exit codes: 0 ok, 2 verification failed, 3 not allowed, 4 usage.
// No panics on malformed input: every fallible path returns a Result and is
// mapped to an exit code. clap handles usage errors (exit 4 via try_parse).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};

use pos_gate::{is_allowed, verify_allowlist, AllowlistDoc, Keyring};

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
enum Cmd {
    /// Verify an allowlist against a keyring.
    Verify {
        /// Path to allowlist.json
        allowlist: PathBuf,
        /// Path to keyring.json
        #[arg(long)]
        keyring: PathBuf,
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
    },
    /// Sign an allowlist.json (signed_by and packages set; signature_hex is overwritten).
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

fn cmd_verify(allowlist: PathBuf, keyring: PathBuf) -> ExitCode {
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
    let doc = match AllowlistDoc::from_json(&allowlist_bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: invalid allowlist: {e}");
            return ExitCode::from(2);
        }
    };

    match verify_allowlist(&kr, &doc, now_secs()) {
        Ok(()) => {
            println!("ok: allowlist verified");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("verification failed: {e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_install(package: String, allowlist: PathBuf, keyring: PathBuf, dry_run: bool) -> ExitCode {
    let bytes = match read_json(&allowlist) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let doc = match AllowlistDoc::from_json(&bytes) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: invalid allowlist: {e}");
            return ExitCode::from(2);
        }
    };

    let kr = match read_json(&keyring).and_then(|b| Keyring::from_json(&b).map_err(|e| e.to_string())) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: invalid keyring: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = verify_allowlist(&kr, &doc, now_secs()) {
        eprintln!("verification failed: {e}");
        return ExitCode::from(2);
    }

    if package.is_empty()
        || package.starts_with('-')
        || !package.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | ':'))
    {
        eprintln!("invalid package identifier: {package}");
        return ExitCode::from(4);
    }
    if !is_allowed(&doc, &package) {
        eprintln!("not allowed: {package} is not in the allowlist");
        return ExitCode::from(3);
    }

    if dry_run {
        println!("dry-run: would install {package} (allowed)");
    } else {
        // The real installer is out of scope for this task; print intent.
        // In a full build this would shell out to the platform package manager
        // after re-verifying the signature.
        println!("install: {package} is allowed (installer not wired in this build)");
    }
    ExitCode::SUCCESS
}

fn cmd_sign(allowlist: PathBuf, private_key: PathBuf, out: PathBuf) -> ExitCode {
    use ed25519_dalek::SigningKey;
    let run = || -> Result<(), String> {
        let mut doc = AllowlistDoc::from_json(&read_json(&allowlist)?).map_err(|e| e.to_string())?;
        let pk: serde_json::Value = serde_json::from_slice(&read_json(&private_key)?).map_err(|e| e.to_string())?;
        let hexs = pk.get("private_key_hex").and_then(|v| v.as_str()).ok_or("private_key_hex missing")?;
        let bytes: [u8; 32] = hex::decode(hexs).map_err(|e| e.to_string())?.try_into().map_err(|_| "private key must be 32 bytes")?;
        doc.sign(&SigningKey::from_bytes(&bytes));
        std::fs::write(&out, serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
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

    if let Err(e) = std::fs::write(&keyring_path, serde_json::to_vec_pretty(&keyring).unwrap_or_default()) {
        eprintln!("error: cannot write {}: {e}", keyring_path.display());
        return ExitCode::from(2);
    }
    if let Err(e) = std::fs::write(&private_path, serde_json::to_vec_pretty(&private).unwrap_or_default()) {
        eprintln!("error: cannot write {}: {e}", private_path.display());
        return ExitCode::from(2);
    }

    // Best-effort: restrict private key permissions on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600));
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
        Cmd::Verify { allowlist, keyring } => cmd_verify(allowlist, keyring),
        Cmd::Install { package, allowlist, keyring, dry_run } => cmd_install(package, allowlist, keyring, dry_run),
        Cmd::Sign { allowlist, private_key, out } => cmd_sign(allowlist, private_key, out),
        Cmd::Keygen { out } => cmd_keygen(out),
    }
}
