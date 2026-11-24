//! Usage: pos-gate <package-name> <file-list> [desktop-entry-file...]
//! `file-list` has one installed path per line. Env POS_LICENSED=1 means an
//! active PassAura Premium membership. Exit 0 = allow, 1 = block,
//! 2 = usage error or unreadable input (callers must treat any non-zero as block).
use pos_gate::{verdict, PackageFacts};
use pos_core::blocking::Verdict;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: pos-gate <package> <file-list> [desktop-file...]");
        std::process::exit(2);
    }
    // Fail closed: an unreadable input must not become an empty (and so more
    // permissive) set of facts. Exit 2 is a non-zero code, so callers block.
    let files = match std::fs::read_to_string(&a[2]) {
        Ok(t) => t.lines().map(|s| s.trim().to_string()).collect(),
        Err(e) => {
            eprintln!("pos-gate: cannot read file list {}: {e}", a[2]);
            std::process::exit(2);
        }
    };
    let mut desktop_entries = Vec::new();
    for p in &a[3..] {
        match std::fs::read_to_string(p) {
            Ok(t) => desktop_entries.push(t),
            Err(e) => {
                eprintln!("pos-gate: cannot read desktop entry {p}: {e}");
                std::process::exit(2);
            }
        }
    }
    let licensed = std::env::var("POS_LICENSED").map(|v| v == "1").unwrap_or(false);
    let f = PackageFacts { name: a[1].clone(), files, desktop_entries };
    match verdict(&f, licensed) {
        Verdict::Allow => println!("allow {}", f.name),
        Verdict::Block(why) => {
            println!("BLOCK {}: {}", f.name, why);
            std::process::exit(1);
        }
    }
}
