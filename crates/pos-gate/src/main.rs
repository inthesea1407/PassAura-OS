//! Usage: pos-gate <package-name> <file-list> [desktop-entry-file...]
//! `file-list` has one installed path per line. Env POS_LICENSED=1 means an
//! active PassAura Premium membership. Exit 0 = allow, 1 = block.
use pos_gate::{verdict, PackageFacts};
use pos_core::blocking::Verdict;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: pos-gate <package> <file-list> [desktop-file...]");
        std::process::exit(2);
    }
    let files = std::fs::read_to_string(&a[2]).unwrap_or_default().lines().map(|s| s.trim().to_string()).collect();
    let desktop_entries = a[3..].iter().filter_map(|p| std::fs::read_to_string(p).ok()).collect();
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
