//! Writes seed files for `fuzz_vault_open` into the directory given as the
//! first argument. Dev tool, run by hand:
//!
//! ```sh
//! cargo run -p pos-vault-store --example make_fuzz_seeds -- fuzz/corpus/fuzz_vault_open
//! ```
//!
//! Every seed is sealed with a passphrase DIFFERENT from the one the fuzz
//! target uses (`fuzz-passphrase`), so the target's "open must fail" assertion
//! drives execution past the header and parameter checks into the KDF and the
//! AEAD layer instead of stopping at the magic check. Truncations cover the
//! length checks. None of these files may ever open under the fuzz passphrase.

use pos_vault_store::*;
use std::path::Path;

/// The passphrase the seeds are sealed with. Never the fuzz target's.
const SEED_PW: &[u8] = b"seed-passphrase-not-the-fuzz-one";

struct Fixed(u8);
impl Random for Fixed {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        for x in b.iter_mut() {
            self.0 = self.0.wrapping_add(1);
            *x = self.0;
        }
        Ok(())
    }
}

fn lim() -> WriteLimits {
    WriteLimits::new(Tier::Gb2)
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
    println!("{name}: {} bytes", bytes.len());
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: make_fuzz_seeds <output dir>");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();

    let floor = ArgonParams {
        m_kib: FLOOR_M_KIB,
        t: FLOOR_T,
        p: FLOOR_P,
    };
    // Valid and inside the Gb2 ceiling, but above the floor: explores the
    // parameter bounds and the KDF at a second point.
    let higher = ArgonParams {
        m_kib: 32 * 1024,
        t: 3,
        p: 4,
    };

    // 1. V1, floor params, short plaintext.
    let v1 = seal(
        SEED_PW,
        b"seed payload",
        Suite::V1,
        &floor,
        &lim(),
        &mut Fixed(0),
    )
    .unwrap();
    write(dir, "v1_floor", &v1);

    // 2. V1 after a rewrap: envelope version 2, same payload.
    let v1_rw = rewrap(
        SEED_PW,
        b"seed-passphrase-two",
        &v1,
        Suite::V1,
        &floor,
        &lim(),
        &mut Fixed(0),
    )
    .unwrap();
    write(dir, "v1_rewrapped", &v1_rw);

    // 3. V1, higher (still valid) params, empty plaintext.
    let v1_hi = seal(SEED_PW, b"", Suite::V1, &higher, &lim(), &mut Fixed(0)).unwrap();
    write(dir, "v1_higher_params", &v1_hi);

    // 4. L1, floor params (L1 nonces come from OS randomness inside
    // pos-crypto-suites; only the header/envelope are deterministic).
    let l1 = seal(
        SEED_PW,
        b"seed payload",
        Suite::L1,
        &floor,
        &lim(),
        &mut Fixed(0),
    )
    .unwrap();
    write(dir, "l1_floor", &l1);

    // 5. Truncations of the V1 seed: header-only, header+partial envelope,
    // header+envelope, and one byte short of full.
    for (name, n) in [
        ("v1_trunc_header", HEADER_LEN),
        ("v1_trunc_envelope_half", HEADER_LEN + ENVELOPE_LEN / 2),
        ("v1_trunc_envelope", HEADER_LEN + ENVELOPE_LEN),
        ("v1_trunc_one_short", v1.len() - 1),
    ] {
        write(dir, name, &v1[..n]);
    }
}
