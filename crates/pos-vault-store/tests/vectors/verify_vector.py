#!/usr/bin/env python3
"""Independent cross-implementation check of the v2 golden vector.

Verifies the frozen vector in tests/format_vectors.rs using Python
implementations (argon2-cffi for Argon2id, PyNaCl for XChaCha20-Poly1305),
so a bug shared by the Rust crates cannot hide in the vector.
Manual tool, not part of CI: pip install argon2-cffi pynacl, then run.
"""
import argon2.low_level, nacl.bindings

GOLDEN = (
    "504156530002010102030405060708090a0b0c0d0e0f1001"
    "00004c0000000002000000013132333435363738393a3b3c"
    "3d3e3f404142434445464748494a4b4c4d4e4f5051525354"
    "5556575800000000000000017de319a0eae1786533077a83"
    "5dabf3ebdbd254c89f87b429cd76ae298bdd186ac409a645"
    "afc42e0dc6ab733ba006c808595a5b5c5d5e5f6061626364"
    "65666768696a6b6c6d6e6f7017dabf6e134548ad7eacb8c5"
    "df901d7fda537409837b916a965eef"
)
f = bytes.fromhex(GOLDEN)
PW = b"format-vector-passphrase"
HEADER_LEN, ENV_LEN, SALT_LEN, NONCE_LEN, VER_LEN, DEK_LEN, TAG_LEN = 23, 109, 16, 24, 8, 32, 16

header = f[:HEADER_LEN]
env = f[HEADER_LEN:HEADER_LEN + ENV_LEN]
assert f[:4] == b"PAVS" and int.from_bytes(f[4:6], "big") == 2 and f[6] == 1
assert env[0] == 1, "kdf id"
m = int.from_bytes(env[1:5], "big"); t = int.from_bytes(env[5:9], "big"); p = int.from_bytes(env[9:13], "big")
assert (m, t, p) == (19456, 2, 1), (m, t, p)
salt = env[13:13 + SALT_LEN]
nonce = env[13 + SALT_LEN:13 + SALT_LEN + NONCE_LEN]
vo = 13 + SALT_LEN + NONCE_LEN
assert int.from_bytes(env[vo:vo + VER_LEN], "big") == 1
wrapped = env[vo + VER_LEN:]
assert len(wrapped) == DEK_LEN + TAG_LEN

kek = argon2.low_level.hash_secret_raw(
    PW, salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=32,
    type=argon2.low_level.Type.ID, version=19)

aad = b"pos-vault-store/v2/dek-wrap" + header + env[:vo + VER_LEN]
dek = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(wrapped, aad, nonce, kek)
assert dek == bytes(range(0x11, 0x31)), "DEK is not the injected rng sequence"

payload = f[HEADER_LEN + ENV_LEN:]
pnonce, ct = payload[:NONCE_LEN], payload[NONCE_LEN:]
pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, header, pnonce, dek)
assert pt == b"hello vault", pt
print("OK: independent Python verification of the golden v2 vector passed")
print("  argon2id m=%d t=%d p=%d v=19; XChaCha20-Poly1305 wrap+payload; DEK recovered" % (m, t, p))
