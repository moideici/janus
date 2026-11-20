# Janus v1 — Python client

An independent implementation of the [Janus v1 file format](../../spec/janus-v1.md), written from the specification (not from the Rust code). It opens the reference test vectors, and its files open with the reference tool and the other clients.

> **Interoperability client, not for real secrets.** Not audited, and **not constant-time**: Python integers, dictionaries and branches leak timing, and the Curve25519, Elligator 2, Kemeleon and Bech32m code here is plain Python. The obvious precautions are taken (`hmac.compare_digest`, all 16 slots and all 4 tags always tried, the same work whether or not a slot matches, nothing written on failure), but they do not make it safe. Use it to read and write test files and to check the specification.

## Requirements

- Python 3.11 or later.
- The [`cryptography`](https://cryptography.io/) package, version 44 or later (ML-KEM-768 appeared there). Nothing else; nothing is downloaded.

## Usage

```
python clients/python/janus.py keygen me.key                  # prints the public key janus1…
python clients/python/janus.py pubkey me.key
python clients/python/janus.py encrypt out.janus decoy.zip --pass "decoy password" \
       --hidden diary.txt --to janus1… --to-file friends.txt \
       --hidden notes.txt --pass "other password"
python clients/python/janus.py decrypt out.janus diary.txt --id me.key
python clients/python/janus.py decrypt out.janus decoy.zip --pass "decoy password"
```

`python -m janus_py …` works too, from `clients/python/`. The commands are the common command line of [`clients/README.md`](../README.md):

- `encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...`, with `RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+`. Rules R1, R3 and R5 are enforced (and at most 3 hidden faces); a refused encryption exits with status 2.
- `decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)`. The file is decrypted and verified in memory, then written; on failure nothing is written, `cannot decrypt` (or `these credentials open several faces`) is printed on stderr and the status is 1.
- Output files, identity files included (`keygen`), must not exist already: nothing is ever overwritten. They are written to a temporary file and renamed.
- Usage errors (unknown command or option, missing argument, existing output file) exit with status 2.
- Public keys are rejected if the ML-KEM part fails the FIPS 203 check or if `pk_X` is not canonical (bit 255 set, or ≥ 2^255 − 19); canonical low-order `pk_X` values are accepted (spec § 3.1).
- Identity files: a UTF-8 BOM is skipped, CRLF accepted, lines trimmed; if the first `JANUS-SECRET-KEY-1…` line does not decode, the file is invalid (spec § 3.3).

Passwords on the command line are visible to other local users: acceptable for test files only. Passwords are taken as UTF-8, without normalization.

## Tests

```
python clients/python/test_janus.py
```

Only `unittest` is used. The script checks:

1. X-Wing (draft-connolly-cfrg-xwing-kem-11) test vector 1. The `cryptography` package only offers randomized ML-KEM encapsulation, so the test contains a small pure-Python FIPS 203 `Encaps_internal` to produce the deterministic ciphertext from the vector's `eseed`; the library then decapsulates it, and the combined secret must equal the vector's. Also: RFC 7748 vector, X25519 against the library, the full-group generator `u(G)`, Elligator 2 round trips, hidden encapsulation, Kemeleon round trips and preimage counts, the encapsulation-key check.
2. Bech32m against the BIP 350 vectors, and the strictness rules of spec § 3.3 (case, prefix, length, padding).
3. `janus-rs/vecteurs/cles.json`, reproduced exactly from the seeds.
4. Every file of `janus-rs/vecteurs/manifeste.json` with every listed credential and every hidden face (SHA-256 of each plaintext), and failure with a foreign identity and a wrong password; tampered and truncated files fail.
5. Round trips of its own files: password, 1 and 16 keys, a decoy with 1 and 3 hidden faces mixing passwords and keys, empty and multi-block plaintexts (65 535, 65 536, 65 537, 200 000 bytes), and the rule violations (17 recipients, a password or a key in two faces, hidden faces too big for the reserve, 4 hidden faces, a password mixed with keys).
6. The command line.
7. Interoperability with the reference binary `janus-rs/target/release/janus(.exe)` in both directions (password, key, decoy + 3 hidden faces); skipped with a message if the binary is absent.

The cross-implementation script [`clients/interop.py`](../interop.py) runs this client as `python clients/python/janus.py`.

## Where things are

| File | Content | Spec |
|---|---|---|
| `janus_py/curve25519.py` | GF(2^255 − 19), X25519, unclamped 256-bit Montgomery ladder, Elligator 2 map and representative, uniform ephemeral over the whole curve | § 2.1, 5.2, 5.4 |
| `janus_py/kemeleon.py` | Kemeleon encoding of ML-KEM-768 ciphertexts (big-endian vectors) | § 5.5 |
| `janus_py/bech32m.py` | Bech32m, strict 8-to-5-bit conversion | § 3.3 |
| `janus_py/xwing.py` | key pair from the seed, encapsulation-key check, X-Wing combiner, hidden encapsulation and decapsulation | § 3.1, 3.2, 5.2, 5.3 |
| `janus_py/keys.py` | text encoding of identities and public keys, identity files | § 3.3 |
| `janus_py/container.py` | sizes, PADME, placement of hidden faces, slots, tags, STREAM, encryption and decryption | § 5.1, 6, 7, 8 |
| `janus_py/cli.py` | the common command line | `clients/README.md` |
| `test_janus.py` | the tests | § 10 |

Taken from `cryptography`: ML-KEM-768, Argon2id, ChaCha20-Poly1305. From the standard library: SHA-2, SHA-3/SHAKE, HMAC (HKDF is written on top of `hmac`), `secrets` for all randomness.

## Limitations

- Not constant-time (see above), not audited.
- Files are read and written whole in memory.
- The v0.1.0-alpha identity strings (`JANUS-SECRET-V0-…`), which the spec allows reading until 1.0, are not supported.
