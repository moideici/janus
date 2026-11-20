# Janus clients in other languages

Independent implementations of the [Janus v1 format](../spec/janus-v1.md), written from the specification rather than from the Rust code. They exist to prove that the specification is complete and unambiguous: every client opens the reference test vectors, and files written by any client open with every other one, and with the reference implementation.

> ⚠️ **Interoperability clients, not for real secrets.** Like the reference implementation, they have not been audited. Unlike it, they make no constant-time guarantee: Python, JavaScript, Java and C# big integers are not constant-time, and some primitives are written here from scratch. Use them to read and write test files, and to check the specification.

| Directory | Language | Runs with | Primitives taken from the platform | Written here |
|---|---|---|---|---|
| [`python/`](python/) | Python 3.11+ | `python` + the `cryptography` package (≥ 44) | ML-KEM-768, Argon2id, ChaCha20-Poly1305, HKDF, HMAC, SHA-2, SHA-3/SHAKE | Curve25519 arithmetic, Elligator 2, Kemeleon, Bech32m, format |
| [`typescript/`](typescript/) | TypeScript | Node.js 26 (runs `.ts` directly; tested with 26.12) | ML-KEM-768, Argon2id, ChaCha20-Poly1305, HKDF, HMAC, SHA-2, SHA-3/SHAKE (`node:crypto`) | Curve25519 arithmetic, Elligator 2, Kemeleon, Bech32m, format |
| [`csharp/`](csharp/) | C# | .NET 10 SDK | SHA-256, HMAC, HKDF, random | ML-KEM-768, Keccak/SHAKE, Argon2id with BLAKE2b, ChaCha20-Poly1305, Curve25519, Elligator 2, Kemeleon, Bech32m, format |
| [`java/`](java/) | Java | JDK 21 (`javac`, no build tool) | SHA-256, SHA3-256, SHA3-512, HMAC, ChaCha20-Poly1305, random | ML-KEM-768, SHAKE, Argon2id with BLAKE2b, HKDF, Curve25519, Elligator 2, Kemeleon, Bech32m, format |

No client downloads anything at build or run time. Only the Python client needs a third-party package (`cryptography`), which most Python installations already have.

## Common command line

Every client provides the same commands, so they can be tested against each other. Messages are in English.

```
<client> keygen IDENTITY_FILE        create an identity file; print the public key (janus1…) on stdout
<client> pubkey IDENTITY_FILE        print the public key of an identity
<client> encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
<client> decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)

RECIPIENTS := --pass PASSWORD                       one password, alone in its face
            | (--to PUBLIC_KEY | --to-file FILE)+   1 to 16 public keys (FILE: one key per line, # comments)
```

- `encrypt`: the first `INPUT` is the main face (the decoy); each `--hidden` adds a hidden face (3 at most). The encryptor enforces rules R1, R3 and R5 of the specification.
- `decrypt`: opens the face that the credential opens, and nothing else. On any failure, it writes nothing, prints `cannot decrypt` on stderr and exits with status 1. If the credentials open several faces, it prints `these credentials open several faces` and exits with status 1.
- `keygen`, `encrypt` and `decrypt` refuse to overwrite an existing output file. A usage error exits with status 2.
- Passwords on the command line are visible to other local users: acceptable for test files only.
- Identity files are those of the specification, § 3.3: comment lines starting with `#`, and one `JANUS-SECRET-KEY-1…` line.

The reference Rust tool uses French commands (`janus cles`, `janus chiffrer -m …`, `janus dechiffrer -i …`) and reads passwords from environment variables in tests: `JANUS_MDP` for the main face, then `JANUS_MDP_CACHE`, `JANUS_MDP_CACHE2` and `JANUS_MDP_CACHE3` for the first, second and third `--cache` (by position, even when an earlier hidden face uses keys).

## Tests

Each client has a test script that:

1. checks its X-Wing against test vector 1 of `draft-connolly-cfrg-xwing-kem-11`, and its Bech32m against the BIP 350 vectors;
2. reproduces `janus-rs/vecteurs/cles.json` exactly from the seeds;
3. opens every file of `janus-rs/vecteurs/` with every credential listed in `manifeste.json` (and every hidden face), checks the SHA-256 of each plaintext, and fails to open each file with a foreign identity or a wrong password;
4. encrypts its own files (password, keys, several hidden faces, empty and multi-block plaintexts) and opens them again.

The cross-implementation test, [`interop.py`](interop.py), encrypts with every implementation and decrypts with every other one.
