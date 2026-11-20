# Janus v1 — Java client

An independent implementation of the [Janus v1 format](../../spec/janus-v1.md) in Java 21, written from the specification, with no third-party library and no build tool.

> ⚠️ **Interoperability client, not for real secrets.** It has not been audited, and it is **not constant-time**: Curve25519 arithmetic, Elligator 2 and Kemeleon use `java.math.BigInteger`, and the JIT gives no timing guarantee for anything. It does the obvious things — all 16 slots and all 4 tags are always tried, with the same work on success and failure (spec § 8), comparisons use `MessageDigest.isEqual`, ML-KEM implicit rejection selects its key without a branch, secrets are wiped with `Arrays.fill` where practical — but that is not a side-channel guarantee. Use it to read and write test files and to check the specification.

## Requirements

A JDK 21 (`javac`, `jar`, `java`). Nothing is downloaded at build or run time.

## Build

```sh
clients/java/build.sh          # Git Bash, Linux, macOS
clients/java/build.ps1         # PowerShell
```

Both compile `src/org/janus/*.java` into `clients/java/out/classes` and build the runnable `clients/java/out/janus.jar`.

## Usage

The common command line of the clients ([`clients/README.md`](../README.md)):

```
java -jar clients/java/out/janus.jar keygen IDENTITY_FILE
java -jar clients/java/out/janus.jar pubkey IDENTITY_FILE
java -jar clients/java/out/janus.jar encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
java -jar clients/java/out/janus.jar decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)
java -jar clients/java/out/janus.jar selftest [REPOSITORY_ROOT]

RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
```

- `keygen`, `encrypt` and `decrypt` refuse to overwrite an existing output file (status 1).
- `decrypt` works in memory and writes nothing on failure: it prints `cannot decrypt` (or `these credentials open several faces`) on stderr and exits with status 1. Usage errors exit with status 2.
- `encrypt` enforces rules R1, R3 and R5 (at most 16 recipients, hidden faces within the reserve, no password or public key shared between faces, no public key repeated within a face) and refuses a fourth hidden face.
- Public keys are checked as spec § 3.1 requires: the FIPS 203 encapsulation-key check, and a canonical `pk_X` (bit 255 clear, below p); a canonical low-order `pk_X` is accepted.
- Identity files (spec § 3.3): a UTF-8 or UTF-16 byte-order mark is skipped, CRLF accepted, lines trimmed; the first `JANUS-SECRET-KEY-1` line is the identity, and if it does not decode the file is invalid.
- Passwords are taken as UTF-8 bytes, without normalization. On the command line they are visible to other local users.

Example:

```sh
J="java -jar clients/java/out/janus.jar"
PK=$($J keygen me.id)
$J encrypt vault.janus holiday.zip --pass decoy --hidden diary.txt --to "$PK"
$J decrypt vault.janus diary.out --id me.id
```

## Tests

```sh
clients/java/test.sh           # or: clients/java/test.ps1
```

builds the jar and runs `org.janus.Tests` (also reachable as `janus selftest`), a plain `main` with no test framework:

1. **Primitives:** SHAKE128/SHAKE256/SHA3 known answers (FIPS 202), the Keccak sponge cross-checked against the JDK's SHA3-256/512 on 61 lengths, HKDF (RFC 5869 test case 1), BLAKE2b-512 (RFC 7693 “abc”), Argon2id (RFC 9106 § 5.3), X25519 (RFC 7748 § 5.2); it also prints the time of one Argon2id with the Janus parameters.
2. **X-Wing:** test vector 1 of `draft-connolly-cfrg-xwing-kem-11` (deterministic encapsulation, then decapsulation), ML-KEM implicit rejection, the encapsulation-key check, the canonical-`pk_X` check (low-order points accepted), Elligator 2 round trips, the unclamped full-group ladder against the recipient's X25519, Kemeleon round trip, hidden encapsulation/decapsulation.
3. **Bech32m:** the BIP 350 valid and invalid strings, the identity/public-key rules of spec § 3.3 (case, prefix, checksum, length, padding), and identity files (BOM, CRLF, UTF-16, invalid first identity line).
4. **`cles.json`** reproduced exactly from its seeds.
5. **Test vectors:** every file of `janus-rs/vecteurs/` opened with every credential of `manifeste.json`, hidden faces included, plaintext SHA-256 checked; a foreign identity (32 bytes `0xEE`), a wrong password and a file truncated by one byte all fail.
6. **Round trips:** password, 1 and 16 keys, decoy + 1 and + 3 hidden faces (passwords and keys mixed), empty, 65 536- and 65 537-byte plaintexts, tampering, “several faces”, and refusal of 17 recipients, a shared password or key, hidden faces larger than the reserve, 4 hidden faces, a key repeated within a face, a password face with a key.
7. **Interoperability** with the reference binary `janus-rs/target/release/janus[.exe]` (skipped with a message if it is absent): files written here open with the Rust tool and the reverse (password, public key, decoy with hidden faces), and identity files are exchanged both ways.
8. **Command line:** exit statuses (0, 1, 2 for usage errors), `cannot decrypt` with nothing written, and refusal to overwrite outputs.

The cross-implementation script [`clients/interop.py`](../interop.py) also drives this client through its command line.

## What is written here

| Class | Content |
|---|---|
| `Keccak` | Keccak-f[1600], SHAKE128, SHAKE256 (Java 21 has no SHAKE API) |
| `Blake2b`, `Argon2id` | BLAKE2b (RFC 7693); Argon2id v0x13 (RFC 9106), the 4 lanes of each slice in parallel threads |
| `Hkdf` | HKDF-SHA-256 (RFC 5869) over the JDK's HMAC-SHA-256 |
| `MlKem768` | ML-KEM-768 (FIPS 203): KeyGen_internal, Encaps(_internal), Decaps with implicit rejection, encapsulation-key check |
| `Curve25519` | field arithmetic on `BigInteger`, RFC 7748 Montgomery ladder (clamped X25519, and unclamped over all 256 bits for the hidden encapsulation) |
| `Elligator2`, `Kemeleon` | spec § 5.4 and § 5.5 |
| `XWing` | key pairs from a seed, the X-Wing combiner, hidden encapsulation and decapsulation (spec § 5.2, § 5.3) |
| `Bech32m`, `Keys` | BIP 350, key strings and identity files (spec § 3.3) |
| `Janus` | sizes, PADME, placement of hidden faces, encryption and decryption (spec § 6–8) |
| `Aead`, `Bytes` | thin wrappers over the JDK |
| `Main`, `Tests`, `Json` | command line, self-test, a minimal JSON reader for the vectors |

Taken from the JDK: SHA-256, SHA3-256 and SHA3-512 (`MessageDigest`), HMAC-SHA-256 (`Mac`), ChaCha20-Poly1305 (`Cipher`, SunJCE; a new instance per call, since the JDK refuses to encrypt twice with one key and nonce), `SecureRandom`, `BigInteger`.

## Limitations

- Not constant-time, not audited (see above).
- Files are processed in memory: inputs and outputs are limited to about 2 GiB, and need that much heap.
- Old v0.1.0-alpha identity strings (`JANUS-SECRET-V0-…`), which the spec allows reading until 1.0, are not accepted.
- On Windows, non-ASCII passwords on the command line depend on how the shell passes arguments to the JVM.
