# Janus v1 — C# client

An independent C# implementation of the [Janus v1 format](../../spec/janus-v1.md), written from the
specification (not from the Rust code). It provides the [common command line](../README.md) of the
Janus clients and a self-test suite.

> ⚠️ **Interoperability client, not for real secrets.** Not audited. **Not constant-time**:
> Curve25519 and Kemeleon use `System.Numerics.BigInteger`, and the primitives written here make no
> timing guarantee. Use it to read and write test files and to check the specification.

## Requirements

- .NET 10 SDK (tested with 10.0.302), on Windows, Linux or macOS.
- Nothing else: the project has **no NuGet package** and builds offline.

Only portable platform primitives are used: `SHA256`, `HMACSHA256`, `HKDF`,
`RandomNumberGenerator`, `BigInteger`. Everything else is written here in managed code, because
.NET's ML-KEM, SHA-3/SHAKE and ChaCha20-Poly1305 classes are not available on every OS.

| File | Content |
|---|---|
| `Keccak.cs` | Keccak-f[1600]; SHA3-256, SHA3-512, SHAKE128, SHAKE256 (FIPS 202) |
| `Blake2b.cs` | BLAKE2b (RFC 7693) |
| `Argon2id.cs` | Argon2id v0x13 (RFC 9106); lanes of a slice run in parallel |
| `ChaCha20Poly1305.cs` | ChaCha20, Poly1305, AEAD (RFC 8439) |
| `MlKem768.cs` | ML-KEM-768 (FIPS 203): KeyGen_internal, Encaps(_internal), Decaps with implicit rejection, encapsulation-key check |
| `Curve25519.cs` | Montgomery ladder (clamped X25519 and the unclamped ladder of § 5.2), Elligator 2 map and representative (§ 5.4) |
| `Kemeleon.cs` | Kemeleon encoding of ML-KEM ciphertexts (§ 5.5) |
| `XWing.cs` | X-Wing key pair and combiner, hidden encapsulation and decapsulation (§ 3, § 5.2–5.3) |
| `Bech32m.cs`, `KeyText.cs` | Bech32m (BIP 350), key strings and identity files (§ 3.3) |
| `JanusFile.cs` | Sizes, layout, encryption and decryption (§ 6–8) |
| `RandomUniform.cs` | Unbiased random integers and permutations |
| `Program.cs` | Command line |
| `SelfTest.cs` | Test suite |

## Build

```
dotnet build -c Release clients/csharp/Janus
```

The build output is `clients/csharp/Janus/bin/Release/net10.0/Janus.dll` (the path
[`../interop.py`](../interop.py) uses). Build in Release: Argon2id is much slower in Debug.

## Usage

```
dotnet run -c Release --project clients/csharp/Janus -- <command> ...
# or, after building:
dotnet clients/csharp/Janus/bin/Release/net10.0/Janus.dll <command> ...

keygen IDENTITY_FILE        create an identity file (refuses to overwrite); print the public key
pubkey IDENTITY_FILE        print the public key of an identity
encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)
selftest [--vectors DIR] [--reference JANUS_EXE] [--quick]

RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
```

Example:

```
dotnet Janus.dll keygen me.id > me.pub
dotnet Janus.dll encrypt out.janus decoy.zip --pass "decoy" --hidden diary.txt --to-file me.pub
dotnet Janus.dll decrypt out.janus diary.txt --id me.id
```

`decrypt` reads and verifies everything in memory and writes the output only on success; on
failure it prints `cannot decrypt` (or `these credentials open several faces`) and exits with
status 1. Usage errors exit with status 2. `keygen` refuses to overwrite an existing file;
`encrypt` and `decrypt` overwrite an existing output.

Public keys are refused if their ML-KEM part fails the FIPS 203 check or if `pk_X` is not
canonical (bit 255 set, or value ≥ 2^255 − 19); canonical low-order `pk_X` values are accepted.
The encryptor also refuses a public key repeated within one face (R5). In an identity file, a BOM,
CRLF line ends and surrounding blanks are accepted; if the first `JANUS-SECRET-KEY-1…` line does not
decode, the file is invalid. Files are processed in memory, so they must be
smaller than 2 GiB.

## Tests

The tests are a mode of the program (no test framework, since no package may be downloaded):

```
dotnet run -c Release --project clients/csharp/Janus -- selftest
```

Run it from anywhere inside the repository: it finds `janus-rs/vecteurs/` and the reference binary
`janus-rs/target/release/janus(.exe)` by walking up from the current directory (or use `--vectors`
and `--reference`). It checks:

1. known answers: SHA3-256, SHA3-512, SHAKE128, SHAKE256 (FIPS 202), BLAKE2b "abc" (RFC 7693),
   Poly1305 and ChaCha20-Poly1305 (RFC 8439 § 2.5.2, § 2.8.2), Argon2id (RFC 9106 § 5.3),
   X25519 (RFC 7748 § 5.2);
2. X-Wing test vector 1 of draft-connolly-cfrg-xwing-kem-11 (deterministic ML-KEM encapsulation,
   then decapsulation), ML-KEM implicit rejection and the encapsulation-key check;
3. the order of u(G), unclamped ladder vs. clamped X25519, Elligator 2 and Kemeleon round trips;
4. BIP 350 Bech32m vectors, the key-string rules of § 3.3, the `pk_X` canonicity check of § 3.1,
   identity-file parsing (BOM, CRLF, invalid first identity line), and the `keygen` / usage-error
   exit codes;
5. `cles.json` reproduced exactly from its seeds;
6. every file of `manifeste.json` opened with every listed credential, hidden faces included,
   plaintext SHA-256 checked; a wrong password and a foreign identity (seed 32 × `0xEE`) fail;
7. round trips: password, 1 and 16 keys, empty / 65 536 / 65 537-byte plaintexts, decoy + 1 and
   + 3 hidden faces mixing passwords and keys, a hidden face filling the reserve exactly, tampering,
   "several faces", and the rules (17 recipients, shared password or key, hidden faces too big,
   4 hidden faces, invalid public key);
8. interoperability with the reference binary in both directions (password, key, decoy + 3 hidden
   faces), skipped with a message if the binary is absent.

`--quick` skips opening the 16-key vector with all 16 identities at once.

The cross-implementation test is [`../interop.py`](../interop.py).

## Limitations

- Not constant-time (BigInteger, managed primitives). The decryption still does the work § 8
  requires: one Argon2id, all 16 slots for every identity, all 4 tag comparisons, constant-time
  comparisons and ML-KEM implicit rejection select.
- Not audited; written to check the specification and to interoperate.
- Whole files are held in memory.
- The v0 identity strings (`JANUS-SECRET-V0-…`, appendix A) are not read.
