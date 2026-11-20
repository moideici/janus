# Janus v1 — TypeScript client

An independent implementation of the [Janus v1 format](../../spec/janus-v1.md), written from the specification, not from the Rust code. It opens the reference test vectors, and its files open with the reference implementation (and the reverse).

> **Interoperability client, not for real secrets.** Not audited. **Not constant-time**: JavaScript `bigint` arithmetic (Curve25519, Elligator 2, Kemeleon) and the surrounding code make no timing guarantee. It does the obvious things (`timingSafeEqual` for tag comparisons; always all 16 slots, all identities and all 4 tags, with the same work on success and failure, as § 8 requires), but that is not a side-channel defence.

## Requirements

Node.js with type stripping and the `node:crypto` features below. Developed and tested with **Node.js 26.12**; Argon2id arrived in Node 24.7, and older versions are untested. No dependency, no build step, no download: Node runs the `.ts` files directly (erasable TypeScript syntax only, imports with `.ts` extensions).

## Usage

The common command line of [`clients/README.md`](../README.md):

```
node janus.ts keygen IDENTITY_FILE        create an identity file; print the public key (janus1…)
node janus.ts pubkey IDENTITY_FILE        print the public key of an identity
node janus.ts encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
node janus.ts decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)

RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
```

Example:

```
node janus.ts keygen me.id > me.pub
node janus.ts encrypt vault.janus holidays.zip --pass decoy --hidden diary.txt --to-file me.pub
node janus.ts decrypt vault.janus diary.txt --id me.id
```

Output files (including `keygen`'s identity file) are never overwritten: they are written to a temporary file and renamed, and nothing is written on failure; refusing an existing file exits with status 1. On failure `decrypt` prints `cannot decrypt` (or `these credentials open several faces`) and exits with status 1. Usage errors exit with status 2.

Public keys are rejected if the ML-KEM part fails the FIPS 203 check or if `pk_X` is not canonical (bit 255 set, or ≥ p); a canonical low-order `pk_X` is accepted (§ 3.1). In an identity file, the first `JANUS-SECRET-KEY-1` line decides: if it does not decode, the file is invalid. A UTF-8 BOM, CRLF line ends and surrounding whitespace are accepted (§ 3.3). Passwords on the command line are visible to other local users: for test files only.

## Tests

```
node --test clients/typescript/test.ts      # or: node clients/typescript/test.ts
```

From the repository root (paths are resolved relative to `test.ts`, so any working directory works). The script checks:

1. X-Wing draft-11 test vector 1 (see below), the RFC 7748 X25519 vector, the unclamped ladder and Elligator 2 round trip, Kemeleon round trip;
2. the BIP 350 Bech32m vectors, the rejections of § 3.3 (mixed case, wrong part, checksum, length, padding, invalid ML-KEM key), non-canonical `pk_X` rejected and low-order `pk_X` accepted, identity-file parsing (BOM, CRLF, invalid first identity line);
3. `janus-rs/vecteurs/cles.json`, reproduced exactly;
4. every vector of `manifeste.json` with every credential and every hidden face (plaintext SHA-256), failure with a foreign identity (32 × `0xEE`) and a wrong password, failure on truncated or modified files;
5. round trips: password; 1 and 16 keys; decoy + 1 and + 3 hidden faces mixing passwords and keys; the "several faces" error; empty, 65 535, 65 536, 65 537 and 196 608-byte plaintexts; a hidden face filling the reserve exactly; refused rule violations (17 recipients, a password or key in two faces, hidden faces too big, 4 hidden faces);
6. interoperability with `janus-rs/target/release/janus(.exe)`, both ways, including a decoy with three hidden faces (skipped, with a message, if the binary is absent); and the command line.

The command-line test also checks the refusals to overwrite (status 1) and usage errors (status 2). The whole run takes about 11 s; the vector test about 2 s.

## What comes from where

| From `node:crypto` | Written here (`src/`) |
|---|---|
| ML-KEM-768 key generation from the seed `d ‖ z` (`createPrivateKey` with `format: 'raw-seed'`), encapsulation-key import and check (`format: 'raw-public'`), `encapsulate`, `decapsulate` | Curve25519 field arithmetic, X25519 and the unclamped Montgomery ladder (`curve25519.ts`) |
| Argon2id (`argon2Sync`) | Elligator 2 map and representative (`curve25519.ts`) |
| ChaCha20-Poly1305, HKDF-SHA-256, HMAC-SHA-256, SHA-256, SHA3-256/512, SHAKE128/256 | Kemeleon encoding (`kemeleon.ts`), Bech32m and key strings (`bech32m.ts`) |
| Random bytes, `randomInt`, `timingSafeEqual` | Keys and identity files (`keys.ts`), hidden X-Wing (`xwing.ts`), the format (`format.ts`), the CLI (`janus.ts`) |

`node:crypto` has no derandomized ML-KEM encapsulation, which the X-Wing test vector needs (it fixes the ML-KEM randomness `m`). For that test only, [`src/mlkem-derand.ts`](src/mlkem-derand.ts) implements FIPS 203 `ML-KEM.Encaps_internal`; the test checks that `node:crypto`'s decapsulation agrees with it, then the X-Wing shared secret. Janus itself never uses that file.

## Limitations

- Not constant-time, not audited (see above). Whole files are held in memory.
- Encryption refuses, in addition to rules R1, R3 and R5: more than 3 hidden faces, a face without recipients, and the same public key twice in one face.
- The `JANUS-SECRET-V0-` identities of the preview release (spec, appendix A) are not read.
