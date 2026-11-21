# The Janus v1 file format

**Status:** format candidate for freeze, 19 November 2026. No further change is planned; the format would only change to fix a flaw found by review or audit, and is frozen for good at Janus 1.0. Research prototype: not audited, not for real secrets.

**Reference implementation:** [`janus-rs/`](../janus-rs/) (Rust). **Test vectors:** [`janus-rs/vecteurs/`](../janus-rs/vecteurs/).

**Design rationale and security proofs** (in French): [`docs/`](../docs/). This document is the normative description; where it and the French documents disagree, this document and the test vectors win, and the disagreement is a bug to report.

---

## 1. Overview

Janus encrypts a file to one or more recipients, each given either by a password or by a post-quantum hybrid public key (X-Wing: ML-KEM-768 + X25519). It has three distinguishing properties:

1. **Every byte of a Janus file is indistinguishable from random.** There is no magic number, no version field, no length field and no algorithm identifier. The X25519 ephemeral is hidden with Elligator 2, the ML-KEM ciphertext with Kemeleon, and the file size is randomized.
2. **Recipients are hidden.** Every file has exactly 16 recipient slots, used or not. A third party cannot tell how many recipients there are, nor whether they are passwords or keys.
3. **Several faces.** A file opens on a *decoy* (the main face) with one credential, and on up to three *hidden faces* with other credentials. Every file has the same structure whether or not it contains hidden faces, so someone who holds the decoy credential cannot prove that a hidden face exists.

A file is a fixed-size **header** followed by a **body**:

```
offset        size          content
0             4 × 32        T_0 … T_3    header tags (HMAC-SHA-256)
128           32            salt         shared Argon2id salt
160           16 × 1632     E_0 … E_15   recipient slots
H = 26272     F − H         body         faces, reserve and padding
```

Each face has a 32-byte file key `K`, a start offset `d` and a plaintext length `l`. The triple `(K, d, l)` is wrapped in a slot for each recipient of the face, and bound to the header and to the file size by one tag `T_x`.

## 2. Conventions

- The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119.
- `‖` is concatenation. `0^n` is `n` zero bytes. `BE64(x)` is the 8-byte big-endian encoding of an unsigned integer `x < 2^64`. `byte(i)` is the single byte of value `i`.
- `random(n)` is `n` bytes from a cryptographically secure random generator. "Uniform in `[a, b]`" includes both bounds, and MUST be sampled without bias (e.g. by rejection).
- Strings in quotes, such as `"janus/v1/corps"`, denote their ASCII bytes, without a terminator. The labels are French words; they are part of the format and MUST be used exactly as written.
- `⌈x/y⌉` is integer division rounded up.

### 2.1 Primitives

| Name | Definition |
|---|---|
| `SHA-256`, `HMAC-SHA-256` | FIPS 180-4, RFC 2104 |
| `HKDF(ikm, info)` | HKDF-SHA-256 (RFC 5869) with an absent salt (i.e. 32 zero bytes), output length 32 |
| `SHA3-256`, `SHAKE256(x, n)` | FIPS 202; `SHAKE256(x, n)` is the first `n` bytes of output |
| `AEAD.Seal(k, n, p)` | ChaCha20-Poly1305 (RFC 8439), 32-byte key, 12-byte nonce, empty associated data; output is ciphertext ‖ 16-byte tag |
| `Argon2id(pw, salt)` | Argon2id version `0x13` (RFC 9106), memory 65 536 KiB, 3 passes, parallelism 4, no secret, no associated data, 32-byte output |
| `ML-KEM-768` | FIPS 203, final version (August 2024), not Kyber nor the draft; `Encaps` returns the shared key `ss_M` and the ciphertext `ct_M` |
| `X25519(k, u)` | RFC 7748, including scalar clamping; `u` and the output are 32-byte little-endian |

### 2.2 Constants

| Name | Value | Meaning |
|---|---|---|
| `N_SLOTS` | 16 | recipient slots |
| `N_TAGS` | 4 | header tags, hence faces: one main face and up to 3 hidden faces |
| `S` | 1632 | slot size |
| `H` | 26 272 | header size: `32·N_TAGS + 32 + N_SLOTS·S` |
| `TB` | 65 536 | plaintext block size |
| `R_MIN` | 65 536 | minimum reserve |
| `RHO` | 16 | reserve ratio |

Domain-separation labels:

| Label | Use |
|---|---|
| `"janus/v1/entete"` | header-tag key |
| `"janus/v1/corps"` | body key |
| `"janus/v1/emballage/xwing"` | slot wrapping key, public-key recipient |
| `"janus/v1/emballage/mdp"` | slot wrapping key, password recipient |
| `"janus/v1/masque"` | Kemeleon ciphertext mask |

The `v1` in each label *is* the version number: there is no version field. A future format will use new labels; a v1 reader opening such a file simply fails, as for a file that is not addressed to it.

## 3. Keys

### 3.1 Identity and public key

An **identity** (secret key) is a 32-byte seed. The key pair is derived from it exactly as in X-Wing (`draft-connolly-cfrg-xwing-kem-11`):

```
expanded = SHAKE256(seed, 96)
(ek_M, dk_M) = ML-KEM-768.KeyGen_internal(d = expanded[0:32], z = expanded[32:64])
sk_X = expanded[64:96]
pk_X = X25519(sk_X, 9)
pk   = ek_M ‖ pk_X                       (1184 + 32 = 1216 bytes)
```

A public key MUST be rejected if its ML-KEM part fails the FIPS 203 encapsulation-key check (every coefficient of `ek_M` decodes to a value below `q`), or if `pk_X` is not canonical (bit 255 set, or value ≥ p). KeyGen never produces such a `pk_X`, and the recipient, who combines its own canonical `pk_X`, could not open the file.

### 3.2 X-Wing combiner

```
XWingLabel = 5c 2e 2f 2f 5e 5c                    (the 6 ASCII bytes \.//^\)
Combine(ss_M, ss_X, ct_X, pk_X) = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)
```

This is the X-Wing combiner of draft-11. Janus uses the X-Wing key pair and combiner, but transmits the ciphertext differently (§ 5).

Implementations SHOULD check their key derivation and combiner against test vector 1 of the draft's appendix C. That vector uses the **standard** X-Wing encapsulation (not § 5.2): `m = eseed[0:32]` is the ML-KEM encapsulation randomness, `eseed[32:64]` is a standard (clamped) X25519 ephemeral secret, and `ct = ct_M ‖ ct_X`.

| | Value |
|---|---|
| seed | `7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26` |
| eseed | `3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2` |
| SHA-256(pk), 1216 bytes | `2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb` |
| pk_X | `859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534` |
| SHA-256(ct), 1120 bytes | `17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33` |
| ct_X | `e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15` |
| ss | `d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384` |

A library without deterministic ML-KEM encapsulation can still check the key derivation (SHA-256 of `pk`) and, given the draft's full `ct`, the decapsulation.

Implementations MUST NOT reject a canonical low-order `pk_X`: as in X-Wing, the X25519 secret is then predictable, and the shared secret rests on ML-KEM alone.

### 3.3 Text encoding of keys

Keys are written in **Bech32m** (BIP 350):

| Key | Human-readable part | Case | Data | Length |
|---|---|---|---|---|
| Identity | `JANUS-SECRET-KEY-` | upper | the 32-byte seed | 76 characters |
| Public key | `janus` | lower | the 1216-byte `pk` | 1958 characters |

- Data bytes are converted to 5-bit groups with zero padding, as in BIP 173/350.
- As in BIP 173, the checksum is computed on the **lowercase** form (`janus-secret-key-` for identities); an identity is then written in uppercase.
- The 90-character limit of BIP 173 applies to identities, and is lifted for public keys (as in age).
- Decoders MUST accept either all-lowercase or all-uppercase strings, and MUST reject mixed case, a wrong human-readable part, a wrong checksum, a wrong data length, and non-zero or over-long padding.
- Decoders MUST NOT accept a public key as an identity, or the reverse.
- Implementations SHOULD decode identities without data-dependent table lookups or branches.

These file conventions are for tools, not part of the encrypted format:

- An **identity file** is UTF-8 text. Lines starting with `#` are comments; the first line that starts with `JANUS-SECRET-KEY-1` (any case) is the identity; if that line does not decode, the file is invalid (no later line is tried). The reference tool writes:

  ```
  # Identité Janus (PROTOTYPE). Clé publique :
  # janus1…
  JANUS-SECRET-KEY-1…
  ```
- A **public-key file** has one public key per line; empty lines and lines starting with `#` are ignored.
- Readers SHOULD skip a UTF-8 byte-order mark, accept CRLF line ends, and trim whitespace around each line. The reference tool also reads UTF-16 files with a byte-order mark, which some Windows shells write.

## 4. Passwords

A password is an arbitrary byte string. Text passwords are encoded in UTF-8, exactly as entered; implementations MUST NOT normalize them. The format allows an empty password; tools SHOULD refuse it. All password recipients of a file share the header `salt`; each password is stretched once per opening:

```
A = Argon2id(password, salt)
```

## 5. Slots

A slot is 1632 bytes:

```
offset   size   content
0        32     r       Elligator 2 representative (public-key slots)
32       1536   κ'      masked Kemeleon encoding of ct_M (public-key slots)
1568     64     W       wrapped (K, d, l)
```

In a password slot, and in an unused slot, the first 1568 bytes are random. In an unused slot `W` is random too.

### 5.1 The wrap

For the slot at index `i` (0 ≤ i < 16) and a wrapping key `k_i`:

```
W = AEAD.Seal(k_i, 0^12, K ‖ BE64(d) ‖ BE64(l))          (48 + 16 = 64 bytes)

password recipient:    k_i = HKDF(A,  "janus/v1/emballage/mdp"   ‖ byte(i))
public-key recipient:  k_i = HKDF(ss, "janus/v1/emballage/xwing" ‖ byte(i))
```

The constant nonce is safe because every wrapping key is used once: it depends on the slot index, and on a fresh `ss` or on the fresh `salt`.

### 5.2 Hidden X-Wing encapsulation (sender)

Given the recipient's `pk = ek_M ‖ pk_X`:

1. **Ephemeral point.** Pick a point `P` **uniformly among all points of Curve25519**, in the full group of order `8ℓ` (where ℓ = 2^252 + 27742317777372353535851937790883648493), together with a scalar `s` such that `P = s·G` for a fixed point `G` of order `8ℓ`. Recommended method:
   - `s` uniform in `[0, 8ℓ − 1]`;
   - `u(G) = bb72312170e8156f7a836313f85bee9b1fdce926ba9804a29e8d137ec67f2533` (little-endian; `G` = Ed25519 base point plus a point of order 8);
   - `ct_X = u(P) = Ladder(s, u(G))`, where `Ladder` is the Montgomery ladder of RFC 7748 **without clamping**, run on all 256 bits of `s`: the loop starts at bit 255, not 254 as in the RFC, because `s` can exceed 2^255.

   The reference implementation draws `e` uniform modulo ℓ and adds a uniform point `L` of order dividing 8; the distribution is the same.

   A **clamped** scalar MUST NOT be used: it covers only half of the prime-order subgroup, which an adversary able to compute discrete logarithms can test (docs/04, § 7.1). A point from the prime-order subgroup only MUST NOT be used either: about 7 in 8 random points are not in it, so its representatives would be distinguishable.
2. **Representative.** Compute an Elligator 2 representative `r` of `ct_X` (§ 5.4). If `ct_X` has none (about half the time), go back to step 1.
3. **X25519 secret.** `ss_X = Ladder(s, pk_X)` (again all bits of `s`, no clamping). The recipient computes the same value as `X25519(sk_X, ct_X)`: its clamped scalar is a multiple of 8, which cancels the low-order component of `P`.
4. **ML-KEM.** `(ss_M, ct_M) = ML-KEM-768.Encaps(ek_M)`.
5. **Shared secret.** `ss = Combine(ss_M, ss_X, ct_X, pk_X)`.
6. **Encoding and mask.** `κ = Kemeleon.EncodeCtxt(ct_M)` (§ 5.5), then
   ```
   κ' = κ ⊕ SHAKE256("janus/v1/masque" ‖ ss_X ‖ ct_X, 1536)
   ```
   The mask makes `κ'` pseudorandom if *either* ML-KEM (MLWE) *or* X25519 holds.
7. The slot holds `r ‖ κ' ‖ W`, with `W` wrapped under `HKDF(ss, "janus/v1/emballage/xwing" ‖ byte(i))`.

### 5.3 Hidden X-Wing decapsulation (recipient)

Given a slot and the identity's `dk_M`, `sk_X`, `pk_X`:

```
ct_X = Elligator2.Map(r)                 (§ 5.4)
ss_X = X25519(sk_X, ct_X)
κ    = κ' ⊕ SHAKE256("janus/v1/masque" ‖ ss_X ‖ ct_X, 1536)
ct_M = Kemeleon.DecodeCtxt(κ)            (cannot fail)
ss_M = ML-KEM-768.Decaps(dk_M, ct_M)     (implicit rejection: never fails)
ss   = Combine(ss_M, ss_X, ct_X, pk_X)
```

None of these steps can fail: a slot that is not for this identity yields an unrelated `ss`, and the wrap then fails to open (§ 7).

### 5.4 Elligator 2 on Curve25519

Field `GF(p)`, `p = 2^255 − 19`; Montgomery curve `v² = u³ + A·u² + u` with `A = 486662`. A field element is written as 32 little-endian bytes, canonical (`< p`).

**Map** (decoding; RFC 9380 § 6.7.1 `map_to_curve_elligator2` with `Z = 2`, `u` coordinate only):

```
Map(r32):
    r  = little-endian integer of r32, with bits 254 and 255 cleared
    x1 = −A / (1 + 2·r²)        (1 + 2·r² is never 0: −1/2 is not a square, as p ≡ 5 mod 8)
    if g(x1) = x1³ + A·x1² + x1 is a square (0 counts as a square): u = x1
    else: u = −x1 − A
    return u, as 32 canonical little-endian bytes
```

**Representative** (encoding; Bernstein, Hamburg, Krasnova, Lange 2013):

```
Representative(u):
    den = −2·u·(u + A)
    if den = 0 or den is not a square: no representative
    t   = u or u + A, chosen uniformly at random
    r   = t / sqrt(den)                (either square root)
    if r > (p − 1)/2: r = p − r
    r32 = r as 32 little-endian bytes; set bits 254 and 255 of r32 to two uniform random bits
```

Both choices of `t` give a representative that maps back to `u`: with `t = u + A`, `Map` takes its first branch (`x1 = u`, and `g(u)` is a square because `u` is on the curve); with `t = u`, it takes the second (`x1 = −u − A`, and `g(x1)` is then a non-square because 2 is not a square). The point at infinity has `u = 0` (RFC 7748 convention) and no representative, since `den = 0`. Choosing `t`, the root normalization and the two top bits as above makes `r32` (statistically) uniform over all 2^256 strings when `P` is uniform. These three random choices are REQUIRED for indistinguishability, not for interoperability.

### 5.5 Kemeleon encoding of ML-KEM-768 ciphertexts

This is `draft-irtf-cfrg-kemeleon-02`, default (non-rejecting) variant, with vectors written **big-endian** (the draft leaves the byte order open; Janus v1 fixes it). Parameters: `q = 3329`, `n = 256`, `k = 3`, `d_u = 10`, `d_v = 4`.

`Compress_d`, `Decompress_d`, `ByteEncode_d` and `ByteDecode_d` are those of FIPS 203. In integers, `Compress_d(x) = ⌊(x·2^d + 1664) / q⌋ mod 2^d`. A ciphertext `ct_M` (1088 bytes) is `ByteEncode_10(c_1) ‖ ByteEncode_4(c_2)`, where `c_1` holds 3 × 256 coefficients and `c_2` 256 coefficients.

```
EncodeCtxt(ct_M):                                         (1088 → 1536 bytes)
    parse ct_M into c_1[0..768] (10-bit) and c_2[0..256] (4-bit)
    for every coefficient c (with its d ∈ {10, 4}):
        a = uniform element of { x ∈ [0, q−1] : Compress_d(x) = c }
    split the resulting 1024 values into 4 vectors of 256: u_0, u_1, u_2 (from c_1, in order), v (from c_2)
    return VectorEncode(u_0) ‖ VectorEncode(u_1) ‖ VectorEncode(u_2) ‖ VectorEncode(v)

VectorEncode(a[0..256]):                                  (→ 384 bytes)
    R = Σ_{i=0}^{255} a[i]·q^i
    m = uniform integer in [0, ⌊(2^3072 − 1 − R) / q^256⌋]
    return R + m·q^256, as a 384-byte big-endian integer

DecodeCtxt(κ):                                            (1536 → 1088 bytes, never fails)
    for each 384-byte block j = 0..3, as a big-endian integer R_j:
        a_j[i] = ⌊R_j / q^i⌋ mod q,  for i = 0..255
    c_1 = Compress_10 of a_0, a_1, a_2 (768 values);  c_2 = Compress_4 of a_3
    return ByteEncode_10(c_1) ‖ ByteEncode_4(c_2)
```

Each value of `Compress_10` has 3 or 4 preimages, each value of `Compress_4` 208 or 209. The preimage and `m` MUST be (statistically) uniform; the reference implementation stays within 2^-77 of uniform. `m` is about 77 bits.

## 6. Sizes and layout

### 6.1 Face sizes

```
blocks(l) = max(1, ⌈l / TB⌉)              an empty face still has one block
c(l)      = l + 16·blocks(l)               size of an encrypted face
Reserve(L1) = max(R_MIN, ⌈L1 / RHO⌉)       L1 = plaintext length of the main face
```

### 6.2 File size

```
Ref = H + c(L1) + Reserve(L1)
X   = PADME(Ref)
F   = uniform integer in [X, X + BucketMask(X)]
B   = F − H                                 body size
```

`PADME` is the padding function of Nikitin et al. (2019):

```
PADME(L):
    if L < 2: return L
    E = ⌊log2 L⌋
    S = ⌊log2 E⌋ + 1
    mask = 2^(E − S) − 1
    return (L + mask) & ~mask

BucketMask(X):                              (the same mask, computed on X)
    if X < 2: return 0
    E = ⌊log2 X⌋
    S = ⌊log2 E⌋ + 1
    return 2^(E − S) − 1
```

`F` depends only on the main face. Hidden faces do not change the file size.

The *buckets* `[X, X + BucketMask(X)]` of the values `X` that PADME outputs tile the integers. `F` is drawn uniformly in the bucket of `PADME(Ref)`, so it depends on `L1` only through `PADME(Ref)`: the size leaks exactly what PADME leaks, and its low-order bits stay uniform, so the size carries no padding signature. Readers do not check this rule (any `F` with room for the faces opens), but encryptors MUST follow it. An earlier draft drew `F` uniformly in `[Ref, PADME(Ref)]`, which leaks more, because `F ≥ Ref` bounds `L1` from above: about 0.8 bit more mutual information and 3 to 4 bits more maximal leakage (docs/09, § 1).

### 6.3 Body layout

- The main face (the decoy) starts at body offset `d = 0` and occupies `c(L1)` bytes.
- Hidden faces `j = 1..h` (`h ≤ 3`) MUST satisfy `Σ c(L_j) ≤ Reserve(L1)`.
- Every byte of the body that does not belong to a face is random.

Placement of hidden faces (sender). This procedure is REQUIRED: the positions must not depend on anything but randomness and the main face.

```
free  = B − c(L1) − Σ_j c(L_j)
order = uniform random permutation of the hidden faces
b_1 ≤ … ≤ b_h = h independent uniform integers in [0, free], sorted
placed = 0
for m = 1..h:
    j   = order[m]
    d_j = c(L1) + b_m + placed
    placed = placed + c(L_j)
```

The reader does not need this procedure: each face's `d` and `l` come from its slots.

## 7. Encryption

Inputs: a main face (plaintext of length `L1`, recipients), and up to 3 hidden faces (plaintext, recipients). A face's recipients are **either** one password **or** 1 to 16 public keys.

**Rules.** The numbering follows the design document (docs/03, § 7). R2 and R4 constrain the encryptor's randomness (steps 3 and 5 below); the encryptor MUST refuse inputs that break R1, R3 or R5.
- R1: a password face has exactly one recipient, its password.
- R2: slot positions are drawn at random (step 3).
- R3: at most 16 recipients over all faces, and at most 3 hidden faces.
- R4: tag positions are drawn at random; unused tags stay random (step 5).
- R5: the hidden faces fit in the reserve (§ 6.3); no two faces share a password (compared byte for byte); no public key appears in two faces. Repeating a public key within one face is useless; encryptors SHOULD refuse it.

**Procedure:**

1. Compute `F` (§ 6.2) and the hidden faces' `d_j` (§ 6.3). The main face has `d = 0`.
2. Fill the whole header with random bytes. `salt` = header bytes `[128, 160)`.
3. Choose a uniform random permutation `π` of the 16 slot indices. Take the faces in any fixed order (the reference uses the main face, then the hidden faces in input order), and give each recipient of each face the next index of `π`. Since `π` is random, the order is not observable.
4. For each face, draw `K = random(32)`. For each of its recipients, at slot index `i`:
   - password: write `W` at slot offset 1568, with `k_i` from `A = Argon2id(password, salt)`;
   - public key: run § 5.2 and write `r ‖ κ' ‖ W`.
5. Choose a uniform random permutation `σ` of the 4 tag positions. For face number `f` (0 for the main face), write at offset `32·σ(f)`:
   ```
   T = HMAC-SHA-256(HKDF(K, "janus/v1/entete"), BE64(F) ‖ BE64(d) ‖ BE64(l) ‖ header[128 : H])
   ```
   `header[128 : H]` is the salt and all 16 slots, as written in step 4. Unused tag positions keep their random bytes.
6. Write the header, then the body: each face encrypted as in § 7.1 at offset `d`, with random bytes everywhere else, for a total of exactly `F` bytes.

### 7.1 Face encryption (STREAM)

```
K_body = HKDF(K, "janus/v1/corps")
n = blocks(l); split the plaintext into n blocks P_0 … P_(n−1) of TB bytes; the last one may be shorter, or empty if l = 0
nonce_j = 0^3 ‖ BE64(j) ‖ byte(1 if j = n − 1 else 0)            (12 bytes)
face ciphertext = AEAD.Seal(K_body, nonce_0, P_0) ‖ … ‖ AEAD.Seal(K_body, nonce_(n−1), P_(n−1))
```

The final-block flag prevents truncation; the counter prevents reordering.

## 8. Decryption

Input: a file of `F` bytes, and **either** one password **or** one or more identities. There is a single, uninformative error, "cannot decrypt" (one exception below).

1. If `F < H`: fail. Read the header; `salt = header[128:160]`.
2. **Candidates.** Try every slot, always all 16, even after a success:
   - password: compute `A` once, then for each `i`: `k_i = HKDF(A, "janus/v1/emballage/mdp" ‖ byte(i))`;
   - identities: for each `i` and each identity: decapsulate (§ 5.3), then `k_i = HKDF(ss, "janus/v1/emballage/xwing" ‖ byte(i))`.

   Open `W` with `k_i` and nonce `0^12`. On success, the plaintext is `K ‖ BE64(d) ‖ BE64(l)`; on failure, use 48 zero bytes.
3. **Tags.** For **every** attempt, successful or not, compute
   `T = HMAC-SHA-256(HKDF(K, "janus/v1/entete"), BE64(F) ‖ BE64(d) ‖ BE64(l) ‖ header[128:H])`, where `F` is the **actual size of the file**.
   The attempt is valid if the wrap opened **and** `T` equals one of `T_0 … T_3`. All comparisons MUST be constant-time.
4. **Deduplicate** valid attempts on the full triple `(K, d, l)`, not on `K` alone.
   - 0 distinct triples: fail.
   - More than 1: fail with a distinct error, "these credentials open several faces". Only someone who holds several faces' credentials, or who opens a maliciously built file, can trigger it.
   - Exactly 1: continue with `(K, d, l)`.
5. **Bounds.** Let `n = blocks(l)`. Require `d + l + 16·n ≤ F − H` (that is, `d + c(l) ≤ B`), computed without overflow. Otherwise fail.
6. **Body.** Decrypt the `n` blocks at file offset `H + d` (§ 7.1, same nonces). Any block failing authentication fails the whole decryption.
7. Output the plaintext (`l` bytes).

**Requirements:**
- An implementation that streams plaintext before the last block is verified MUST make the caller discard all output on failure. The reference CLI writes to a temporary file, or decrypts fully in memory, and releases nothing on failure.
- The work of steps 2 to 4 MUST NOT depend on which slot or tag matched, or on whether any did: same Argon2id, same 16 attempts, same MACs.
- Bytes outside the opened face are not authenticated by that face. In particular, overwriting the reserve does not affect the decoy, but destroys hidden faces (this is intended; docs/03, pitfall 10.9).

## 9. Security properties (summary)

The proofs are on paper, in French, and have not been reviewed:

| Property | Notion | Assumptions | Document |
|---|---|---|---|
| Confidentiality, indistinguishability from random, deniability of hidden faces | IND$, DENI | MLWE **or** gap-DH; Elligator 2 statistical; random oracles | docs/04 |
| The hidden KEM (§ 5.2–5.3), at the level of decoded ciphertexts | IND-CCA, **machine-checked** with CryptoVerif (`preuves/cryptoverif/`) | (IND-CCA2 of ML-KEM and SHA3-256 as a PRF keyed by `ss_M`) **or** (gap-DH and C2PRI of ML-KEM) | docs/09 |
| Key commitment (at most 4 keys per file), per-face integrity and consistency, at most 4 passwords tested per partition-oracle query | collisions, INT-CTXT | SHA-256, HMAC, ChaCha20-Poly1305 | docs/05 |
| Active confidentiality | IND-RCCA (strict IND-CCA is impossible with several tags) | the above, plus IND-CCA of ML-KEM **or** gap-DH | docs/06 |
| File size | leaks exactly what PADME leaks | none (information-theoretic) | docs/09 |

**Against quantum adversaries** (docs/09, § 3), the ML-KEM path of every proof holds in the standard model, without random oracles, assuming IND-CCA of ML-KEM, MLWE, SHA3-256 as a PRF keyed by `ss_M`, and HMAC-SHA-256 as a PRF and dual PRF. Password faces rely on Argon2id as a random oracle: against a quantum adversary, a password of `h` bits of entropy is worth about `h/2` bits.

Known limitations:
- Different recipients of one file can be shown different contents, one per tag. Comparing ciphertext hashes does not prove two people read the same plaintext; compare plaintext hashes.
- Deniability does not cover traces left by the operating system or by keeping several versions of a file.
- Implementations in languages without constant-time guarantees (the non-Rust clients) are for interoperability, not for protecting real secrets.

## 10. Test vectors

`janus-rs/vecteurs/manifeste.json` lists one entry per file:

| Field | Meaning |
|---|---|
| `format`, `clair`, `graines` (top level) | free-text reminders, in French, of the format and of the plaintext and seed rules below |
| `nom` | vector name |
| `fichier`, `taille`, `sha256_fichier` | file name, size, SHA-256 |
| `ouverture.type` | `mot_de_passe` (password, in `valeur`) or `identites` (each seed in `chacune_ouvre` opens the file) |
| `ouverture.visages_caches` | hidden faces, each opened by a password (`mot_de_passe`) or by the identity whose seed is `identite` (hex); with `clair_longueur` and `sha256_clair` |
| `ouverture.plusieurs_visages` | seeds (hex) of identities that, given **together**, must make opening fail with the "several faces" error of § 8, step 4 |
| `clair_longueur`, `sha256_clair` | main-face plaintext length and SHA-256 |

Plaintexts: main face byte `k` = `(31·k + 7) mod 256`; hidden face number `j` (from 0) byte `k` = `(17·k + 3 + 50·j) mod 256`. Seeds: recipient `i` (from 0) has the seed of 32 bytes equal to `i + 1`. The vector `visages-cles` has a decoy for two keys, a hidden face for a third key and a hidden face for a password. An implementation MUST open every vector with every listed credential, MUST fail on each with a foreign identity (for instance the seed of 32 bytes equal to 0xEE) and with a wrong password, and its own files MUST open with the reference implementation.

`janus-rs/vecteurs/cles.json` lists, under `cles`, three entries with the fields `graine` (seed, hex), `description`, `identite` (expected identity string), `cle_publique` (expected public-key string) and `cle_publique_hex_sha256` (SHA-256 of the 1216-byte public key).

## Appendix A. Changes from earlier drafts

- Before 21 November 2026, encryptors drew `F` uniformly in `[Ref, PADME(Ref)]` (§ 6.2). Such files still open.
- The preview release v0.1.0-alpha used 2 tags (`H = 26 208`) and base64 key encoding. Its files do not open with this format. Its identity strings (`JANUS-SECRET-V0-` followed by base64url(seed ‖ SHA-256(prefix ‖ seed)[0:4])) MAY still be read until 1.0; the key pair is the same.
