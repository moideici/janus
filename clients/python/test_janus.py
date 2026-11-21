#!/usr/bin/env python3
"""Tests of the Python Janus v1 client. Run:  python clients/python/test_janus.py

Only unittest and the `cryptography` package are needed. The interoperability tests
with the Rust reference binary are skipped if janus-rs/target/release/janus(.exe) is absent.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from janus_py import (  # noqa: E402
    CannotDecrypt,
    EncryptionRuleError,
    Face,
    Identity,
    Password,
    SeveralFaces,
    decode_identity,
    decode_public_key,
    decrypt,
    encode_identity,
    encode_public_key,
    encrypt,
)
from janus_py import bech32m, container, curve25519, kemeleon, keys, xwing  # noqa: E402

ROOT = HERE.parent.parent
VECTORS = ROOT / "janus-rs" / "vecteurs"
RUST = ROOT / "janus-rs" / "target" / "release" / ("janus.exe" if os.name == "nt" else "janus")
CLI = [sys.executable, str(HERE / "janus.py")]


def main_plaintext(n: int) -> bytes:
    return bytes((31 * k + 7) % 256 for k in range(n))


def hidden_plaintext(j: int, n: int) -> bytes:
    return bytes((17 * k + 3 + 50 * j) % 256 for k in range(n))


def seed(i: int) -> bytes:
    return bytes([i + 1]) * 32


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# =========================================================================== ML-KEM-768, deterministic
# The `cryptography` package only offers randomized encapsulation. To check X-Wing
# test vector 1 completely, this minimal FIPS 203 Encaps_internal(ek, m) computes
# the ciphertext from the vector's eseed; the library then decapsulates it.

Q = 3329


def _bitrev7(i: int) -> int:
    return int(f"{i:07b}"[::-1], 2)


ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def _ntt(f):
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = z * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def _intt(f):
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = z * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def _mul_ntt(f, g):
    h = [0] * 256
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def _add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def _sample_ntt(seed34: bytes):
    stream = hashlib.shake_128(seed34).digest(1344)
    out, pos = [], 0
    while len(out) < 256:
        if pos + 3 > len(stream):
            stream = hashlib.shake_128(seed34).digest(2 * len(stream))
        c0, c1, c2 = stream[pos : pos + 3]
        pos += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = c1 // 16 + 16 * c2
        if d1 < Q:
            out.append(d1)
        if d2 < Q and len(out) < 256:
            out.append(d2)
    return out


def _cbd2(b: bytes):
    bits = int.from_bytes(b, "little")
    f = []
    for i in range(256):
        x = ((bits >> (4 * i)) & 1) + ((bits >> (4 * i + 1)) & 1)
        y = ((bits >> (4 * i + 2)) & 1) + ((bits >> (4 * i + 3)) & 1)
        f.append((x - y) % Q)
    return f


def mlkem768_encaps_derand(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """FIPS 203 ML-KEM.Encaps_internal for ML-KEM-768: return (ss, ct)."""
    g = hashlib.sha3_512(m + hashlib.sha3_256(ek).digest()).digest()
    ss, r = g[:32], g[32:]
    t_hat = [kemeleon_decode12(ek[384 * i : 384 * (i + 1)]) for i in range(3)]
    rho = ek[1152:1184]
    a_hat = [[_sample_ntt(rho + bytes([j, i])) for j in range(3)] for i in range(3)]
    prf = lambda n: hashlib.shake_256(r + bytes([n])).digest(128)  # noqa: E731
    y = [_cbd2(prf(i)) for i in range(3)]
    e1 = [_cbd2(prf(3 + i)) for i in range(3)]
    e2 = _cbd2(prf(6))
    y_hat = [_ntt(p) for p in y]
    u = []
    for i in range(3):
        acc = [0] * 256
        for j in range(3):
            acc = _add(acc, _mul_ntt(a_hat[j][i], y_hat[j]))
        u.append(_add(_intt(acc), e1[i]))
    acc = [0] * 256
    for j in range(3):
        acc = _add(acc, _mul_ntt(t_hat[j], y_hat[j]))
    mu = [((m[i // 8] >> (i % 8)) & 1) * 1665 for i in range(256)]
    v = _add(_add(_intt(acc), e2), mu)
    c1 = kemeleon.byte_encode([kemeleon.compress(x, 10) for p in u for x in p], 10)
    c2 = kemeleon.byte_encode([kemeleon.compress(x, 4) for x in v], 4)
    return ss, c1 + c2


def kemeleon_decode12(b: bytes):
    v = int.from_bytes(b, "little")
    return [(v >> (12 * i)) & 0xFFF for i in range(256)]


# =========================================================================== 1. primitives

class TestXWing(unittest.TestCase):
    SEED = bytes.fromhex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    ESEED = bytes.fromhex(
        "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
        "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
    )
    SS = "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384"

    def test_draft11_vector1(self):
        ident = Identity(self.SEED)
        pk = ident.public_key
        # Deterministic standard X-Wing encapsulation.
        ss_m, ct_m = mlkem768_encaps_derand(pk.ek_m, self.ESEED[:32])
        ek_x = self.ESEED[32:]
        base = curve25519.encode_u(9)
        ct_x = curve25519.x25519(ek_x, base)
        ss_x = curve25519.x25519(ek_x, pk.pk_x)
        self.assertEqual(xwing.combine(ss_m, ss_x, ct_x, pk.pk_x).hex(), self.SS)
        # Decapsulation side: library ML-KEM and our X25519.
        self.assertEqual(ident.decapsulate_ml_kem(ct_m), ss_m)
        self.assertEqual(curve25519.x25519(ident.sk_x, ct_x), ss_x)
        self.assertEqual(xwing.combine(ident.decapsulate_ml_kem(ct_m), curve25519.x25519(ident.sk_x, ct_x),
                                       ct_x, ident.pk_x).hex(), self.SS)

    def test_deterministic_mlkem_matches_library(self):
        ident = Identity(secrets.token_bytes(32))
        m = secrets.token_bytes(32)
        ss, ct = mlkem768_encaps_derand(ident.public_key.ek_m, m)
        self.assertEqual(ident.decapsulate_ml_kem(ct), ss)

    def test_x25519_matches_library(self):
        for _ in range(5):
            a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
            raw_a = a.private_bytes_raw()
            pub_b = b.public_key().public_bytes_raw()
            self.assertEqual(curve25519.x25519(raw_a, pub_b), a.exchange(b.public_key()))

    def test_rfc7748_vector(self):
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(curve25519.x25519(k, u).hex(),
                         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    def test_generator_of_full_group(self):
        g = curve25519.U_G
        self.assertEqual(curve25519.ladder(8, g), curve25519.ladder(8, 9))  # 8G = 8B
        self.assertEqual(curve25519.ladder(curve25519.FULL_ORDER, g), 0)
        self.assertNotEqual(curve25519.ladder(curve25519.ELL, g), 0)  # order 8 component
        self.assertNotEqual(curve25519.ladder(4 * curve25519.ELL, g), 1)

    def test_hidden_x25519_agreement(self):
        ident = Identity(secrets.token_bytes(32))
        for _ in range(8):
            s, ct_x, r = curve25519.hidden_ephemeral()
            self.assertEqual(curve25519.elligator2_map(r), ct_x)
            sender = curve25519.encode_u(curve25519.ladder(s, curve25519.decode_u(ident.pk_x)))
            self.assertEqual(sender, curve25519.x25519(ident.sk_x, ct_x))

    def test_hidden_encapsulation_roundtrip(self):
        ident = Identity(secrets.token_bytes(32))
        ss, r, kappa = xwing.hidden_encapsulate(ident.public_key)
        self.assertEqual(xwing.hidden_decapsulate(ident, curve25519.elligator2_map(r), kappa), ss)
        other = Identity(secrets.token_bytes(32))
        self.assertNotEqual(xwing.hidden_decapsulate(other, curve25519.elligator2_map(r), kappa), ss)

    def test_representative_top_bits_vary(self):
        tops = {curve25519.hidden_ephemeral()[2][31] >> 6 for _ in range(40)}
        self.assertGreater(len(tops), 1)

    def test_kemeleon(self):
        for d, lo, hi in ((10, 3, 4), (4, 208, 209)):
            self.assertEqual({len(p) for p in kemeleon.PREIMAGES[d]}, {lo, hi})
        ident = Identity(secrets.token_bytes(32))
        _, ct = xwing.MLKEM768PublicKey.from_public_bytes(ident.public_key.ek_m).encapsulate()
        enc = kemeleon.encode_ctxt(ct)
        self.assertEqual(len(enc), 1536)
        self.assertEqual(kemeleon.decode_ctxt(enc), ct)
        self.assertNotEqual(kemeleon.encode_ctxt(ct), enc)  # randomized
        self.assertEqual(len(kemeleon.decode_ctxt(secrets.token_bytes(1536))), 1088)

    def test_public_key_check(self):
        raw = bytearray(Identity(seed(0)).public_key.raw)
        raw[0], raw[1] = 0xFF, 0x0F  # first coefficient = 4095 >= q
        with self.assertRaises(ValueError):
            xwing.PublicKey(bytes(raw))

    def test_public_key_pk_x_canonical(self):
        ek_m = Identity(seed(0)).public_key.ek_m
        p = curve25519.P
        # Non-canonical pk_X: bit 255 set, or a value >= p.
        for bad in (Identity(seed(0)).pk_x[:31] + bytes([Identity(seed(0)).pk_x[31] | 0x80]),
                    p.to_bytes(32, "little"), (p + 5).to_bytes(32, "little"), b"\xff" * 32):
            with self.assertRaises(ValueError):
                xwing.PublicKey(ek_m + bad)
            with self.assertRaises(keys.KeyFormatError):
                decode_public_key(bech32m.encode("janus", bech32m.to_5bit(ek_m + bad)))
        # Canonical values are accepted, low-order points included (0, 1, an order-8 point, p - 1).
        order8 = 325606250916557431795983626356110631294008115727848805560023387167927233504
        for good in (0, 1, order8, p - 1):
            pk = xwing.PublicKey(ek_m + good.to_bytes(32, "little"))
            self.assertEqual(decode_public_key(encode_public_key(pk)).raw, pk.raw)
            encrypt(Face(b"x", [pk]))  # encryption to it still works


class TestBech32m(unittest.TestCase):
    def test_valid(self):
        for s in ["A1LQFN3A", "a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa",
                  "split1checkupstagehandshakeupstreamerranterredcaperredlc445v"]:
            hrp, data = bech32m.decode(s)
            self.assertEqual(bech32m.encode(hrp, data), s.lower())

    def test_invalid(self):
        for s in ["a12uel5l", "A1lqfn3a", "A1G7SGD8", "1qzzfhee", "x1b4n0q5v", "li1dgmt3", "de1lg7wt\xff",
                  "A1LQFN3", "qyrz8wqd2c9m"]:
            with self.assertRaises(bech32m.Bech32Error, msg=s):
                bech32m.decode(s)

    def test_key_strictness(self):
        ident = Identity(seed(0))
        sid = encode_identity(ident)
        spk = encode_public_key(ident.public_key)
        self.assertEqual(len(sid), 76)
        self.assertEqual(len(spk), 1958)
        self.assertEqual(decode_identity(sid.lower()).seed, ident.seed)
        self.assertEqual(decode_public_key(spk.upper()).raw, ident.public_key.raw)
        with self.assertRaises(keys.KeyFormatError):
            decode_identity(spk)
        with self.assertRaises(keys.KeyFormatError):
            decode_public_key(sid)
        with self.assertRaises(keys.KeyFormatError):
            decode_identity(sid[:20] + sid[20:].lower())  # mixed case
        bad = sid[:-1] + ("Q" if sid[-1] != "Q" else "P")
        with self.assertRaises(keys.KeyFormatError):
            decode_identity(bad)
        # Wrong data length: 31 bytes under the identity prefix.
        short = bech32m.encode("JANUS-SECRET-KEY-", bech32m.to_5bit(bytes(31))).upper()
        with self.assertRaises(keys.KeyFormatError):
            decode_identity(short)
        # Non-zero padding: 52 groups carry 260 bits for 256; set a padding bit.
        data5 = bech32m.to_5bit(bytes(32))
        data5[-1] |= 1
        with self.assertRaises(keys.KeyFormatError):
            decode_identity(bech32m.encode("JANUS-SECRET-KEY-", data5).upper())
        # Over-long padding: one extra zero group.
        with self.assertRaises(keys.KeyFormatError):
            decode_identity(bech32m.encode("JANUS-SECRET-KEY-", bech32m.to_5bit(bytes(32)) + [0]).upper())

    def test_identity_file(self):
        ident = Identity(seed(2))
        text = "# comment\r\n#JANUS-SECRET-KEY-1 not this one\r\n\r\n" + encode_identity(ident).lower() + "\r\n"
        self.assertEqual(keys.parse_identity_file(text).seed, ident.seed)
        self.assertEqual(keys.parse_identity_file(keys.identity_file_text(ident)).seed, ident.seed)
        # UTF-8 BOM, CRLF and surrounding whitespace.
        raw = ("﻿# c\r\n   " + encode_identity(ident) + " \t\r\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "id.key"
            f.write_bytes(raw)
            self.assertEqual(keys.read_identity_file(f).seed, ident.seed)
        self.assertEqual(keys.parse_identity_file(raw.decode("utf-8")).seed, ident.seed)

    def test_identity_file_first_line_only(self):
        good = encode_identity(Identity(seed(1)))
        bad = good[:-1] + ("Q" if good[-1] != "Q" else "P")  # wrong checksum
        with self.assertRaises(keys.KeyFormatError):
            keys.parse_identity_file(f"# c\n{bad}\n{good}\n")
        with self.assertRaises(keys.KeyFormatError):
            keys.parse_identity_file(f"janus-secret-key-1zzz\n{good}\n")


# =========================================================================== 2-3. reference vectors

class TestReferenceVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((VECTORS / "manifeste.json").read_text(encoding="utf-8"))
        cls.keys = json.loads((VECTORS / "cles.json").read_text(encoding="utf-8"))

    def test_cles_json(self):
        for c in self.keys["cles"]:
            ident = Identity(bytes.fromhex(c["graine"]))
            self.assertEqual(encode_identity(ident), c["identite"])
            self.assertEqual(encode_public_key(ident.public_key), c["cle_publique"])
            self.assertEqual(sha256(ident.public_key.raw), c["cle_publique_hex_sha256"])
            self.assertEqual(decode_identity(c["identite"]).seed, ident.seed)
            self.assertEqual(decode_public_key(c["cle_publique"]).raw, ident.public_key.raw)

    # Every field of the manifest is handled explicitly: an unknown one fails the test
    # instead of being silently skipped.
    VECTOR_KEYS = {"nom", "fichier", "taille", "sha256_fichier", "ouverture", "clair_longueur", "sha256_clair"}
    OPENING_KEYS = {
        "mot_de_passe": {"type", "valeur", "visages_caches", "plusieurs_visages"},
        "identites": {"type", "chacune_ouvre", "visages_caches", "plusieurs_visages"},
    }
    HIDDEN_KEYS = {"clair", "clair_longueur", "sha256_clair"}
    HIDDEN_CREDENTIALS = {"mot_de_passe", "identite"}

    def _open_hidden(self, data: bytes, j: int, h: dict) -> None:
        self.assertLessEqual(set(h), self.HIDDEN_KEYS | self.HIDDEN_CREDENTIALS, f"unknown hidden-face field: {h}")
        kinds = set(h) & self.HIDDEN_CREDENTIALS
        self.assertEqual(len(kinds), 1, f"a hidden face needs exactly one credential: {h}")
        if "mot_de_passe" in kinds:
            plain = decrypt(data, password=h["mot_de_passe"].encode())
        else:
            plain = decrypt(data, identities=[Identity(bytes.fromhex(h["identite"]))])
        self.assertEqual(sha256(plain), h["sha256_clair"])
        self.assertEqual(plain, hidden_plaintext(j, h["clair_longueur"]))

    def test_manifest(self):
        t0 = time.time()
        foreign = Identity(b"\xee" * 32)
        seen = {"key hidden face": 0, "password hidden face": 0, "several faces": 0}
        for v in self.manifest["vecteurs"]:
            with self.subTest(v["nom"]):
                self.assertLessEqual(set(v), self.VECTOR_KEYS, f"unknown vector field in {v['nom']}")
                data = (VECTORS / v["fichier"]).read_bytes()
                self.assertEqual(len(data), v["taille"])
                self.assertEqual(sha256(data), v["sha256_fichier"])
                o = v["ouverture"]
                self.assertIn(o["type"], self.OPENING_KEYS, f"unknown opening type in {v['nom']}")
                self.assertLessEqual(set(o), self.OPENING_KEYS[o["type"]], f"unknown opening field in {v['nom']}")
                # Main face.
                if o["type"] == "mot_de_passe":
                    plain = decrypt(data, password=o["valeur"].encode())
                    self.assertEqual(sha256(plain), v["sha256_clair"])
                    self.assertEqual(plain, main_plaintext(v["clair_longueur"]))
                else:
                    self.assertTrue(o["chacune_ouvre"])
                    for s in o["chacune_ouvre"]:
                        plain = decrypt(data, identities=[Identity(bytes.fromhex(s))])
                        self.assertEqual(sha256(plain), v["sha256_clair"])
                        self.assertEqual(plain, main_plaintext(v["clair_longueur"]))
                    # Several identities of the same face still give one triple.
                    if len(o["chacune_ouvre"]) > 1:
                        ids = [Identity(bytes.fromhex(s)) for s in o["chacune_ouvre"][:3]]
                        self.assertEqual(sha256(decrypt(data, identities=ids)), v["sha256_clair"])
                # Hidden faces.
                for j, h in enumerate(o.get("visages_caches", [])):
                    self._open_hidden(data, j, h)
                    seen["key hidden face" if "identite" in h else "password hidden face"] += 1
                # Identities that open different faces, given together.
                if "plusieurs_visages" in o:
                    ids = [Identity(bytes.fromhex(s)) for s in o["plusieurs_visages"]]
                    self.assertGreater(len(ids), 1)
                    with self.assertRaises(SeveralFaces):
                        decrypt(data, identities=ids)
                    seen["several faces"] += 1
                with self.assertRaises(CannotDecrypt):
                    decrypt(data, identities=[foreign])
                with self.assertRaises(CannotDecrypt):
                    decrypt(data, password=b"wrong password")
        # The manifest exercises each kind of check at least once.
        for kind, n in seen.items():
            self.assertGreater(n, 0, f"no vector covers: {kind}")
        print(f"\n  [vectors opened in {time.time() - t0:.2f} s]", end=" ", file=sys.stderr)

    def test_tampering_fails(self):
        data = bytearray((VECTORS / "deux-blocs.janus").read_bytes())
        ident = Identity(seed(0))
        cut = bytes(data[:-1])
        with self.assertRaises(CannotDecrypt):
            decrypt(cut, identities=[ident])  # the size is in the tags
        data[container.H + 100] ^= 1
        with self.assertRaises(CannotDecrypt):
            decrypt(bytes(data), identities=[ident])
        with self.assertRaises(CannotDecrypt):
            decrypt(bytes(container.H - 1), password=b"x")


# =========================================================================== 4. own files

class TestRoundTrips(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ids = [Identity(seed(i)) for i in range(17)]

    def check_size(self, data: bytes, l1: int):
        ref = container.H + container.face_size(l1) + container.reserve(l1)
        x = container.padme(ref)  # spec § 6.2: F lies in the PADME bucket of Ref
        self.assertTrue(x <= len(data) <= x + container.bucket_mask(x))

    def test_password(self):
        f = encrypt(Face(b"hello", [Password(b"pw")]))
        self.check_size(f, 5)
        self.assertEqual(decrypt(f, password=b"pw"), b"hello")
        with self.assertRaises(CannotDecrypt):
            decrypt(f, password=b"pW")
        with self.assertRaises(CannotDecrypt):
            decrypt(f, identities=[self.ids[0]])

    def test_unicode_password(self):
        pw = "mot de passe é".encode()
        f = encrypt(Face(b"x", [Password(pw)]))
        self.assertEqual(decrypt(f, password=pw), b"x")
        with self.assertRaises(CannotDecrypt):
            decrypt(f, password="mot de passe é".encode())  # no normalization

    def test_one_and_sixteen_keys(self):
        f = encrypt(Face(b"one key", [self.ids[0].public_key]))
        self.assertEqual(decrypt(f, identities=[self.ids[0]]), b"one key")
        with self.assertRaises(CannotDecrypt):
            decrypt(f, identities=[self.ids[1]])
        f = encrypt(Face(b"sixteen", [i.public_key for i in self.ids[:16]]))
        for i in self.ids[:16]:
            self.assertEqual(decrypt(f, identities=[i]), b"sixteen")
        self.assertEqual(decrypt(f, identities=self.ids[:16]), b"sixteen")
        with self.assertRaises(CannotDecrypt):
            decrypt(f, identities=[self.ids[16]])

    def test_hidden_faces(self):
        decoy = main_plaintext(3000)
        h = [hidden_plaintext(j, 500 + 100 * j) for j in range(3)]
        f = encrypt(Face(decoy, [Password(b"decoy")]), [Face(h[0], [self.ids[0].public_key])])
        self.check_size(f, len(decoy))
        self.assertEqual(decrypt(f, password=b"decoy"), decoy)
        self.assertEqual(decrypt(f, identities=[self.ids[0]]), h[0])
        f = encrypt(
            Face(decoy, [self.ids[0].public_key, self.ids[1].public_key]),
            [Face(h[0], [Password(b"one")]), Face(h[1], [self.ids[2].public_key]), Face(h[2], [Password(b"three")])],
        )
        self.check_size(f, len(decoy))
        self.assertEqual(decrypt(f, identities=[self.ids[1]]), decoy)
        self.assertEqual(decrypt(f, password=b"one"), h[0])
        self.assertEqual(decrypt(f, identities=[self.ids[2]]), h[1])
        self.assertEqual(decrypt(f, password=b"three"), h[2])
        with self.assertRaises(SeveralFaces):
            decrypt(f, identities=[self.ids[0], self.ids[2]])

    def test_hidden_faces_fill_reserve(self):
        # Two hidden faces of exactly half the reserve each: no free space.
        half = container.R_MIN // 2 - 16
        h = [hidden_plaintext(0, half), hidden_plaintext(1, half)]
        f = encrypt(Face(b"", [Password(b"a")]), [Face(h[0], [Password(b"b")]), Face(h[1], [Password(b"c")])])
        self.assertEqual(decrypt(f, password=b"b"), h[0])
        self.assertEqual(decrypt(f, password=b"c"), h[1])

    def test_sizes(self):
        for n in (0, 1, 65535, 65536, 65537, 200_000):
            with self.subTest(n=n):
                p = main_plaintext(n)
                f = encrypt(Face(p, [self.ids[0].public_key]))
                self.check_size(f, n)
                self.assertEqual(decrypt(f, identities=[self.ids[0]]), p)

    def test_padme(self):
        self.assertEqual(container.padme(91837), 92160)
        self.assertEqual(container.padme(1), 1)
        self.assertEqual(container.padme(4), 4)
        self.assertEqual(container.padme(9), 10)

    def test_rules(self):
        pk = [i.public_key for i in self.ids]
        with self.assertRaises(EncryptionRuleError):  # R3: 17 recipients
            encrypt(Face(b"x", pk[:17]))
        with self.assertRaises(EncryptionRuleError):  # R3, over several faces
            encrypt(Face(b"x", pk[:10]), [Face(b"y", pk[10:17])])
        with self.assertRaises(EncryptionRuleError):  # R5: same password in two faces
            encrypt(Face(b"x", [Password(b"p")]), [Face(b"y", [Password(b"p")])])
        with self.assertRaises(EncryptionRuleError):  # R5: same key in two faces
            encrypt(Face(b"x", [pk[0]]), [Face(b"y", [pk[0]])])
        with self.assertRaises(EncryptionRuleError):  # R5: hidden faces too big
            encrypt(Face(b"x", [Password(b"a")]), [Face(bytes(container.R_MIN - 15), [Password(b"b")])])
        with self.assertRaises(EncryptionRuleError):  # R5: together too big
            encrypt(Face(b"x", [Password(b"a")]),
                    [Face(bytes(40000), [Password(b"b")]), Face(bytes(40000), [Password(b"c")])])
        with self.assertRaises(EncryptionRuleError):  # 4 hidden faces
            encrypt(Face(b"x", [Password(b"a")]), [Face(b"y", [Password(bytes([i]))]) for i in range(4)])
        with self.assertRaises(EncryptionRuleError):  # R1: password and key in one face
            encrypt(Face(b"x", [Password(b"a"), pk[0]]))
        with self.assertRaises(EncryptionRuleError):  # R1: two passwords in one face
            encrypt(Face(b"x", [Password(b"a"), Password(b"b")]))
        with self.assertRaises(EncryptionRuleError):  # no recipient
            encrypt(Face(b"x", []))
        # At the limit: exactly the reserve, 16 recipients over all faces.
        f = encrypt(Face(b"x", pk[:13]), [Face(bytes(container.R_MIN - 16), pk[13:16])])
        self.assertEqual(decrypt(f, identities=[self.ids[14]]), bytes(container.R_MIN - 16))


# =========================================================================== command line

class TestCli(unittest.TestCase):
    def run_cli(self, *args, code=0):
        r = subprocess.run(CLI + [str(a) for a in args], capture_output=True, timeout=300)
        self.assertEqual(r.returncode, code, r.stderr.decode(errors="replace"))
        return r

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            idf = d / "me.key"
            pk = self.run_cli("keygen", idf).stdout.decode().strip()
            self.assertTrue(pk.startswith("janus1"))
            self.assertEqual(self.run_cli("pubkey", idf).stdout.decode().strip(), pk)
            (d / "keys.txt").write_text(f"# my keys\n{pk}\n")
            (d / "a").write_bytes(b"decoy" * 1000)
            (d / "b").write_bytes(b"secret")
            self.run_cli("encrypt", d / "f", d / "a", "--pass", "x", "--hidden", d / "b", "--to-file", d / "keys.txt")
            self.run_cli("decrypt", d / "f", d / "o1", "--pass", "x")
            self.assertEqual((d / "o1").read_bytes(), b"decoy" * 1000)
            self.run_cli("decrypt", d / "f", d / "o2", "--id", idf)
            self.assertEqual((d / "o2").read_bytes(), b"secret")
            r = self.run_cli("decrypt", d / "f", d / "o3", "--pass", "y", code=1)
            self.assertIn(b"cannot decrypt", r.stderr)
            self.assertFalse((d / "o3").exists())
            self.run_cli("encrypt", d / "g", d / "a", "--to", pk, "--hidden", d / "b", "--pass", "x")
            self.run_cli("encrypt", d / "h", d / "a", "--pass", "x", "--hidden", d / "b", "--pass", "x", code=2)
            self.assertFalse((d / "h").exists())

    def test_cli_refusals_and_usage(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            idf = d / "me.key"
            self.run_cli("keygen", idf)
            before = idf.read_bytes()
            r = self.run_cli("keygen", idf, code=2)  # never overwrites
            self.assertEqual(r.stdout, b"")
            self.assertEqual(idf.read_bytes(), before)
            (d / "a").write_bytes(b"a")
            (d / "exists").write_bytes(b"keep")
            self.run_cli("encrypt", d / "exists", d / "a", "--pass", "x", code=2)
            self.assertEqual((d / "exists").read_bytes(), b"keep")
            self.run_cli("encrypt", d / "f", d / "a", "--pass", "x")
            self.run_cli("decrypt", d / "f", d / "exists", "--pass", "x", code=2)
            self.assertEqual((d / "exists").read_bytes(), b"keep")
            # Usage errors: status 2.
            self.run_cli(code=2)
            self.run_cli("frobnicate", code=2)
            self.run_cli("keygen", code=2)
            self.run_cli("decrypt", d / "f", d / "o", code=2)
            self.run_cli("decrypt", d / "f", d / "o", "--pass", "x", "--id", idf, code=2)
            self.run_cli("decrypt", d / "f", d / "o", "--bogus", "x", code=2)
            self.run_cli("encrypt", d / "g", d / "a", code=2)
            self.run_cli("encrypt", d / "g", d / "a", "--to", code=2)
            self.assertFalse((d / "o").exists())
            self.assertFalse((d / "g").exists())


# =========================================================================== 5. interoperability with Rust

@unittest.skipUnless(RUST.exists(), f"reference binary not found ({RUST}): build janus-rs in release mode")
class TestRustInterop(unittest.TestCase):
    def rust(self, *args, env=None, code=0):
        e = dict(os.environ)
        e.update(env or {})
        r = subprocess.run([str(RUST)] + [str(a) for a in args], capture_output=True, env=e, timeout=300)
        self.assertEqual(r.returncode, code, r.stderr.decode(errors="replace"))
        return r

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_python_to_rust(self):
        d = self.d
        ident = Identity(secrets.token_bytes(32))
        idf = d / "py.key"
        idf.write_text(keys.identity_file_text(ident), encoding="utf-8")
        decoy, h = main_plaintext(70_000), [hidden_plaintext(j, 900 * (j + 1)) for j in range(3)]
        # Password.
        (d / "p.janus").write_bytes(encrypt(Face(decoy, [Password("mot de passe é".encode())])))
        self.rust("dechiffrer", "-m", d / "p.janus", d / "p.out", env={"JANUS_MDP": "mot de passe é"})
        self.assertEqual((d / "p.out").read_bytes(), decoy)
        self.rust("dechiffrer", "-m", d / "p.janus", d / "p.bad", env={"JANUS_MDP": "faux"}, code=1)
        # Public key; the Rust tool reads our identity file.
        (d / "k.janus").write_bytes(encrypt(Face(b"", [Identity(seed(5)).public_key, ident.public_key])))
        self.rust("dechiffrer", "-i", idf, d / "k.janus", d / "k.out")
        self.assertEqual((d / "k.out").read_bytes(), b"")
        self.assertEqual(self.rust("publique", idf).stdout.decode().strip(), encode_public_key(ident.public_key))
        # Decoy + 3 hidden faces, passwords and a key.
        f = encrypt(Face(decoy, [Password(b"leurre")]),
                    [Face(h[0], [Password(b"un")]), Face(h[1], [ident.public_key]), Face(h[2], [Password(b"trois")])])
        (d / "h.janus").write_bytes(f)
        for n, (opt, cred, expected) in enumerate([("-m", "leurre", decoy), ("-m", "un", h[0]),
                                                   ("-i", idf, h[1]), ("-m", "trois", h[2])]):
            out = d / f"h{n}.out"
            if opt == "-m":
                self.rust("dechiffrer", "-m", d / "h.janus", out, env={"JANUS_MDP": cred})
            else:
                self.rust("dechiffrer", "-i", cred, d / "h.janus", out)
            self.assertEqual(out.read_bytes(), expected)

    def test_rust_to_python(self):
        d = self.d
        idf = d / "rust.key"
        pk = self.rust("cles", idf).stdout.decode().strip()
        ident = keys.read_identity_file(idf)
        self.assertEqual(encode_public_key(ident.public_key), pk)
        decoy, h = main_plaintext(65537), [hidden_plaintext(j, 1000 + j) for j in range(3)]
        for name, data in [("decoy", decoy), ("h0", h[0]), ("h1", h[1]), ("h2", h[2])]:
            (d / name).write_bytes(data)
        # Password.
        self.rust("chiffrer", "-m", d / "decoy", d / "p.janus", env={"JANUS_MDP": "secret é"})
        self.assertEqual(decrypt((d / "p.janus").read_bytes(), password="secret é".encode()), decoy)
        # Public key.
        self.rust("chiffrer", "-r", pk, d / "h0", d / "k.janus")
        self.assertEqual(decrypt((d / "k.janus").read_bytes(), identities=[ident]), h[0])
        # Decoy + 3 hidden faces.
        self.rust("chiffrer", "-m", d / "decoy", d / "h.janus",
                  "--cache", "-m", d / "h0", "--cache", "-r", pk, d / "h1", "--cache", "-m", d / "h2",
                  env={"JANUS_MDP": "leurre", "JANUS_MDP_CACHE": "un", "JANUS_MDP_CACHE2": "deux",
                       "JANUS_MDP_CACHE3": "trois"})
        data = (d / "h.janus").read_bytes()
        self.assertEqual(decrypt(data, password=b"leurre"), decoy)
        self.assertEqual(decrypt(data, password=b"un"), h[0])
        self.assertEqual(decrypt(data, identities=[ident]), h[1])
        self.assertEqual(decrypt(data, password=b"trois"), h[2])
        with self.assertRaises(CannotDecrypt):
            decrypt(data, password=b"deux")


if __name__ == "__main__":
    unittest.main(verbosity=2)
