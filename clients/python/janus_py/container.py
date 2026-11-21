"""The Janus v1 file format: sizes, layout, encryption and decryption (spec § 6-8)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Sequence, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import curve25519
from .xwing import Identity, PublicKey, hidden_decapsulate, hidden_encapsulate

# --------------------------------------------------------------------------- constants (§ 2.2)

N_SLOTS = 16
N_TAGS = 4
S = 1632
H = 32 * N_TAGS + 32 + N_SLOTS * S  # 26 272
TB = 65536
R_MIN = 65536
RHO = 16
MAX_HIDDEN = N_TAGS - 1

SALT_OFFSET = 32 * N_TAGS  # 128
SLOTS_OFFSET = SALT_OFFSET + 32  # 160
W_OFFSET = 1568  # offset of W inside a slot
W_SIZE = 64

LABEL_HEADER = b"janus/v1/entete"
LABEL_BODY = b"janus/v1/corps"
LABEL_WRAP_XWING = b"janus/v1/emballage/xwing"
LABEL_WRAP_PASSWORD = b"janus/v1/emballage/mdp"

ZERO_NONCE = bytes(12)


class JanusError(Exception):
    pass


class EncryptionRuleError(JanusError):
    """The encryptor refuses the faces and recipients it was given (rules R1, R3, R5)."""


class CannotDecrypt(JanusError):
    def __init__(self):
        super().__init__("cannot decrypt")


class SeveralFaces(JanusError):
    def __init__(self):
        super().__init__("these credentials open several faces")


# --------------------------------------------------------------------------- primitives (§ 2.1)

def hkdf(ikm: bytes, info: bytes) -> bytes:
    """HKDF-SHA-256 with an absent salt (32 zero bytes), 32-byte output."""
    prk = hmac.digest(bytes(32), ikm, "sha256")
    return hmac.digest(prk, info + b"\x01", "sha256")


def argon2id(password: bytes, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(password)


def be64(x: int) -> bytes:
    return x.to_bytes(8, "big")


# --------------------------------------------------------------------------- sizes (§ 6)

def blocks(l: int) -> int:
    return max(1, -(-l // TB))


def face_size(l: int) -> int:
    """c(l): size of an encrypted face."""
    return l + 16 * blocks(l)


def reserve(l1: int) -> int:
    return max(R_MIN, -(-l1 // RHO))


def padme(length: int) -> int:
    if length < 2:
        return length
    e = length.bit_length() - 1  # ⌊log2 L⌋
    s = e.bit_length()  # ⌊log2 E⌋ + 1
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask


def bucket_mask(x: int) -> int:
    """Spec § 6.2: width − 1 of the PADME bucket of an aligned size x."""
    if x < 2:
        return 0
    e = x.bit_length() - 1
    s = e.bit_length()
    return (1 << (e - s)) - 1


# --------------------------------------------------------------------------- faces

@dataclass(frozen=True)
class Password:
    value: bytes


Recipient = Union[Password, PublicKey]


@dataclass
class Face:
    plaintext: bytes
    recipients: Sequence[Recipient] = field(default_factory=list)


def _check_rules(faces: list[Face]) -> None:
    if len(faces) > 1 + MAX_HIDDEN:
        raise EncryptionRuleError(f"at most {MAX_HIDDEN} hidden faces")
    total = 0
    passwords: set[bytes] = set()
    keys: set[bytes] = set()
    for face in faces:
        rec = list(face.recipients)
        if not rec:
            raise EncryptionRuleError("every face needs at least one recipient")
        n_pw = sum(isinstance(r, Password) for r in rec)
        if n_pw and len(rec) != 1:
            raise EncryptionRuleError("R1: a password face has exactly one recipient, its password")
        if not n_pw and not all(isinstance(r, PublicKey) for r in rec):
            raise EncryptionRuleError("a recipient is a password or a public key")
        total += len(rec)
        for r in rec:
            if isinstance(r, Password):
                if r.value in passwords:
                    raise EncryptionRuleError("R5: two faces share a password")
                passwords.add(r.value)
            else:
                if r.raw in keys:
                    raise EncryptionRuleError("R5: a public key appears twice")
                keys.add(r.raw)
    if total > N_SLOTS:
        raise EncryptionRuleError(f"R3: at most {N_SLOTS} recipients over all faces")
    if sum(face_size(len(f.plaintext)) for f in faces[1:]) > reserve(len(faces[0].plaintext)):
        raise EncryptionRuleError("R5: the hidden faces do not fit in the reserve")


def _uniform(lo: int, hi: int) -> int:
    """Uniform integer in [lo, hi], bounds included."""
    return lo + secrets.randbelow(hi - lo + 1)


def _permutation(n: int) -> list[int]:
    p = list(range(n))
    secrets.SystemRandom().shuffle(p)  # Fisher-Yates over an unbiased randbelow
    return p


def _tag(k: bytes, f: int, d: int, l: int, header_tail: bytes) -> bytes:
    return hmac.digest(hkdf(k, LABEL_HEADER), be64(f) + be64(d) + be64(l) + header_tail, "sha256")


def _nonce(j: int, last: bool) -> bytes:
    return bytes(3) + be64(j) + (b"\x01" if last else b"\x00")


def encrypt_face(k: bytes, plaintext: bytes) -> bytes:
    """STREAM encryption of one face (§ 7.1)."""
    aead = ChaCha20Poly1305(hkdf(k, LABEL_BODY))
    c = blocks(len(plaintext))
    return b"".join(
        aead.encrypt(_nonce(j, j == c - 1), plaintext[j * TB : (j + 1) * TB], None) for j in range(c)
    )


def decrypt_face(k: bytes, body: bytes, d: int, l: int) -> bytes:
    """STREAM decryption of one face at body offset d; raises CannotDecrypt."""
    aead = ChaCha20Poly1305(hkdf(k, LABEL_BODY))
    c = blocks(l)
    out = []
    pos = d
    for j in range(c):
        size = min(TB, l - j * TB) + 16
        try:
            out.append(aead.decrypt(_nonce(j, j == c - 1), body[pos : pos + size], None))
        except InvalidTag:
            raise CannotDecrypt() from None
        pos += size
    return b"".join(out)


# --------------------------------------------------------------------------- encryption (§ 7)

def encrypt(main: Face, hidden: Sequence[Face] = ()) -> bytes:
    """Encrypt a main face (the decoy) and up to 3 hidden faces into a Janus v1 file."""
    faces = [main, *hidden]
    _check_rules(faces)

    # 1. File size (§ 6.2) and offsets (§ 6.3).
    l1 = len(main.plaintext)
    ref = H + face_size(l1) + reserve(l1)
    x = padme(ref)
    f_size = _uniform(x, x + bucket_mask(x))  # spec § 6.2: the whole PADME bucket
    body_size = f_size - H
    offsets = [0]
    if hidden:
        sizes = [face_size(len(x.plaintext)) for x in hidden]
        free = body_size - face_size(l1) - sum(sizes)
        order = _permutation(len(hidden))
        b = sorted(_uniform(0, free) for _ in hidden)
        hidden_d = [0] * len(hidden)
        placed = 0
        for m, j in enumerate(order):
            hidden_d[j] = face_size(l1) + b[m] + placed
            placed += sizes[j]
        offsets += hidden_d

    # 2. Random header; the salt is part of it.
    header = bytearray(secrets.token_bytes(H))
    salt = bytes(header[SALT_OFFSET:SLOTS_OFFSET])

    # 3-4. Slots.
    pi = _permutation(N_SLOTS)
    next_slot = 0
    keys = []
    for face, d in zip(faces, offsets):
        k = secrets.token_bytes(32)
        keys.append(k)
        payload = k + be64(d) + be64(len(face.plaintext))
        for r in face.recipients:
            i = pi[next_slot]
            next_slot += 1
            base = SLOTS_OFFSET + i * S
            if isinstance(r, Password):
                k_i = hkdf(argon2id(r.value, salt), LABEL_WRAP_PASSWORD + bytes([i]))
            else:
                ss, rep, kappa = hidden_encapsulate(r)
                header[base : base + 32] = rep
                header[base + 32 : base + W_OFFSET] = kappa
                k_i = hkdf(ss, LABEL_WRAP_XWING + bytes([i]))
            header[base + W_OFFSET : base + S] = ChaCha20Poly1305(k_i).encrypt(ZERO_NONCE, payload, None)

    # 5. Tags, at a random permutation of the tag positions.
    tail = bytes(header[SALT_OFFSET:H])
    sigma = _permutation(N_TAGS)
    for fnum, (face, d, k) in enumerate(zip(faces, offsets, keys)):
        pos = 32 * sigma[fnum]
        header[pos : pos + 32] = _tag(k, f_size, d, len(face.plaintext), tail)

    # 6. Body: random bytes, with each face at its offset.
    body = bytearray(secrets.token_bytes(body_size))
    for face, d, k in zip(faces, offsets, keys):
        ct = encrypt_face(k, face.plaintext)
        body[d : d + len(ct)] = ct
    return bytes(header) + bytes(body)


# --------------------------------------------------------------------------- decryption (§ 8)

def _open_wrap(k_i: bytes, w: bytes) -> tuple[bool, bytes]:
    try:
        return True, ChaCha20Poly1305(k_i).decrypt(ZERO_NONCE, w, None)
    except InvalidTag:
        return False, bytes(48)


def decrypt(data: bytes, password: bytes | None = None, identities: Sequence[Identity] = ()) -> bytes:
    """Open the face that the credential opens.

    Give either one password or one or more identities. Raises CannotDecrypt,
    or SeveralFaces if the credentials open more than one face.
    """
    if (password is None) == (not identities):
        raise ValueError("give either one password or one or more identities")
    f_size = len(data)
    if f_size < H:
        raise CannotDecrypt()
    header = data[:H]
    salt = header[SALT_OFFSET:SLOTS_OFFSET]
    tags = [header[32 * t : 32 * t + 32] for t in range(N_TAGS)]
    tail = header[SALT_OFFSET:H]

    # 2. Candidate wrapping keys: always all 16 slots.
    candidates: list[tuple[bytes, bytes]] = []  # (k_i, W)
    if password is not None:
        a = argon2id(password, salt)
        for i in range(N_SLOTS):
            base = SLOTS_OFFSET + i * S
            candidates.append((hkdf(a, LABEL_WRAP_PASSWORD + bytes([i])), header[base + W_OFFSET : base + S]))
    else:
        for i in range(N_SLOTS):
            base = SLOTS_OFFSET + i * S
            ct_x = curve25519.elligator2_map(header[base : base + 32])
            kappa = header[base + 32 : base + W_OFFSET]
            w = header[base + W_OFFSET : base + S]
            for ident in identities:
                ss = hidden_decapsulate(ident, ct_x, kappa)
                candidates.append((hkdf(ss, LABEL_WRAP_XWING + bytes([i])), w))

    # 3. Tags, for every attempt.
    valid: set[tuple[bytes, int, int]] = set()
    for k_i, w in candidates:
        opened, plain = _open_wrap(k_i, w)
        k, d, l = plain[:32], int.from_bytes(plain[32:40], "big"), int.from_bytes(plain[40:48], "big")
        t = _tag(k, f_size, d, l, tail)
        matched = 0
        for tag in tags:
            matched |= hmac.compare_digest(t, tag)
        if opened & bool(matched):
            valid.add((k, d, l))

    # 4. Deduplicate on the full triple.
    if not valid:
        raise CannotDecrypt()
    if len(valid) > 1:
        raise SeveralFaces()
    k, d, l = valid.pop()

    # 5. Bounds.
    if d + l + 16 * blocks(l) > f_size - H:
        raise CannotDecrypt()

    # 6-7. Body.
    return decrypt_face(k, memoryview(data)[H:], d, l)
