"""Curve25519 arithmetic with Python integers (spec § 2.1, § 5.2, § 5.4).

- X25519 as in RFC 7748 (clamped scalar), used by the recipient and for keys.
- An *unclamped* Montgomery ladder over all 256 bits of the scalar, used by the
  sender of a hidden X-Wing encapsulation (spec § 5.2).
- Elligator 2: the map (representative -> u) and its inverse (u -> representative).

Python integers are not constant-time: this module is for interoperability only.
"""

from __future__ import annotations

import secrets

P = 2**255 - 19
A = 486662
A24 = 121665  # (A - 2) / 4, RFC 7748
# Order of the prime subgroup, and of the full group (cofactor 8).
ELL = 2**252 + 27742317777372353535851937790883648493
FULL_ORDER = 8 * ELL
# u(G), G = Ed25519 base point plus a point of order 8: a generator of the full group (spec § 5.2).
U_G = int.from_bytes(bytes.fromhex("bb72312170e8156f7a836313f85bee9b1fdce926ba9804a29e8d137ec67f2533"), "little")
U_BASE = 9

_SQRT_M1 = pow(2, (P - 1) // 4, P)  # a square root of -1
_HALF_P = (P - 1) // 2


# --------------------------------------------------------------------------- field

def inv(x: int) -> int:
    return pow(x, P - 2, P)


def is_square(x: int) -> bool:
    """True if x is a square in GF(p); 0 counts as a square."""
    x %= P
    return x == 0 or pow(x, _HALF_P, P) == 1


def sqrt(x: int) -> int | None:
    """A square root of x in GF(p), or None. p = 5 mod 8 (Atkin's variant)."""
    x %= P
    r = pow(x, (P + 3) // 8, P)
    if r * r % P == x:
        return r
    r = r * _SQRT_M1 % P
    if r * r % P == x:
        return r
    return None


def decode_u(b: bytes) -> int:
    """RFC 7748 decodeUCoordinate: mask bit 255, reduce modulo p."""
    if len(b) != 32:
        raise ValueError("a u-coordinate is 32 bytes")
    return (int.from_bytes(b, "little") & ((1 << 255) - 1)) % P


def encode_u(u: int) -> bytes:
    return (u % P).to_bytes(32, "little")


# --------------------------------------------------------------------------- ladder

def ladder(k: int, u: int, bits: int = 256) -> int:
    """Montgomery ladder of RFC 7748 § 5 on `bits` bits of k, without clamping.

    Returns the u-coordinate of k·(u); the point at infinity gives 0.
    """
    x1 = u % P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(bits)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = x2 + z2
        aa = a * a % P
        b = x2 - z2
        bb = b * b % P
        e = aa - bb
        c = x3 + z3
        d = x3 - z3
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return x2 * inv(z2) % P


def clamp(k32: bytes) -> int:
    k = bytearray(k32)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(k32: bytes, u32: bytes) -> bytes:
    """X25519 of RFC 7748 (clamped scalar)."""
    if len(k32) != 32:
        raise ValueError("an X25519 scalar is 32 bytes")
    return encode_u(ladder(clamp(k32), decode_u(u32), 255))


# --------------------------------------------------------------------------- Elligator 2

def elligator2_map(r32: bytes) -> bytes:
    """Representative -> u (spec § 5.4; RFC 9380 map_to_curve_elligator2, Z = 2)."""
    if len(r32) != 32:
        raise ValueError("a representative is 32 bytes")
    r = int.from_bytes(r32, "little") & ((1 << 254) - 1)
    d = (1 + 2 * r * r) % P
    x1 = (-A) % P if d == 0 else (-A) * inv(d) % P
    g = (x1 * x1 % P * x1 + A * x1 * x1 + x1) % P
    u = x1 if is_square(g) else (-x1 - A) % P
    return encode_u(u)


def elligator2_representative(u: int) -> bytes | None:
    """u -> a uniformly chosen representative, or None if u has none (spec § 5.4).

    The choice of t, the root normalisation and the two top bits are random so
    that the representative is uniform over all 2^256 strings.
    """
    u %= P
    den = (-2 * u * (u + A)) % P
    if den == 0:
        return None
    root = sqrt(den)
    if root is None:
        return None
    t = u if secrets.randbits(1) else (u + A) % P
    r = t * inv(root) % P
    if r > _HALF_P:
        r = P - r
    r |= secrets.randbits(2) << 254
    return r.to_bytes(32, "little")


def hidden_ephemeral() -> tuple[int, bytes, bytes]:
    """Draw (s, ct_X, r): P = s·G uniform over the whole curve, with a representative.

    Spec § 5.2 steps 1-2: s uniform in [0, 8ℓ − 1], ct_X = Ladder(s, u(G))
    unclamped, retried until ct_X has an Elligator 2 representative r.
    """
    while True:
        s = secrets.randbelow(FULL_ORDER)
        u = ladder(s, U_G)
        r = elligator2_representative(u)
        if r is not None:
            return s, encode_u(u), r
