"""Kemeleon encoding of ML-KEM-768 ciphertexts (spec § 5.5).

draft-irtf-cfrg-kemeleon-02, default (non-rejecting) variant, with each vector
written as a 384-byte big-endian integer.
"""

from __future__ import annotations

import secrets

Q = 3329
N = 256
K = 3
DU = 10
DV = 4
CT_SIZE = 32 * (K * DU + DV)  # 1088
VECTOR_SIZE = 384
ENCODED_SIZE = (K + 1) * VECTOR_SIZE  # 1536
_Q_N = Q**N
_MAX = 2 ** (8 * VECTOR_SIZE) - 1


def compress(x: int, d: int) -> int:
    """FIPS 203 Compress_d, in integers: ⌊(x·2^d + 1664) / q⌋ mod 2^d."""
    return ((x << d) + 1664) // Q % (1 << d)


# Preimages of every compressed value: 3 or 4 for d = 10, 208 or 209 for d = 4.
PREIMAGES = {d: [[] for _ in range(1 << d)] for d in (DU, DV)}
for _d in (DU, DV):
    for _x in range(Q):
        PREIMAGES[_d][compress(_x, _d)].append(_x)


def byte_decode(data: bytes, d: int, count: int) -> list[int]:
    """FIPS 203 ByteDecode_d (little-endian bit packing), for d < 12."""
    v = int.from_bytes(data, "little")
    mask = (1 << d) - 1
    return [(v >> (d * i)) & mask for i in range(count)]


def byte_encode(values: list[int], d: int) -> bytes:
    """FIPS 203 ByteEncode_d."""
    v = 0
    for i, c in enumerate(values):
        v |= c << (d * i)
    return v.to_bytes(len(values) * d // 8, "little")


def _vector_encode(a: list[int]) -> bytes:
    r = 0
    for x in reversed(a):
        r = r * Q + x
    m = secrets.randbelow((_MAX - r) // _Q_N + 1)
    return (r + m * _Q_N).to_bytes(VECTOR_SIZE, "big")


def _vector_decode(block: bytes) -> list[int]:
    r = int.from_bytes(block, "big") % _Q_N
    out = []
    for _ in range(N):
        r, x = divmod(r, Q)
        out.append(x)
    return out


def encode_ctxt(ct: bytes) -> bytes:
    """1088-byte ML-KEM-768 ciphertext -> 1536 pseudorandom bytes."""
    if len(ct) != CT_SIZE:
        raise ValueError("an ML-KEM-768 ciphertext is 1088 bytes")
    c1 = byte_decode(ct[: 32 * K * DU], DU, K * N)
    c2 = byte_decode(ct[32 * K * DU :], DV, N)
    values = [secrets.choice(PREIMAGES[DU][c]) for c in c1]
    values += [secrets.choice(PREIMAGES[DV][c]) for c in c2]
    return b"".join(_vector_encode(values[N * j : N * (j + 1)]) for j in range(K + 1))


def decode_ctxt(kappa: bytes) -> bytes:
    """1536 bytes -> ML-KEM-768 ciphertext. Never fails."""
    if len(kappa) != ENCODED_SIZE:
        raise ValueError("a Kemeleon encoding is 1536 bytes")
    a = [_vector_decode(kappa[VECTOR_SIZE * j : VECTOR_SIZE * (j + 1)]) for j in range(K + 1)]
    c1 = [compress(x, DU) for j in range(K) for x in a[j]]
    c2 = [compress(x, DV) for x in a[K]]
    return byte_encode(c1, DU) + byte_encode(c2, DV)
