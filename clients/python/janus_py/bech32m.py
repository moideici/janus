"""Bech32m (BIP 350), with an optional lifted length limit (spec § 3.3)."""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_REV = {c: i for i, c in enumerate(CHARSET)}
BECH32M_CONST = 0x2BC830A3
BIP173_MAX_LENGTH = 90


class Bech32Error(ValueError):
    pass


def _polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def encode(hrp: str, data5: list[int]) -> str:
    values = _hrp_expand(hrp.lower()) + data5
    mod = _polymod(values + [0] * 6) ^ BECH32M_CONST
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data5 + checksum)


def decode(s: str, max_length: int | None = BIP173_MAX_LENGTH) -> tuple[str, list[int]]:
    """Return (hrp, 5-bit data) of a Bech32m string; the hrp is returned lowercase."""
    if max_length is not None and len(s) > max_length:
        raise Bech32Error("too long")
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        raise Bech32Error("invalid character")
    if s.lower() != s and s.upper() != s:
        raise Bech32Error("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise Bech32Error("missing separator, empty human-readable part or short checksum")
    hrp, rest = s[:pos], s[pos + 1 :]
    try:
        data = [_REV[c] for c in rest]
    except KeyError:
        raise Bech32Error("invalid data character") from None
    if _polymod(_hrp_expand(hrp) + data) != BECH32M_CONST:
        raise Bech32Error("wrong checksum")
    return hrp, data[:-6]


def to_5bit(data: bytes) -> list[int]:
    acc, bits, out = 0, 0, []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def from_5bit(data5: list[int]) -> bytes:
    """Strict conversion: padding must be shorter than 5 bits and zero."""
    acc, bits, out = 0, 0, bytearray()
    for v in data5:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5:
        raise Bech32Error("over-long padding")
    if acc & ((1 << bits) - 1):
        raise Bech32Error("non-zero padding")
    return bytes(out)
