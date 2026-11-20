"""Text encoding of keys and identity files (spec § 3.3)."""

from __future__ import annotations

from pathlib import Path

from . import bech32m
from .xwing import PK_SIZE, SEED_SIZE, Identity, PublicKey

IDENTITY_HRP = "JANUS-SECRET-KEY-"
PUBLIC_HRP = "janus"
IDENTITY_LENGTH = 76
PUBLIC_LENGTH = 1958


class KeyFormatError(ValueError):
    pass


def encode_identity(identity: Identity) -> str:
    return bech32m.encode(IDENTITY_HRP, bech32m.to_5bit(identity.seed)).upper()


def encode_public_key(pk: PublicKey) -> str:
    return bech32m.encode(PUBLIC_HRP, bech32m.to_5bit(pk.raw))


def _decode(text: str, hrp: str, size: int, max_length: int | None) -> bytes:
    try:
        got_hrp, data5 = bech32m.decode(text, max_length)
        if got_hrp != hrp.lower():
            raise KeyFormatError("wrong human-readable part")
        data = bech32m.from_5bit(data5)
    except bech32m.Bech32Error as e:
        raise KeyFormatError(str(e)) from None
    if len(data) != size:
        raise KeyFormatError("wrong data length")
    return data


def decode_identity(text: str) -> Identity:
    return Identity(_decode(text.strip(), IDENTITY_HRP, SEED_SIZE, bech32m.BIP173_MAX_LENGTH))


def decode_public_key(text: str) -> PublicKey:
    raw = _decode(text.strip(), PUBLIC_HRP, PK_SIZE, None)
    try:
        return PublicKey(raw)
    except ValueError as e:
        raise KeyFormatError(str(e)) from None


def identity_file_text(identity: Identity) -> str:
    return (
        "# Janus identity (PROTOTYPE). Public key:\n"
        f"# {encode_public_key(identity.public_key)}\n"
        f"{encode_identity(identity)}\n"
    )


def parse_identity_file(text: str) -> Identity:
    """The first line starting with JANUS-SECRET-KEY-1 (any case) is the identity.

    A UTF-8 BOM is skipped, CRLF is accepted and lines are trimmed. If that first
    line does not decode, the file is invalid: later lines are not tried.
    """
    for line in text.removeprefix("﻿").splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        if line.upper().startswith(IDENTITY_HRP + "1"):
            return decode_identity(line)
    raise KeyFormatError("no JANUS-SECRET-KEY-1 line in the identity file")


def read_identity_file(path: str | Path) -> Identity:
    return parse_identity_file(Path(path).read_text(encoding="utf-8-sig"))


def parse_public_keys(text: str) -> list[PublicKey]:
    """One public key per line; blank lines and # comments are ignored."""
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keys.append(decode_public_key(line))
    return keys
