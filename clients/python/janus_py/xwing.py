"""X-Wing key pairs and Janus's hidden X-Wing encapsulation (spec § 3.1, § 3.2, § 5.2, § 5.3)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey

from . import curve25519, kemeleon

SEED_SIZE = 32
EK_M_SIZE = 1184
PK_SIZE = EK_M_SIZE + 32  # 1216
XWING_LABEL = b"\\.//^\\"  # 5c 2e 2f 2f 5e 5c
MASK_LABEL = b"janus/v1/masque"
_Q = 3329


def combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """The X-Wing (draft-11) combiner."""
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def mask(ss_x: bytes, ct_x: bytes) -> bytes:
    return hashlib.shake_256(MASK_LABEL + ss_x + ct_x).digest(kemeleon.ENCODED_SIZE)


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def check_ek_m(ek_m: bytes) -> bool:
    """FIPS 203 encapsulation-key check: every 12-bit coefficient is below q."""
    if len(ek_m) != EK_M_SIZE:
        return False
    v = int.from_bytes(ek_m[: 384 * 3], "little")
    return all((v >> (12 * i)) & 0xFFF < _Q for i in range(768))


@dataclass(frozen=True)
class PublicKey:
    """A recipient's public key pk = ek_M ‖ pk_X (1216 bytes)."""

    raw: bytes

    def __post_init__(self):
        if len(self.raw) != PK_SIZE:
            raise ValueError("a public key is 1216 bytes")
        if not check_ek_m(self.raw[:EK_M_SIZE]):
            raise ValueError("invalid public key (ML-KEM encapsulation-key check)")
        # pk_X must be canonical: bit 255 clear and value below p (low-order points are accepted).
        if int.from_bytes(self.raw[EK_M_SIZE:], "little") >= curve25519.P:
            raise ValueError("invalid public key (non-canonical X25519 part)")

    @property
    def ek_m(self) -> bytes:
        return self.raw[:EK_M_SIZE]

    @property
    def pk_x(self) -> bytes:
        return self.raw[EK_M_SIZE:]


class Identity:
    """A secret key: a 32-byte seed, expanded as in X-Wing (spec § 3.1)."""

    def __init__(self, seed: bytes):
        if len(seed) != SEED_SIZE:
            raise ValueError("an identity is a 32-byte seed")
        self.seed = bytes(seed)
        expanded = hashlib.shake_256(self.seed).digest(96)
        # from_seed_bytes takes the FIPS 203 seed d ‖ z.
        self._dk_m = MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])
        self.sk_x = expanded[64:96]
        self.pk_x = curve25519.x25519(self.sk_x, curve25519.encode_u(curve25519.U_BASE))
        ek_m = self._dk_m.public_key().public_bytes_raw()
        self.public_key = PublicKey(ek_m + self.pk_x)

    def decapsulate_ml_kem(self, ct_m: bytes) -> bytes:
        return self._dk_m.decapsulate(ct_m)


def hidden_encapsulate(pk: PublicKey) -> tuple[bytes, bytes, bytes]:
    """Spec § 5.2: return (ss, r, κ') for a slot addressed to pk."""
    s, ct_x, r = curve25519.hidden_ephemeral()
    ss_x = curve25519.encode_u(curve25519.ladder(s, curve25519.decode_u(pk.pk_x)))
    ss_m, ct_m = MLKEM768PublicKey.from_public_bytes(pk.ek_m).encapsulate()
    ss = combine(ss_m, ss_x, ct_x, pk.pk_x)
    kappa_masked = _xor(kemeleon.encode_ctxt(ct_m), mask(ss_x, ct_x))
    return ss, r, kappa_masked


def hidden_decapsulate(identity: Identity, ct_x: bytes, kappa_masked: bytes) -> bytes:
    """Spec § 5.3, with ct_X = Elligator2.Map(r) computed by the caller. Never fails."""
    ss_x = curve25519.x25519(identity.sk_x, ct_x)
    ct_m = kemeleon.decode_ctxt(_xor(kappa_masked, mask(ss_x, ct_x)))
    ss_m = identity.decapsulate_ml_kem(ct_m)
    return combine(ss_m, ss_x, ct_x, identity.pk_x)
