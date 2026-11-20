// Hidden X-Wing encapsulation (spec § 3.2, § 5.2, § 5.3).

import { decapsulate, encapsulate } from 'node:crypto';
import {
  elligatorMap,
  elligatorRepresentative,
  G_FULL_U,
  ladderUnclamped,
  randomFullScalar,
  x25519,
} from './curve25519.ts';
import { decodeCtxt, encodeCtxt } from './kemeleon.ts';
import type { Identity, PublicKey } from './keys.ts';
import { concat, sha3_256, shake256, utf8, type Bytes } from './primitives.ts';

export const XWING_LABEL = Uint8Array.from([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]); // \.//^\
const MASK_LABEL = utf8('janus/v1/masque');

/** X-Wing draft-11 combiner. */
export function combine(ssM: Bytes, ssX: Bytes, ctX: Bytes, pkX: Bytes): Bytes {
  return sha3_256(concat(ssM, ssX, ctX, pkX, XWING_LABEL));
}

function mask(ssX: Bytes, ctX: Bytes): Bytes {
  return shake256(concat(MASK_LABEL, ssX, ctX), 1536);
}

function xor(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** Sender side: returns the 1568-byte slot prefix r ‖ κ' and the secret ss. */
export function hiddenEncapsulate(pub: PublicKey): { prefix: Bytes; ss: Bytes } {
  let s: bigint, ctX: Bytes, r: Bytes | null;
  do {
    // P = s·G uniform in the full group of order 8ℓ; no clamping.
    s = randomFullScalar();
    ctX = ladderUnclamped(s, G_FULL_U);
    r = elligatorRepresentative(ctX);
  } while (r === null);
  const ssX = ladderUnclamped(s, pub.pkX);
  const { sharedKey: ssM, ciphertext: ctM } = encapsulate(pub.ekM);
  const ss = combine(ssM, ssX, ctX, pub.pkX);
  const kappa = xor(encodeCtxt(ctM), mask(ssX, ctX));
  return { prefix: concat(r, kappa), ss };
}

/** Recipient side: never fails; a foreign slot yields an unrelated ss. */
export function hiddenDecapsulate(id: Identity, prefix: Bytes): Bytes {
  const ctX = elligatorMap(prefix.subarray(0, 32));
  const ssX = x25519(id.skX, ctX);
  const kappa = xor(prefix.subarray(32, 1568), mask(ssX, ctX));
  const ctM = decodeCtxt(kappa);
  const ssM = decapsulate(id.dkM, ctM);
  return combine(ssM, ssX, ctX, id.pkX);
}
