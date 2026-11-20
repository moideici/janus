// Bech32m (BIP 350) and the Janus key strings of spec § 3.3.

import type { Bytes } from './primitives.ts';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

/**
 * Value of a (lowercase) data character, scanning the whole charset with
 * masks instead of a data-dependent table lookup or branch; -1 if invalid.
 */
function charValue(code: number): number {
  let v = -1;
  for (let i = 0; i < 32; i++) {
    const diff = code ^ CHARSET.charCodeAt(i);
    const isEq = ((diff - 1) >>> 31) & 1; // 1 iff diff == 0
    v = (v & (isEq - 1)) | (i & -isEq);
  }
  return v;
}

/** Encodes hrp + 5-bit data; the result is lowercase. */
export function bech32mEncode(hrp: string, data: number[]): string {
  const h = hrp.toLowerCase();
  const values = [...hrpExpand(h), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ BECH32M_CONST;
  let s = h + '1';
  for (const d of data) s += CHARSET[d];
  for (let i = 0; i < 6; i++) s += CHARSET[(mod >>> (5 * (5 - i))) & 31];
  return s;
}

/**
 * Decodes a Bech32m string. Accepts all-lowercase or all-uppercase only.
 * maxLength: 90 for BIP 173/350 strings, Infinity to lift the limit.
 */
export function bech32mDecode(str: string, maxLength = 90): { hrp: string; data: number[] } {
  if (str.length > maxLength) throw new Error('bech32m: string too long');
  let lower = false, upper = false;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 33 || c > 126) throw new Error('bech32m: invalid character');
    if (c >= 97 && c <= 122) lower = true;
    if (c >= 65 && c <= 90) upper = true;
  }
  if (lower && upper) throw new Error('bech32m: mixed case');
  const s = str.toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) throw new Error('bech32m: bad separator position');
  const hrp = s.slice(0, pos);
  const data: number[] = [];
  let bad = 0;
  for (let i = pos + 1; i < s.length; i++) {
    const v = charValue(s.charCodeAt(i));
    bad |= v >>> 31;
    data.push(v & 31);
  }
  if (bad) throw new Error('bech32m: invalid data character');
  if (polymod([...hrpExpand(hrp), ...data]) !== BECH32M_CONST) {
    throw new Error('bech32m: wrong checksum');
  }
  return { hrp, data: data.slice(0, data.length - 6) };
}

/** 8-bit bytes → 5-bit groups, zero padding. */
export function toWords(bytes: Bytes): number[] {
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const b of bytes) {
    acc = ((acc << 8) | b) & 0xfff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
}

/** 5-bit groups → bytes; rejects non-zero or over-long (≥ 5 bits) padding. */
export function fromWords(words: number[]): Bytes {
  const out: number[] = [];
  let acc = 0, bits = 0;
  for (const w of words) {
    acc = ((acc << 5) | w) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  if (bits >= 5) throw new Error('bech32m: over-long padding');
  if ((acc & ((1 << bits) - 1)) !== 0) throw new Error('bech32m: non-zero padding');
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------- Janus keys

export const IDENTITY_HRP = 'JANUS-SECRET-KEY-';
export const PUBLIC_HRP = 'janus';
export const SEED_BYTES = 32;
export const PUBLIC_KEY_BYTES = 1216;

export function encodeIdentity(seed: Bytes): string {
  if (seed.length !== SEED_BYTES) throw new Error('an identity seed is 32 bytes');
  return bech32mEncode(IDENTITY_HRP, toWords(seed)).toUpperCase();
}

export function decodeIdentity(s: string): Bytes {
  const { hrp, data } = bech32mDecode(s, 90);
  if (hrp !== IDENTITY_HRP.toLowerCase()) throw new Error('not a Janus identity');
  const seed = fromWords(data);
  if (seed.length !== SEED_BYTES) throw new Error('wrong identity length');
  return seed;
}

export function encodePublicKey(pk: Bytes): string {
  if (pk.length !== PUBLIC_KEY_BYTES) throw new Error('a public key is 1216 bytes');
  return bech32mEncode(PUBLIC_HRP, toWords(pk));
}

/** Decodes the text form only; the ML-KEM check is in keys.ts. */
export function decodePublicKeyBytes(s: string): Bytes {
  const { hrp, data } = bech32mDecode(s, Infinity);
  if (hrp !== PUBLIC_HRP) throw new Error('not a Janus public key');
  const pk = fromWords(data);
  if (pk.length !== PUBLIC_KEY_BYTES) throw new Error('wrong public key length');
  return pk;
}
