// Kemeleon encoding of ML-KEM-768 ciphertexts (spec § 5.5):
// draft-irtf-cfrg-kemeleon-02, non-rejecting variant, big-endian vectors.

import { randomInt } from 'node:crypto';
import { uniformBigInt, type Bytes } from './primitives.ts';

const Q = 3329;
const QB = 3329n;
const N = 256;
const CT_BYTES = 1088;
const VEC_BYTES = 384;
export const KEMELEON_BYTES = 4 * VEC_BYTES; // 1536
const Q256 = QB ** 256n;
const MAX_3072 = (1n << 3072n) - 1n;

/** Compress_d(x) = ⌊(x·2^d + 1664) / q⌋ mod 2^d (FIPS 203). */
export function compress(x: number, d: number): number {
  return Math.floor((x * (1 << d) + 1664) / Q) % (1 << d);
}

/** preimages[d][c] = every x in [0, q−1] with Compress_d(x) = c. */
function preimageTable(d: number): number[][] {
  const t: number[][] = Array.from({ length: 1 << d }, () => []);
  for (let x = 0; x < Q; x++) t[compress(x, d)].push(x);
  return t;
}
const PRE10 = preimageTable(10);
const PRE4 = preimageTable(4);

/** ByteDecode_d of FIPS 203 (little-endian bit order), count values. */
function byteDecode(b: Bytes, d: number, count: number): number[] {
  const out = new Array<number>(count);
  let acc = 0, accBits = 0, pos = 0;
  for (let i = 0; i < count; i++) {
    while (accBits < d) {
      acc |= b[pos++] << accBits;
      accBits += 8;
    }
    out[i] = acc & ((1 << d) - 1);
    acc >>>= d;
    accBits -= d;
  }
  return out;
}

/** ByteEncode_d of FIPS 203. */
function byteEncode(vals: number[], d: number): Bytes {
  const out = new Uint8Array((vals.length * d) / 8);
  let acc = 0, accBits = 0, pos = 0;
  for (const v of vals) {
    acc |= v << accBits;
    accBits += d;
    while (accBits >= 8) {
      out[pos++] = acc & 0xff;
      acc >>>= 8;
      accBits -= 8;
    }
  }
  return out;
}

function vectorEncode(a: number[]): Bytes {
  let r = 0n;
  for (let i = N - 1; i >= 0; i--) r = r * QB + BigInt(a[i]);
  const m = uniformBigInt((MAX_3072 - r) / Q256);
  const x = r + m * Q256;
  return Buffer.from(x.toString(16).padStart(2 * VEC_BYTES, '0'), 'hex');
}

function vectorDecode(block: Bytes): number[] {
  let r = BigInt('0x' + Buffer.from(block).toString('hex'));
  const a = new Array<number>(N);
  for (let i = 0; i < N; i++) {
    a[i] = Number(r % QB);
    r /= QB;
  }
  return a;
}

/** EncodeCtxt: 1088-byte ML-KEM-768 ciphertext → 1536 uniform-looking bytes. */
export function encodeCtxt(ct: Bytes): Bytes {
  if (ct.length !== CT_BYTES) throw new Error('an ML-KEM-768 ciphertext is 1088 bytes');
  const c1 = byteDecode(ct.subarray(0, 960), 10, 3 * N);
  const c2 = byteDecode(ct.subarray(960), 4, N);
  const a1 = c1.map((c) => { const s = PRE10[c]; return s[randomInt(s.length)]; });
  const a2 = c2.map((c) => { const s = PRE4[c]; return s[randomInt(s.length)]; });
  return Buffer.concat([
    vectorEncode(a1.slice(0, N)),
    vectorEncode(a1.slice(N, 2 * N)),
    vectorEncode(a1.slice(2 * N)),
    vectorEncode(a2),
  ]);
}

/** DecodeCtxt: 1536 bytes → 1088-byte ciphertext. Never fails. */
export function decodeCtxt(k: Bytes): Bytes {
  if (k.length !== KEMELEON_BYTES) throw new Error('a Kemeleon encoding is 1536 bytes');
  const a: number[][] = [];
  for (let j = 0; j < 4; j++) a.push(vectorDecode(k.subarray(j * VEC_BYTES, (j + 1) * VEC_BYTES)));
  const c1 = [...a[0], ...a[1], ...a[2]].map((x) => compress(x, 10));
  const c2 = a[3].map((x) => compress(x, 4));
  return Buffer.concat([byteEncode(c1, 10), byteEncode(c2, 4)]);
}
