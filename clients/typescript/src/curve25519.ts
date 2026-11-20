// Curve25519 with bigint: field arithmetic, the Montgomery ladder (clamped
// X25519 of RFC 7748, and the unclamped ladder of spec § 5.2), and
// Elligator 2 (spec § 5.4). Not constant-time: JavaScript bigints are not.

import { random, uniformBigInt, type Bytes } from './primitives.ts';

export const P = (1n << 255n) - 19n;
export const A = 486662n;
/** Order of the prime-order subgroup. */
export const ELL = (1n << 252n) + 27742317777372353535851937790883648493n;
const A24 = 121665n; // (A - 2) / 4
const SQRT_M1 = modPow(2n, (P - 1n) / 4n); // a square root of -1

// ---------------------------------------------------------------- field

export function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function modPow(b: bigint, e: bigint): bigint {
  let result = 1n;
  b = ((b % P) + P) % P;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

export function inv(a: bigint): bigint {
  return modPow(a, P - 2n); // inv(0) = 0
}

/** Euler's criterion; 0 counts as a square. */
export function isSquare(a: bigint): boolean {
  const l = modPow(a, (P - 1n) / 2n);
  return l === 0n || l === 1n;
}

/** A square root of a, or null if a is not a square (p ≡ 5 mod 8). */
export function sqrt(a: bigint): bigint | null {
  a = mod(a);
  let x = modPow(a, (P + 3n) / 8n);
  if (mod(x * x) === a) return x;
  x = mod(x * SQRT_M1);
  if (mod(x * x) === a) return x;
  return null;
}

// ---------------------------------------------------------------- encoding

export function bytesToBigLE(b: Bytes): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

export function bigToBytesLE(x: bigint, n: number): Bytes {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** RFC 7748 decodeUCoordinate: clears bit 255 and reduces mod p. */
function decodeU(u: Bytes): bigint {
  if (u.length !== 32) throw new Error('a u-coordinate is 32 bytes');
  return mod(bytesToBigLE(u) & ((1n << 255n) - 1n));
}

// ---------------------------------------------------------------- ladder

/**
 * Montgomery ladder of RFC 7748 § 5 on the given number of scalar bits,
 * from the top. Returns the u-coordinate of k·(u, ·), 0 for the point at
 * infinity.
 */
function ladder(k: bigint, u: bigint, bits: number): bigint {
  const x1 = u;
  let x2 = 1n, z2 = 0n, x3 = u, z3 = 1n;
  let swap = 0n;
  for (let t = bits - 1; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = kt;
    const a = x2 + z2, aa = mod(a * a);
    const b = x2 - z2, bb = mod(b * b);
    const e = aa - bb;
    const c = x3 + z3, d = x3 - z3;
    const da = mod(d * a), cb = mod(c * b);
    x3 = mod((da + cb) * (da + cb));
    z3 = mod(x1 * mod((da - cb) * (da - cb)));
    x2 = mod(aa * bb);
    z2 = mod(e * (aa + A24 * e));
  }
  if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
  return mod(x2 * inv(z2));
}

/** X25519(k, u) of RFC 7748, with scalar clamping. */
export function x25519(k: Bytes, u: Bytes): Bytes {
  if (k.length !== 32) throw new Error('an X25519 scalar is 32 bytes');
  const s = Uint8Array.from(k);
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  return bigToBytesLE(ladder(bytesToBigLE(s), decodeU(u), 255), 32);
}

/** Ladder(s, u) of spec § 5.2: all 256 bits of s, no clamping. */
export function ladderUnclamped(s: bigint, u: Bytes): Bytes {
  if (s < 0n || s >= 1n << 256n) throw new Error('scalar out of range');
  return bigToBytesLE(ladder(s, decodeU(u), 256), 32);
}

export const BASE_U = bigToBytesLE(9n, 32);

/** u(G), G = Ed25519 base point plus a point of order 8 (spec § 5.2). */
export const G_FULL_U = Buffer.from(
  'bb72312170e8156f7a836313f85bee9b1fdce926ba9804a29e8d137ec67f2533',
  'hex',
);

/** A uniform scalar in [0, 8ℓ − 1]. */
export function randomFullScalar(): bigint {
  return uniformBigInt(8n * ELL - 1n);
}

// ---------------------------------------------------------------- Elligator 2

/** Elligator2.Map (spec § 5.4): RFC 9380 map with Z = 2, u only. */
export function elligatorMap(r32: Bytes): Bytes {
  if (r32.length !== 32) throw new Error('a representative is 32 bytes');
  const r = mod(bytesToBigLE(r32) & ((1n << 254n) - 1n));
  const den = mod(1n + 2n * r * r);
  const x1 = den === 0n ? mod(-A) : mod(-A * inv(den));
  const g = mod(x1 * x1 * x1 + A * x1 * x1 + x1);
  const u = isSquare(g) ? x1 : mod(-x1 - A);
  return bigToBytesLE(u, 32);
}

/**
 * Representative(u) (spec § 5.4), with the three random choices that make it
 * uniform. Returns null if u has no representative.
 */
export function elligatorRepresentative(uBytes: Bytes): Bytes | null {
  const u = bytesToBigLE(uBytes);
  if (u >= P) return null;
  const den = mod(-2n * u * (u + A));
  if (den === 0n) return null;
  const root = sqrt(den);
  if (root === null) return null;
  const rnd = random(1)[0];
  const t = (rnd & 1) === 0 ? u : mod(u + A);
  let r = mod(t * inv(root));
  if (r > (P - 1n) / 2n) r = P - r;
  const out = bigToBytesLE(r, 32);
  out[31] |= rnd & 0xc0; // bits 254 and 255: two uniform random bits
  return out;
}
