// Byte helpers and the symmetric primitives of spec § 2.1, all from node:crypto.

import {
  argon2Sync,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from 'node:crypto';

export type Bytes = Uint8Array;

export function concat(...parts: Bytes[]): Bytes {
  return Buffer.concat(parts);
}

export function utf8(s: string): Bytes {
  return Buffer.from(s, 'utf8');
}

export function hex(b: Bytes): string {
  return Buffer.from(b).toString('hex');
}

export function fromHex(s: string): Bytes {
  if (!/^([0-9a-fA-F]{2})*$/.test(s)) throw new Error('invalid hex string');
  return Buffer.from(s, 'hex');
}

/** BE64(x): 8-byte big-endian encoding of an unsigned integer x < 2^64. */
export function be64(x: number | bigint): Bytes {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(x));
  return out;
}

export function readBe64(b: Bytes, offset: number): bigint {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).readBigUInt64BE(offset);
}

/** Constant-time equality of two byte strings (lengths are public). */
export function ctEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ---------------------------------------------------------------- randomness

export function random(n: number): Bytes {
  return randomBytes(n);
}

/** Uniform integer in [lo, hi] (both included), without bias. */
export function uniformInt(lo: number, hi: number): number {
  if (!Number.isSafeInteger(lo) || !Number.isSafeInteger(hi) || hi < lo) {
    throw new Error('uniformInt: bad range');
  }
  if (hi - lo < 2 ** 48 - 1) return randomInt(lo, hi + 1);
  return Number(BigInt(lo) + uniformBigInt(BigInt(hi - lo)));
}

/** Uniform bigint in [0, max] (max included), by rejection sampling. */
export function uniformBigInt(max: bigint): bigint {
  if (max < 0n) throw new Error('uniformBigInt: negative bound');
  if (max === 0n) return 0n;
  const bits = max.toString(2).length;
  const nbytes = Math.ceil(bits / 8);
  const excess = BigInt(nbytes * 8 - bits);
  for (;;) {
    let x = BigInt('0x' + hex(randomBytes(nbytes)));
    x >>= excess;
    if (x <= max) return x;
  }
}

/** Uniform random permutation of [0, n) (Fisher-Yates). */
export function randomPermutation(n: number): number[] {
  const p = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [p[i], p[j]] = [p[j], p[i]];
  }
  return p;
}

// ---------------------------------------------------------------- hashes

export function sha256(data: Bytes): Bytes {
  return createHash('sha256').update(data).digest();
}

export function sha3_256(data: Bytes): Bytes {
  return createHash('sha3-256').update(data).digest();
}

export function sha3_512(data: Bytes): Bytes {
  return createHash('sha3-512').update(data).digest();
}

/** SHAKE256(x, n): the first n bytes of output. */
export function shake256(data: Bytes, n: number): Bytes {
  return createHash('shake256', { outputLength: n }).update(data).digest();
}

export function shake128(data: Bytes, n: number): Bytes {
  return createHash('shake128', { outputLength: n }).update(data).digest();
}

export function hmacSha256(key: Bytes, data: Bytes): Bytes {
  return createHmac('sha256', key).update(data).digest();
}

/** HKDF-SHA-256 with an absent salt (32 zero bytes), 32-byte output. */
export function hkdf(ikm: Bytes, info: Bytes): Bytes {
  return new Uint8Array(hkdfSync('sha256', ikm, Buffer.alloc(32), info, 32));
}

// ---------------------------------------------------------------- AEAD

/** ChaCha20-Poly1305, empty associated data; returns ciphertext ‖ tag. */
export function aeadSeal(key: Bytes, nonce: Bytes, plaintext: Bytes): Bytes {
  const c = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  const body = c.update(plaintext);
  const fin = c.final();
  return concat(body, fin, c.getAuthTag());
}

/** Opens ciphertext ‖ tag; returns null on authentication failure. */
export function aeadOpen(key: Bytes, nonce: Bytes, sealed: Bytes): Bytes | null {
  if (sealed.length < 16) return null;
  const d = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  const body = d.update(sealed.subarray(0, sealed.length - 16));
  try {
    const fin = d.final();
    return concat(body, fin);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- Argon2id

/** Argon2id v0x13, 64 MiB, 3 passes, parallelism 4, 32-byte output. */
export function argon2id(password: Bytes, salt: Bytes): Bytes {
  return argon2Sync('argon2id', {
    message: password,
    nonce: salt,
    parallelism: 4,
    tagLength: 32,
    memory: 65536,
    passes: 3,
  });
}
