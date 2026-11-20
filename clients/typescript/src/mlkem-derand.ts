// ML-KEM-768.Encaps_internal (FIPS 203, Algorithms 14 and 17), for TESTS
// ONLY. node:crypto has no derandomized encapsulation, and the X-Wing test
// vector fixes the ML-KEM randomness m. Janus itself uses node:crypto's
// ML-KEM-768 (keys.ts, xwing.ts); this file only lets the tests reproduce
// draft-connolly-cfrg-xwing-kem-11 test vector 1.

import { compress } from './kemeleon.ts';
import { concat, sha3_256, sha3_512, shake128, shake256, type Bytes } from './primitives.ts';

const Q = 3329;
const K = 3;
const ETA = 2;

function bitRev7(i: number): number {
  let r = 0;
  for (let b = 0; b < 7; b++) r |= ((i >> b) & 1) << (6 - b);
  return r;
}

function powMod(b: number, e: number): number {
  let r = 1;
  for (let i = 0; i < e; i++) r = (r * b) % Q;
  return r;
}

const ZETAS = Array.from({ length: 128 }, (_, i) => powMod(17, bitRev7(i)));
const GAMMAS = Array.from({ length: 128 }, (_, i) => powMod(17, 2 * bitRev7(i) + 1));

const m = (x: number) => ((x % Q) + Q) % Q;

function ntt(f: number[]): number[] {
  const a = f.slice();
  let i = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const z = ZETAS[i++];
      for (let j = start; j < start + len; j++) {
        const t = m(z * a[j + len]);
        a[j + len] = m(a[j] - t);
        a[j] = m(a[j] + t);
      }
    }
  }
  return a;
}

function invNtt(f: number[]): number[] {
  const a = f.slice();
  let i = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const z = ZETAS[i--];
      for (let j = start; j < start + len; j++) {
        const t = a[j];
        a[j] = m(t + a[j + len]);
        a[j + len] = m(z * (a[j + len] - t));
      }
    }
  }
  return a.map((x) => m(x * 3303));
}

function mulNtt(f: number[], g: number[]): number[] {
  const h = new Array<number>(256);
  for (let i = 0; i < 128; i++) {
    const [a0, a1, b0, b1] = [f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]];
    h[2 * i] = m(a0 * b0 + m(a1 * b1) * GAMMAS[i]);
    h[2 * i + 1] = m(a0 * b1 + a1 * b0);
  }
  return h;
}

const add = (f: number[], g: number[]) => f.map((x, i) => m(x + g[i]));

function bits(b: Bytes): number[] {
  const out: number[] = [];
  for (const x of b) for (let i = 0; i < 8; i++) out.push((x >> i) & 1);
  return out;
}

function byteDecode(b: Bytes, d: number): number[] {
  const bs = bits(b);
  const out: number[] = [];
  for (let i = 0; i < bs.length / d; i++) {
    let v = 0;
    for (let j = 0; j < d; j++) v |= bs[i * d + j] << j;
    out.push(v);
  }
  return out;
}

function byteEncode(f: number[], d: number): Bytes {
  const bs: number[] = [];
  for (const v of f) for (let j = 0; j < d; j++) bs.push((v >> j) & 1);
  const out = new Uint8Array(bs.length / 8);
  for (let i = 0; i < bs.length; i++) out[i >> 3] |= bs[i] << (i & 7);
  return out;
}

function sampleNtt(seed: Bytes): number[] {
  for (let len = 840; ; len *= 2) {
    const s = shake128(seed, len);
    const a: number[] = [];
    for (let p = 0; p + 3 <= s.length && a.length < 256; p += 3) {
      const d1 = s[p] + 256 * (s[p + 1] & 15);
      const d2 = (s[p + 1] >> 4) + 16 * s[p + 2];
      if (d1 < Q) a.push(d1);
      if (d2 < Q && a.length < 256) a.push(d2);
    }
    if (a.length === 256) return a;
  }
}

function cbd(b: Bytes): number[] {
  const bs = bits(b);
  const f: number[] = [];
  for (let i = 0; i < 256; i++) {
    let x = 0, y = 0;
    for (let j = 0; j < ETA; j++) {
      x += bs[2 * i * ETA + j];
      y += bs[2 * i * ETA + ETA + j];
    }
    f.push(m(x - y));
  }
  return f;
}

const prf = (s: Bytes, n: number) => shake256(concat(s, Uint8Array.of(n)), 64 * ETA);

/** ML-KEM-768.Encaps_internal(ek, m) → (K, ct). */
export function mlkemEncapsDerand(ek: Bytes, msg: Bytes): { ss: Bytes; ct: Bytes } {
  const g = sha3_512(concat(msg, sha3_256(ek)));
  const ss = g.subarray(0, 32);
  const r = g.subarray(32, 64);
  const tHat = [0, 1, 2].map((i) => byteDecode(ek.subarray(384 * i, 384 * (i + 1)), 12));
  const rho = ek.subarray(384 * K);
  let n = 0;
  const y = [0, 1, 2].map(() => ntt(cbd(prf(r, n++))));
  const e1 = [0, 1, 2].map(() => cbd(prf(r, n++)));
  const e2 = cbd(prf(r, n++));
  const u = [0, 1, 2].map((i) => {
    // (Â^T ∘ ŷ)[i] = Σ_j Â[j][i] ∘ ŷ[j], with Â[j][i] = SampleNTT(ρ ‖ i ‖ j).
    let acc = new Array<number>(256).fill(0);
    for (let j = 0; j < K; j++) acc = add(acc, mulNtt(sampleNtt(concat(rho, Uint8Array.of(i, j))), y[j]));
    return add(invNtt(acc), e1[i]);
  });
  const mu = byteDecode(msg, 1).map((b) => (b ? 1665 : 0));
  let vHat = new Array<number>(256).fill(0);
  for (let j = 0; j < K; j++) vHat = add(vHat, mulNtt(tHat[j], y[j]));
  const v = add(add(invNtt(vHat), e2), mu);
  const c1 = concat(...u.map((p) => byteEncode(p.map((x) => compress(x, 10)), 10)));
  const c2 = byteEncode(v.map((x) => compress(x, 4)), 4);
  return { ss: Uint8Array.from(ss), ct: concat(c1, c2) };
}
