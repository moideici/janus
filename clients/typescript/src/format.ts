// The Janus v1 file format: sizes and layout (§ 6), encryption (§ 7) and
// decryption (§ 8).

import type { Identity, PublicKey } from './keys.ts';
import {
  aeadOpen,
  aeadSeal,
  argon2id,
  be64,
  concat,
  ctEqual,
  hex,
  hkdf,
  hmacSha256,
  random,
  randomPermutation,
  readBe64,
  uniformInt,
  utf8,
  type Bytes,
} from './primitives.ts';
import { hiddenDecapsulate, hiddenEncapsulate } from './xwing.ts';

// ---------------------------------------------------------------- constants

export const N_SLOTS = 16;
export const N_TAGS = 4;
export const S = 1632;
export const H = 32 * N_TAGS + 32 + N_SLOTS * S; // 26 272
export const TB = 65536;
export const R_MIN = 65536;
export const RHO = 16;

const SALT_OFF = 32 * N_TAGS; // 128
const SLOTS_OFF = SALT_OFF + 32; // 160
const W_OFF = 1568; // W inside a slot

const LABEL_HEADER = utf8('janus/v1/entete');
const LABEL_BODY = utf8('janus/v1/corps');
const LABEL_WRAP_XWING = utf8('janus/v1/emballage/xwing');
const LABEL_WRAP_PASSWORD = utf8('janus/v1/emballage/mdp');

const ZERO_NONCE = new Uint8Array(12);

export class JanusError extends Error {}
export const CANNOT_DECRYPT = 'cannot decrypt';
export const SEVERAL_FACES = 'these credentials open several faces';

// ---------------------------------------------------------------- sizes (§ 6)

export function blocks(l: number): number {
  return Math.max(1, Math.ceil(l / TB));
}

/** Size of an encrypted face. */
export function faceSize(l: number): number {
  return l + 16 * blocks(l);
}

export function reserve(l1: number): number {
  return Math.max(R_MIN, Math.ceil(l1 / RHO));
}

/** PADME (Nikitin et al. 2019), with bigints to avoid 32-bit bit operations. */
export function padme(l: number): number {
  if (l < 2) return l;
  const L = BigInt(l);
  const e = BigInt(L.toString(2).length - 1); // ⌊log2 L⌋
  const s = BigInt(e.toString(2).length); // ⌊log2 E⌋ + 1
  const mask = (1n << (e - s)) - 1n;
  return Number((L + mask) & ~mask);
}

/** Spec § 6.2: width − 1 of the PADME bucket of an aligned size x. */
export function bucketMask(x: number): number {
  if (x < 2) return 0;
  const X = BigInt(x);
  const e = BigInt(X.toString(2).length - 1);
  const s = BigInt(e.toString(2).length);
  return Number((1n << (e - s)) - 1n);
}

// ---------------------------------------------------------------- inputs

export type Recipients =
  | { password: Bytes }
  | { keys: PublicKey[] };

export interface Face {
  plaintext: Bytes;
  recipients: Recipients;
}

export type Credentials =
  | { password: Bytes }
  | { identities: Identity[] };

/** Rules R1, R3, R5 of § 7 (plus the obvious structural limits). */
export function checkRules(main: Face, hidden: Face[]): void {
  const faces = [main, ...hidden];
  if (hidden.length > N_TAGS - 1) {
    throw new JanusError(`at most ${N_TAGS - 1} hidden faces`);
  }
  let total = 0;
  const passwords = new Set<string>();
  const keys = new Set<string>();
  for (const f of faces) {
    const r = f.recipients;
    if ('password' in r) {
      total += 1; // R1: a password face has exactly one recipient
      const k = hex(r.password);
      if (passwords.has(k)) throw new JanusError('two faces share a password');
      passwords.add(k);
    } else {
      if (r.keys.length < 1) throw new JanusError('a face needs at least one recipient');
      total += r.keys.length;
      const own = new Set<string>();
      for (const pk of r.keys) {
        const k = hex(pk.pk);
        if (own.has(k)) throw new JanusError('a public key appears twice in a face');
        if (keys.has(k)) throw new JanusError('a public key appears in two faces');
        own.add(k);
      }
      for (const k of own) keys.add(k);
    }
  }
  if (total > N_SLOTS) throw new JanusError(`at most ${N_SLOTS} recipients over all faces`);
  const hiddenSize = hidden.reduce((acc, f) => acc + faceSize(f.plaintext.length), 0);
  if (hiddenSize > reserve(main.plaintext.length)) {
    throw new JanusError('the hidden faces do not fit in the reserve');
  }
}

// ---------------------------------------------------------------- face STREAM (§ 7.1)

function blockNonce(j: number, last: boolean): Bytes {
  return concat(new Uint8Array(3), be64(j), Uint8Array.of(last ? 1 : 0));
}

function encryptFace(k: Bytes, plaintext: Bytes): Bytes {
  const kBody = hkdf(k, LABEL_BODY);
  const c = blocks(plaintext.length);
  const parts: Bytes[] = [];
  for (let j = 0; j < c; j++) {
    const block = plaintext.subarray(j * TB, Math.min((j + 1) * TB, plaintext.length));
    parts.push(aeadSeal(kBody, blockNonce(j, j === c - 1), block));
  }
  return concat(...parts);
}

function decryptFace(k: Bytes, body: Bytes, d: number, l: number): Bytes | null {
  const kBody = hkdf(k, LABEL_BODY);
  const c = blocks(l);
  const out = new Uint8Array(l);
  let pos = d;
  for (let j = 0; j < c; j++) {
    const plen = Math.min(TB, l - j * TB);
    const block = aeadOpen(kBody, blockNonce(j, j === c - 1), body.subarray(pos, pos + plen + 16));
    if (block === null) return null;
    out.set(block, j * TB);
    pos += plen + 16;
  }
  return out;
}

// ---------------------------------------------------------------- header helpers

function tag(k: Bytes, F: number | bigint, d: number | bigint, l: number | bigint, headerTail: Bytes): Bytes {
  return hmacSha256(hkdf(k, LABEL_HEADER), concat(be64(F), be64(d), be64(l), headerTail));
}

function passwordWrapKey(a: Bytes, i: number): Bytes {
  return hkdf(a, concat(LABEL_WRAP_PASSWORD, Uint8Array.of(i)));
}

function xwingWrapKey(ss: Bytes, i: number): Bytes {
  return hkdf(ss, concat(LABEL_WRAP_XWING, Uint8Array.of(i)));
}

function wrapPayload(k: Bytes, d: number, l: number): Bytes {
  return concat(k, be64(d), be64(l));
}

// ---------------------------------------------------------------- encryption (§ 7)

export function encrypt(main: Face, hidden: Face[] = []): Bytes {
  checkRules(main, hidden);
  const faces = [main, ...hidden];
  const L1 = main.plaintext.length;

  // 1. File size and offsets.
  const ref = H + faceSize(L1) + reserve(L1);
  const X = padme(ref);
  const F = uniformInt(X, X + bucketMask(X)); // spec § 6.2: the whole PADME bucket
  const B = F - H;
  const offsets = [0];
  const hiddenSizes = hidden.map((f) => faceSize(f.plaintext.length));
  const free = B - faceSize(L1) - hiddenSizes.reduce((a, b) => a + b, 0);
  const order = randomPermutation(hidden.length);
  const bs = hidden.map(() => uniformInt(0, free)).sort((x, y) => x - y);
  let placed = 0;
  for (let m = 0; m < hidden.length; m++) {
    const j = order[m];
    offsets[j + 1] = faceSize(L1) + bs[m] + placed;
    placed += hiddenSizes[j];
  }

  // 2. Random header; the salt is header[128:160].
  const header = random(H);
  const salt = header.subarray(SALT_OFF, SLOTS_OFF);

  // 3-4. Slots.
  const pi = randomPermutation(N_SLOTS);
  let next = 0;
  const keys: Bytes[] = [];
  for (let f = 0; f < faces.length; f++) {
    const face = faces[f];
    const K = random(32);
    keys.push(K);
    const payload = wrapPayload(K, offsets[f], face.plaintext.length);
    const r = face.recipients;
    if ('password' in r) {
      const i = pi[next++];
      const a = argon2id(r.password, salt);
      const w = aeadSeal(passwordWrapKey(a, i), ZERO_NONCE, payload);
      header.set(w, SLOTS_OFF + i * S + W_OFF);
    } else {
      for (const pub of r.keys) {
        const i = pi[next++];
        const { prefix, ss } = hiddenEncapsulate(pub);
        const w = aeadSeal(xwingWrapKey(ss, i), ZERO_NONCE, payload);
        header.set(concat(prefix, w), SLOTS_OFF + i * S);
      }
    }
  }

  // 5. Tags, at a random permutation of the 4 positions.
  const sigma = randomPermutation(N_TAGS);
  const tail = header.subarray(SALT_OFF, H);
  const tags = faces.map((face, f) => tag(keys[f], F, offsets[f], face.plaintext.length, tail));
  tags.forEach((t, f) => header.set(t, 32 * sigma[f]));

  // 6. Body: random, with each face at its offset.
  const body = random(B);
  faces.forEach((face, f) => body.set(encryptFace(keys[f], face.plaintext), offsets[f]));
  return concat(header, body);
}

// ---------------------------------------------------------------- decryption (§ 8)

/**
 * Opens the face that the credentials open. Throws JanusError with
 * CANNOT_DECRYPT or SEVERAL_FACES. Steps 2 to 4 do the same work whatever
 * matches: 16 slot attempts (× identities), one MAC per attempt, 4 tag
 * comparisons per MAC.
 */
export function decrypt(file: Bytes, cred: Credentials): Bytes {
  if (file.length < H) throw new JanusError(CANNOT_DECRYPT);
  const F = file.length;
  const header = file.subarray(0, H);
  const salt = header.subarray(SALT_OFF, SLOTS_OFF);
  const tail = header.subarray(SALT_OFF, H);
  const fileTags = Array.from({ length: N_TAGS }, (_, t) => header.subarray(32 * t, 32 * t + 32));

  // 2. Candidate wrapping keys, always for all 16 slots.
  const attempts: { i: number; key: Bytes }[] = [];
  if ('password' in cred) {
    const a = argon2id(cred.password, salt);
    for (let i = 0; i < N_SLOTS; i++) attempts.push({ i, key: passwordWrapKey(a, i) });
  } else {
    if (cred.identities.length === 0) throw new JanusError(CANNOT_DECRYPT);
    for (let i = 0; i < N_SLOTS; i++) {
      const slot = header.subarray(SLOTS_OFF + i * S, SLOTS_OFF + (i + 1) * S);
      for (const id of cred.identities) {
        attempts.push({ i, key: xwingWrapKey(hiddenDecapsulate(id, slot.subarray(0, W_OFF)), i) });
      }
    }
  }

  // 2-3. Open every W, compute every tag.
  const valid = new Map<string, Bytes>();
  for (const { i, key } of attempts) {
    const w = header.subarray(SLOTS_OFF + i * S + W_OFF, SLOTS_OFF + (i + 1) * S);
    const opened = aeadOpen(key, ZERO_NONCE, w);
    const triple = opened ?? new Uint8Array(48);
    const t = tag(triple.subarray(0, 32), F, readBe64(triple, 32), readBe64(triple, 40), tail);
    let matched = false;
    for (const ft of fileTags) matched = ctEqual(t, ft) || matched;
    // 4. Deduplicate on the full triple (K, d, l).
    if (opened !== null && matched) valid.set(hex(triple), triple);
  }
  if (valid.size === 0) throw new JanusError(CANNOT_DECRYPT);
  if (valid.size > 1) throw new JanusError(SEVERAL_FACES);
  const [triple] = valid.values();
  const K = triple.subarray(0, 32);
  const d = readBe64(triple, 32);
  const l = readBe64(triple, 40);

  // 5. Bounds, in bigints (no overflow).
  const c = l === 0n ? 1n : (l + BigInt(TB) - 1n) / BigInt(TB);
  if (d + l + 16n * c > BigInt(F - H)) throw new JanusError(CANNOT_DECRYPT);

  // 6. Body.
  const out = decryptFace(K, file.subarray(H), Number(d), Number(l));
  if (out === null) throw new JanusError(CANNOT_DECRYPT);
  return out;
}
