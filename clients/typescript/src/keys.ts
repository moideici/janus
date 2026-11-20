// Identities and public keys (spec § 3.1, § 3.3).

import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { BASE_U, bytesToBigLE, P, x25519 } from './curve25519.ts';
import {
  decodeIdentity,
  decodePublicKeyBytes,
  encodeIdentity,
  encodePublicKey,
  PUBLIC_KEY_BYTES,
} from './bech32m.ts';
import { concat, random, shake256, type Bytes } from './primitives.ts';

export const EK_M_BYTES = 1184;

/** Key pair derived from a 32-byte seed, exactly as in X-Wing draft-11. */
export interface Identity {
  seed: Bytes;
  dkM: KeyObject; // ML-KEM-768 decapsulation key, from d ‖ z
  skX: Bytes;
  pkX: Bytes;
  pk: Bytes; // ek_M ‖ pk_X, 1216 bytes
}

export function identityFromSeed(seed: Bytes): Identity {
  if (seed.length !== 32) throw new Error('an identity seed is 32 bytes');
  const expanded = shake256(seed, 96);
  // node:crypto's ML-KEM "raw-seed" is the FIPS 203 seed d ‖ z (64 bytes):
  // importing it runs ML-KEM.KeyGen_internal(d, z).
  const dkM = createPrivateKey({
    key: Buffer.from(expanded.subarray(0, 64)),
    format: 'raw-seed',
    asymmetricKeyType: 'ml-kem-768',
  });
  const ekM = createPublicKey(dkM).export({ format: 'raw-public' });
  const skX = expanded.subarray(64, 96);
  const pkX = x25519(skX, BASE_U);
  return { seed, dkM, skX, pkX, pk: concat(ekM, pkX) };
}

export function newIdentity(): Identity {
  return identityFromSeed(random(32));
}

/** A recipient's public key, its ML-KEM part checked and imported. */
export interface PublicKey {
  pk: Bytes;
  ekM: KeyObject;
  pkX: Bytes;
}

/**
 * Imports a 1216-byte public key. node:crypto's raw-public import performs
 * the FIPS 203 encapsulation-key check (every coefficient below q).
 */
export function publicKeyFromBytes(pk: Bytes): PublicKey {
  if (pk.length !== PUBLIC_KEY_BYTES) throw new Error('a public key is 1216 bytes');
  let ekM: KeyObject;
  try {
    ekM = createPublicKey({
      key: Buffer.from(pk.subarray(0, EK_M_BYTES)),
      format: 'raw-public',
      asymmetricKeyType: 'ml-kem-768',
    });
  } catch {
    throw new Error('invalid public key (ML-KEM encapsulation-key check failed)');
  }
  // § 3.1: pk_X must be canonical (bit 255 clear, value < p). A canonical
  // low-order point is accepted, as in X-Wing.
  const pkX = pk.slice(EK_M_BYTES);
  if (bytesToBigLE(pkX) >= P) throw new Error('invalid public key (non-canonical X25519 part)');
  return { pk: Uint8Array.from(pk), ekM, pkX };
}

export function parsePublicKey(s: string): PublicKey {
  return publicKeyFromBytes(decodePublicKeyBytes(s.trim()));
}

export function publicKeyString(id: Identity): string {
  return encodePublicKey(id.pk);
}

export function identityString(id: Identity): string {
  return encodeIdentity(id.seed);
}

/** The text of an identity file, as written by the reference tool. */
export function identityFileText(id: Identity): string {
  return (
    '# Identité Janus (PROTOTYPE). Clé publique :\n' +
    `# ${publicKeyString(id)}\n` +
    `${identityString(id)}\n`
  );
}

/**
 * Parses an identity file: lines starting with '#' are comments; the first
 * line starting with JANUS-SECRET-KEY-1 (any case) is the identity, and if it
 * does not decode the file is invalid (later lines are not tried).
 * Surrounding whitespace (including a CR from CRLF line ends) and a leading
 * UTF-8 byte-order mark are ignored.
 */
export function parseIdentityFile(text: string): Identity {
  for (const raw of text.replace(/^﻿/, '').split('\n')) {
    const line = raw.trim();
    if (line.startsWith('#')) continue;
    if (line.toUpperCase().startsWith('JANUS-SECRET-KEY-1')) {
      return identityFromSeed(decodeIdentity(line));
    }
  }
  throw new Error('no JANUS-SECRET-KEY-1 line in the identity file');
}

/** Parses a recipients file: one public key per line, '#' comments. */
export function parseRecipientsFile(text: string): PublicKey[] {
  const keys: PublicKey[] = [];
  for (const raw of text.replace(/^﻿/, '').split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    keys.push(parsePublicKey(line));
  }
  return keys;
}
