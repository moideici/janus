// Tests of the TypeScript Janus client. Run with:
//   node --test clients/typescript/test.ts      or      node clients/typescript/test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decapsulate } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bech32mDecode, decodeIdentity, decodePublicKeyBytes, encodeIdentity, encodePublicKey, bech32mEncode, toWords } from './src/bech32m.ts';
import { BASE_U, bigToBytesLE, elligatorMap, elligatorRepresentative, G_FULL_U, ladderUnclamped, randomFullScalar, x25519 } from './src/curve25519.ts';
import { decrypt, encrypt, faceSize, H, JanusError, padme, reserve, SEVERAL_FACES, CANNOT_DECRYPT, type Face, type Credentials } from './src/format.ts';
import { decodeCtxt, encodeCtxt } from './src/kemeleon.ts';
import {
  identityFileText,
  identityFromSeed,
  identityString,
  newIdentity,
  parseIdentityFile,
  parsePublicKey,
  publicKeyFromBytes,
  publicKeyString,
  type Identity,
} from './src/keys.ts';
import { mlkemEncapsDerand } from './src/mlkem-derand.ts';
import { concat, fromHex, hex, random, sha256, utf8, type Bytes } from './src/primitives.ts';
import { combine } from './src/xwing.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const VECTORS = join(ROOT, 'janus-rs', 'vecteurs');
const RUST = join(ROOT, 'janus-rs', 'target', 'release', process.platform === 'win32' ? 'janus.exe' : 'janus');

const seedOf = (i: number) => new Uint8Array(32).fill(i + 1);
const pw = (s: string): Credentials => ({ password: utf8(s) });
const ids = (...list: Identity[]): Credentials => ({ identities: list });
const pk = (id: Identity) => publicKeyFromBytes(id.pk);

function mainPlain(n: number): Bytes {
  return Uint8Array.from({ length: n }, (_, k) => (31 * k + 7) % 256);
}

function assertFails(file: Bytes, cred: Credentials, message = CANNOT_DECRYPT): void {
  assert.throws(() => decrypt(file, cred), (e: unknown) => e instanceof JanusError && e.message === message);
}

// ---------------------------------------------------------------- 1. X-Wing

test('X-Wing draft-11 test vector 1', () => {
  const id = identityFromSeed(fromHex('7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'));
  const eseed = fromHex(
    '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
      '35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2',
  );
  // node:crypto has no derandomized ML-KEM encapsulation: the test-only
  // FIPS 203 Encaps_internal computes ct_M from m = eseed[0:32], and
  // node:crypto's decapsulation (the one Janus uses) must agree with it.
  const { ss: ssM, ct: ctM } = mlkemEncapsDerand(id.pk.subarray(0, 1184), eseed.subarray(0, 32));
  assert.equal(hex(decapsulate(id.dkM, ctM)), hex(ssM));
  const ekX = eseed.subarray(32, 64);
  const ctX = x25519(ekX, BASE_U);
  const ssX = x25519(ekX, id.pkX);
  assert.equal(hex(x25519(id.skX, ctX)), hex(ssX));
  assert.equal(hex(combine(ssM, ssX, ctX, id.pkX)), 'd2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384');
});

test('RFC 7748 X25519 test vector', () => {
  const k = fromHex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
  const u = fromHex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
  assert.equal(hex(x25519(k, u)), 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');
});

test('hidden X25519: unclamped ladder, Elligator 2 round trip', () => {
  const id = identityFromSeed(seedOf(0));
  for (let n = 0; n < 8; n++) {
    let s: bigint, ctX: Bytes, r: Bytes | null;
    do {
      s = randomFullScalar();
      ctX = ladderUnclamped(s, G_FULL_U);
      r = elligatorRepresentative(ctX);
    } while (r === null);
    assert.equal(hex(elligatorMap(r)), hex(ctX));
    assert.equal(hex(ladderUnclamped(s, id.pkX)), hex(x25519(id.skX, ctX)));
  }
});

test('Kemeleon encode/decode round trip', () => {
  const id = identityFromSeed(seedOf(0));
  const { ct } = mlkemEncapsDerand(id.pk.subarray(0, 1184), random(32));
  const k = encodeCtxt(ct);
  assert.equal(k.length, 1536);
  assert.equal(hex(decodeCtxt(k)), hex(ct));
});

// ---------------------------------------------------------------- 2. Bech32m

test('BIP 350 Bech32m vectors', () => {
  for (const s of ['A1LQFN3A', 'a1lqfn3a', 'abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx', '?1v759aa']) {
    const { hrp, data } = bech32mDecode(s);
    assert.equal(bech32mEncode(hrp, data), s.toLowerCase());
  }
  for (const s of ['a12uel5l', 'A1lqfn3a']) assert.throws(() => bech32mDecode(s));
});

test('Janus key strings: rejections', () => {
  const id = identityFromSeed(seedOf(0));
  const idStr = identityString(id);
  const pkStr = publicKeyString(id);
  assert.equal(idStr.length, 76);
  assert.equal(pkStr.length, 1958);
  assert.equal(hex(decodeIdentity(idStr.toLowerCase())), hex(seedOf(0)));
  assert.throws(() => decodeIdentity(idStr.slice(0, 30) + idStr.slice(30).toLowerCase())); // mixed case
  assert.throws(() => decodeIdentity(pkStr)); // public key as identity
  assert.throws(() => decodePublicKeyBytes(idStr)); // identity as public key
  assert.throws(() => decodeIdentity(idStr.slice(0, -1) + (idStr.endsWith('Q') ? 'P' : 'Q'))); // checksum
  assert.throws(() => decodeIdentity(bech32mEncode('janus-secret-key-', toWords(new Uint8Array(31))))); // length
  // Non-zero padding: 32 bytes = 52 groups with 4 padding bits; set one.
  const words = toWords(seedOf(0));
  words[words.length - 1] |= 1;
  assert.throws(() => decodeIdentity(bech32mEncode('janus-secret-key-', words)));
  // Over-long padding: one extra zero group.
  assert.throws(() => decodeIdentity(bech32mEncode('janus-secret-key-', [...toWords(seedOf(0)), 0])));
  // ML-KEM encapsulation-key check: a coefficient ≥ q.
  const bad = Uint8Array.from(id.pk);
  bad[0] = 0xff;
  bad[1] = 0x0f; // first 12-bit coefficient = 4095
  assert.throws(() => publicKeyFromBytes(bad));
  // Identity files: comments, CRLF, any case.
  const text = identityFileText(id).replace(/\n/g, '\r\n');
  assert.equal(hex(parseIdentityFile(text).pk), hex(id.pk));
  assert.equal(hex(parseIdentityFile(`# x\n${idStr.toLowerCase()}\n`).pk), hex(id.pk));
  assert.equal(encodeIdentity(seedOf(0)), idStr);
});

test('§ 3.1: non-canonical pk_X rejected, canonical low-order pk_X accepted', () => {
  const id = identityFromSeed(seedOf(0));
  const withX = (x: Bytes) => concat(id.pk.subarray(0, 1184), x);
  const pBytes = Buffer.alloc(32, 0xff);
  pBytes[0] = 0xed;
  pBytes[31] = 0x7f; // p = 2^255 − 19
  const bit255 = Uint8Array.from(id.pkX);
  bit255[31] |= 0x80;
  for (const x of [pBytes, bit255, Buffer.alloc(32, 0xff)]) {
    assert.throws(() => publicKeyFromBytes(withX(x)));
    assert.throws(() => parsePublicKey(encodePublicKey(withX(x))));
  }
  const pMinus1 = Buffer.from(pBytes);
  pMinus1[0] = 0xec;
  const lowOrder = [
    new Uint8Array(32), // u = 0
    bigToBytesLE(1n, 32), // u = 1
    fromHex('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'), // order 8
    pMinus1, // u = −1, order 4
  ];
  for (const x of lowOrder) {
    const pub = parsePublicKey(encodePublicKey(withX(x)));
    assert.equal(hex(pub.pkX), hex(x));
    assert.ok(encrypt({ plaintext: random(10), recipients: { keys: [pub] } }).length > H);
  }
});

test('§ 3.3: identity files', () => {
  const id = identityFromSeed(seedOf(0));
  const good = identityString(id);
  const other = identityString(identityFromSeed(seedOf(1)));
  // UTF-8 BOM, CRLF, surrounding whitespace.
  const text = '﻿# comment\r\n\r\n  ' + good + '  \r\n';
  assert.equal(hex(parseIdentityFile(text).pk), hex(id.pk));
  assert.equal(hex(parseIdentityFile(Buffer.from(text, 'utf8').toString('utf8')).pk), hex(id.pk));
  // The first JANUS-SECRET-KEY-1 line decides: an invalid one makes the
  // file invalid, even if a valid identity follows.
  const broken = good.slice(0, -1) + (good.endsWith('Q') ? 'P' : 'Q');
  assert.throws(() => parseIdentityFile(`${broken}\n${good}\n`));
  assert.throws(() => parseIdentityFile(`# ${good}\njanus-secret-key-1qqqq\n${good}\n`));
  // Only the first valid line counts.
  assert.equal(hex(parseIdentityFile(`${good}\n${other}\n`).pk), hex(id.pk));
  assert.throws(() => parseIdentityFile('# nothing here\n'));
});

// ---------------------------------------------------------------- 3. cles.json

test('cles.json reproduced from its seeds', () => {
  const doc = JSON.parse(readFileSync(join(VECTORS, 'cles.json'), 'utf8'));
  assert.equal(doc.cles.length, 3);
  for (const c of doc.cles) {
    const id = identityFromSeed(fromHex(c.graine));
    assert.equal(identityString(id), c.identite);
    assert.equal(publicKeyString(id), c.cle_publique);
    assert.equal(hex(sha256(id.pk)), c.cle_publique_hex_sha256);
    assert.equal(hex(parsePublicKey(c.cle_publique).pk), hex(id.pk));
  }
});

// ---------------------------------------------------------------- 4. vectors

test('manifeste.json: every vector, every credential, every hidden face', () => {
  const t0 = performance.now();
  const doc = JSON.parse(readFileSync(join(VECTORS, 'manifeste.json'), 'utf8'));
  const foreign = identityFromSeed(new Uint8Array(32).fill(0xee));
  let opened = 0;
  for (const v of doc.vecteurs) {
    const file = readFileSync(join(VECTORS, v.fichier));
    assert.equal(file.length, v.taille, v.nom);
    assert.equal(hex(sha256(file)), v.sha256_fichier, v.nom);
    const o = v.ouverture;
    if (o.type === 'mot_de_passe') {
      const out = decrypt(file, pw(o.valeur));
      assert.equal(out.length, v.clair_longueur, v.nom);
      assert.equal(hex(sha256(out)), v.sha256_clair, v.nom);
      opened++;
      for (const [j, h] of (o.visages_caches ?? []).entries()) {
        const hid = decrypt(file, pw(h.mot_de_passe));
        assert.equal(hid.length, h.clair_longueur, `${v.nom} hidden ${j}`);
        assert.equal(hex(sha256(hid)), h.sha256_clair, `${v.nom} hidden ${j}`);
        const expected = Uint8Array.from({ length: h.clair_longueur }, (_, k) => (17 * k + 3 + 50 * j) % 256);
        assert.equal(hex(hid), hex(expected));
        opened++;
      }
      assertFails(file, pw('wrong password'));
    } else {
      for (const s of o.chacune_ouvre) {
        const out = decrypt(file, ids(identityFromSeed(fromHex(s))));
        assert.equal(hex(sha256(out)), v.sha256_clair, `${v.nom} ${s.slice(0, 2)}`);
        opened++;
      }
      assert.equal(hex(decrypt(file, ids(foreign, identityFromSeed(fromHex(o.chacune_ouvre[0]))))), hex(mainPlain(v.clair_longueur)));
      assertFails(file, pw('janus'));
    }
    assertFails(file, ids(foreign));
  }
  console.log(`# vectors: ${opened} openings in ${(performance.now() - t0).toFixed(0)} ms`);
});

test('vectors: truncated or modified files fail', () => {
  const file = readFileSync(join(VECTORS, 'mot-de-passe.janus'));
  assertFails(file.subarray(0, H - 1), pw('janus'));
  assertFails(file.subarray(0, file.length - 1), pw('janus')); // F is in the tag
  assertFails(Buffer.concat([file, Buffer.alloc(1)]), pw('janus'));
  const flipped = Buffer.from(file);
  flipped[H + 5] ^= 1; // main face body
  assertFails(flipped, pw('janus'));
  const salt = Buffer.from(file);
  salt[130] ^= 1;
  assertFails(salt, pw('janus'));
});

// ---------------------------------------------------------------- 5. round trips

const ALICE = identityFromSeed(seedOf(0));
const BOB = identityFromSeed(seedOf(1));
const CAROL = identityFromSeed(seedOf(2));

function face(plaintext: Bytes, r: { pass: string } | { to: Identity[] }): Face {
  return { plaintext, recipients: 'pass' in r ? { password: utf8(r.pass) } : { keys: r.to.map(pk) } };
}

function checkSize(file: Bytes, l1: number): void {
  const ref = H + faceSize(l1) + reserve(l1);
  assert.ok(file.length >= ref && file.length <= padme(ref), `size ${file.length} not in [${ref}, ${padme(ref)}]`);
}

test('round trip: password', () => {
  const p = utf8('un mot de passe — été');
  const f = encrypt(face(p, { pass: 'motdepasse' }));
  checkSize(f, p.length);
  assert.equal(hex(decrypt(f, pw('motdepasse'))), hex(p));
  assertFails(f, pw('motdepass'));
  assertFails(f, ids(ALICE));
});

test('round trip: one key and sixteen keys', () => {
  const p = random(1234);
  const f1 = encrypt(face(p, { to: [ALICE] }));
  assert.equal(hex(decrypt(f1, ids(ALICE))), hex(p));
  assert.equal(hex(decrypt(f1, ids(BOB, ALICE))), hex(p));
  assertFails(f1, ids(BOB));
  const sixteen = Array.from({ length: 16 }, (_, i) => identityFromSeed(seedOf(i)));
  const f16 = encrypt(face(p, { to: sixteen }));
  for (const id of sixteen) assert.equal(hex(decrypt(f16, ids(id))), hex(p));
  assertFails(f16, ids(identityFromSeed(new Uint8Array(32).fill(0xee))));
});

test('round trip: decoy + 1 hidden face, decoy + 3 hidden faces', () => {
  const decoy = random(5000);
  const h1 = random(700);
  const f = encrypt(face(decoy, { pass: 'leurre' }), [face(h1, { to: [ALICE, BOB] })]);
  checkSize(f, decoy.length);
  assert.equal(hex(decrypt(f, pw('leurre'))), hex(decoy));
  assert.equal(hex(decrypt(f, ids(ALICE))), hex(h1));
  assert.equal(hex(decrypt(f, ids(BOB))), hex(h1));
  assertFails(f, ids(CAROL));

  const hs = [random(30000), random(0), random(20000)];
  const g = encrypt(face(decoy, { to: [ALICE] }), [
    face(hs[0], { pass: 'premier' }),
    face(hs[1], { to: [BOB] }),
    face(hs[2], { pass: 'troisieme' }),
  ]);
  checkSize(g, decoy.length);
  assert.equal(hex(decrypt(g, ids(ALICE))), hex(decoy));
  assert.equal(hex(decrypt(g, pw('premier'))), hex(hs[0]));
  assert.equal(hex(decrypt(g, ids(BOB))), hex(hs[1]));
  assert.equal(hex(decrypt(g, pw('troisieme'))), hex(hs[2]));
  // Credentials of two faces at once: the distinct error.
  assertFails(g, ids(ALICE, BOB), SEVERAL_FACES);
});

test('round trip: empty plaintext, 65 536 and 65 537 bytes', () => {
  for (const n of [0, 1, 65535, 65536, 65537, 3 * 65536]) {
    const p = random(n);
    const f = encrypt(face(p, { to: [ALICE] }));
    checkSize(f, n);
    assert.equal(hex(decrypt(f, ids(ALICE))), hex(p), `length ${n}`);
  }
  // A hidden face filling the whole reserve exactly (64 KiB minimum).
  const f = encrypt(face(random(10), { pass: 'a' }), [face(random(65536 - 16), { pass: 'b' })]);
  assert.equal(decrypt(f, pw('b')).length, 65536 - 16);
});

test('encryption rules are enforced', () => {
  const p = random(10);
  const seventeen = Array.from({ length: 17 }, (_, i) => identityFromSeed(seedOf(i)));
  const refuse = (fn: () => unknown) => assert.throws(fn, JanusError);
  refuse(() => encrypt(face(p, { to: seventeen })));
  refuse(() => encrypt(face(p, { to: seventeen.slice(0, 15) }), [face(p, { pass: 'x' }), face(p, { pass: 'y' })]));
  refuse(() => encrypt(face(p, { pass: 'same' }), [face(p, { pass: 'same' })]));
  refuse(() => encrypt(face(p, { pass: 'a' }), [face(p, { pass: 'b' }), face(p, { pass: 'b' })]));
  refuse(() => encrypt(face(p, { to: [ALICE] }), [face(p, { to: [BOB, ALICE] })]));
  refuse(() => encrypt(face(p, { to: [ALICE, ALICE] })));
  refuse(() => encrypt(face(p, { pass: 'a' }), [face(random(65536 - 15), { pass: 'b' })])); // reserve + 1
  refuse(() => encrypt(face(random(16 * 65536 * 2), { pass: 'a' }), [face(random(70000), { pass: 'b' }), face(random(70000), { pass: 'c' })]));
  refuse(() => encrypt(face(p, { pass: 'a' }), [face(p, { pass: 'b' }), face(p, { pass: 'c' }), face(p, { pass: 'd' }), face(p, { pass: 'e' })]));
  refuse(() => encrypt(face(p, { to: [] })));
  // 16 recipients over 4 faces is fine.
  const ok = encrypt(face(p, { to: seventeen.slice(0, 13) }), [face(p, { pass: 'x' }), face(p, { pass: 'y' }), face(p, { pass: 'z' })]);
  assert.equal(hex(decrypt(ok, ids(seventeen[12]))), hex(p));
});

// ---------------------------------------------------------------- 6. interop

function rust(args: string[], env: Record<string, string> = {}): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(RUST, args, { env: { ...process.env, ...env }, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function ok(r: { status: number | null; stderr: string }): void {
  assert.equal(r.status, 0, r.stderr);
}

test('interoperability with the reference binary', { skip: existsSync(RUST) ? false : `reference binary not found (${RUST}); build janus-rs to run this test` }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'janus-ts-'));
  try {
    const p = (name: string) => join(dir, name);
    const decoy = random(150000);
    const s1 = utf8('premier secret '.repeat(100));
    const s2 = random(5000);
    const s3 = random(300);
    writeFileSync(p('decoy'), decoy);
    writeFileSync(p('s1'), s1);
    writeFileSync(p('s2'), s2);
    writeFileSync(p('s3'), s3);

    // Identities: one made by the reference tool, one by us; files swap.
    const rustPkStr = rust(['cles', p('rust.id')]).stdout.trim();
    const rustId = parseIdentityFile(readFileSync(p('rust.id'), 'utf8'));
    assert.equal(publicKeyString(rustId), rustPkStr);
    const tsId = newIdentity();
    writeFileSync(p('ts.id'), identityFileText(tsId));
    assert.equal(rust(['publique', p('ts.id')]).stdout.trim(), publicKeyString(tsId));

    // --- ours → Rust
    const rustOpens = (file: string, out: string, cred: { pass: string } | { id: string }) =>
      'pass' in cred
        ? rust(['dechiffrer', '-m', file, p(out)], { JANUS_MDP: cred.pass })
        : rust(['dechiffrer', '-i', cred.id, file, p(out)]);
    const expect = (r: ReturnType<typeof rust>, out: string, data: Bytes) => {
      ok(r);
      assert.equal(hex(sha256(readFileSync(p(out)))), hex(sha256(data)));
    };

    writeFileSync(p('a.janus'), encrypt(face(s1, { pass: 'correct horse é' })));
    expect(rustOpens(p('a.janus'), 'a.out', { pass: 'correct horse é' }), 'a.out', s1);
    const bad = rustOpens(p('a.janus'), 'a.bad', { pass: 'wrong' });
    assert.notEqual(bad.status, 0);
    assert.ok(!existsSync(p('a.bad')));

    writeFileSync(p('b.janus'), encrypt(face(decoy, { to: [publicKeyFromBytes(rustId.pk)] })));
    expect(rustOpens(p('b.janus'), 'b.out', { id: p('rust.id') }), 'b.out', decoy);

    writeFileSync(
      p('c.janus'),
      encrypt(face(decoy, { pass: 'leurre' }), [
        face(s1, { pass: 'visage-1' }),
        face(s2, { to: [publicKeyFromBytes(rustId.pk)] }),
        face(s3, { pass: 'visage-3' }),
      ]),
    );
    expect(rustOpens(p('c.janus'), 'c0.out', { pass: 'leurre' }), 'c0.out', decoy);
    expect(rustOpens(p('c.janus'), 'c1.out', { pass: 'visage-1' }), 'c1.out', s1);
    expect(rustOpens(p('c.janus'), 'c2.out', { id: p('rust.id') }), 'c2.out', s2);
    expect(rustOpens(p('c.janus'), 'c3.out', { pass: 'visage-3' }), 'c3.out', s3);

    // --- Rust → ours
    ok(rust(['chiffrer', '-m', p('s1'), p('d.janus')], { JANUS_MDP: 'correct horse é' }));
    assert.equal(hex(decrypt(readFileSync(p('d.janus')), pw('correct horse é'))), hex(s1));

    ok(rust(['chiffrer', '-r', publicKeyString(tsId), '-r', rustPkStr, p('decoy'), p('e.janus')]));
    const e = readFileSync(p('e.janus'));
    assert.equal(hex(decrypt(e, ids(tsId))), hex(decoy));
    assert.equal(hex(decrypt(e, ids(rustId))), hex(decoy));

    ok(
      rust(
        ['chiffrer', '-m', p('decoy'), p('f.janus'), '--cache', '-m', p('s1'), '--cache', '-r', publicKeyString(tsId), p('s2'), '--cache', '-m', p('s3')],
        { JANUS_MDP: 'leurre', JANUS_MDP_CACHE: 'secret', JANUS_MDP_CACHE3: 'troisieme' },
      ),
    );
    const f = readFileSync(p('f.janus'));
    assert.equal(hex(decrypt(f, pw('leurre'))), hex(decoy));
    assert.equal(hex(decrypt(f, pw('secret'))), hex(s1));
    assert.equal(hex(decrypt(f, ids(tsId))), hex(s2));
    assert.equal(hex(decrypt(f, pw('troisieme'))), hex(s3));
    assertFails(f, pw('mauvais'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('command line: keygen, pubkey, encrypt, decrypt', () => {
  const dir = mkdtempSync(join(tmpdir(), 'janus-ts-cli-'));
  try {
    const cli = (...args: string[]) => spawnSync(process.execPath, [join(HERE, 'janus.ts'), ...args], { encoding: 'utf8' });
    const p = (name: string) => join(dir, name);
    const k = cli('keygen', p('me.id'));
    assert.equal(k.status, 0, k.stderr);
    const pub = k.stdout.trim();
    assert.equal(cli('pubkey', p('me.id')).stdout.trim(), pub);
    writeFileSync(p('in'), 'decoy');
    writeFileSync(p('secret'), 'hidden');
    writeFileSync(p('keys'), `# recipients\n${pub}\n`);
    const e = cli('encrypt', p('x.janus'), p('in'), '--pass', 'pw', '--hidden', p('secret'), '--to-file', p('keys'));
    assert.equal(e.status, 0, e.stderr);
    assert.equal(cli('decrypt', p('x.janus'), p('o1'), '--pass', 'pw').status, 0);
    assert.equal(readFileSync(p('o1'), 'utf8'), 'decoy');
    assert.equal(cli('decrypt', p('x.janus'), p('o2'), '--id', p('me.id')).status, 0);
    assert.equal(readFileSync(p('o2'), 'utf8'), 'hidden');
    const bad = cli('decrypt', p('x.janus'), p('o3'), '--pass', 'nope');
    assert.equal(bad.status, 1);
    assert.equal(bad.stderr.trim(), 'cannot decrypt');
    assert.ok(!existsSync(p('o3')));
    // No overwriting (keygen, encrypt, decrypt): status 1, file untouched.
    const before = readFileSync(p('me.id'), 'utf8');
    const again = cli('keygen', p('me.id'));
    assert.equal(again.status, 1, again.stderr);
    assert.equal(again.stdout, '');
    assert.equal(readFileSync(p('me.id'), 'utf8'), before);
    assert.equal(cli('encrypt', p('o1'), p('in'), '--pass', 'pw').status, 1);
    assert.equal(readFileSync(p('o1'), 'utf8'), 'decoy');
    assert.equal(cli('decrypt', p('x.janus'), p('o2'), '--pass', 'pw').status, 1);
    assert.equal(readFileSync(p('o2'), 'utf8'), 'hidden');
    // Usage errors: status 2.
    for (const args of [[], ['frobnicate'], ['keygen'], ['encrypt', p('o9')], ['encrypt', p('o9'), p('in')],
      ['encrypt', p('o9'), p('in'), '--bogus', 'x'], ['decrypt', p('x.janus'), p('o9')],
      ['decrypt', p('x.janus'), p('o9'), '--pass', 'pw', '--id', p('me.id')]]) {
      const r = cli(...args);
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stderr}`);
      assert.ok(!existsSync(p('o9')));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
