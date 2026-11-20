// Janus v1 TypeScript client: the common command line of clients/README.md.
// Run with: node janus.ts <command> ...

import { closeSync, existsSync, openSync, readFileSync, renameSync, rmSync, writeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join, basename } from 'node:path';
import {
  identityFileText,
  newIdentity,
  parseIdentityFile,
  parsePublicKey,
  parseRecipientsFile,
  publicKeyString,
  type Identity,
  type PublicKey,
} from './src/keys.ts';
import {
  CANNOT_DECRYPT,
  decrypt,
  encrypt,
  JanusError,
  SEVERAL_FACES,
  type Face,
  type Recipients,
} from './src/format.ts';
import { utf8 } from './src/primitives.ts';

const USAGE = `usage:
  janus keygen IDENTITY_FILE        create an identity file; print the public key
  janus pubkey IDENTITY_FILE        print the public key of an identity
  janus encrypt OUTPUT INPUT RECIPIENTS [--hidden INPUT RECIPIENTS]...
  janus decrypt INPUT OUTPUT (--pass PASSWORD | --id IDENTITY_FILE ...)

RECIPIENTS := --pass PASSWORD | (--to PUBLIC_KEY | --to-file FILE)+
Interoperability client: not audited, not constant-time, not for real secrets.`;

/** Bad command line: exit status 2. */
class UsageError extends Error {}
/** Refusal to overwrite an existing output file: exit status 1. */
class ExistsError extends Error {}

/** Writes a new file atomically (temporary file, then rename); never overwrites. */
function writeNewFile(path: string, data: Uint8Array | string): void {
  if (existsSync(path)) throw new ExistsError(`${path}: file already exists`);
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(6).toString('hex')}.tmp`);
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeSync(fd, typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
  } finally {
    closeSync(fd);
  }
  try {
    if (existsSync(path)) throw new ExistsError(`${path}: file already exists`);
    renameSync(tmp, path);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

function readIdentity(path: string): Identity {
  return parseIdentityFile(readFileSync(path, 'utf8'));
}

/** Parses INPUT RECIPIENTS starting at args[pos]; returns the face and the next position. */
function parseFace(args: string[], pos: number): { face: Face; pos: number } {
  const input = args[pos++];
  if (input === undefined || input.startsWith('--')) throw new UsageError('missing INPUT');
  let password: Uint8Array | null = null;
  const keys: PublicKey[] = [];
  while (pos < args.length && args[pos] !== '--hidden') {
    const opt = args[pos++];
    const val = args[pos++];
    if (val === undefined) throw new UsageError(`${opt} needs a value`);
    if (opt === '--pass') {
      if (password !== null) throw new UsageError('a password face has exactly one password');
      password = utf8(val);
    } else if (opt === '--to') {
      keys.push(parsePublicKey(val));
    } else if (opt === '--to-file') {
      keys.push(...parseRecipientsFile(readFileSync(val, 'utf8')));
    } else {
      throw new UsageError(`unknown option ${opt}`);
    }
  }
  let recipients: Recipients;
  if (password !== null) {
    if (keys.length > 0) throw new UsageError('a face has either one password or public keys, not both');
    recipients = { password };
  } else if (keys.length > 0) {
    recipients = { keys };
  } else {
    throw new UsageError(`no recipient for ${input}`);
  }
  return { face: { plaintext: readFileSync(input), recipients }, pos };
}

function cmdEncrypt(args: string[]): void {
  const output = args[0];
  if (output === undefined) throw new UsageError('missing OUTPUT');
  if (existsSync(output)) throw new ExistsError(`${output}: file already exists`);
  const first = parseFace(args, 1);
  const main = first.face;
  let pos = first.pos;
  const hidden: Face[] = [];
  while (pos < args.length) {
    // args[pos] is '--hidden'
    const r = parseFace(args, pos + 1);
    hidden.push(r.face);
    pos = r.pos;
  }
  writeNewFile(output, encrypt(main, hidden));
}

function cmdDecrypt(args: string[]): void {
  const [input, output, ...rest] = args;
  if (input === undefined || output === undefined) throw new UsageError('missing INPUT or OUTPUT');
  let password: Uint8Array | null = null;
  const ids: Identity[] = [];
  for (let i = 0; i < rest.length; i += 2) {
    const val = rest[i + 1];
    if (val === undefined) throw new UsageError(`${rest[i]} needs a value`);
    if (rest[i] === '--pass' && password === null) password = utf8(val);
    else if (rest[i] === '--id') ids.push(readIdentity(val));
    else throw new UsageError(`unexpected argument ${rest[i]}`);
  }
  if ((password === null) === (ids.length === 0)) {
    throw new UsageError('give either --pass PASSWORD or one or more --id IDENTITY_FILE');
  }
  if (existsSync(output)) throw new ExistsError(`${output}: file already exists`);
  const file = readFileSync(input);
  const plaintext = decrypt(file, password !== null ? { password } : { identities: ids });
  writeNewFile(output, plaintext);
}

function main(argv: string[]): number {
  const [cmd, ...args] = argv;
  try {
    switch (cmd) {
      case 'keygen': {
        if (args.length !== 1) throw new UsageError('usage: janus keygen IDENTITY_FILE');
        const id = newIdentity();
        writeNewFile(args[0], identityFileText(id));
        process.stdout.write(publicKeyString(id) + '\n');
        return 0;
      }
      case 'pubkey':
        if (args.length !== 1) throw new UsageError('usage: janus pubkey IDENTITY_FILE');
        process.stdout.write(publicKeyString(readIdentity(args[0])) + '\n');
        return 0;
      case 'encrypt':
        cmdEncrypt(args);
        return 0;
      case 'decrypt':
        try {
          cmdDecrypt(args);
        } catch (e) {
          if (e instanceof UsageError || e instanceof ExistsError) throw e;
          const msg = e instanceof JanusError && e.message === SEVERAL_FACES ? SEVERAL_FACES : CANNOT_DECRYPT;
          process.stderr.write(msg + '\n');
          return 1;
        }
        return 0;
      case '-h':
      case '--help':
      case 'help':
        process.stdout.write(USAGE + '\n');
        return 0;
      default:
        throw new UsageError(USAGE);
    }
  } catch (e) {
    process.stderr.write(`janus: ${(e as Error).message}\n`);
    return e instanceof UsageError ? 2 : 1;
  }
}

process.exitCode = main(process.argv.slice(2));
