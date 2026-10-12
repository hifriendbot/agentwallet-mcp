/**
 * Encrypted keyfiles.
 *
 * A plaintext key in an environment variable or a file is readable by anything
 * that can read the process or the disk. This format keeps it under a
 * passphrase: scrypt (N=2^17, r=8, p=1) derives a 256-bit key, AES-256-GCM
 * seals the material, and the parameters travel in the file so they can be
 * raised later without a format change. Node's own crypto only; no new
 * dependency.
 *
 * The passphrase comes from AGENTWALLET_KEYFILE_PASSPHRASE or the file named
 * by AGENTWALLET_KEYFILE_PASSPHRASE_FILE. Both EVM and Solana keyfiles accept
 * the format; a plain keyfile still works unchanged.
 */
import { randomBytes, scryptSync, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const KEYFILE_MARKER = 'agentwallet-keyfile';
const SCRYPT = { N: 1 << 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

export interface EncryptedKeyfile {
  [KEYFILE_MARKER]: 1;
  kdf: 'scrypt';
  N: number; r: number; p: number;
  salt: string;
  cipher: 'aes-256-gcm';
  iv: string;
  tag: string;
  ct: string;
  /** What the material is for, so a human can tell the files apart. Never the key. */
  family?: 'evm' | 'solana';
}

export function isEncryptedKeyfile(text: string): boolean {
  const t = text.trim();
  if (!t.startsWith('{')) return false;
  try { const j = JSON.parse(t); return j && typeof j === 'object' && j[KEYFILE_MARKER] === 1; } catch { return false; }
}

export function encryptKeyfile(material: string, passphrase: string, family?: 'evm' | 'solana'): string {
  if (passphrase.length < 8) throw new Error('The passphrase must be at least 8 characters.');
  const salt = randomBytes(16);
  const key = scryptSync(passphrase, salt, 32, SCRYPT);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(material, 'utf8')), c.final()]);
  const out: EncryptedKeyfile = {
    [KEYFILE_MARKER]: 1, kdf: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64'),
    cipher: 'aes-256-gcm', iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64'), ...(family ? { family } : {}),
  };
  key.fill(0);
  return JSON.stringify(out, null, 2) + '\n';
}

export function decryptKeyfile(text: string, passphrase: string): string {
  let j: EncryptedKeyfile;
  try { j = JSON.parse(text); } catch { throw new Error('The encrypted keyfile is not valid JSON.'); }
  if (j[KEYFILE_MARKER] !== 1 || j.kdf !== 'scrypt' || j.cipher !== 'aes-256-gcm') throw new Error('The encrypted keyfile has an unknown format version, kdf or cipher.');
  for (const [k, v] of Object.entries({ N: j.N, r: j.r, p: j.p })) if (!Number.isInteger(v) || v <= 0 || v > 1 << 22) throw new Error(`The encrypted keyfile has an invalid scrypt parameter ${k}.`);
  const salt = Buffer.from(String(j.salt), 'base64');
  const iv = Buffer.from(String(j.iv), 'base64');
  const tag = Buffer.from(String(j.tag), 'base64');
  const ct = Buffer.from(String(j.ct), 'base64');
  if (salt.length < 16 || iv.length !== 12 || tag.length !== 16) throw new Error('The encrypted keyfile has a malformed salt, iv or tag.');
  const key = scryptSync(passphrase, salt, 32, { N: j.N, r: j.r, p: j.p, maxmem: SCRYPT.maxmem });
  try {
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    const out = Buffer.concat([d.update(ct), d.final()]).toString('utf8');
    return out;
  } catch {
    throw new Error('The keyfile could not be decrypted: wrong passphrase or a damaged file. The passphrase and the key are never logged.');
  } finally {
    key.fill(0);
  }
}

/** The passphrase the operator configured, or a refusal naming the variables. */
export function keyfilePassphrase(env: NodeJS.ProcessEnv = process.env): string {
  const inline = env.AGENTWALLET_KEYFILE_PASSPHRASE;
  const file = (env.AGENTWALLET_KEYFILE_PASSPHRASE_FILE || '').trim();
  if (inline !== undefined && file) throw new Error('Both AGENTWALLET_KEYFILE_PASSPHRASE and AGENTWALLET_KEYFILE_PASSPHRASE_FILE are set; keep one.');
  if (inline !== undefined) {
    if (!inline) throw new Error('AGENTWALLET_KEYFILE_PASSPHRASE is set but blank.');
    return inline;
  }
  if (file) {
    let t: string;
    try { t = readFileSync(file, 'utf8'); } catch (e) { throw new Error(`Could not read AGENTWALLET_KEYFILE_PASSPHRASE_FILE at ${file}: ${(e as Error).message}`); }
    t = t.replace(/\r?\n$/, '');
    if (!t) throw new Error(`AGENTWALLET_KEYFILE_PASSPHRASE_FILE at ${file} is empty.`);
    return t;
  }
  throw new Error('The keyfile is encrypted but no passphrase is configured. Set AGENTWALLET_KEYFILE_PASSPHRASE or AGENTWALLET_KEYFILE_PASSPHRASE_FILE.');
}

/** Read a keyfile's material, decrypting it when it is in the encrypted format. */
export function openKeyfile(text: string, env: NodeJS.ProcessEnv = process.env): string {
  return isEncryptedKeyfile(text) ? decryptKeyfile(text, keyfilePassphrase(env)) : text;
}

/** Constant-time equality for two short secrets (used by tests and the CLI's confirm step). */
export function secretsEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}
