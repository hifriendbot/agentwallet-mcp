/**
 * Local (non-custodial) Casper signing.
 *
 * Same contract as local-wallet.ts on the EVM side and local-solana.ts on the
 * Solana side: the secret key is loaded once into this process, never written
 * anywhere, never logged, and never put in an error message. Deploys are built
 * and signed here and submitted straight to an RPC endpoint. The AgentWallet
 * API is not involved.
 *
 * Deploys are serialized from raw bytes rather than pulling in casper-js-sdk on
 * purpose, for the same reason the Solana side hand-rolls its two SPL
 * instructions: the SDK is a large dependency tree (it drags in a second x402
 * core and an EIP-712 package) and a wallet has no business shipping that for
 * the handful of primitives it actually needs. blake2b-256 is implemented here
 * because Node's crypto only exposes the 512-bit variant.
 */

import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, createECDH, sign as cryptoSign, KeyObject } from 'node:crypto';

/* ── blake2b-256 ─────────────────────────────────────────────────── */

const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const MASK64 = (1n << 64n) - 1n;
const rotr64 = (x: bigint, n: bigint) => ((x >> n) | (x << (64n - n))) & MASK64;

/** blake2b with a 32-byte digest, unkeyed. Casper hashes everything with this. */
export function blake2b256(input: Uint8Array): Buffer {
  const h = BLAKE2B_IV.slice();
  h[0] ^= 0x01010000n ^ 32n;

  let counter = 0n;
  const compress = (block: Buffer, t: bigint, last: boolean) => {
    const m: bigint[] = [];
    for (let i = 0; i < 16; i++) m.push(block.readBigUInt64LE(i * 8));

    const v = h.concat(BLAKE2B_IV);
    v[12] ^= t & MASK64;
    v[13] ^= (t >> 64n) & MASK64;
    if (last) v[14] ^= MASK64;

    const mix = (a: number, b: number, c: number, d: number, x: bigint, y: bigint) => {
      v[a] = (v[a] + v[b] + x) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 63n);
    };

    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      mix(0, 4, 8, 12, m[s[0]], m[s[1]]);
      mix(1, 5, 9, 13, m[s[2]], m[s[3]]);
      mix(2, 6, 10, 14, m[s[4]], m[s[5]]);
      mix(3, 7, 11, 15, m[s[6]], m[s[7]]);
      mix(0, 5, 10, 15, m[s[8]], m[s[9]]);
      mix(1, 6, 11, 12, m[s[10]], m[s[11]]);
      mix(2, 7, 8, 13, m[s[12]], m[s[13]]);
      mix(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  };

  const data = Buffer.from(input);
  let offset = 0;
  while (data.length - offset > 128) {
    counter += 128n;
    compress(data.subarray(offset, offset + 128), counter, false);
    offset += 128;
  }
  const tail = Buffer.alloc(128);
  const remaining = data.subarray(offset);
  remaining.copy(tail);
  counter += BigInt(remaining.length);
  compress(tail, counter, true);

  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(h[i], i * 8);
  return out;
}

/* ── Key loading ─────────────────────────────────────────────────── */

export type CasperAlgo = 'ed25519' | 'secp256k1';

export interface CasperKey {
  algo: CasperAlgo;
  key: KeyObject;
  /** Casper account public key: 1-byte algorithm tag followed by the raw key. */
  publicKey: Buffer;
}

const ED25519_TAG = 0x01;
const SECP256K1_TAG = 0x02;

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SECP256K1_SEC1_PREFIX = Buffer.from('302e0201010420', 'hex');
const SECP256K1_SEC1_SUFFIX = Buffer.from('a00706052b8104000a', 'hex');

let cached: CasperKey | null = null;

function fromKeyObject(key: KeyObject): CasperKey {
  if (key.asymmetricKeyType === 'ed25519') {
    const spki = key.type === 'private'
      ? createPublicKey(key).export({ format: 'der', type: 'spki' })
      : key.export({ format: 'der', type: 'spki' });
    const raw = Buffer.from(spki).subarray(-32);
    return { algo: 'ed25519', key, publicKey: Buffer.concat([Buffer.from([ED25519_TAG]), raw]) };
  }
  if (key.asymmetricKeyType === 'ec') {
    if (key.asymmetricKeyDetails?.namedCurve !== 'secp256k1') {
      throw new Error(`Casper EC keys must use the secp256k1 curve, got "${key.asymmetricKeyDetails?.namedCurve}".`);
    }
    const spki = createPublicKey(key).export({ format: 'der', type: 'spki' });
    // The uncompressed point is the trailing 65 bytes (0x04 || X || Y).
    const point = Buffer.from(spki).subarray(-65);
    const compressed = Buffer.concat([
      Buffer.from([point[64] % 2 === 0 ? 0x02 : 0x03]),
      point.subarray(1, 33),
    ]);
    return { algo: 'secp256k1', key, publicKey: Buffer.concat([Buffer.from([SECP256K1_TAG]), compressed]) };
  }
  throw new Error(`Unsupported Casper key algorithm "${key.asymmetricKeyType}". Use ed25519 or secp256k1.`);
}

function fromRawSecret(secret: Buffer, algo: CasperAlgo): CasperKey {
  if (secret.length !== 32) {
    throw new Error(`Casper hex secret key must be 32 bytes, got ${secret.length}.`);
  }
  if (algo === 'ed25519') {
    const der = Buffer.concat([ED25519_PKCS8_PREFIX, secret]);
    return fromKeyObject(createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }));
  }
  // Validate the scalar produces a point before handing it to createPrivateKey,
  // which gives a far less useful error for an out-of-range secret.
  const ecdh = createECDH('secp256k1');
  ecdh.setPrivateKey(secret);
  const der = Buffer.concat([SECP256K1_SEC1_PREFIX, secret, SECP256K1_SEC1_SUFFIX]);
  return fromKeyObject(createPrivateKey({ key: der, format: 'der', type: 'sec1' }));
}

/**
 * Accepts every format a Casper user is likely to already have:
 *   - a PEM secret key, what casper-client keygen writes to secret_key.pem
 *     (both ed25519 and secp256k1)
 *   - a raw 32-byte hex secret, optionally 0x-prefixed, with the algorithm
 *     taken from AGENTWALLET_CASPER_ALGO (default ed25519)
 */
export function parseCasperKey(raw: string, algoHint?: string): CasperKey {
  const text = raw.trim();

  if (text.includes('-----BEGIN')) {
    return fromKeyObject(createPrivateKey(text));
  }

  const hex = text.startsWith('0x') || text.startsWith('0X') ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Casper key must be a PEM secret key or a 32-byte hex secret.');
  }

  const algo = (algoHint || 'ed25519').trim().toLowerCase();
  if (algo !== 'ed25519' && algo !== 'secp256k1') {
    throw new Error(`AGENTWALLET_CASPER_ALGO must be "ed25519" or "secp256k1", got "${algo}".`);
  }
  return fromRawSecret(Buffer.from(hex, 'hex'), algo);
}

export function isCasperLocalMode(): boolean {
  return Boolean(
    (process.env.AGENTWALLET_CASPER_KEY || '').trim() ||
    (process.env.AGENTWALLET_CASPER_KEYFILE || '').trim()
  );
}

export function getCasperKey(): CasperKey {
  if (cached) return cached;

  const inline = (process.env.AGENTWALLET_CASPER_KEY || '').trim();
  const file = (process.env.AGENTWALLET_CASPER_KEYFILE || '').trim();

  let raw = inline;
  if (!raw && file) {
    try {
      raw = readFileSync(file, 'utf8');
    } catch (e) {
      throw new Error(`Could not read AGENTWALLET_CASPER_KEYFILE at ${file}: ${(e as Error).message}`);
    }
  }
  if (!raw) throw new Error('Casper local signing is not configured.');

  try {
    cached = parseCasperKey(raw, process.env.AGENTWALLET_CASPER_ALGO);
  } catch (e) {
    // Re-thrown deliberately without the key material in the message.
    throw new Error(`Invalid Casper key: ${(e as Error).message}`);
  }
  return cached;
}

/** Hex account public key, the address form Casper users paste around. */
export function getCasperAddress(): string {
  return getCasperKey().publicKey.toString('hex');
}

/** A Casper account public key is 01 + 32 bytes (ed25519) or 02 + 33 (secp256k1). */
export function isValidCasperPublicKey(value: string): boolean {
  const hex = value.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) return false;
  if (hex.startsWith('01')) return hex.length === 66;
  if (hex.startsWith('02')) return hex.length === 68;
  return false;
}

/** blake2b(<algo name> || 0x00 || raw public key), the on-chain account identity. */
export function accountHash(publicKeyHex: string): Buffer {
  if (!isValidCasperPublicKey(publicKeyHex)) {
    throw new Error(`Invalid Casper public key "${publicKeyHex}".`);
  }
  const bytes = Buffer.from(publicKeyHex.trim().toLowerCase(), 'hex');
  const name = bytes[0] === ED25519_TAG ? 'ed25519' : 'secp256k1';
  return blake2b256(Buffer.concat([Buffer.from(name, 'utf8'), Buffer.from([0]), bytes.subarray(1)]));
}

export function signDigest(digest: Buffer): Buffer {
  const { algo, key } = getCasperKey();
  const sig = algo === 'ed25519'
    ? cryptoSign(null, digest, key)
    : cryptoSign('sha256', digest, { key, dsaEncoding: 'ieee-p1363' });
  return Buffer.concat([Buffer.from([algo === 'ed25519' ? ED25519_TAG : SECP256K1_TAG]), sig]);
}

/* ── Networks ────────────────────────────────────────────────────── */

/**
 * Casper has no EVM-style chain ID, so the server uses synthetic IDs in the
 * same spirit as the 900/901 Solana IDs already in use here.
 */
export const CASPER_MAINNET_CHAIN_ID = 5000;
export const CASPER_TESTNET_CHAIN_ID = 5001;

export const CASPER_CHAIN_NAMES: Record<number, string> = {
  [CASPER_MAINNET_CHAIN_ID]: 'casper',
  [CASPER_TESTNET_CHAIN_ID]: 'casper-test',
};

const DEFAULT_CASPER_RPC: Record<number, string> = {
  [CASPER_MAINNET_CHAIN_ID]: 'https://node.mainnet.casper.network/rpc',
  [CASPER_TESTNET_CHAIN_ID]: 'https://node.testnet.casper.network/rpc',
};

export function resolveCasperRpc(chainId = CASPER_MAINNET_CHAIN_ID): string {
  const explicit = (process.env.AGENTWALLET_CASPER_RPC || '').trim();
  if (explicit) return explicit;
  const fallback = DEFAULT_CASPER_RPC[chainId];
  if (fallback) return fallback;
  throw new Error(`No Casper RPC for chain ${chainId}. Set AGENTWALLET_CASPER_RPC.`);
}

export function casperChainName(chainId: number): string {
  const name = CASPER_CHAIN_NAMES[chainId];
  if (!name) throw new Error(`Unknown Casper chain ${chainId}.`);
  return name;
}

async function rpc(method: string, params: unknown, chainId: number): Promise<any> {
  const res = await fetch(resolveCasperRpc(chainId), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`Casper RPC ${method} failed with HTTP ${res.status}.`);
  const json = await res.json() as { result?: unknown; error?: { message?: string } };
  if (json.error) throw new Error(`Casper RPC ${method} error: ${json.error.message || 'unknown'}`);
  return json.result;
}

/* ── Amount math ─────────────────────────────────────────────────── */

export const CSPR_DECIMALS = 9;

/**
 * Convert a human-readable CSPR amount to motes, exactly.
 *
 * CSPR has 9 decimals. Anything finer than one mote is not representable
 * on-chain, so this throws rather than truncating: silently dropping a digit
 * from a payment amount is how a payer under-pays an invoice and then cannot
 * explain why settlement failed.
 */
export function csprToMotes(amount: string): bigint {
  const text = String(amount).trim();
  if (!/^\d+(\.\d+)?$/.test(text)) {
    throw new Error(`Invalid CSPR amount "${amount}". Must be a positive decimal number (e.g. "1.5").`);
  }
  const [whole, frac = ''] = text.split('.');
  if (frac.length > CSPR_DECIMALS) {
    const extra = frac.slice(CSPR_DECIMALS).replace(/0+$/, '');
    if (extra.length > 0) {
      throw new Error(
        `CSPR amount "${amount}" has sub-mote precision. CSPR has ${CSPR_DECIMALS} decimals ` +
        `(1 mote = 0.000000001 CSPR); refusing to truncate. Round the amount to ${CSPR_DECIMALS} decimals.`
      );
    }
  }
  return BigInt(whole + frac.slice(0, CSPR_DECIMALS).padEnd(CSPR_DECIMALS, '0'));
}

/** Format motes back to a human-readable CSPR string. Exact, never lossy. */
export function motesToCspr(motes: string | bigint): string {
  const raw = BigInt(motes).toString();
  const padded = raw.padStart(CSPR_DECIMALS + 1, '0');
  const whole = padded.slice(0, padded.length - CSPR_DECIMALS);
  const frac = padded.slice(padded.length - CSPR_DECIMALS).replace(/0+$/, '') || '0';
  return `${whole}.${frac}`;
}

/* ── Guards ──────────────────────────────────────────────────────── */

function assertWithinCsprCap(motes: bigint) {
  const cap = (process.env.AGENTWALLET_MAX_TX_CSPR || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_CSPR must be a decimal number, got "${cap}".`);
  }
  if (motes > csprToMotes(cap)) {
    throw new Error(
      `Blocked by local guard: amount exceeds AGENTWALLET_MAX_TX_CSPR (${cap} CSPR).`
    );
  }
}

/* ── CL serialization ────────────────────────────────────────────── */

const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const u64 = (n: bigint) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
const clString = (s: string) => Buffer.concat([u32(Buffer.byteLength(s)), Buffer.from(s, 'utf8')]);

/** U512/U256 wire form: a length byte followed by that many little-endian bytes. */
export function clBigNumber(value: bigint): Buffer {
  if (value < 0n) throw new Error('Casper big numbers cannot be negative.');
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const le = Buffer.from(hex, 'hex').reverse();
  const trimmed = value === 0n ? Buffer.alloc(0) : le;
  return Buffer.concat([Buffer.from([trimmed.length]), trimmed]);
}

const CL_U64 = Buffer.from([5]);
const CL_U256 = Buffer.from([7]);
const CL_U512 = Buffer.from([8]);
const CL_KEY = Buffer.from([11]);
const CL_OPTION = Buffer.from([13]);
const CL_PUBLIC_KEY = Buffer.from([22]);

function namedArg(name: string, value: Buffer, clType: Buffer): Buffer {
  return Buffer.concat([clString(name), u32(value.length), value, clType]);
}

function runtimeArgs(args: Buffer[]): Buffer {
  return Buffer.concat([u32(args.length), ...args]);
}

/** ExecutableDeployItem::ModuleBytes with only an `amount` arg — standard payment. */
function paymentItem(motes: bigint): Buffer {
  return Buffer.concat([
    Buffer.from([0]),
    u32(0),
    runtimeArgs([namedArg('amount', clBigNumber(motes), CL_U512)]),
  ]);
}

/** ExecutableDeployItem::Transfer — the native mote transfer. */
function transferItem(target: string, motes: bigint, id: bigint): Buffer {
  const targetBytes = Buffer.from(target.trim().toLowerCase(), 'hex');
  return Buffer.concat([
    Buffer.from([5]),
    runtimeArgs([
      namedArg('amount', clBigNumber(motes), CL_U512),
      namedArg('target', targetBytes, CL_PUBLIC_KEY),
      namedArg('id', Buffer.concat([Buffer.from([1]), u64(id)]), Buffer.concat([CL_OPTION, CL_U64])),
    ]),
  ]);
}

/** ExecutableDeployItem::StoredContractByHash — used for CEP-18 (wCSPR) transfers. */
function cep18TransferItem(contractHashHex: string, recipient: string, amount: bigint): Buffer {
  const contract = Buffer.from(contractHashHex.replace(/^hash-/, '').trim().toLowerCase(), 'hex');
  if (contract.length !== 32) {
    throw new Error(`CEP-18 contract hash must be 32 bytes, got ${contract.length}.`);
  }
  // Key::Account = tag 0 followed by the 32-byte account hash.
  const recipientKey = Buffer.concat([Buffer.from([0]), accountHash(recipient)]);
  return Buffer.concat([
    Buffer.from([1]),
    contract,
    clString('transfer'),
    runtimeArgs([
      namedArg('recipient', recipientKey, CL_KEY),
      namedArg('amount', clBigNumber(amount), CL_U256),
    ]),
  ]);
}

export interface CasperDeploy {
  hash: string;
  header: Record<string, unknown>;
  payment: unknown;
  session: unknown;
  approvals: Array<{ signer: string; signature: string }>;
}

/**
 * Build and sign a deploy. The signature is produced in-process from the local
 * key; the returned object is the JSON shape a Casper node (and the x402
 * facilitator) accepts for `account_put_deploy`.
 */
function buildSignedDeploy(
  chainId: number,
  session: Buffer,
  sessionJson: unknown,
  paymentMotes: bigint,
  paymentJson: unknown
): CasperDeploy {
  const { publicKey } = getCasperKey();
  const chainName = casperChainName(chainId);
  const timestamp = Date.now();
  const ttl = Number(process.env.AGENTWALLET_CASPER_TTL_MS || 30 * 60 * 1000);

  const payment = paymentItem(paymentMotes);
  const bodyHash = blake2b256(Buffer.concat([payment, session]));

  const header = Buffer.concat([
    publicKey,
    u64(BigInt(timestamp)),
    u64(BigInt(ttl)),
    u64(1n),
    u32(0),
    bodyHash,
    clString(chainName),
  ]);
  const deployHash = blake2b256(header);
  const signature = signDigest(deployHash);

  return {
    hash: deployHash.toString('hex'),
    header: {
      account: publicKey.toString('hex'),
      timestamp: new Date(timestamp).toISOString(),
      ttl: `${Math.round(ttl / 60000)}m`,
      gas_price: 1,
      body_hash: bodyHash.toString('hex'),
      dependencies: [],
      chain_name: chainName,
    },
    payment: paymentJson,
    session: sessionJson,
    approvals: [{ signer: publicKey.toString('hex'), signature: signature.toString('hex') }],
  };
}

export function buildTransferDeploy(
  to: string,
  motes: bigint,
  chainId: number,
  paymentMotes: bigint,
  id = 0n
): CasperDeploy {
  if (!isValidCasperPublicKey(to)) {
    throw new Error(`Invalid Casper recipient "${to}". Expected a hex account public key (01… or 02…).`);
  }
  const session = transferItem(to, motes, id);
  const sessionJson = {
    Transfer: {
      args: [
        ['amount', { cl_type: 'U512', bytes: clBigNumber(motes).toString('hex'), parsed: motes.toString() }],
        ['target', { cl_type: 'PublicKey', bytes: to.toLowerCase(), parsed: to.toLowerCase() }],
        ['id', { cl_type: { Option: 'U64' }, bytes: Buffer.concat([Buffer.from([1]), u64(id)]).toString('hex'), parsed: Number(id) }],
      ],
    },
  };
  const paymentJson = {
    ModuleBytes: {
      module_bytes: '',
      args: [['amount', { cl_type: 'U512', bytes: clBigNumber(paymentMotes).toString('hex'), parsed: paymentMotes.toString() }]],
    },
  };
  return buildSignedDeploy(chainId, session, sessionJson, paymentMotes, paymentJson);
}

export function buildCep18TransferDeploy(
  contractHash: string,
  to: string,
  amount: bigint,
  chainId: number,
  paymentMotes: bigint
): CasperDeploy {
  const session = cep18TransferItem(contractHash, to, amount);
  const recipientKey = Buffer.concat([Buffer.from([0]), accountHash(to)]);
  const sessionJson = {
    StoredContractByHash: {
      hash: contractHash.replace(/^hash-/, '').toLowerCase(),
      entry_point: 'transfer',
      args: [
        ['recipient', { cl_type: 'Key', bytes: recipientKey.toString('hex'), parsed: { Account: `account-hash-${accountHash(to).toString('hex')}` } }],
        ['amount', { cl_type: 'U256', bytes: clBigNumber(amount).toString('hex'), parsed: amount.toString() }],
      ],
    },
  };
  const paymentJson = {
    ModuleBytes: {
      module_bytes: '',
      args: [['amount', { cl_type: 'U512', bytes: clBigNumber(paymentMotes).toString('hex'), parsed: paymentMotes.toString() }]],
    },
  };
  return buildSignedDeploy(chainId, session, sessionJson, paymentMotes, paymentJson);
}

/* ── Reads ───────────────────────────────────────────────────────── */

export async function localCsprBalance(chainId = CASPER_MAINNET_CHAIN_ID) {
  const address = getCasperAddress();
  const state = await rpc('query_balance', {
    purse_identifier: { main_purse_under_public_key: address },
  }, chainId);
  const motes = String((state as { balance?: string }).balance ?? '0');
  return {
    address,
    chain_id: chainId,
    balance_motes: motes,
    balance: motesToCspr(motes),
    mode: 'local',
  };
}

/* ── Writes ──────────────────────────────────────────────────────── */

export interface LocalCasperResult {
  deploy_hash: string;
  from: string;
  to: string;
  value: string;
  chain_id: number;
  mode: 'local';
  signed_locally: true;
}

/** Default payment for a native transfer: 0.1 CSPR, the network's standard fee. */
const DEFAULT_TRANSFER_PAYMENT_MOTES = 100_000_000n;

export async function localCsprTransfer(
  to: string,
  motes: string,
  chainId = CASPER_MAINNET_CHAIN_ID
): Promise<LocalCasperResult> {
  const amount = BigInt(motes);
  assertWithinCsprCap(amount);

  const paymentMotes = BigInt(
    (process.env.AGENTWALLET_CASPER_PAYMENT_MOTES || '').trim() || DEFAULT_TRANSFER_PAYMENT_MOTES
  );
  const deploy = buildTransferDeploy(to, amount, chainId, paymentMotes);
  const result = await rpc('account_put_deploy', { deploy }, chainId);

  return {
    deploy_hash: String((result as { deploy_hash?: string }).deploy_hash || deploy.hash),
    from: getCasperAddress(),
    to,
    value: amount.toString(),
    chain_id: chainId,
    mode: 'local',
    signed_locally: true,
  };
}

export function casperWalletRecord() {
  return {
    id: 'local-casper',
    address: getCasperAddress(),
    wallet_type: 'casper',
    mode: 'local',
    custody: 'self',
    note: 'Signed in-process. The secret key is never sent to AgentWallet servers.',
  };
}
