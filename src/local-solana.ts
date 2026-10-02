/**
 * Local (non-custodial) Solana signing.
 *
 * Same contract as local-wallet.ts on the EVM side: the secret key is loaded
 * once into this process, never written anywhere, never logged, and never put
 * in an error message. Transactions are signed here and submitted straight to
 * an RPC endpoint. The AgentWallet API is not involved.
 *
 * SPL transfers are built from raw instructions rather than @solana/spl-token
 * on purpose. That package pulls in bigint-buffer, which carries a high
 * severity buffer overflow advisory, and a wallet has no business shipping
 * that when the two instructions it needs are a dozen lines each.
 */

import { readFileSync } from 'node:fs';
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import bs58 from 'bs58';
import { lookupTrustedDecimals } from './x402-payment.js';

/* ── Program IDs ─────────────────────────────────────────────────── */

const TOKEN_PROGRAM = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const TOKEN_2022_PROGRAM = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
const ASSOCIATED_TOKEN_PROGRAM = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');

/* ── Key loading ─────────────────────────────────────────────────── */

let cached: Keypair | null = null;

/**
 * Accepts every format a Solana user is likely to already have:
 *   - solana-keygen id.json, a JSON array of 64 bytes
 *   - base58 secret key, what Phantom and friends export
 *   - base64, 64 bytes, or the 96-byte sodium keypair AgentWallet exports
 *     for hosted Solana wallets (its first 64 bytes are the secret key)
 */
function parseSolanaKey(raw: string): Keypair {
  const text = raw.trim();

  if (text.startsWith('[')) {
    let arr: unknown;
    // JSON.parse quotes the offending source in its message, which for a key
    // array means key bytes; replace it with a fixed message.
    try { arr = JSON.parse(text); } catch { throw new Error('Solana key JSON did not parse (expected a JSON array of 64 numbers).'); }
    if (!Array.isArray(arr) || arr.length < 64) {
      throw new Error('Solana key JSON must be an array of at least 64 bytes.');
    }
    return Keypair.fromSecretKey(Uint8Array.from(arr.slice(0, 64)));
  }

  // base64 tends to contain characters base58 never does.
  if (/[+/=]/.test(text)) {
    const buf = Buffer.from(text, 'base64');
    if (buf.length !== 64 && buf.length !== 96) {
      throw new Error(`Base64 Solana key must decode to 64 or 96 bytes, got ${buf.length}.`);
    }
    return Keypair.fromSecretKey(Uint8Array.from(buf.subarray(0, 64)));
  }

  const decoded = bs58.decode(text);
  if (decoded.length !== 64) {
    throw new Error(`Base58 Solana key must decode to 64 bytes, got ${decoded.length}.`);
  }
  return Keypair.fromSecretKey(decoded);
}

export function isSolanaLocalMode(): boolean {
  return Boolean(
    (process.env.AGENTWALLET_SOLANA_KEY || '').trim() ||
    (process.env.AGENTWALLET_SOLANA_KEYFILE || '').trim()
  );
}

export function getSolanaKeypair(): Keypair {
  if (cached) return cached;

  const inline = (process.env.AGENTWALLET_SOLANA_KEY || '').trim();
  const file = (process.env.AGENTWALLET_SOLANA_KEYFILE || '').trim();

  let raw = inline;
  if (!raw && file) {
    try {
      raw = readFileSync(file, 'utf8');
    } catch (e) {
      throw new Error(`Could not read AGENTWALLET_SOLANA_KEYFILE at ${file}: ${(e as Error).message}`);
    }
  }
  if (!raw) throw new Error('Solana local signing is not configured.');

  try {
    cached = parseSolanaKey(raw);
  } catch (e) {
    // Re-thrown deliberately without the key material in the message.
    throw new Error(`Invalid Solana key: ${(e as Error).message}`);
  }
  return cached;
}

export function getSolanaAddress(): string {
  return getSolanaKeypair().publicKey.toBase58();
}

/* ── Connection ──────────────────────────────────────────────────── */

const DEFAULT_SOLANA_RPC: Record<number, string> = {
  900: 'https://api.mainnet-beta.solana.com',
  901: 'https://api.devnet.solana.com',
  902: 'https://api.testnet.solana.com',
};

export function resolveSolanaRpc(chainId = 900): string {
  const perChain = (process.env[`AGENTWALLET_SOLANA_RPC_${chainId}`] || '').trim();
  if (perChain) return perChain;
  const explicit = (process.env.AGENTWALLET_SOLANA_RPC || '').trim();
  if (explicit) return explicit;
  const fallback = DEFAULT_SOLANA_RPC[chainId];
  if (fallback) return fallback;
  throw new Error(`No Solana RPC for chain ${chainId}. Set AGENTWALLET_SOLANA_RPC.`);
}

function connection(chainId = 900): Connection {
  return new Connection(resolveSolanaRpc(chainId), 'confirmed');
}

/** Genesis hashes of the public clusters, so a chain id can be checked against what the RPC actually serves. */
const CLUSTER_GENESIS: Record<number, string> = {
  900: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d', // mainnet-beta
  901: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG', // devnet
  902: '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY', // testnet
};
const verifiedClusters = new Map<string, string>();

/**
 * One AGENTWALLET_SOLANA_RPC used to answer every chain id, so a chain_id 901
 * "test" transfer ran on whatever cluster the URL pointed at and the result
 * echoed 901. Now the RPC's genesis hash is checked once per URL.
 */
async function assertCluster(conn: Connection, chainId: number): Promise<void> {
  const expected = CLUSTER_GENESIS[chainId];
  if (!expected) return; // a private cluster the operator configured on purpose
  const url = conn.rpcEndpoint;
  let actual = verifiedClusters.get(url);
  if (!actual) {
    actual = await conn.getGenesisHash();
    verifiedClusters.set(url, actual);
  }
  if (actual !== expected) {
    const served = Object.entries(CLUSTER_GENESIS).find(([, h]) => h === actual)?.[0] ?? 'an unknown cluster';
    throw new Error(`Solana RPC for chain ${chainId} serves ${served} (genesis ${actual.slice(0, 8)}...), not chain ${chainId}. Set AGENTWALLET_SOLANA_RPC_${chainId}.`);
  }
}

/* ── Guards ──────────────────────────────────────────────────────── */

function assertWithinSolCap(lamports: bigint) {
  const cap = (process.env.AGENTWALLET_MAX_TX_SOL || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_SOL must be a decimal number, got "${cap}".`);
  }
  const [whole, frac = ''] = cap.split('.');
  const capLamports = BigInt(whole + frac.padEnd(9, '0').slice(0, 9));
  if (lamports > capLamports) {
    throw new Error(
      `Blocked by local guard: amount exceeds AGENTWALLET_MAX_TX_SOL (${cap} SOL).`
    );
  }
}

/**
 * Bound SPL movement. AGENTWALLET_MAX_TX_SOL only ever covered native SOL, so
 * an SPL transfer, which is how USDC moves on Solana and the whole point of the
 * x402 rail here, went out with no local ceiling at all. Mirrors
 * AGENTWALLET_MAX_TX_TOKEN on the EVM side and uses the same variable so an
 * operator sets one token cap, not one per chain family.
 *
 * Decimals for the cap come from the trusted table when the mint is known, then
 * from the mint account itself, and finally 0. The caller-supplied value is
 * never used for the ceiling: an inflated one would inflate the cap exactly
 * like the x402 bypass.
 *
 * 0 is the only safe fallback. Assuming 6 for an unknown mint is what AW-001
 * exploited: for a mint with d decimals, a ceiling evaluated at 6 is 10**(6-d)
 * times too permissive, and SPL mints with 0 to 5 decimals are common.
 */
const splDecimalsCache = new Map<string, number>();

async function resolveMintDecimals(mint: string, chainId: number): Promise<number> {
  const known = lookupTrustedDecimals(chainId, mint);
  if (typeof known === 'number') return known;

  const cacheKey = `${chainId}:${mint}`; // the same mint address can exist on two clusters with different decimals
  const cached = splDecimalsCache.get(cacheKey);
  if (typeof cached === 'number') return cached;

  try {
    const conn = connection(chainId);
    const info = await conn.getParsedAccountInfo(new PublicKey(mint));
    const data: any = info?.value?.data;
    const d = Number(data?.parsed?.info?.decimals);
    if (Number.isInteger(d) && d >= 0 && d <= 36) {
      splDecimalsCache.set(cacheKey, d);
      return d;
    }
  } catch {
    // Unreachable RPC or non-standard mint: fall through to the safe floor.
  }
  return 0;
}

async function assertWithinSplCap(mint: string, rawAmount: bigint, chainId = 900) {
  const cap = (process.env.AGENTWALLET_MAX_TX_TOKEN || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_TOKEN must be a decimal number, got "${cap}".`);
  }
  const decimals = await resolveMintDecimals(mint, chainId);
  const [whole, frac = ''] = cap.split('.');
  const capRaw = BigInt(whole + frac.padEnd(decimals, '0').slice(0, decimals));
  if (rawAmount > capRaw) {
    throw new Error(
      `Blocked by local guard: SPL transfer of ${rawAmount} base units exceeds ` +
      `AGENTWALLET_MAX_TX_TOKEN (${cap}, evaluated at ${decimals} decimals). ` +
      `Raise the cap deliberately if this is intended.`
    );
  }
}

/* ── Reads ───────────────────────────────────────────────────────── */

export async function localSolBalance(chainId = 900) {
  const conn = connection(chainId);
  const owner = getSolanaKeypair().publicKey;
  const lamports = await conn.getBalance(owner);
  return {
    address: owner.toBase58(),
    chain_id: chainId,
    balance_lamports: String(lamports),
    balance: String(lamports / LAMPORTS_PER_SOL),
    mode: 'local',
  };
}

/** Which token program owns this mint, and how big a token account for it is. */
async function mintLayout(conn: Connection, mint: PublicKey): Promise<{ tokenProgram: PublicKey; ataSize: number }> {
  const info = await conn.getAccountInfo(mint);
  if (!info) throw new Error(`Mint ${mint.toBase58()} not found on this cluster.`);
  const token2022 = info.owner.equals(TOKEN_2022_PROGRAM);
  return {
    tokenProgram: token2022 ? TOKEN_2022_PROGRAM : TOKEN_PROGRAM,
    ataSize: associatedAccountSize(token2022, info.data),
  };
}

/** Which token program owns this mint: classic SPL or Token-2022. */
async function tokenProgramFor(conn: Connection, mint: PublicKey): Promise<PublicKey> {
  return (await mintLayout(conn, mint)).tokenProgram;
}

/* Token-2022 mint extensions that make every token account for the mint carry
   an extension of its own, and the size of that account extension's value.
   Mirrors required_init_account_extensions in the token-2022 program. */
const ACCOUNT_EXTENSION_FOR_MINT_EXTENSION: Record<number, number> = {
  1: 8,   // TransferFeeConfig -> TransferFeeAmount (withheld amount, u64)
  9: 0,   // NonTransferable   -> NonTransferableAccount (plus ImmutableOwner, always present below)
  14: 1,  // TransferHook      -> TransferHookAccount (one flag byte)
  26: 0,  // Pausable          -> PausableAccount
};
/** Highest extension type this table was written against (PermissionedBurn). */
const HIGHEST_KNOWN_EXTENSION = 28;
/** Charged for a mint extension newer than the table, so the estimate errs high, never low. */
const UNKNOWN_EXTENSION_ALLOWANCE = 64;
const TLV_HEADER = 4;       // u16 type + u16 length
const MULTISIG_SIZE = 355;  // the program pads an account that would collide with a multisig's size

/**
 * Bytes the Associated Token Account program allocates for a new token account
 * of this mint. Classic SPL is always 165. Token-2022 adds an account-type byte
 * and one TLV entry per account extension: ImmutableOwner on every associated
 * account, plus whatever the mint's own extensions require.
 *
 * The rent charged follows this size, so the SOL cap has to be checked against
 * it. A flat 165 under-counted every Token-2022 account (2026-10-02 report).
 */
export function associatedAccountSize(token2022: boolean, mintData: Uint8Array): number {
  if (!token2022) return TOKEN_ACCOUNT_SIZE;
  let tlvBytes = TLV_HEADER; // ImmutableOwner, zero-length value
  const seen = new Set<number>();
  // Mint layout: 82 bytes of base state padded to 165, the account-type byte, then TLV entries.
  let offset = TOKEN_ACCOUNT_SIZE + 1;
  while (offset + TLV_HEADER <= mintData.length) {
    const type = mintData[offset] | (mintData[offset + 1] << 8);
    const length = mintData[offset + 2] | (mintData[offset + 3] << 8);
    if (type === 0) break; // uninitialized: the rest is padding
    if (!seen.has(type)) {
      seen.add(type);
      const accountValue = ACCOUNT_EXTENSION_FOR_MINT_EXTENSION[type];
      if (accountValue !== undefined) tlvBytes += TLV_HEADER + accountValue;
      else if (type > HIGHEST_KNOWN_EXTENSION) tlvBytes += TLV_HEADER + UNKNOWN_EXTENSION_ALLOWANCE;
    }
    offset += TLV_HEADER + length;
  }
  const size = TOKEN_ACCOUNT_SIZE + 1 + tlvBytes;
  return size === MULTISIG_SIZE ? size + 2 : size;
}

function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram: PublicKey): PublicKey {
  const [ata] = PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    ASSOCIATED_TOKEN_PROGRAM
  );
  return ata;
}

export async function localSplBalance(mintStr: string, chainId = 900) {
  const conn = connection(chainId);
  const owner = getSolanaKeypair().publicKey;
  const mint = new PublicKey(mintStr);
  const tokenProgram = await tokenProgramFor(conn, mint);
  const ata = associatedTokenAddress(owner, mint, tokenProgram);

  const res = await conn.getTokenAccountBalance(ata).catch(() => null);
  return {
    address: owner.toBase58(),
    chain_id: chainId,
    mint: mintStr,
    token_account: ata.toBase58(),
    balance_raw: res?.value.amount ?? '0',
    balance: res?.value.uiAmountString ?? '0',
    decimals: res?.value.decimals ?? 0,
    mode: 'local',
  };
}

/* ── Writes ──────────────────────────────────────────────────────── */

export interface LocalSolResult {
  signature: string;
  from: string;
  to: string;
  value: string;
  chain_id: number;
  mode: 'local';
  signed_locally: true;
}

export async function localSolTransfer(to: string, lamports: string, chainId = 900): Promise<LocalSolResult> {
  const amount = BigInt(lamports);
  assertWithinSolCap(amount);
  // Number() silently loses precision past 2**53 lamports. Refuse rather than
  // sign a transaction for an amount other than the one that was requested.
  if (amount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`Amount ${lamports} lamports exceeds safe integer range and was refused.`);
  }

  const conn = connection(chainId);
  await assertCluster(conn, chainId);
  await assertRecipientIsWallet(conn, new PublicKey(to));
  const payer = getSolanaKeypair();
  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: new PublicKey(to),
      lamports: Number(amount),
    })
  );

  const signature = await sendAndConfirmTransaction(conn, tx, [payer]);
  return {
    signature,
    from: payer.publicKey.toBase58(),
    to,
    value: lamports,
    chain_id: chainId,
    mode: 'local',
    signed_locally: true,
  };
}

/** SPL transferChecked, opcode 12: amount as u64 LE followed by decimals. */
function transferCheckedIx(
  tokenProgram: PublicKey,
  source: PublicKey,
  mint: PublicKey,
  dest: PublicKey,
  owner: PublicKey,
  amount: bigint,
  decimals: number
): TransactionInstruction {
  const data = Buffer.alloc(10);
  data.writeUInt8(12, 0);
  data.writeBigUInt64LE(amount, 1);
  data.writeUInt8(decimals, 9);
  return new TransactionInstruction({
    programId: tokenProgram,
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: dest, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    data,
  });
}

/** Associated token account create, idempotent variant (opcode 1). */
function createAtaIdempotentIx(
  payer: PublicKey,
  ata: PublicKey,
  owner: PublicKey,
  mint: PublicKey,
  tokenProgram: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([1]),
  });
}

/**
 * Transfer SPL tokens. The recipient's associated account is created if it does
 * not exist, using the idempotent instruction so a race cannot fail the send.
 */
export async function localSplTransfer(
  mintStr: string,
  to: string,
  rawAmount: string,
  decimals: number,
  chainId = 900
): Promise<LocalSolResult> {
  // Checked before any RPC round trip: a blocked transfer should cost nothing
  // and should not announce itself to the RPC provider first.
  await assertWithinSplCap(mintStr, BigInt(rawAmount), chainId);

  const conn = connection(chainId);
  await assertCluster(conn, chainId);
  const payer = getSolanaKeypair();
  const mint = new PublicKey(mintStr);
  const recipient = new PublicKey(to);
  await assertRecipientIsWallet(conn, recipient);
  const { tokenProgram, ataSize } = await mintLayout(conn, mint);
  // The instruction's decimals byte is the mint's real value, not whatever the
  // caller passed; TransferChecked would reject a wrong one on-chain anyway.
  decimals = await resolveMintDecimals(mintStr, chainId);

  const sourceAta = associatedTokenAddress(payer.publicKey, mint, tokenProgram);
  const destAta = associatedTokenAddress(recipient, mint, tokenProgram);

  const tx = new Transaction();
  const destInfo = await conn.getAccountInfo(destAta);
  if (!destInfo) {
    // Creating the recipient's token account costs the payer rent in SOL, an
    // outflow the SOL cap must see (0.002 SOL a time adds up over many sends).
    // Rent follows the account's real size, which for Token-2022 is above 165.
    const rent = await conn.getMinimumBalanceForRentExemption(ataSize);
    assertWithinSolCap(BigInt(rent));
    tx.add(createAtaIdempotentIx(payer.publicKey, destAta, recipient, mint, tokenProgram));
  }
  tx.add(
    transferCheckedIx(tokenProgram, sourceAta, mint, destAta, payer.publicKey, BigInt(rawAmount), decimals)
  );

  const signature = await sendAndConfirmTransaction(conn, tx, [payer]);
  return {
    signature,
    from: payer.publicKey.toBase58(),
    to,
    value: rawAmount,
    chain_id: chainId,
    mode: 'local',
    signed_locally: true,
  };
}

const TOKEN_ACCOUNT_SIZE = 165;
const MINT_SIZE = 82;
/** Token-2022 pads a mint to the token-account size and tags the next byte: 1 = mint, 2 = token account. */
const TOKEN_2022_TYPE_MINT = 1;

/**
 * A recipient must be something that can own a token account: a wallet or a
 * program-derived wallet (Squads and friends), never a program and never an
 * account the token programs own. SPL sent to ATA(ATA), ATA(mint) or a program
 * id is gone for good, or belongs to whoever kept the mint's keypair.
 *
 * Ownership alone decides. A length gate (>= 165 bytes) used to sit here and
 * let an 82-byte mint through as a "wallet" (2026-10-02 report): everything
 * the token programs own is a mint, a token account or a multisig, and none
 * of those is a wallet.
 */
async function assertRecipientIsWallet(conn: Connection, recipient: PublicKey): Promise<void> {
  const info = await conn.getAccountInfo(recipient);
  if (!info) return; // never seen on chain: an ordinary fresh wallet
  if (info.executable) throw new Error(`Refusing to send to ${recipient.toBase58()}: it is a program, not a wallet.`);
  if (info.owner.equals(TOKEN_PROGRAM) || info.owner.equals(TOKEN_2022_PROGRAM)) {
    const isMint = info.data.length === MINT_SIZE
      || (info.data.length > TOKEN_ACCOUNT_SIZE && info.data[TOKEN_ACCOUNT_SIZE] === TOKEN_2022_TYPE_MINT);
    if (isMint) {
      throw new Error(`Refusing to send to ${recipient.toBase58()}: it is a token mint, not a wallet. Pass the recipient's wallet address; the mint belongs in token_mint.`);
    }
    if (info.data.length >= TOKEN_ACCOUNT_SIZE) {
      throw new Error(`Refusing to send to ${recipient.toBase58()}: it is a token account, not a wallet. Pass the owner's wallet address instead.`);
    }
    throw new Error(`Refusing to send to ${recipient.toBase58()}: it is an account owned by the SPL token program, not a wallet.`);
  }
}

export function solanaWalletRecord() {
  return {
    id: 'local-solana',
    address: getSolanaAddress(),
    wallet_type: 'solana',
    mode: 'local',
    custody: 'self',
    note: 'Signed in-process. The secret key is never sent to AgentWallet servers.',
  };
}
