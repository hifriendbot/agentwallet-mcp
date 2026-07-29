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
    const arr = JSON.parse(text);
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
  const explicit = (process.env.AGENTWALLET_SOLANA_RPC || '').trim();
  if (explicit) return explicit;
  const fallback = DEFAULT_SOLANA_RPC[chainId];
  if (fallback) return fallback;
  throw new Error(`No Solana RPC for chain ${chainId}. Set AGENTWALLET_SOLANA_RPC.`);
}

function connection(chainId = 900): Connection {
  return new Connection(resolveSolanaRpc(chainId), 'confirmed');
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

/** Which token program owns this mint: classic SPL or Token-2022. */
async function tokenProgramFor(conn: Connection, mint: PublicKey): Promise<PublicKey> {
  const info = await conn.getAccountInfo(mint);
  if (!info) throw new Error(`Mint ${mint.toBase58()} not found on this cluster.`);
  if (info.owner.equals(TOKEN_2022_PROGRAM)) return TOKEN_2022_PROGRAM;
  return TOKEN_PROGRAM;
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

  const conn = connection(chainId);
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
  const conn = connection(chainId);
  const payer = getSolanaKeypair();
  const mint = new PublicKey(mintStr);
  const recipient = new PublicKey(to);
  const tokenProgram = await tokenProgramFor(conn, mint);

  const sourceAta = associatedTokenAddress(payer.publicKey, mint, tokenProgram);
  const destAta = associatedTokenAddress(recipient, mint, tokenProgram);

  const tx = new Transaction();
  const destInfo = await conn.getAccountInfo(destAta);
  if (!destInfo) {
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
