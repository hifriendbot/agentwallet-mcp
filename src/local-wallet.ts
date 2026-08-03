/**
 * Local (non-custodial) signing mode.
 *
 * When AGENTWALLET_PRIVATE_KEY or AGENTWALLET_KEYFILE is set, every signing
 * operation happens in this process with a key that never leaves the machine.
 * The AgentWallet API is not called, not consulted, and not trusted for any
 * funds-moving step. Transactions are broadcast straight to an RPC endpoint.
 *
 * This is the mode that makes the custody claim verifiable: an operator can
 * read this file, run the server offline against their own RPC, and confirm the
 * key is never transmitted. Nothing here writes the key to disk, logs it, or
 * puts it in an error message.
 *
 * EVM only for now. Solana local signing is not implemented; those calls stay
 * on the custodial path and say so explicitly rather than silently downgrading.
 */

import { readFileSync } from 'node:fs';
import {
  createPublicClient,
  createWalletClient,
  http,
  encodeFunctionData,
  parseAbi,
  formatUnits,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { lookupTrustedDecimals } from './x402-payment.js';

/* ── Key loading ─────────────────────────────────────────────────── */

/**
 * Read the key once at startup. Kept module-private: nothing exports the key
 * itself, only an account object that can sign.
 */
let cachedAccount: ReturnType<typeof privateKeyToAccount> | null = null;
let keyLoadError: string | null = null;

function loadKeyMaterial(): string | null {
  const inline = (process.env.AGENTWALLET_PRIVATE_KEY || '').trim();
  if (inline) return inline;

  const file = (process.env.AGENTWALLET_KEYFILE || '').trim();
  if (file) {
    try {
      return readFileSync(file, 'utf8').trim();
    } catch (e) {
      keyLoadError = `Could not read AGENTWALLET_KEYFILE at ${file}: ${(e as Error).message}`;
      return null;
    }
  }
  return null;
}

function normalizeKey(raw: string): Hex {
  const hex = raw.startsWith('0x') ? raw.slice(2) : raw;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      'Invalid private key. Expected 64 hex characters, with or without a 0x prefix. ' +
      'The value itself is never logged.'
    );
  }
  return `0x${hex}` as Hex;
}

/** True when the server is running non-custodially. */
export function isLocalMode(): boolean {
  return Boolean(
    (process.env.AGENTWALLET_PRIVATE_KEY || '').trim() ||
    (process.env.AGENTWALLET_KEYFILE || '').trim()
  );
}

export function getLocalAccount() {
  if (cachedAccount) return cachedAccount;
  if (keyLoadError) throw new Error(keyLoadError);

  const raw = loadKeyMaterial();
  if (!raw) throw new Error('Local signing mode is not configured.');
  if (keyLoadError) throw new Error(keyLoadError);

  cachedAccount = privateKeyToAccount(normalizeKey(raw));
  return cachedAccount;
}

/** The address the local key controls. Safe to log. */
export function getLocalAddress(): Address {
  return getLocalAccount().address;
}

/* ── Chains and RPC ──────────────────────────────────────────────── */

/**
 * Public RPC endpoints used only when the operator has not supplied their own.
 * Anyone serious about privacy should set AGENTWALLET_RPC_<chainId>, because
 * a public RPC sees every address you query.
 */
const DEFAULT_RPC: Record<number, string> = {
  1: 'https://eth.llamarpc.com',
  10: 'https://mainnet.optimism.io',
  56: 'https://bsc-dataseed.binance.org',
  137: 'https://polygon-rpc.com',
  8453: 'https://mainnet.base.org',
  42161: 'https://arb1.arbitrum.io/rpc',
  43114: 'https://api.avax.network/ext/bc/C/rpc',
  7777777: 'https://rpc.zora.energy',
  369: 'https://rpc.pulsechain.com',
};

export function resolveRpcUrl(chainId: number): string {
  const perChain = (process.env[`AGENTWALLET_RPC_${chainId}`] || '').trim();
  if (perChain) return perChain;
  const generic = (process.env.AGENTWALLET_RPC_URL || '').trim();
  if (generic) return generic;
  const fallback = DEFAULT_RPC[chainId];
  if (fallback) return fallback;
  throw new Error(
    `No RPC endpoint for chain ${chainId} in local mode. ` +
    `Set AGENTWALLET_RPC_${chainId} to an endpoint you trust.`
  );
}

function clients(chainId: number) {
  const url = resolveRpcUrl(chainId);
  const transport = http(url);
  // The chain object is deliberately minimal: viem only needs the id for
  // signing, and not pinning a chain definition keeps any EVM network usable.
  const chain = { id: chainId, name: `chain-${chainId}`, nativeCurrency: { name: 'Native', symbol: 'NATIVE', decimals: 18 }, rpcUrls: { default: { http: [url] } } } as const;
  return {
    pub: createPublicClient({ chain, transport }),
    wallet: createWalletClient({ account: getLocalAccount(), chain, transport }),
  };
}

/* ── Spend guards ────────────────────────────────────────────────── */

/**
 * Per-transaction ceiling for local mode, in native units (ETH, MATIC...).
 * Custodial mode enforces limits server-side; local mode has no server, so the
 * guard has to live here or it does not exist at all.
 */
function assertWithinNativeCap(valueWei: bigint) {
  const cap = (process.env.AGENTWALLET_MAX_TX_NATIVE || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_NATIVE must be a decimal number, got "${cap}".`);
  }
  const [whole, frac = ''] = cap.split('.');
  const capWei = BigInt(whole + frac.padEnd(18, '0').slice(0, 18));
  if (valueWei > capWei) {
    throw new Error(
      `Blocked by local guard: transaction value exceeds AGENTWALLET_MAX_TX_NATIVE (${cap}). ` +
      `Raise the cap deliberately if this is intended.`
    );
  }
}

/* ── Read operations ─────────────────────────────────────────────── */

export async function localNativeBalance(chainId: number) {
  const { pub } = clients(chainId);
  const address = getLocalAddress();
  const wei = await pub.getBalance({ address });
  return { address, chain_id: chainId, balance_wei: wei.toString(), balance: formatUnits(wei, 18), mode: 'local' };
}

const ERC20_ABI = parseAbi([
  'function balanceOf(address) view returns (uint256)',
  'function decimals() view returns (uint8)',
  'function symbol() view returns (string)',
  'function transfer(address,uint256) returns (bool)',
  'function approve(address,uint256) returns (bool)',
  'function allowance(address,address) view returns (uint256)',
]);

export async function localTokenBalance(chainId: number, token: Address) {
  const { pub } = clients(chainId);
  const address = getLocalAddress();
  const [raw, decimals, symbol] = await Promise.all([
    pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'balanceOf', args: [address] }) as Promise<bigint>,
    pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'decimals' }).catch(() => 18) as Promise<number>,
    pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'symbol' }).catch(() => '') as Promise<string>,
  ]);
  return {
    address, chain_id: chainId, token, symbol,
    decimals: Number(decimals),
    balance_raw: raw.toString(),
    balance: formatUnits(raw, Number(decimals)),
    mode: 'local',
  };
}

/* ── Write operations ────────────────────────────────────────────── */

export interface LocalSendResult {
  tx_hash: string;
  from: string;
  to: string;
  value: string;
  chain_id: number;
  mode: 'local';
  signed_locally: true;
}

/**
 * Sign and broadcast a transaction. viem fills nonce, gas and EIP-1559 fees
 * from the RPC unless they are supplied.
 */
/**
 * Bound ERC-20 movement, which the native cap does not see.
 *
 * A token transfer is `to = tokenContract, value = 0, data = transfer(...)`, so
 * assertWithinNativeCap always passed it. In local mode there is no server-side
 * limit behind this, and the README tells operators the local guard is the only
 * one they have, so a wallet holding USDC was effectively uncapped. Covers
 * transfer, transferFrom and approve, since an unbounded approval is a drain
 * waiting to happen.
 *
 * Opt-in via AGENTWALLET_MAX_TX_TOKEN, expressed in human units of the token.
 * When the token's decimals are not known locally we assume 6, the smallest in
 * common use, which makes the raw ceiling the tightest one and fails closed
 * rather than open.
 */
function assertWithinTokenCap(chainId: number, token: Address, data: Hex) {
  const cap = (process.env.AGENTWALLET_MAX_TX_TOKEN || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_TOKEN must be a decimal number, got "${cap}".`);
  }

  const hex = data.slice(2);
  const selector = hex.slice(0, 8).toLowerCase();
  // transfer(address,uint256) | approve(address,uint256) | transferFrom(address,address,uint256)
  const layouts: Record<string, number> = { a9059cbb: 1, '095ea7b3': 1, '23b872dd': 2 };
  const argIndex = layouts[selector];
  if (argIndex === undefined) return; // not a value-moving ERC-20 call

  const word = hex.slice(8 + argIndex * 64, 8 + (argIndex + 1) * 64);
  if (word.length !== 64) return; // malformed; leave it to the node to reject
  const amount = BigInt('0x' + word);

  const decimals = lookupTrustedDecimals(chainId, token) ?? 6;
  const [whole, frac = ''] = cap.split('.');
  const capRaw = BigInt(whole + frac.padEnd(decimals, '0').slice(0, decimals));

  if (amount > capRaw) {
    const what = selector === '095ea7b3' ? 'approval' : 'token transfer';
    throw new Error(
      `Blocked by local guard: ${what} of ${amount} base units exceeds ` +
      `AGENTWALLET_MAX_TX_TOKEN (${cap}, evaluated at ${decimals} decimals). ` +
      `Raise the cap deliberately if this is intended.`
    );
  }
}

export async function localSend(
  chainId: number,
  to: Address,
  valueWei: bigint,
  data?: Hex
): Promise<LocalSendResult> {
  assertWithinNativeCap(valueWei);
  if (data && data.length >= 10) assertWithinTokenCap(chainId, to, data);
  const { wallet } = clients(chainId);
  const hash = await wallet.sendTransaction({
    to,
    value: valueWei,
    ...(data ? { data } : {}),
  } as Parameters<typeof wallet.sendTransaction>[0]);

  return {
    tx_hash: hash,
    from: getLocalAddress(),
    to,
    value: valueWei.toString(),
    chain_id: chainId,
    mode: 'local',
    signed_locally: true,
  };
}

/** ERC-20 transfer, encoded locally. */
export async function localTransferToken(
  chainId: number,
  token: Address,
  to: Address,
  rawAmount: string
): Promise<LocalSendResult> {
  const data = encodeFunctionData({
    abi: ERC20_ABI,
    functionName: 'transfer',
    args: [to, BigInt(rawAmount)],
  });
  const res = await localSend(chainId, token, 0n, data);
  return { ...res, to, value: rawAmount };
}

/** ERC-20 approve, encoded locally. */
export async function localApproveToken(
  chainId: number,
  token: Address,
  spender: Address,
  rawAmount: string
): Promise<LocalSendResult> {
  const data = encodeFunctionData({
    abi: ERC20_ABI,
    functionName: 'approve',
    args: [spender, BigInt(rawAmount)],
  });
  const res = await localSend(chainId, token, 0n, data);
  return { ...res, to: spender, value: rawAmount };
}

/** Sign a message without broadcasting anything. */
export async function localSignMessage(message: string): Promise<{ address: string; message: string; signature: string; mode: 'local' }> {
  const signature = await getLocalAccount().signMessage({ message });
  return { address: getLocalAddress(), message, signature, mode: 'local' };
}

/**
 * One-line summary for tools that report wallet identity. Deliberately mirrors
 * the shape of a custodial wallet record so callers do not need to branch.
 */
export function localWalletRecord() {
  return {
    id: 'local',
    address: getLocalAddress(),
    wallet_type: 'evm',
    mode: 'local',
    custody: 'self',
    note: 'Signed in-process. The private key is never sent to AgentWallet servers.',
  };
}
