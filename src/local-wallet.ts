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
  BaseError,
  ContractFunctionZeroDataError,
  ContractFunctionRevertedError,
  ExecutionRevertedError,
  AbiDecodingDataSizeTooSmallError,
  AbiDecodingDataSizeInvalidError,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { lookupTrustedDecimals } from './x402-payment.js';
import { typedDataFor, type Eip3009Authorization } from './x402-eip3009.js';
import { uptoTypedData, type UptoPermit2Authorization } from './x402-permit2.js';

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
 *
 * Decimals decide the ceiling, so getting them wrong breaks the guard. They are
 * resolved in this order: the trusted registry, then the token's own decimals()
 * on chain (cached), and finally 0. Assuming 0 for an unresolvable token is the
 * only value that cannot fail open: any real token has decimals >= 0, so a cap
 * evaluated at 0 is never larger than the true one.
 *
 * Do not "assume 6 because it is the smallest in common use". It is not: GUSD
 * and EURS use 2, and some tokens use 0. For a token with d decimals, a ceiling
 * evaluated at 6 is 10**(6-d) times too permissive, which is how AW-001 let a
 * 2-decimal token move 10,000x the configured cap.
 */
const decimalsCache = new Map<string, number>();

/**
 * What a decimals() probe learned about an address. The four outcomes are
 * kept apart on purpose: only `not-a-token` may ever reach an allow branch.
 *
 * - a number: the contract answered decimals() with a usable value
 * - `unusable`: it answered, but with a value no real token has (outside
 *   0..36) or data that does not decode; it IS a contract that implements
 *   decimals(), so treat it as a token and price nothing on trust
 * - `not-a-token`: the call reverted or returned no data, which is how a
 *   router, bridge or plain account answers
 * - `unreachable`: the RPC failed, so nothing is known either way
 *
 * Reported privately 2026-09-26: the previous shape collapsed `unusable` and
 * `unreachable` into the same null as `not-a-token`, so a token whose
 * decimals() returned 77 was classified as "not a token" and unpriced
 * calldata to it went through the cap unrefused. Byte-identical contracts
 * differing only in that immutable were blocked (18) and sent (77).
 */
type DecimalsProbe = number | 'unusable' | 'not-a-token' | 'unreachable';

/**
 * Decimals for `token`: the trusted registry, then the contract's own
 * decimals() (cached on success). See DecimalsProbe for the other outcomes.
 */
async function probeTokenDecimals(chainId: number, token: Address): Promise<DecimalsProbe> {
  const known = lookupTrustedDecimals(chainId, token);
  if (typeof known === 'number') return known;

  const key = `${chainId}:${token.toLowerCase()}`;
  const cached = decimalsCache.get(key);
  if (typeof cached === 'number') return cached;

  let onChain: number | bigint;
  try {
    const { pub } = clients(chainId);
    onChain = await pub.readContract({
      address: token,
      abi: ERC20_ABI,
      functionName: 'decimals',
    }) as number | bigint;
  } catch (err) {
    // viem wraps every readContract failure in ContractFunctionExecutionError;
    // the cause says whether the contract itself declined (revert, empty
    // return: not an ERC-20) or the answer never arrived (RPC down, timeout,
    // malformed response). Only the first is evidence of anything.
    const declined = err instanceof BaseError && err.walk(
      (e) => e instanceof ContractFunctionZeroDataError
        || e instanceof ContractFunctionRevertedError
        || e instanceof ExecutionRevertedError // nodes that report a revert as -32000 rather than 3
    ) !== null;
    if (declined) return 'not-a-token';
    // A decode failure on non-empty data means the contract answered
    // decimals() with something that is not a uint8: a token, just a broken one.
    const decodeFailed = err instanceof BaseError && err.walk(
      (e) => e instanceof AbiDecodingDataSizeTooSmallError || e instanceof AbiDecodingDataSizeInvalidError
    ) !== null;
    return decodeFailed ? 'unusable' : 'unreachable';
  }
  const d = Number(onChain);
  // Reject nonsense rather than trusting it; an out-of-range value would
  // widen the ceiling exactly like the old assumption did.
  if (Number.isInteger(d) && d >= 0 && d <= 36) {
    decimalsCache.set(key, d);
    return d;
  }
  return 'unusable';
}

/**
 * Decimals to price a known transfer or approval at. Anything short of a
 * usable answer is evaluated at 0, the only value that cannot fail open.
 */
async function resolveTokenDecimals(chainId: number, token: Address): Promise<number> {
  const probe = await probeTokenDecimals(chainId, token);
  return typeof probe === 'number' ? probe : 0;
}

/** Canonical Permit2, the same address on every EVM chain it is deployed to. */
const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';

/**
 * Calls the token cap knows how to price: which calldata word holds the
 * amount, and (for Permit2) which holds the token, since there `to` is
 * Permit2 itself rather than the token.
 */
type CapLayout = { amountIndex: number; tokenIndex?: number; what: string };
const CAP_LAYOUTS: Record<string, CapLayout> = {
  a9059cbb: { amountIndex: 1, what: 'token transfer' },                        // transfer(address,uint256)
  '23b872dd': { amountIndex: 2, what: 'token transfer' },                      // transferFrom(address,address,uint256)
  '095ea7b3': { amountIndex: 1, what: 'approval' },                            // approve(address,uint256)
  '39509351': { amountIndex: 1, what: 'allowance increase' },                  // increaseAllowance(address,uint256)
  '87517c45': { amountIndex: 2, tokenIndex: 0, what: 'Permit2 approval' },     // Permit2.approve(address,address,uint160,uint48)
};

/**
 * The selector table used to be an allowlist that returned early for anything
 * it did not recognise, so `increaseAllowance`, a direct Permit2 `approve`, or
 * any other function on a token contract went through uncapped while the guard
 * reported nothing. Reported privately 2026-09-25. Now: priced calls are
 * checked, and unpriced calldata aimed at a token contract or at Permit2 is
 * refused, because any state change there can move funds. Calls to other
 * contracts (routers, bridges) still pass: they can only pull what an approval
 * already allowed, and approvals are what this guard bounds.
 */
async function assertWithinTokenCap(chainId: number, to: Address, data: Hex) {
  const cap = (process.env.AGENTWALLET_MAX_TX_TOKEN || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_TOKEN must be a decimal number, got "${cap}".`);
  }

  const hex = data.slice(2);
  const selector = hex.slice(0, 8).toLowerCase();
  const isPermit2 = to.toLowerCase() === PERMIT2;
  const layout = CAP_LAYOUTS[selector];
  const priced = layout && (layout.tokenIndex === undefined || isPermit2);

  if (!priced) {
    if (process.env.AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS === '1') return;
    // Only a contract that demonstrably declines decimals() is let through.
    // "Answered nonsense" and "could not ask" both refuse: the first is a
    // token with a broken or hostile decimals(), the second is no evidence at
    // all, and this guard does not allow on no evidence (2026-09-26 report).
    const probe: DecimalsProbe = isPermit2 ? 'unusable' : await probeTokenDecimals(chainId, to);
    if (probe !== 'not-a-token') {
      const why = probe === 'unreachable'
        ? `the RPC for chain ${chainId} could not be reached to classify the target, so the guard cannot tell a token from a router`
        : `the target is ${isPermit2 ? 'Permit2' : 'a token contract'} and this calldata is not one AGENTWALLET_MAX_TX_TOKEN can price`;
      throw new Error(
        `Blocked by local guard: calldata selector 0x${selector} refused rather than let through uncapped: ${why}. ` +
        `Use transfer, transferFrom, approve, increaseAllowance or Permit2 approve, ` +
        `or set AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1 to allow it deliberately.`
      );
    }
    return; // an ordinary contract call; it can only pull what an approval already allowed
  }

  const wordAt = (i: number) => hex.slice(8 + i * 64, 8 + (i + 1) * 64);
  const word = wordAt(layout.amountIndex);
  if (word.length !== 64) return; // malformed; leave it to the node to reject
  const amount = BigInt('0x' + word);

  let token = to;
  if (layout.tokenIndex !== undefined) {
    const tw = wordAt(layout.tokenIndex);
    if (tw.length !== 64) return;
    token = ('0x' + tw.slice(24)) as Address;
  }

  const decimals = await resolveTokenDecimals(chainId, token);
  const [whole, frac = ''] = cap.split('.');
  const capRaw = BigInt(whole + frac.padEnd(decimals, '0').slice(0, decimals));

  if (amount > capRaw) {
    throw new Error(
      `Blocked by local guard: ${layout.what} of ${amount} base units exceeds ` +
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
  if (data && data.length >= 10) await assertWithinTokenCap(chainId, to, data);
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

/* ── x402 "exact": EIP-3009 authorization signed in-process ──────── */

/**
 * Sign a TransferWithAuthorization for an x402 payment. Nothing is broadcast;
 * the resource server's facilitator settles it on-chain. The amount is put
 * through the same AGENTWALLET_MAX_TX_TOKEN guard as a transfer, because that
 * is exactly what the authorization lets someone else execute.
 */
export async function localSignAuthorization(
  chainId: number,
  asset: Address,
  domain: { name: string; version: string },
  auth: Eip3009Authorization,
): Promise<{ signature: `0x${string}`; from: Address; mode: 'local' }> {
  if (!/^0x[a-fA-F0-9]{40}$/.test(asset)) throw new Error(`Local mode needs an EVM token address for x402, got "${asset}".`);
  if (!/^0x[a-fA-F0-9]{40}$/.test(auth.to)) throw new Error(`Local mode needs an EVM payTo address for x402, got "${auth.to}".`);
  if (!/^\d+$/.test(auth.value)) throw new Error(`x402 authorization value must be integer base units, got "${auth.value}".`);
  const calldata = ('0xa9059cbb'
    + auth.to.slice(2).toLowerCase().padStart(64, '0')
    + BigInt(auth.value).toString(16).padStart(64, '0')) as Hex;
  await assertWithinTokenCap(chainId, asset, calldata);
  const from = getLocalAddress();
  const signature = await getLocalAccount().signTypedData(typedDataFor(chainId, asset, domain.name, domain.version, { ...auth, from }));
  return { signature, from, mode: 'local' };
}

/** Read-only eth_call against the local RPC, same shape as the hosted /eth-call route. */
export async function localEthCall(chainId: number, to: Address, data: Hex): Promise<{ result: string }> {
  const client = createPublicClient({ transport: http(resolveRpcUrl(chainId)) });
  const r = await client.call({ to, data });
  return { result: r.data ?? '0x' };
}

/** Read-only eth_getCode against the local RPC, same shape as the hosted /eth-get-code route. */
export async function localGetCode(chainId: number, address: Address): Promise<{ code: string }> {
  const client = createPublicClient({ transport: http(resolveRpcUrl(chainId)) });
  const code = await client.getCode({ address });
  return { code: code ?? '0x' };
}

/** x402 "upto": sign a Permit2 max-authorization in-process. The maximum goes through the token cap like a transfer would. */
export async function localSignPermit2Upto(chainId: number, auth: UptoPermit2Authorization): Promise<{ signature: `0x${string}`; from: Address; mode: 'local' }> {
  const token = auth.permitted.token;
  if (!/^0x[a-fA-F0-9]{40}$/.test(token)) throw new Error(`Local mode needs an EVM token address for x402 upto, got "${token}".`);
  if (!/^\d+$/.test(auth.permitted.amount)) throw new Error(`x402 upto amount must be integer base units, got "${auth.permitted.amount}".`);
  const calldata = ('0xa9059cbb' + auth.witness.to.slice(2).toLowerCase().padStart(64, '0') + BigInt(auth.permitted.amount).toString(16).padStart(64, '0')) as Hex;
  await assertWithinTokenCap(chainId, token, calldata);
  const from = getLocalAddress();
  const signature = await getLocalAccount().signTypedData(uptoTypedData(chainId, { ...auth, from }));
  return { signature, from, mode: 'local' };
}
