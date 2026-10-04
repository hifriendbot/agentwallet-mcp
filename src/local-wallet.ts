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

import { readFileSync, statSync } from 'node:fs';
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
  keccak256,
  type Address,
  type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { nonceManager } from 'viem/nonce';
import { lookupTrustedDecimals, maxAuthWindowSeconds } from './x402-payment.js';
import { wrappedNativeAddress } from './wrapped-native.js';
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
      if (process.platform !== 'win32') {
        const mode = statSync(file).mode & 0o777;
        if (mode & 0o077) console.error(`AgentWallet MCP: warning, AGENTWALLET_KEYFILE ${file} is readable by other users (mode ${mode.toString(8)}); chmod 600 it.`);
      }
      return readFileSync(file, 'utf8').trim();
    } catch (e) {
      keyLoadError = `Could not read AGENTWALLET_KEYFILE at ${file}: ${(e as Error).message}`;
      return null;
    }
  }
  return null;
}

const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
function normalizeKey(raw: string): Hex {
  const hex = raw.startsWith('0x') ? raw.slice(2) : raw;
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(
      'Invalid private key. Expected 64 hex characters, with or without a 0x prefix. ' +
      'The value itself is never logged.'
    );
  }
  // Checked here with a fixed message: the curve library's own range error
  // prints the offending value in decimal (2026-10-04 audit).
  const n = BigInt('0x' + hex);
  if (n === 0n || n >= SECP256K1_N) {
    throw new Error('Invalid private key: the value is outside the secp256k1 range. The value itself is never logged.');
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
  if (keyLoadError) throw new Error(keyLoadError); // the keyfile's own reason, before the generic line
  if (!raw) throw new Error('Local signing mode is not configured.');

  // The nonce manager hands parallel sends consecutive nonces; without it every
  // concurrent send read the same pending nonce and all but one failed (round 3).
  cachedAccount = privateKeyToAccount(normalizeKey(raw), { nonceManager });
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
  if (perChain) return assertRpcScheme(perChain, `AGENTWALLET_RPC_${chainId}`);
  const generic = (process.env.AGENTWALLET_RPC_URL || '').trim();
  if (generic) return assertRpcScheme(generic, 'AGENTWALLET_RPC_URL');
  const fallback = DEFAULT_RPC[chainId];
  if (fallback) return fallback;
  throw new Error(
    `No RPC endpoint for chain ${chainId} in local mode. ` +
    `Set AGENTWALLET_RPC_${chainId} to an endpoint you trust.`
  );
}

/** An RPC over plain http to anything but loopback is the hostile-node model in full; refused like the API URL is. */
function assertRpcScheme(url: string, name: string): string {
  let u: URL;
  try { u = new URL(url); } catch { throw new Error(`${name} is not a URL: "${url}".`); }
  const loopback = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) {
    throw new Error(`${name} must be https (got ${u.protocol}//${u.host}); plain http is allowed only for localhost.`);
  }
  return url;
}

/**
 * Chain ids each RPC URL has been seen to serve, so an operator pointing
 * AGENTWALLET_RPC_URL at one node for every chain, or mistyping a per-chain
 * URL, cannot have cap pricing (decimals, token-or-router) answered by a
 * different chain than the one the transaction or authorization is bound to.
 */
const verifiedRpcChains = new Map<string, number>();

export async function assertRpcServesChain(chainId: number): Promise<void> {
  const url = resolveRpcUrl(chainId);
  const seen = verifiedRpcChains.get(url);
  if (seen === chainId) return;
  if (seen !== undefined) throw new Error(`RPC for chain ${chainId} (${new URL(url).origin}) serves chain ${seen}. Set AGENTWALLET_RPC_${chainId} to a node on chain ${chainId}.`);
  const actual = await createPublicClient({ transport: http(url) }).getChainId();
  if (actual !== chainId) throw new Error(`RPC for chain ${chainId} (${new URL(url).origin}) answers eth_chainId = ${actual}. Refusing to sign for chain ${chainId} against it; set AGENTWALLET_RPC_${chainId}.`);
  verifiedRpcChains.set(url, actual);
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
      `Blocked by local guard: transaction value exceeds AGENTWALLET_MAX_TX_NATIVE (${cap}), a cap only the operator can change. ` +
      `Do not edit the environment or config to raise it.`
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
  const [raw, decimalsRaw, symbol] = await Promise.all([
    pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'balanceOf', args: [address] }) as Promise<bigint>,
    pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'decimals' }).catch(() => null) as Promise<number | null>,
    pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'symbol' }).catch(() => '') as Promise<string>,
  ]);
  // A decimals() of 2^20 handed to viem's formatUnits held the whole server for
  // minutes (quadratic trailing-zero trim, round 4): only 0..36 is formatted.
  const d = Number(decimalsRaw);
  const safe = Number.isInteger(d) && d >= 0 && d <= 36 ? d : null;
  return {
    address, chain_id: chainId, token, symbol,
    decimals: safe,
    balance_raw: raw.toString(),
    balance: safe === null ? null : formatUnits(raw, safe),
    ...(safe === null ? { warning: 'the token reported decimals outside 0..36 (or none); only the raw balance is shown' } : {}),
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
  gas?: string; max_fee_per_gas?: string; worst_case_fee?: string;
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

  // The raw JSON-RPC envelope is classified here rather than through viem's
  // readContract: viem maps error code -32603 ("Internal error", what an
  // overloaded node or a proxy answers) and an empty envelope to "the contract
  // reverted", which is the one answer this guard treats as evidence of a
  // non-token (2026-10-04 audit). Only an explicit revert counts as that.
  let result: unknown;
  try {
    const { pub } = clients(chainId);
    result = await pub.request({ method: 'eth_call', params: [{ to: token, data: DECIMALS_SELECTOR }, 'latest'] } as never);
  } catch (err) {
    return classifyDecimalsError(err);
  }
  if (result === '0x') return 'not-a-token'; // answered with nothing: no decimals() here
  if (typeof result !== 'string' || !/^0x([0-9a-fA-F]{2})+$/.test(result)) return 'unreachable'; // not an answer at all
  if (result.length !== 66) return 'unusable'; // answered, but not one uint8 word
  const d = Number(BigInt(result));
  // Reject nonsense rather than trusting it; an out-of-range value would
  // widen the ceiling exactly like the old assumption did. Above 18 the RPC is
  // the only witness and a lie there scales the cap by 10^18 (a node saying 36
  // for mainnet WETH, round 4): such tokens must be pinned with
  // AGENTWALLET_TOKEN_DECIMALS.
  if (Number.isInteger(d) && d >= 0 && d <= 18) {
    decimalsCache.set(key, d);
    return d;
  }
  return 'unusable';
}

const DECIMALS_SELECTOR = '0x313ce567';
/** An eth_call failure is a revert only when the node says so; every other failure is "could not ask". */
export function classifyDecimalsError(err: unknown): DecimalsProbe {
  const e = err as { code?: unknown; data?: unknown; message?: string; details?: string; shortMessage?: string };
  const code = typeof e?.code === 'number' ? e.code : NaN;
  const text = [e?.message, e?.details, e?.shortMessage].filter(Boolean).join(' ');
  const hasRevertData = typeof e?.data === 'string' && /^0x[0-9a-fA-F]+$/.test(e.data); // "0x" alone is not revert data
  if (code === 3) return 'not-a-token'; // the JSON-RPC "execution error" code
  if ((code === -32000 || code === -32603 || code === -32015) && (/revert/i.test(text) || hasRevertData)) return 'not-a-token';
  return 'unreachable';
}

/**
 * Decimals to price a known transfer or approval at. Anything short of a
 * usable answer is evaluated at 0, the only value that cannot fail open.
 */
async function resolveTokenDecimals(chainId: number, token: Address): Promise<number> {
  const probe = await probeTokenDecimals(chainId, token);
  return typeof probe === 'number' ? probe : 0;
}

/** Canonical Permit2, plus the chains that run a different deployment. */
const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';
const PERMIT2_BY_CHAIN: Record<number, string> = { 324: '0x0000000000225e31d15943971f47ad3022f714fa' }; // zkSync Era
export function permit2AddressFor(chainId: number): string { return PERMIT2_BY_CHAIN[chainId] || PERMIT2; }
/* Permit2's own function selectors. Calldata with one of these aimed at a
   contract that declines decimals() is a Permit2 call on a deployment this
   table does not know, and is refused rather than let through as "a router"
   (2026-10-04 audit). approve, permit (2 shapes), transferFrom (2), lockdown,
   permitTransferFrom (2), permitWitnessTransferFrom (2), invalidateNonces/UnorderedNonces. */
const PERMIT2_SELECTORS = new Set(['87517c45', '2b67b570', '2a2d80d1', '36c78516', '0d58b1db', 'cc53287f', '30f28b7a', 'edd9444b', '137c29fe', 'fe8ec1a7', '3ff9dcb1', '65d9723c']);
/* ERC-721 / ERC-1155 approvals and transfers. A collection declines decimals()
   and so read as "not a token" to the cap, which let setApprovalForAll to an
   attacker through uncapped (2026-10-04 round 2, verified on a live
   collection). Nothing prices an NFT, so these are refused outright. */
const NFT_SELECTORS = new Set(['a22cb465', '42842e0e', 'b88d4fde', 'f242432a', '2eb2c2d6']);

/**
 * Calls the token cap knows how to price: which calldata word holds the
 * amount, and (for Permit2) which holds the token, since there `to` is
 * Permit2 itself rather than the token.
 */
type CapLayout = { amountIndex: number; tokenIndex?: number; what: string; wrappedNativeOnly?: boolean };
const CAP_LAYOUTS: Record<string, CapLayout> = {
  a9059cbb: { amountIndex: 1, what: 'token transfer' },                        // transfer(address,uint256)
  '23b872dd': { amountIndex: 2, what: 'token transfer' },                      // transferFrom(address,address,uint256)
  '095ea7b3': { amountIndex: 1, what: 'approval' },                            // approve(address,uint256)
  '39509351': { amountIndex: 1, what: 'allowance increase' },                  // increaseAllowance(address,uint256)
  '87517c45': { amountIndex: 2, tokenIndex: 0, what: 'Permit2 approval' },     // Permit2.approve(address,address,uint160,uint48)
  // WETH9 calls, priced only when `to` is the chain's own wrapped-native
  // contract (wrappedNativeOnly). deposit() carries its amount as msg.value,
  // not in calldata, hence amountIndex -1; withdraw(uint256) has it at word 0.
  d0e30db0: { amountIndex: -1, what: 'wrap of native into the wrapped token', wrappedNativeOnly: true }, // deposit()
  '2e1a7d4d': { amountIndex: 0, what: 'unwrap of the wrapped token', wrappedNativeOnly: true },         // withdraw(uint256)
};

/**
 * The selector table used to be an allowlist that returned early for anything
 * it did not recognise, so `increaseAllowance`, a direct Permit2 `approve`, or
 * any other function on a token contract went through uncapped while the guard
 * reported nothing. Reported privately 2026-09-25. Now: priced calls are
 * checked, and unpriced calldata aimed at a token contract or at Permit2 is
 * refused, because any state change there can move funds. Calls to other
 * contracts (routers, bridges) still pass: they can only pull what an approval
 * already allows. Approvals granted through this guard are bounded by it; an
 * allowance that existed before the cap was set, or was granted elsewhere, is
 * not, and a router call can spend up to that allowance (noted 2026-10-04).
 *
 * Reported privately 2026-09-27: that refusal also caught our own wrap_eth and
 * unwrap_eth, whose WETH deposit() / withdraw(uint256) calldata was unpriced,
 * so both tools died the moment the cap was set and the only way back was
 * AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1, which weakens the guard for every
 * call. Now both are priced, but only on the chain's own wrapped-native
 * contract; the same selectors on any other token stay refused.
 */
async function assertWithinTokenCap(chainId: number, to: Address, data: Hex, valueWei = 0n) {
  const cap = (process.env.AGENTWALLET_MAX_TX_TOKEN || '').trim();
  if (!cap) return;
  if (!/^\d+(\.\d+)?$/.test(cap)) {
    throw new Error(`AGENTWALLET_MAX_TX_TOKEN must be a decimal number, got "${cap}".`);
  }

  const hex = data.slice(2);
  const selector = hex.slice(0, 8).toLowerCase();
  const isPermit2 = to.toLowerCase() === PERMIT2 || to.toLowerCase() === permit2AddressFor(chainId);
  const layout = CAP_LAYOUTS[selector];
  const isWrappedNative = to.toLowerCase() === wrappedNativeAddress(chainId);
  const priced = layout
    && (layout.tokenIndex === undefined || isPermit2)
    && (!layout.wrappedNativeOnly || isWrappedNative);

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
        `Use transfer, transferFrom, approve, increaseAllowance, Permit2 approve, ` +
        `or deposit/withdraw on the chain's wrapped-native contract, ` +
        `or ask the operator, who alone can set AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1.`
      );
    }
    if (NFT_SELECTORS.has(selector)) {
      throw new Error(
        `Blocked by local guard: calldata selector 0x${selector} is an NFT approval or transfer (ERC-721/1155) aimed at ${to}; AGENTWALLET_MAX_TX_TOKEN cannot price it, ` +
        `so it is refused rather than let through uncapped. Only the operator can allow it (AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1).`
      );
    }
    if (PERMIT2_SELECTORS.has(selector)) {
      throw new Error(
        `Blocked by local guard: calldata selector 0x${selector} is a Permit2 function aimed at ${to}, which is not the Permit2 deployment this guard knows for chain ${chainId}; ` +
        `refused rather than let through uncapped. Only the operator can allow it (AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1).`
      );
    }
    return; // an ordinary contract call; it can only pull what an existing approval allows (see the note above)
  }

  const wordAt = (i: number) => hex.slice(8 + i * 64, 8 + (i + 1) * 64);
  let amount: bigint;
  if (layout.amountIndex < 0) {
    amount = valueWei; // deposit(): what gets wrapped is the native value sent along
  } else {
    const word = wordAt(layout.amountIndex);
    // A short word is not "malformed, the node will reject it": pre-0.5 Solidity
    // (mainnet WETH9 among others) zero-pads truncated calldata and reads an
    // amount 256x larger per missing byte. Refuse, never assume.
    if (word.length !== 64) throw new Error(`Blocked by local guard: calldata for ${layout.what} is truncated (amount word has ${word.length / 2} bytes, expected 32).`);
    amount = BigInt('0x' + word);
  }

  let token = to;
  if (layout.tokenIndex !== undefined) {
    const tw = wordAt(layout.tokenIndex);
    if (tw.length !== 64) throw new Error(`Blocked by local guard: calldata for ${layout.what} is truncated (token word has ${tw.length / 2} bytes, expected 32).`);
    token = ('0x' + tw.slice(24)) as Address;
  }

  // Every wrapped native in the table is a WETH9 clone with 18 decimals, the
  // same figure wrap_eth and unwrap_eth encode with; no RPC needed to price it.
  const decimals = layout.wrappedNativeOnly ? 18 : await resolveTokenDecimals(chainId, token);
  const [whole, frac = ''] = cap.split('.');
  const capRaw = BigInt(whole + frac.padEnd(decimals, '0').slice(0, decimals));

  if (amount > capRaw) {
    throw new Error(
      `Blocked by local guard: ${layout.what} of ${amount} base units exceeds ` +
      `AGENTWALLET_MAX_TX_TOKEN (${cap}, evaluated at ${decimals} decimals), a cap only the operator can change. ` +
      `Do not edit the environment or config to raise it.`
    );
  }

  // increaseAllowance ADDS to what a spender may already pull. Checking the
  // increment alone let two individually compliant calls leave a standing
  // allowance above the cap (2026-09-28 report), so the resulting total is
  // what gets checked, and an allowance that cannot be read refuses rather
  // than assumes zero. approve() is absolute and needs no read.
  if (selector === '39509351') {
    const spenderWord = wordAt(0);
    if (spenderWord.length !== 64) throw new Error(`Blocked by local guard: calldata for ${layout.what} is truncated (spender word has ${spenderWord.length / 2} bytes, expected 32).`);
    const spender = ('0x' + spenderWord.slice(24)) as Address;
    let current: bigint;
    try {
      const { pub } = clients(chainId);
      current = await pub.readContract({ address: token, abi: ERC20_ABI, functionName: 'allowance', args: [getLocalAddress(), spender] }) as bigint;
    } catch (err) {
      throw new Error(
        `Blocked by local guard: could not read the current allowance of ${spender} on ${token} ` +
        `(${String((err as Error).message).split('\n')[0]}), so the resulting total cannot be checked against AGENTWALLET_MAX_TX_TOKEN.`
      );
    }
    const total = current + amount;
    if (total > capRaw) {
      throw new Error(
        `Blocked by local guard: ${layout.what} of ${amount} base units would leave a standing allowance of ${total} base units ` +
        `for ${spender}, above AGENTWALLET_MAX_TX_TOKEN (${cap}, evaluated at ${decimals} decimals). ` +
        `Use approve with an absolute amount; the cap itself is the operator's to change.`
      );
    }
  }
}

/** Caller-chosen gas parameters (wei / gas units as decimal strings); honoured, then bounded by the fee cap. */
export interface FeeOverrides { gas?: string; maxFeePerGas?: string; maxPriorityFeePerGas?: string }

function parseUint(v: string, what: string): bigint {
  if (!/^\d{1,40}$/.test(v)) throw new Error(`${what} must be a non-negative integer string, got "${v}".`);
  return BigInt(v);
}

/**
 * The most a transaction may burn in fees: gas x maxFeePerGas, in native units.
 * Without it a node that answered a 47,000 gwei tip or a 30M gas estimate took
 * the whole balance as fees on a cap-compliant 0.001 ETH transfer (round 4).
 * Default 0.01; AGENTWALLET_MAX_FEE_NATIVE raises or lowers it.
 */
export function feeCapWei(): bigint {
  const raw = (process.env.AGENTWALLET_MAX_FEE_NATIVE || '0.01').trim();
  if (!/^\d+(\.\d+)?$/.test(raw)) throw new Error(`AGENTWALLET_MAX_FEE_NATIVE must be a decimal number, got "${raw}".`);
  const [whole, frac = ''] = raw.split('.');
  return BigInt(whole + frac.padEnd(18, '0').slice(0, 18));
}

export async function localSend(
  chainId: number,
  to: Address,
  valueWei: bigint,
  data?: Hex,
  fees?: FeeOverrides
): Promise<LocalSendResult> {
  assertWithinNativeCap(valueWei);
  if (data && data !== '0x') {
    if (!/^0x([0-9a-fA-F]{2})*$/.test(data)) throw new Error(`Local mode refuses calldata that is not even-length 0x hex (got ${data.length} chars).`);
    await assertWithinTokenCap(chainId, to, data, valueWei);
  }
  await assertRpcServesChain(chainId);
  const { pub, wallet } = clients(chainId);
  const account = getLocalAccount();
  const base = { account, to, value: valueWei, ...(data ? { data } : {}) };

  // Gas: the caller's figure when given (it used to be read and dropped,
  // round 4), otherwise the node's estimate.
  const gas = fees?.gas ? parseUint(fees.gas, 'gas_limit') : await pub.estimateGas(base);

  // Fees: the caller's figures when given, otherwise the node's; either way the
  // worst case gas x maxFeePerGas must fit the fee cap before anything is signed.
  let maxFeePerGas: bigint | undefined;
  let maxPriorityFeePerGas: bigint | undefined;
  let gasPrice: bigint | undefined;
  if (fees?.maxFeePerGas) {
    maxFeePerGas = parseUint(fees.maxFeePerGas, 'max_fee');
    maxPriorityFeePerGas = fees.maxPriorityFeePerGas ? parseUint(fees.maxPriorityFeePerGas, 'priority_fee') : maxFeePerGas;
  } else {
    try {
      const est = await pub.estimateFeesPerGas();
      maxFeePerGas = est.maxFeePerGas;
      maxPriorityFeePerGas = fees?.maxPriorityFeePerGas ? parseUint(fees.maxPriorityFeePerGas, 'priority_fee') : est.maxPriorityFeePerGas;
    } catch {
      gasPrice = (await pub.estimateFeesPerGas({ type: 'legacy' })).gasPrice; // a chain without EIP-1559
    }
  }
  if (maxFeePerGas !== undefined && maxPriorityFeePerGas !== undefined && maxPriorityFeePerGas > maxFeePerGas) maxPriorityFeePerGas = maxFeePerGas;
  const perGas = maxFeePerGas ?? gasPrice ?? 0n;
  const worst = gas * perGas;
  const feeCap = feeCapWei();
  if (worst > feeCap) {
    throw new Error(
      `Blocked by local guard: the transaction could burn up to ${formatUnits(worst, 18)} native in fees (gas ${gas} x ${formatUnits(perGas, 9)} gwei), ` +
      `above AGENTWALLET_MAX_FEE_NATIVE (${formatUnits(feeCap, 18)}). A node answering an absurd fee or gas estimate is the usual cause; ` +
      `pass gas_limit / max_fee / priority_fee explicitly, or the operator can raise the cap.`
    );
  }

  // Sign here, hash here, then hand the bytes to the node: the hash reported is
  // the one computed from the signed transaction, never the node's answer.
  const address = getLocalAddress();
  const nonce = await account.nonceManager!.consume({ address, chainId, client: pub });
  const request = await wallet.prepareTransactionRequest({
    ...base, gas, nonce, chainId,
    ...(gasPrice !== undefined ? { type: 'legacy' as const, gasPrice } : { type: 'eip1559' as const, maxFeePerGas: maxFeePerGas!, maxPriorityFeePerGas: maxPriorityFeePerGas! }),
  } as Parameters<typeof wallet.prepareTransactionRequest>[0]);
  const signed = await wallet.signTransaction(request as Parameters<typeof wallet.signTransaction>[0]);
  const localHash = keccak256(signed);
  let reported: string;
  try {
    reported = await pub.sendRawTransaction({ serializedTransaction: signed });
  } catch (e) {
    account.nonceManager!.reset({ address, chainId });
    throw new Error(`Broadcast of transaction ${localHash} (nonce ${nonce}) failed: ${(e as Error).message.split('\n')[0]}. The transaction is signed and MAY be live if the node forwarded it before answering; check the hash on an explorer before retrying.`);
  }
  if (reported.toLowerCase() !== localHash.toLowerCase()) {
    throw new Error(`Transaction ${localHash} (nonce ${nonce}) was BROADCAST, but the node answered with a different hash (${String(reported).slice(0, 80)}), so it cannot be trusted about its fate. Verify ${localHash} on an explorer before retrying.`);
  }

  return {
    tx_hash: localHash,
    from: address,
    to,
    value: valueWei.toString(),
    chain_id: chainId,
    mode: 'local',
    signed_locally: true,
    gas: gas.toString(),
    max_fee_per_gas: (maxFeePerGas ?? gasPrice ?? 0n).toString(),
    worst_case_fee: formatUnits(worst, 18),
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

/** The builders clamp the window; this re-checks it here, where the signature is made, so no caller can hand in a longer one. */
function assertWindow(untilSeconds: string, what: string): void {
  if (!/^\d+$/.test(untilSeconds)) throw new Error(`x402 authorization ${what} must be an integer timestamp, got "${untilSeconds}".`);
  const limit = BigInt(Math.floor(Date.now() / 1000) + maxAuthWindowSeconds() + 60);
  if (BigInt(untilSeconds) > limit) throw new Error(`x402 authorization ${what} is more than ${maxAuthWindowSeconds()} seconds in the future; refusing to sign a long-lived claim on funds (AGENTWALLET_X402_MAX_TIMEOUT).`);
}

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
  assertWindow(auth.validBefore, 'validBefore');
  const calldata = ('0xa9059cbb'
    + auth.to.slice(2).toLowerCase().padStart(64, '0')
    + BigInt(auth.value).toString(16).padStart(64, '0')) as Hex;
  await assertRpcServesChain(chainId);
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
  assertWindow(auth.deadline, 'deadline');
  const calldata = ('0xa9059cbb' + auth.witness.to.slice(2).toLowerCase().padStart(64, '0') + BigInt(auth.permitted.amount).toString(16).padStart(64, '0')) as Hex;
  await assertRpcServesChain(chainId);
  await assertWithinTokenCap(chainId, token, calldata);
  const from = getLocalAddress();
  const signature = await getLocalAccount().signTypedData(uptoTypedData(chainId, { ...auth, from }));
  return { signature, from, mode: 'local' };
}
