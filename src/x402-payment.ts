/**
 * Pure helpers for x402 auto-pay amount/token derivation.
 *
 * Isolated from the server bootstrap in index.ts so the funds-sensitive amount
 * math can be unit-tested without starting the MCP server.
 *
 * SECURITY INVARIANT: token decimals must NEVER come from the 402 response.
 * A resource server controls `asset`, `payTo`, `maxAmountRequired` AND
 * `requiredDecimals`. If the cap is scaled using server-declared decimals, the
 * server can inflate the cap arbitrarily: declaring 18 decimals for 6-decimal
 * USDC turns a "1 USDC" cap into 10^18 base units, so a request for
 * 1,000,000,000,000 units (1,000,000 USDC) passes a 1 USDC cap. Reported by
 * ARC Security Research, 2026-08-02, against 1.10.1. Decimals are now resolved
 * from a trusted source and the declared value is only ever used to detect a
 * mismatch and refuse.
 */

export interface X402AcceptLike {
  maxAmountRequired: string;
  requiredDecimals?: number;
  asset?: string;
  extra?: { token?: string };
}

/**
 * Decimals for assets that x402 endpoints actually settle in, keyed by
 * chain id then lowercased contract address (or SPL mint on Solana).
 *
 * This exists so the common path needs no network call, and so local
 * self-custody mode (which may have no reachable API) can still verify a cap.
 * It is intentionally small: every entry is a value that can be checked by
 * hand. Anything not listed is resolved on-chain instead, and if that fails
 * the payment is refused rather than guessed.
 */
export const TRUSTED_DECIMALS: Record<number, Record<string, number>> = {
  // Ethereum
  1: {
    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': 6,  // USDC
    '0xdac17f958d2ee523a2206206994597c13d831ec7': 6,  // USDT
    '0x6b175474e89094c44da98b954eedeac495271d0f': 18, // DAI
  },
  // Base
  8453: {
    '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': 6,  // USDC
    '0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca': 6,  // USDbC
    '0x4200000000000000000000000000000000000006': 18, // WETH
  },
  // Polygon
  137: {
    '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': 6,  // USDC (native)
    '0xc2132d05d31c914a87c6611c10748aeb04b58e8f': 6,  // USDT
  },
  // Arbitrum One
  42161: {
    '0xaf88d065e77c8cc2239327c5edb3a432268e5831': 6,  // USDC
  },
  // Optimism
  10: {
    '0x0b2c639c533813f4aa9d7837caf62653d097ff85': 6,  // USDC
  },
};

/**
 * What the registry knows about each asset beyond its decimals: a display
 * symbol and whether one unit is one US dollar. The symbol is what the agent
 * is shown; it is NEVER taken from the 402 body, because a hostile endpoint
 * would happily label 5 ETH as "5 USDC". The stable flag decides whether
 * AGENTWALLET_MAX_AUTOPAY (denominated in dollars) can price the asset at all.
 */
/* exact: false marks a stablecoin that does not implement EIP-3009 (checked on
   chain 2026-10-04: USDT, DAI and USDbC have no authorizationState), so an
   "exact" x402 requirement naming it can never settle; such assets still work
   for "upto" through Permit2. Absent means true. */
export function assetSupportsExact(chainId: number, asset: string): boolean {
  const key = asset.toLowerCase();
  const hit = KNOWN_ASSETS.find(a => a.chainId === chainId && a.address === key);
  return hit ? hit.exact !== false : true;
}
export const KNOWN_ASSETS: ReadonlyArray<{ chainId: number; address: string; symbol: string; stable: boolean; exact?: boolean }> = [
  { chainId: 1, address: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', symbol: 'USDC', stable: true },
  { chainId: 1, address: '0xdac17f958d2ee523a2206206994597c13d831ec7', symbol: 'USDT', stable: true, exact: false },
  { chainId: 1, address: '0x6b175474e89094c44da98b954eedeac495271d0f', symbol: 'DAI', stable: true, exact: false },
  { chainId: 8453, address: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', symbol: 'USDC', stable: true },
  { chainId: 8453, address: '0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca', symbol: 'USDbC', stable: true, exact: false },
  { chainId: 8453, address: '0x4200000000000000000000000000000000000006', symbol: 'WETH', stable: false },
  { chainId: 137, address: '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', symbol: 'USDC', stable: true },
  { chainId: 137, address: '0xc2132d05d31c914a87c6611c10748aeb04b58e8f', symbol: 'USDT0', stable: true, exact: false },
  { chainId: 43114, address: '0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e', symbol: 'USDC', stable: true },
  { chainId: 42161, address: '0xaf88d065e77c8cc2239327c5edb3a432268e5831', symbol: 'USDC', stable: true },
  { chainId: 10, address: '0x0b2c639c533813f4aa9d7837caf62653d097ff85', symbol: 'USDC', stable: true },
  { chainId: 900, address: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', symbol: 'USDC', stable: true },
  { chainId: 900, address: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', symbol: 'USDT', stable: true },
];

const NATIVE_SYMBOL: Record<number, string> = {
  1: 'ETH', 8453: 'ETH', 42161: 'ETH', 10: 'ETH', 7777777: 'ETH',
  137: 'POL', 56: 'BNB', 43114: 'AVAX', 369: 'PLS',
  900: 'SOL', 901: 'SOL', 902: 'SOL',
};

function assetKey(chainId: number, asset: string): string {
  // EVM addresses are case-insensitive hex; SPL mints are case-sensitive base58.
  return `${chainId}:${/^0x/i.test(asset) ? asset.toLowerCase() : asset}`;
}
const KNOWN_BY_KEY = new Map(KNOWN_ASSETS.map(a => [assetKey(a.chainId, a.address), a]));

/** Symbol of the chain's native asset, or "native" for a chain this build does not know. */
export function nativeSymbol(chainId: number): string {
  return NATIVE_SYMBOL[chainId] ?? 'native';
}

/** True when one unit of the asset is one US dollar according to the registry. */
export function isStableAsset(chainId: number, asset: string): boolean {
  return Boolean(asset) && KNOWN_BY_KEY.get(assetKey(chainId, asset))?.stable === true;
}

/**
 * What to call an asset when talking to the agent. Registry symbol, else the
 * chain's native symbol when there is no asset, else the bare address. Never
 * anything the 402 body said.
 */
export function assetLabel(chainId: number, asset: string): string {
  if (!asset) return nativeSymbol(chainId);
  return KNOWN_BY_KEY.get(assetKey(chainId, asset))?.symbol ?? asset;
}

/**
 * Whether an x402 requirement's asset may be paid automatically at all.
 *
 * AGENTWALLET_MAX_AUTOPAY is "1" by default and every operator reads it as one
 * dollar. Measured against native ETH that same "1" is a few thousand dollars,
 * so a requirement with no asset (native) or a non-stable token is refused
 * unless the operator lists it in AGENTWALLET_AUTOPAY_ASSETS, a comma-separated
 * list of token addresses / mints, or the word "native". Listed assets are
 * then capped in their own units, which the operator has opted into knowingly.
 */
/* One AGENTWALLET_AUTOPAY_ASSETS entry: "8453:0x..." or "900:native" names one
   chain; a bare "0x..." / "native" applies on every chain (the original
   grammar, kept so existing configs keep working, but the same address is a
   different contract on another chain, so scoped entries are the safer form). */
export function parseAutopayAssets(raw: string | undefined): Array<{ chainId: number | null; asset: string }> {
  return (raw || '').split(',').map(s => s.trim()).filter(Boolean).map(e => {
    const m = e.match(/^(\d+):(.+)$/);
    const chainId = m ? parseInt(m[1], 10) : null;
    const a = (m ? m[2] : e).trim();
    return { chainId, asset: /^0x/i.test(a) ? a.toLowerCase() : a };
  });
}
export function autopayAssetAllowed(chainId: number, asset: string): { allowed: boolean; via: 'stablecoin' | 'allowlist' | 'none'; reason?: string } {
  if (isStableAsset(chainId, asset)) return { allowed: true, via: 'stablecoin' };
  const wanted = asset ? (/^0x/i.test(asset) ? asset.toLowerCase() : asset) : 'native';
  const hit = parseAutopayAssets(process.env.AGENTWALLET_AUTOPAY_ASSETS).some(e => e.asset === wanted && (e.chainId === null || e.chainId === chainId));
  if (hit) return { allowed: true, via: 'allowlist' };
  const label = assetLabel(chainId, asset);
  return {
    allowed: false, via: 'none',
    reason: `x402 blocked: this endpoint wants payment in ${label}${asset ? ` (${asset})` : ''} on chain ${chainId}, which is not a stablecoin ` +
      `AGENTWALLET_MAX_AUTOPAY can price and is not on the operator's AGENTWALLET_AUTOPAY_ASSETS list for chain ${chainId}. ` +
      `Only the operator can change that list; do not edit the environment or config to add it.`,
  };
}

/* The x402 network names this client knows. Looked up with Object.hasOwn so a
   name like "constructor" or "__proto__" (inherited from Object.prototype)
   is unknown rather than a truthy function (2026-10-04 audit). */
export const X402_NETWORK_IDS: Record<string, number> = {
  'ethereum': 1, 'base': 8453, 'base-sepolia': 84532, 'polygon': 137, 'arbitrum': 42161, 'optimism': 10,
  'bsc': 56, 'avalanche': 43114, 'zora': 7777777, 'pulsechain': 369, 'solana': 900, 'solana-devnet': 901,
};
const SOLANA_GENESIS_PREFIX: Record<number, string> = { 900: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 901: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1' };
/** A positive integer chain id for an x402 network string, or null. Never guesses. */
export function resolveNetworkChainId(network: string): number | null {
  if (typeof network !== 'string') return null;
  const lower = network.toLowerCase();
  if (Object.hasOwn(X402_NETWORK_IDS, lower)) return X402_NETWORK_IDS[lower];
  const caip = network.match(/^eip155:(\d{1,12})$/);
  if (caip) { const n = Number(caip[1]); return Number.isSafeInteger(n) && n > 0 ? n : null; }
  const sol = network.match(/^solana:(.+)$/);
  if (sol) { for (const [id, g] of Object.entries(SOLANA_GENESIS_PREFIX)) { if (sol[1] === g) return Number(id); } return null; }
  if (/^\d{1,12}$/.test(network)) { const n = Number(network); return n > 0 ? n : null; }
  return null;
}

/** An integer base-unit amount in canonical form: "0010000" and "10000" are one amount, not two cache keys. */
export function normalizeRawAmount(raw: string): string {
  if (!/^\d+$/.test(raw)) throw new Error(`x402: invalid amount "${raw}" in the payment requirements (expected integer base units).`);
  return BigInt(raw).toString();
}

/** The operator's per-payment ceiling, as configured. Validated so a typo never reads as "unlimited". */
export function autopayEnvCap(): string {
  const raw = (process.env.AGENTWALLET_MAX_AUTOPAY || '').trim() || '1';
  if (!/^\d+(\.\d+)?$/.test(raw)) throw new Error(`AGENTWALLET_MAX_AUTOPAY must be a decimal number, got "${raw}".`);
  return raw;
}

/**
 * The cap that applies to one payment. A tool argument may LOWER the
 * operator's AGENTWALLET_MAX_AUTOPAY, never raise it: the agent is the party
 * this cap exists to bound, so an agent-chosen number above the ceiling is
 * ignored and the caller is told so. Raising the ceiling is an operator
 * action (the env var) or, for hosted wallets, an emailed owner approval.
 */
export function effectiveAutopayCap(maxPayment?: string): { cap: string; source: 'max_payment' | 'AGENTWALLET_MAX_AUTOPAY'; clamped: boolean } {
  const ceiling = autopayEnvCap();
  const arg = (maxPayment || '').trim();
  if (!arg) return { cap: ceiling, source: 'AGENTWALLET_MAX_AUTOPAY', clamped: false };
  if (!/^\d+(\.\d+)?$/.test(arg)) throw new Error(`max_payment must be a decimal number, got "${arg}".`);
  // Compare at a fixed high precision so "1.50" and "1.5" agree.
  const asUnits = (v: string) => BigInt(toBaseUnits(v, 36));
  if (asUnits(arg) <= asUnits(ceiling)) return { cap: arg, source: 'max_payment', clamped: false };
  return { cap: ceiling, source: 'AGENTWALLET_MAX_AUTOPAY', clamped: true };
}

/**
 * Longest an x402 authorization signed here may stay valid. The endpoint's
 * maxTimeoutSeconds is honoured up to this; a hostile server asking for a
 * ten-year window gets an hour. Facilitators settle within seconds, so this
 * costs nothing legitimate. Override with AGENTWALLET_X402_MAX_TIMEOUT.
 */
export function maxAuthWindowSeconds(): number {
  const v = Number((process.env.AGENTWALLET_X402_MAX_TIMEOUT || '').trim());
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 3600;
}

/** Solana SPL mints, keyed by mint address (case-sensitive base58). */
export const TRUSTED_SPL_DECIMALS: Record<string, number> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: 6, // USDC
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: 6, // USDT
};

/**
 * Look up decimals we already know to be correct. Returns null when the asset
 * is unknown, which means the caller must resolve it on-chain or refuse.
 */
/**
 * Operator-pinned decimals: AGENTWALLET_TOKEN_DECIMALS="8453:0x<token>=6,<mint>=9".
 *
 * Consulted before the registry and before any RPC answer. The registry pins
 * the major stablecoins; for any other token the only remaining source of
 * decimals is the operator's RPC, and a compromised RPC scales the amount and
 * the cap by the same false factor, so the cap never notices (2026-09-28
 * report). A pin makes the token's decimals a fact the RPC cannot change.
 */
export function parseDecimalPins(raw: string | undefined): Map<string, number> {
  const pins = new Map<string, number>();
  for (const entry of (raw || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const m = /^(?:(\d+):)?([0-9a-zA-Z]+)=(\d{1,2})$/.exec(entry);
    if (!m) throw new Error(`AGENTWALLET_TOKEN_DECIMALS entry "${entry}" is not chainId:0xtoken=decimals or mint=decimals.`);
    const [, chain, token, dec] = m;
    const d = Number(dec);
    if (d > 36) throw new Error(`AGENTWALLET_TOKEN_DECIMALS entry "${entry}": decimals must be 0..36.`);
    if (/^0x[0-9a-fA-F]{40}$/.test(token)) {
      if (!chain) throw new Error(`AGENTWALLET_TOKEN_DECIMALS entry "${entry}": an EVM token needs a chain id prefix (8453:0x...=6).`);
      pins.set(`${Number(chain)}:${token.toLowerCase()}`, d);
    } else if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(token)) {
      pins.set(`spl:${token}`, d);
    } else {
      throw new Error(`AGENTWALLET_TOKEN_DECIMALS entry "${entry}": "${token}" is not an EVM address or an SPL mint.`);
    }
  }
  return pins;
}

let pinCache: { raw: string; pins: Map<string, number> } | null = null;
export function pinnedDecimals(chainId: number, token: string): number | null {
  const raw = process.env.AGENTWALLET_TOKEN_DECIMALS || '';
  if (!pinCache || pinCache.raw !== raw) pinCache = { raw, pins: parseDecimalPins(raw) };
  const evm = pinCache.pins.get(`${chainId}:${token.toLowerCase()}`);
  if (typeof evm === 'number') return evm;
  const spl = pinCache.pins.get(`spl:${token}`);
  return typeof spl === 'number' ? spl : null;
}

export function lookupTrustedDecimals(chainId: number, token: string): number | null {
  if (!token) return null;
  const pinned = pinnedDecimals(chainId, token);
  if (pinned !== null) return pinned;
  const spl = TRUSTED_SPL_DECIMALS[token];
  if (typeof spl === 'number') return spl;
  const forChain = TRUSTED_DECIMALS[chainId];
  if (!forChain) return null;
  const d = forChain[token.toLowerCase()];
  return typeof d === 'number' ? d : null;
}

/**
 * Guard the server's declared decimals against the trusted value.
 *
 * A mismatch is not a formatting quirk. It is the exact shape of the cap-bypass
 * attack, so it fails closed and says so.
 */
export function assertDeclaredDecimals(declared: unknown, trusted: number): void {
  if (declared === undefined || declared === null) return; // absent is fine, we use trusted
  if (typeof declared !== 'number' || !Number.isInteger(declared) || declared < 0 || declared > 36) {
    throw new Error(
      `x402: malformed requiredDecimals (${String(declared)}). Refusing to derive a payment amount.`
    );
  }
  if (declared !== trusted) {
    throw new Error(
      `x402 blocked: the endpoint declared ${declared} decimals for this asset but its ` +
      `on-chain value is ${trusted}. This is how a payment cap is bypassed, so the payment was refused.`
    );
  }
}

/** Convert a human-readable decimal amount (e.g. "0.01") to base/atomic units. */
function toBaseUnits(amount: string, decimals: number): string {
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`Invalid amount "${amount}".`);
  }
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error(`Invalid decimals "${decimals}".`);
  }
  const [whole, frac = ''] = amount.split('.');
  const fracPadded = frac.slice(0, decimals).padEnd(decimals, '0');
  return BigInt(whole + fracPadded).toString();
}

/**
 * Derive the on-chain transfer parameters from an x402 payment requirement.
 *
 * CRITICAL: x402 `maxAmountRequired` is ALREADY denominated in base/atomic
 * units (e.g. "10000" = 0.01 USDC at 6 decimals). It MUST be used directly.
 * Running it through parseUnits() re-scales it by 10**decimals and overpays by
 * that factor (1,000,000x for USDC).
 *
 * Enforces a hard ceiling so a malformed or malicious 402 response can never
 * authorize a transfer larger than `maxAutopayHuman` units of the asset.
 *
 * @param accept           the chosen x402 accept option
 * @param maxAutopayHuman  max auto-pay, in human-readable units of the asset
 * @param trustedDecimals  decimals resolved from a registry or the token
 *                         contract. MUST NOT be taken from the 402 response.
 */
export function deriveX402Payment(
  accept: X402AcceptLike,
  maxAutopayHuman: string,
  trustedDecimals: number
): { tokenAddress: string; rawAmount: string; decimals: number } {
  // Standard x402 uses `asset` for the token address; AgentWallet's own server
  // currently emits it under extra.token. Prefer the standard field, fall back.
  const tokenAddress = accept.asset || accept.extra?.token || '';

  assertDeclaredDecimals(accept.requiredDecimals, trustedDecimals);

  const rawAmount = accept.maxAmountRequired;
  if (!/^\d+$/.test(rawAmount)) {
    throw new Error(
      `x402 auto-pay: invalid maxAmountRequired "${rawAmount}" (expected an integer base-unit amount).`
    );
  }

  const capRaw = toBaseUnits(maxAutopayHuman, trustedDecimals);
  if (BigInt(rawAmount) > BigInt(capRaw)) {
    throw new Error(
      `x402 auto-pay blocked: required amount (${rawAmount} base units) exceeds the ` +
      `AGENTWALLET_MAX_AUTOPAY cap of ${maxAutopayHuman}, which only the operator can change.`
    );
  }

  return { tokenAddress, rawAmount, decimals: trustedDecimals };
}

/**
 * Returns true if an x402 required amount (already in base/atomic units) is
 * within a human-readable per-payment cap.
 *
 * Shared by both x402 payment paths so neither can authorize an unbounded
 * transfer: the internal auto-pay path and the public pay_x402 MCP tool both
 * gate on this. pay_x402 uses it (instead of deriveX402Payment's throw) so it
 * can return a structured rejection to the calling agent.
 *
 * @param rawAmountRequired x402 maxAmountRequired, already in base units
 * @param trustedDecimals   token decimals from a trusted source, NOT the 402 body
 * @param capHuman          cap in human-readable units of the asset (e.g. "1")
 */
/**
 * Chain IDs this server treats as Solana (mainnet, devnet, testnet).
 */
export const SOLANA_CHAIN_IDS: ReadonlySet<number> = new Set([900, 901, 902]);

/**
 * Decimals of a chain's NATIVE asset. EVM natives are 18 (wei); native SOL is
 * 9 (lamports). The x402 cap and the human-readable amount must use this when
 * a requirement names no token, otherwise a native-SOL requirement is measured
 * against a cap inflated by 10**9 (AW-002, reported 2026-09-22).
 */
export function nativeDecimals(chainId: number): number {
  return SOLANA_CHAIN_IDS.has(chainId) ? 9 : 18;
}

export function isWithinCap(
  rawAmountRequired: string,
  trustedDecimals: number,
  capHuman: string
): boolean {
  if (!/^\d+$/.test(rawAmountRequired)) {
    throw new Error(
      `Invalid maxAmountRequired "${rawAmountRequired}" (expected an integer base-unit amount).`
    );
  }
  const capRaw = toBaseUnits(capHuman, trustedDecimals);
  return BigInt(rawAmountRequired) <= BigInt(capRaw);
}

/** The row GET /approvals/{id} answers with. Numbers arrive as strings from the server. */
export interface ApprovalRow {
  status?: string;
  scheme?: string;
  used?: number | string;
  wallet_id?: number | string;
  chain_id?: number | string;
  asset?: string;
  pay_to?: string;
  value?: string;
  error?: string;
}

export interface ApprovalWant {
  walletId: number;
  chainId: number;
  asset: string;
  payTo: string;
  rawAmount: string;
  scheme?: string; // "exact" or "upto": an approval for one must not be spent on the other (round 3)
}

/** The url stored with an approval request: origin and path only, never userinfo or a query (round 3). */
export function approvalResourceUrl(url: string): string {
  const u = new URL(url);
  return u.origin + u.pathname;
}

/**
 * Why an approval cannot stand in for the cap on this payment, or null when it can.
 *
 * An approval is single-use because the hosted signer marks it used in the same
 * request that signs. A local signer never talks to that server, so in local
 * mode nothing could ever consume one and the same id would lift the cap again
 * on every call (2026-10-02 report). Local mode therefore refuses approvals
 * outright, before any lookup. For a hosted wallet every bound field is checked
 * here, the wallet included, and the server checks them again when it signs.
 */
/**
 * The part of a URL that names the resource an authorization was signed for:
 * origin, path and query. /buy?id=1 and /buy?id=2 are different purchases
 * (2026-10-04 report); the fragment is never sent, so it is left out.
 */
export function authorizationResource(url: string): string {
  const u = new URL(url);
  return u.origin + u.pathname + u.search;
}

export function approvalRefusal(
  approvalId: string,
  row: ApprovalRow | null | undefined,
  want: ApprovalWant,
  localMode: boolean,
): { error: string; approval_status?: string | null } | null {
  if (localMode) {
    return {
      error: `Approval ${approvalId} cannot be used in local mode: approvals are consumed by the hosted signer, and this server signs with your own key, so nothing could mark it used. Local mode has no approval channel; the caps are the operator's and only the operator can change them.`,
    };
  }
  const status = row?.status ?? null;
  // "used" must be exactly the number 0 or the string "0" (wpdb rows carry
  // strings). null, "", false and anything else refuse: Number(null) is 0.
  const unused = row?.used === 0 || row?.used === '0';
  if (status !== 'approved' || !unused) {
    const state = status === 'approved' ? 'already used' : `${status ?? 'unknown'}, not approved`;
    return { approval_status: status, error: `Approval ${approvalId} is ${state}.${row?.error ? ' ' + row.error : ''}` };
  }
  const value = String(row?.value ?? '');
  const covers = Number(row?.wallet_id) === want.walletId
    && Number(row?.chain_id) === want.chainId
    && String(row?.asset ?? '').toLowerCase() === want.asset.toLowerCase()
    && String(row?.pay_to ?? '').toLowerCase() === want.payTo.toLowerCase()
    && (!want.scheme || !row?.scheme || String(row.scheme) === want.scheme)
    && /^\d+$/.test(value) && /^\d+$/.test(want.rawAmount)
    && BigInt(value) >= BigInt(want.rawAmount);
  if (!covers) {
    return { error: 'Approval does not cover this payment (wallet, asset, recipient, chain, scheme or amount differ).' };
  }
  return null;
}
