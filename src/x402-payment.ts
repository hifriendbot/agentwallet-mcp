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

/** Solana SPL mints, keyed by mint address (case-sensitive base58). */
export const TRUSTED_SPL_DECIMALS: Record<string, number> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: 6, // USDC
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: 6, // USDT
};

/**
 * Look up decimals we already know to be correct. Returns null when the asset
 * is unknown, which means the caller must resolve it on-chain or refuse.
 */
export function lookupTrustedDecimals(chainId: number, token: string): number | null {
  if (!token) return null;
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
      `AGENTWALLET_MAX_AUTOPAY cap of ${maxAutopayHuman}. Raise AGENTWALLET_MAX_AUTOPAY to allow it.`
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
