/**
 * Pure helpers for x402 auto-pay amount/token derivation.
 *
 * Isolated from the server bootstrap in index.ts so the funds-sensitive amount
 * math can be unit-tested without starting the MCP server.
 */

export interface X402AcceptLike {
  maxAmountRequired: string;
  requiredDecimals?: number;
  asset?: string;
  extra?: { token?: string };
}

/** Convert a human-readable decimal amount (e.g. "0.01") to base/atomic units. */
function toBaseUnits(amount: string, decimals: number): string {
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`Invalid amount "${amount}".`);
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
 * that factor (1,000,000x for USDC). This mirrors the pay_x402 tool, which has
 * always used maxAmountRequired directly.
 *
 * Also enforces a hard ceiling so a malformed or malicious 402 response can
 * never authorize a transfer larger than `maxAutopayHuman` units of the asset.
 *
 * @param accept           the chosen x402 accept option
 * @param maxAutopayHuman  max auto-pay, in human-readable units of the asset
 */
export function deriveX402Payment(
  accept: X402AcceptLike,
  maxAutopayHuman: string
): { tokenAddress: string; rawAmount: string; decimals: number } {
  const decimals = accept.requiredDecimals || 6;

  // Standard x402 uses `asset` for the token address; AgentWallet's own server
  // currently emits it under extra.token. Prefer the standard field, fall back.
  const tokenAddress = accept.asset || accept.extra?.token || '';

  const rawAmount = accept.maxAmountRequired;
  if (!/^\d+$/.test(rawAmount)) {
    throw new Error(
      `x402 auto-pay: invalid maxAmountRequired "${rawAmount}" (expected an integer base-unit amount).`
    );
  }

  const capRaw = toBaseUnits(maxAutopayHuman, decimals);
  if (BigInt(rawAmount) > BigInt(capRaw)) {
    throw new Error(
      `x402 auto-pay blocked: required amount (${rawAmount} base units) exceeds the ` +
      `AGENTWALLET_MAX_AUTOPAY cap of ${maxAutopayHuman}. Raise AGENTWALLET_MAX_AUTOPAY to allow it.`
    );
  }

  return { tokenAddress, rawAmount, decimals };
}
