/**
 * Casper x402 support: accepts[] matching, payload construction and the
 * facilitator client.
 *
 * Isolated from the server bootstrap in index.ts for the same reason
 * x402-payment.ts is: the funds-sensitive parts (network matching, mote math,
 * fail-closed verify/settle) are unit-tested without starting the MCP server.
 *
 * Settlement is wCSPR, a CEP-18 token, so the payer signs a CEP-18 transfer
 * deploy locally and hands it to the facilitator, which verifies and submits
 * it. The secret key never leaves this process.
 */

import {
  CASPER_MAINNET_CHAIN_ID,
  CASPER_TESTNET_CHAIN_ID,
  buildCep18TransferDeploy,
  csprToMotes,
  getCasperAddress,
  isValidCasperPublicKey,
  motesToCspr,
  CSPR_DECIMALS,
} from './local-casper.js';

/** CAIP-2 style identifiers the Casper x402 ecosystem uses. */
export const CASPER_X402_NETWORKS: Record<string, number> = {
  'casper:casper': CASPER_MAINNET_CHAIN_ID,
  'casper:casper-test': CASPER_TESTNET_CHAIN_ID,
};

const DEFAULT_FACILITATOR = 'https://x402-facilitator.cspr.cloud';

/** Default wCSPR CEP-18 contract per network; override via the 402 `asset`. */
const DEFAULT_WCSPR: Record<number, string> = {
  [CASPER_MAINNET_CHAIN_ID]: '',
  [CASPER_TESTNET_CHAIN_ID]: '',
};

export function isCasperNetwork(network: string): boolean {
  return resolveCasperChainId(network) !== null;
}

export function resolveCasperChainId(network: string): number | null {
  const key = String(network || '').trim().toLowerCase();
  return CASPER_X402_NETWORKS[key] ?? null;
}

export function isCasperChain(chainId: number): boolean {
  return chainId === CASPER_MAINNET_CHAIN_ID || chainId === CASPER_TESTNET_CHAIN_ID;
}

export function facilitatorUrl(): string {
  const raw = (process.env.AGENTWALLET_CASPER_FACILITATOR_URL || '').trim() || DEFAULT_FACILITATOR;
  return raw.replace(/\/+$/, '');
}

/* ── accepts[] ───────────────────────────────────────────────────── */

export interface CasperAccept {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  payTo: string;
  asset?: string;
  extra?: { name?: string; decimals?: number };
  requiredDecimals?: number;
  resource?: string;
  description?: string;
  maxTimeoutSeconds?: number;
}

/**
 * Pick the Casper option out of an x402 v2 `accepts` array.
 *
 * Only the `exact` scheme is understood, matching the rest of this server; an
 * unknown scheme is skipped rather than guessed at, so a 402 advertising
 * something we cannot settle falls through to the EVM/Solana options instead of
 * producing a payment we cannot prove.
 */
export function selectCasperAccept(accepts: CasperAccept[], preferChainId?: number): CasperAccept | null {
  const candidates = (accepts || []).filter(
    (a) => a && isCasperNetwork(a.network) && (a.scheme || 'exact').toLowerCase() === 'exact'
  );
  if (candidates.length === 0) return null;
  if (preferChainId) {
    const match = candidates.find((a) => resolveCasperChainId(a.network) === preferChainId);
    if (match) return match;
  }
  return candidates[0];
}

/**
 * Resolve the settlement asset and exact mote amount for a Casper accept.
 *
 * `maxAmountRequired` is already in base units per the x402 spec (motes for
 * wCSPR, which has the same 9 decimals as CSPR itself), so it is used directly
 * and only validated — never re-scaled. A non-integer value is rejected rather
 * than rounded.
 */
export function resolveCasperRequirement(accept: CasperAccept): {
  chainId: number;
  network: string;
  asset: string;
  payTo: string;
  amountMotes: bigint;
  decimals: number;
  humanAmount: string;
} {
  const chainId = resolveCasperChainId(accept.network);
  if (chainId === null) {
    throw new Error(
      `Unsupported Casper x402 network "${accept.network}". ` +
      `Supported: ${Object.keys(CASPER_X402_NETWORKS).join(', ')}.`
    );
  }

  const decimals = accept.extra?.decimals ?? accept.requiredDecimals ?? CSPR_DECIMALS;
  if (decimals !== CSPR_DECIMALS) {
    throw new Error(
      `Casper x402 settles in wCSPR, which has ${CSPR_DECIMALS} decimals, but the 402 response ` +
      `declared ${decimals}. Refusing to pay against a mismatched denomination.`
    );
  }

  const raw = String(accept.maxAmountRequired ?? '');
  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `Casper x402: invalid maxAmountRequired "${raw}" (expected an integer mote amount).`
    );
  }

  if (!isValidCasperPublicKey(accept.payTo || '')) {
    throw new Error(`Casper x402: invalid payTo "${accept.payTo}" (expected a hex account public key).`);
  }

  const asset = (accept.asset || DEFAULT_WCSPR[chainId] || '').replace(/^hash-/, '');
  if (!/^[0-9a-fA-F]{64}$/.test(asset)) {
    throw new Error(
      'Casper x402: the 402 response did not include a wCSPR CEP-18 contract hash in "asset".'
    );
  }

  return {
    chainId,
    network: accept.network,
    asset,
    payTo: accept.payTo,
    amountMotes: BigInt(raw),
    decimals,
    humanAmount: motesToCspr(raw),
  };
}

/** True when an integer mote amount is within a human-readable CSPR cap. */
export function isWithinCasperCap(amountMotes: string, capHuman: string): boolean {
  if (!/^\d+$/.test(String(amountMotes))) {
    throw new Error(`Invalid mote amount "${amountMotes}" (expected an integer).`);
  }
  return BigInt(amountMotes) <= csprToMotes(capHuman);
}

/* ── Payment payload ─────────────────────────────────────────────── */

export interface CasperPaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  payload: {
    from: string;
    to: string;
    asset: string;
    amount: string;
    deploy: unknown;
    deployHash: string;
  };
}

/**
 * Build the X-PAYMENT payload for a Casper accept: a locally signed wCSPR
 * CEP-18 transfer deploy the facilitator can verify and submit.
 */
export function buildCasperPayment(accept: CasperAccept, x402Version = 2): CasperPaymentPayload {
  const req = resolveCasperRequirement(accept);
  const paymentMotes = BigInt(
    (process.env.AGENTWALLET_CASPER_PAYMENT_MOTES || '').trim() || '1000000000'
  );
  const deploy = buildCep18TransferDeploy(req.asset, req.payTo, req.amountMotes, req.chainId, paymentMotes);

  return {
    x402Version,
    scheme: accept.scheme || 'exact',
    network: req.network,
    payload: {
      from: getCasperAddress(),
      to: req.payTo,
      asset: req.asset,
      amount: req.amountMotes.toString(),
      deploy,
      deployHash: deploy.hash,
    },
  };
}

export function encodePaymentHeader(payment: CasperPaymentPayload): string {
  return Buffer.from(JSON.stringify(payment), 'utf8').toString('base64');
}

/* ── Facilitator client ──────────────────────────────────────────── */

export interface FacilitatorResult {
  ok: boolean;
  reason?: string;
  transaction?: string;
  raw?: unknown;
}

/**
 * Call a facilitator endpoint and interpret the answer conservatively.
 *
 * Fails CLOSED on every ambiguity: a non-2xx status, a body that is not JSON, a
 * missing verdict field, or anything other than a literal `true` is a failure.
 * A payment that "might" have settled is treated as one that did not, because
 * the alternative is handing out a paid resource for free on a network blip.
 */
async function callFacilitator(endpoint: string, body: unknown): Promise<FacilitatorResult> {
  const url = `${facilitatorUrl()}${endpoint}`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (e) {
    return { ok: false, reason: `facilitator ${endpoint} unreachable: ${(e as Error).message}` };
  }

  const text = await res.text().catch(() => '');
  if (!res.ok) {
    return { ok: false, reason: `facilitator ${endpoint} returned HTTP ${res.status}: ${text.slice(0, 300)}` };
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { ok: false, reason: `facilitator ${endpoint} returned a non-JSON body.` };
  }
  if (!parsed || typeof parsed !== 'object') {
    return { ok: false, reason: `facilitator ${endpoint} returned an unexpected body shape.` };
  }

  const verdict = endpoint === '/verify' ? parsed.isValid : parsed.success;
  if (verdict !== true) {
    return {
      ok: false,
      reason: String(parsed.invalidReason || parsed.errorReason || parsed.error || `facilitator ${endpoint} did not confirm the payment.`),
      raw: parsed,
    };
  }

  return {
    ok: true,
    transaction: typeof parsed.transaction === 'string' ? parsed.transaction : undefined,
    raw: parsed,
  };
}

export function verifyPayment(payment: CasperPaymentPayload, accept: CasperAccept): Promise<FacilitatorResult> {
  return callFacilitator('/verify', {
    x402Version: payment.x402Version,
    paymentPayload: payment,
    paymentRequirements: accept,
  });
}

export function settlePayment(payment: CasperPaymentPayload, accept: CasperAccept): Promise<FacilitatorResult> {
  return callFacilitator('/settle', {
    x402Version: payment.x402Version,
    paymentPayload: payment,
    paymentRequirements: accept,
  });
}
