/**
 * x402 "exact" scheme on EVM, done the way the spec says: an EIP-3009
 * TransferWithAuthorization signed off-chain and handed to the resource server
 * in the payment header. The facilitator settles it; the payer broadcasts
 * nothing and pays no gas.
 *
 * Before v1.11.0 pay_x402 broadcast a plain ERC-20 transfer() and put the tx
 * hash in the header. That only ever worked against AgentWallet's own paywalls
 * (which verify by receipt); every standard x402 server rejected it (issue #7).
 * The receipt-style flow is kept for those paywalls and detected by their
 * shape, see isLegacyAgentWalletAccept().
 *
 * Wire formats, both supported (issue #7 endpoint speaks v1, newer servers v2):
 *   v1: 402 body {x402Version:1, accepts:[{maxAmountRequired, asset, payTo, network:"base", ...}]}
 *       request header  X-PAYMENT: base64({x402Version:1, scheme, network, payload:{signature, authorization}})
 *       response header X-PAYMENT-RESPONSE
 *   v2: 402 header PAYMENT-REQUIRED: base64({x402Version:2, resource, accepts:[{amount, asset, payTo, network:"eip155:8453", ...}]})
 *       request header  PAYMENT-SIGNATURE: base64({x402Version:2, resource, accepted, payload:{signature, authorization}})
 *       response header PAYMENT-RESPONSE
 */
import { randomBytes } from 'node:crypto';
import { isUptoPayable } from './x402-permit2.js';

export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const;

/** One entry of a 402 "accepts" array, v1 or v2 (and AgentWallet's own legacy shape). */
export interface X402Requirement {
  scheme: string;
  network: string;
  payTo: string;
  asset?: string;
  amount?: string;               // v2
  maxAmountRequired?: string;    // v1
  maxTimeoutSeconds?: number;
  resource?: string;
  description?: string;
  mimeType?: string;
  outputSchema?: Record<string, unknown>;
  requiredDecimals?: number;     // AgentWallet legacy
  extra?: { name?: string; version?: string; token?: string; [k: string]: unknown };
  [k: string]: unknown;
}

export interface X402PaymentRequired {
  x402Version: number;
  error?: string;
  resource?: { url: string; description?: string; mimeType?: string };
  accepts: X402Requirement[];
  extensions?: Record<string, unknown>;
}

export interface Eip3009Authorization {
  from: `0x${string}`;
  to: `0x${string}`;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: `0x${string}`;
}

export interface X402Settlement {
  success?: boolean;
  transaction?: string;
  network?: string;
  payer?: string;
  amount?: string;
  errorReason?: string;
  errorMessage?: string;
  [k: string]: unknown;
}

/**
 * AgentWallet's own paywalls (hifriendbot.com /x402/access/{id}) predate the
 * spec's field names: no `asset`, token under `extra.token`, `requiredDecimals`
 * present, and they verify a broadcast transfer by receipt. Anything with an
 * `asset` is treated as standard x402.
 */
export function isLegacyAgentWalletAccept(a: X402Requirement): boolean {
  if (a.asset) return false;
  return Boolean(a.extra?.token) || typeof a.requiredDecimals === 'number';
}

/** Required amount in base units, whichever spelling the server used. */
export function requiredAmount(a: X402Requirement): string {
  const v = a.amount ?? a.maxAmountRequired ?? '';
  return String(v);
}

export function createNonce(): `0x${string}` {
  return ('0x' + randomBytes(32).toString('hex')) as `0x${string}`;
}

const DEFAULT_TIMEOUT_SECONDS = 300;

/** Authorization window mirrors the reference client: valid from 10 minutes ago until maxTimeoutSeconds from now. */
export function buildAuthorization(
  from: string,
  req: X402Requirement,
  nowSeconds = Math.floor(Date.now() / 1000),
  nonce: `0x${string}` = createNonce(),
): Eip3009Authorization {
  const value = requiredAmount(req);
  if (!/^\d+$/.test(value)) throw new Error(`x402: invalid required amount "${value}" (expected integer base units).`);
  if (!/^0x[0-9a-fA-F]{40}$/.test(req.payTo)) throw new Error(`x402: payTo is not an EVM address: "${req.payTo}".`);
  const timeout = Number.isFinite(req.maxTimeoutSeconds) && (req.maxTimeoutSeconds as number) > 0
    ? Math.floor(req.maxTimeoutSeconds as number) : DEFAULT_TIMEOUT_SECONDS;
  return {
    from: from as `0x${string}`,
    to: req.payTo as `0x${string}`,
    value,
    validAfter: String(nowSeconds - 600),
    validBefore: String(nowSeconds + timeout),
    nonce,
  };
}

/** EIP-712 typed data for the authorization. `name`/`version` are the token's own domain values. */
export function typedDataFor(chainId: number, asset: string, name: string, version: string, auth: Eip3009Authorization) {
  return {
    domain: { name, version, chainId, verifyingContract: asset as `0x${string}` },
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
    primaryType: 'TransferWithAuthorization' as const,
    message: {
      from: auth.from,
      to: auth.to,
      value: BigInt(auth.value),
      validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore),
      nonce: auth.nonce,
    },
  };
}

/**
 * Token EIP-712 domains we know without asking the chain. USDC's domain name
 * differs by deployment ("USD Coin" on most mainnets, "USDC" on Base Sepolia),
 * which is exactly the kind of thing that silently produces an unrecoverable
 * signature, so only well-known deployments are listed; anything else is read
 * from the contract's name()/version().
 */
export const KNOWN_TOKEN_DOMAINS: Record<string, { name: string; version: string }> = {
  '8453:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { name: 'USD Coin', version: '2' },   // USDC Base
  '84532:0x036cbd53842c5426634e7929541ec2318f3dcf7e': { name: 'USDC', version: '2' },      // USDC Base Sepolia
  '1:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { name: 'USD Coin', version: '2' },      // USDC Ethereum
  '137:0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': { name: 'USD Coin', version: '2' },    // USDC Polygon (native)
  '42161:0xaf88d065e77c8cc2239327c5edb3a432268e5831': { name: 'USD Coin', version: '2' },  // USDC Arbitrum
  '10:0x0b2c639c533813f4aa9d7837caf62653d097ff85': { name: 'USD Coin', version: '2' },     // USDC Optimism
  '43114:0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e': { name: 'USD Coin', version: '2' },  // USDC Avalanche
};

export function knownTokenDomain(chainId: number, asset: string): { name: string; version: string } | null {
  return KNOWN_TOKEN_DOMAINS[`${chainId}:${asset.toLowerCase()}`] ?? null;
}

/** Decode a single ABI-encoded string return value (name()/version()). */
export function decodeAbiString(hex: string): string {
  const h = (hex || '').replace(/^0x/, '');
  if (h.length < 128) return '';
  const len = parseInt(h.slice(64, 128), 16);
  if (!Number.isFinite(len) || len <= 0 || len > 256) return '';
  const bytes = Buffer.from(h.slice(128, 128 + len * 2), 'hex');
  return bytes.toString('utf8');
}

/** Build the payment payload the resource server expects for this x402 version. */
export function buildPaymentPayload(
  x402Version: number,
  req: X402Requirement,
  auth: Eip3009Authorization,
  signature: string,
  resource?: X402PaymentRequired['resource'],
  extensions?: Record<string, unknown>,
): Record<string, unknown> {
  return buildPaymentPayloadRaw(x402Version, req, { signature, authorization: auth }, resource, extensions);
}

/** Same envelope for any scheme payload (EIP-3009 authorization, Permit2 authorization, tx hash). */
export function buildPaymentPayloadRaw(
  x402Version: number,
  req: X402Requirement,
  payload: Record<string, unknown>,
  resource?: X402PaymentRequired['resource'],
  extensions?: Record<string, unknown>,
): Record<string, unknown> {
  if (x402Version >= 2) {
    const out: Record<string, unknown> = { x402Version, accepted: req, payload };
    if (resource) out.resource = resource;
    const ext = withPaymentIdentifier(extensions);
    if (ext) out.extensions = ext;
    return out;
  }
  return { x402Version: 1, scheme: req.scheme, network: req.network, payload };
}

/** 16-128 chars of [A-Za-z0-9_-], the shape the payment-identifier extension accepts. */
export function generatePaymentId(): string {
  return 'agw_' + randomBytes(16).toString('hex');
}

/**
 * x402 v2 "payment-identifier" extension: the server may ask for a client-chosen
 * id so it can de-duplicate retries. The 402's extensions are echoed back with
 * info.id filled in. Other extensions pass through untouched.
 */
export function withPaymentIdentifier(extensions?: Record<string, unknown>, id?: string): Record<string, unknown> | null {
  if (!extensions || typeof extensions !== 'object') return null;
  const out: Record<string, unknown> = { ...extensions };
  const pid = out['payment-identifier'] as { info?: { required?: boolean; id?: string } } | undefined;
  if (pid && typeof pid === 'object' && pid.info && typeof pid.info === 'object') {
    out['payment-identifier'] = { ...pid, info: { ...pid.info, id: pid.info.id || id || generatePaymentId() } };
  }
  return out;
}

export function paymentHeaderFor(x402Version: number, payload: Record<string, unknown>): { name: string; value: string } {
  const value = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return { name: x402Version >= 2 ? 'PAYMENT-SIGNATURE' : 'X-PAYMENT', value };
}

function decodeBase64Json(v: string | null | undefined): Record<string, unknown> | null {
  if (!v) return null;
  try {
    const parsed = JSON.parse(Buffer.from(v.trim(), 'base64').toString('utf8'));
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch { return null; }
}

/** v2 servers put the requirements in PAYMENT-REQUIRED; v1 servers put them in the JSON body. */
export function parsePaymentRequired(
  getHeader: (name: string) => string | null | undefined,
  body: unknown,
): X402PaymentRequired | null {
  const fromHeader = decodeBase64Json(getHeader('PAYMENT-REQUIRED') ?? getHeader('payment-required'));
  if (fromHeader && Array.isArray(fromHeader.accepts)) return fromHeader as unknown as X402PaymentRequired;
  if (body && typeof body === 'object' && Array.isArray((body as X402PaymentRequired).accepts)) {
    return body as X402PaymentRequired;
  }
  return null;
}

export function parseSettlement(getHeader: (name: string) => string | null | undefined): X402Settlement | null {
  return (decodeBase64Json(getHeader('PAYMENT-RESPONSE') ?? getHeader('payment-response'))
    ?? decodeBase64Json(getHeader('X-PAYMENT-RESPONSE') ?? getHeader('x-payment-response'))) as X402Settlement | null;
}

/**
 * Choose which accepts[] entry to pay. `exact` (EIP-3009, gasless for the
 * payer) is preferred. `upto` is accepted when it carries the facilitator
 * address the Permit2 witness must be bound to; an upto option without it is
 * refused rather than approximated with an upfront transfer (issue #6).
 * Returns the reason when nothing is payable.
 */
export function pickOption(
  accepts: X402Requirement[],
  resolveChainId: (network: string) => number | null,
  preferChain?: number,
): { option: X402Requirement | null; chainId: number | null; reason?: string } {
  const onChain = accepts.filter(a => resolveChainId(a.network) !== null);
  const exact = onChain.filter(a => a.scheme === 'exact');
  const upto = onChain.filter(a => isUptoPayable(a));
  const payable = [...exact, ...upto];
  if (payable.length === 0) {
    const schemes = Array.from(new Set(accepts.map(a => a.scheme))).join(', ') || 'none';
    const reason = accepts.some(a => a.scheme === 'upto')
      ? 'This endpoint offers the x402 "upto" scheme without an extra.facilitatorAddress (or without an asset), so the ' +
        'Permit2 authorization cannot be bound to a facilitator. AgentWallet will not approximate it with an upfront transfer. ' +
        'Ask the endpoint operator to publish facilitatorAddress, or an "exact" option.'
      : `No payable option: schemes offered were ${schemes}.`;
    return { option: null, chainId: null, reason };
  }
  let option = payable[0];
  if (preferChain) option = payable.find(a => resolveChainId(a.network) === preferChain) ?? option;
  return { option, chainId: resolveChainId(option.network) };
}

// ─── Payer account shape (EIP-7702) ──────────────────────────────

/**
 * An EIP-7702 delegated EOA has code 0xef0100 || delegate (23 bytes). A facilitator that
 * checks account code before recovering the signer treats such a payer as a contract
 * wallet and calls ERC-1271 isValidSignature on it; a delegate that does not implement
 * it answers with empty data, and the payment is declined with a signature-shaped error
 * that has nothing to do with the signature (issue #9: a well-known test key that
 * sweeper bots had delegated on Base mainnet).
 */
export function parseEip7702Delegation(code: string | null | undefined): string | null {
  const m = /^0xef0100([0-9a-f]{40})$/.exec(String(code || '').toLowerCase());
  return m ? `0x${m[1]}` : null;
}

export const ERC1271_MAGIC = '0x1626ba7e';

/** Calldata for isValidSignature(bytes32, bytes) with a placeholder hash and a 65-byte placeholder signature. */
export function erc1271ProbeCalldata(): `0x${string}` {
  const hash = '11'.repeat(32);
  const offset = (64).toString(16).padStart(64, '0');
  const length = (65).toString(16).padStart(64, '0');
  const sig = 'aa'.repeat(65).padEnd(192, '0');
  return `${ERC1271_MAGIC}${hash}${offset}${length}${sig}` as `0x${string}`;
}

export type Erc1271Support = 'yes' | 'no' | 'unknown';

/**
 * Classify an isValidSignature probe. Empty return data means the account has no such
 * function (the failure shape from issue #9); a 4-byte word means the interface exists,
 * whatever it thought of the placeholder signature; a revert or transport failure is unknown.
 */
export function classifyErc1271Probe(result: string | null | undefined, failed = false): Erc1271Support {
  if (failed) return 'unknown';
  const r = String(result || '').toLowerCase();
  if (r === '' || r === '0x') return 'no';
  if (/^0x[0-9a-f]{8}0{56}$/.test(r)) return 'yes';
  return 'unknown';
}
