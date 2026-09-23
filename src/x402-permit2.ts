/**
 * x402 "upto" scheme on EVM: a Permit2 PermitWitnessTransferFrom that authorizes
 * a MAXIMUM, which the seller settles at or below actual usage through the
 * x402 upto proxy. Only the facilitator named in the witness can settle it.
 *
 * Needs a one-time ERC-20 approval of the token to the Permit2 contract from
 * the payer (costs gas once per token per chain); see permit2AllowanceCalldata
 * and permit2ApproveCalldata. Reference: coinbase/x402 mechanisms/evm/upto.
 */
import { randomBytes } from 'node:crypto';
import type { X402Requirement } from './x402-eip3009.js';

export const PERMIT2_ADDRESS = '0x000000000022D473030F116dDEE9F6B43aC78BA3' as const;
export const X402_UPTO_PERMIT2_PROXY = '0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002' as const;

/** EIP-712 types. Referenced types must follow the primary type in alphabetical order (TokenPermissions, Witness). */
export const UPTO_PERMIT2_WITNESS_TYPES = {
  PermitWitnessTransferFrom: [
    { name: 'permitted', type: 'TokenPermissions' },
    { name: 'spender', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
    { name: 'witness', type: 'Witness' },
  ],
  TokenPermissions: [
    { name: 'token', type: 'address' },
    { name: 'amount', type: 'uint256' },
  ],
  Witness: [
    { name: 'to', type: 'address' },
    { name: 'facilitator', type: 'address' },
    { name: 'validAfter', type: 'uint256' },
  ],
} as const;

export interface UptoPermit2Authorization {
  from: `0x${string}`;
  permitted: { token: `0x${string}`; amount: string };
  spender: `0x${string}`;
  nonce: string;      // uint256 as decimal string
  deadline: string;   // unix seconds
  witness: { to: `0x${string}`; facilitator: `0x${string}`; validAfter: string };
}

/** Permit2 nonces are uint256; 32 random bytes as a decimal string. */
export function createPermit2Nonce(): string {
  return BigInt('0x' + randomBytes(32).toString('hex')).toString();
}

export function facilitatorAddressOf(req: X402Requirement): `0x${string}` | null {
  const f = req.extra?.facilitatorAddress;
  return typeof f === 'string' && /^0x[0-9a-fA-F]{40}$/.test(f) ? (f as `0x${string}`) : null;
}

/** True when this upto option carries everything the client needs to sign it. */
export function isUptoPayable(req: X402Requirement): boolean {
  return req.scheme === 'upto' && Boolean(facilitatorAddressOf(req)) && /^0x[0-9a-fA-F]{40}$/.test(String(req.asset || ''));
}

export function buildUptoAuthorization(
  from: string,
  req: X402Requirement,
  nowSeconds = Math.floor(Date.now() / 1000),
  nonce: string = createPermit2Nonce(),
): UptoPermit2Authorization {
  const facilitator = facilitatorAddressOf(req);
  if (!facilitator) throw new Error('x402 upto: the payment requirements carry no extra.facilitatorAddress, so the authorization cannot be bound to a facilitator.');
  const amount = String(req.amount ?? req.maxAmountRequired ?? '');
  if (!/^\d+$/.test(amount)) throw new Error(`x402 upto: invalid amount "${amount}" (expected integer base units).`);
  if (!/^0x[0-9a-fA-F]{40}$/.test(req.payTo)) throw new Error(`x402 upto: payTo is not an EVM address: "${req.payTo}".`);
  const timeout = Number.isFinite(req.maxTimeoutSeconds) && (req.maxTimeoutSeconds as number) > 0 ? Math.floor(req.maxTimeoutSeconds as number) : 300;
  return {
    from: from as `0x${string}`,
    permitted: { token: req.asset as `0x${string}`, amount },
    spender: X402_UPTO_PERMIT2_PROXY,
    nonce,
    deadline: String(nowSeconds + timeout),
    witness: { to: req.payTo as `0x${string}`, facilitator, validAfter: String(nowSeconds - 600) },
  };
}

export function uptoTypedData(chainId: number, auth: UptoPermit2Authorization) {
  return {
    domain: { name: 'Permit2', chainId, verifyingContract: PERMIT2_ADDRESS },
    types: UPTO_PERMIT2_WITNESS_TYPES,
    primaryType: 'PermitWitnessTransferFrom' as const,
    message: {
      permitted: { token: auth.permitted.token, amount: BigInt(auth.permitted.amount) },
      spender: auth.spender,
      nonce: BigInt(auth.nonce),
      deadline: BigInt(auth.deadline),
      witness: { to: auth.witness.to, facilitator: auth.witness.facilitator, validAfter: BigInt(auth.witness.validAfter) },
    },
  };
}

/** The payload object that goes under `payload` in the x402 payment. */
export function uptoPayload(auth: UptoPermit2Authorization, signature: string): Record<string, unknown> {
  return { signature, permit2Authorization: auth };
}

function pad(addr: string): string { return addr.replace(/^0x/, '').toLowerCase().padStart(64, '0'); }

/** allowance(owner, Permit2) calldata. */
export function permit2AllowanceCalldata(owner: string): `0x${string}` {
  return ('0xdd62ed3e' + pad(owner) + pad(PERMIT2_ADDRESS)) as `0x${string}`;
}

/** approve(Permit2, max) calldata: the one-time step upto needs. */
export function permit2ApproveCalldata(): `0x${string}` {
  return ('0x095ea7b3' + pad(PERMIT2_ADDRESS) + 'f'.repeat(64)) as `0x${string}`;
}

export function decodeUint(hex: string): bigint {
  const h = (hex || '').replace(/^0x/, '');
  return h && /^[0-9a-fA-F]+$/.test(h) ? BigInt('0x' + h) : 0n;
}
