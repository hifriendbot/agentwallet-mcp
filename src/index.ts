#!/usr/bin/env node
/**
 * AgentWallet MCP Server
 *
 * Gives AI agents access to AgentWallet infrastructure:
 * create wallets, check balances, sign transactions,
 * broadcast on any EVM chain, and track usage.
 *
 * All operations go through the AgentWallet WordPress REST API.
 * Requires authentication via WordPress application password.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { assertPublicUrl, safeFetch, finalUrlOf } from './ssrf-guard.js';
import {
  deriveX402Payment,
  isWithinCap,
  lookupTrustedDecimals,
  assertDeclaredDecimals,
  nativeDecimals,
  SOLANA_CHAIN_IDS,
  assetLabel,
  autopayAssetAllowed,
  autopayEnvCap,
  effectiveAutopayCap,
  maxAuthWindowSeconds,
  parseDecimalPins,
  approvalRefusal,
  type ApprovalRow,
  authorizationResource,
  resolveNetworkChainId,
  normalizeRawAmount,
  parseAutopayAssets,
} from './x402-payment.js';
import { createHash } from 'node:crypto';
import {
  isLocalMode,
  getLocalAddress,
  localWalletRecord,
  localSend,
  localTransferToken,
  localNativeBalance,
  localTokenBalance,
  localSignMessage,
  resolveRpcUrl,
} from './local-wallet.js';
import { localSignAuthorization, localEthCall, localGetCode, localSignPermit2Upto } from './local-wallet.js';
import { WRAPPED_NATIVE } from './wrapped-native.js';
import {
  buildUptoAuthorization, uptoPayload, permit2AllowanceCalldata, permit2ApproveCalldata, decodeUint, PERMIT2_ADDRESS,
  type UptoPermit2Authorization,
} from './x402-permit2.js';
import { assessTokenRisk } from './token-risk.js';
import {
  isLegacyAgentWalletAccept, requiredAmount, buildAuthorization, buildPaymentPayload, buildPaymentPayloadRaw, paymentHeaderFor,
  parsePaymentRequired, parseSettlement, pickOption, knownTokenDomain,
  parseEip7702Delegation, erc1271ProbeCalldata, classifyErc1271Probe,
  type X402Requirement, type Eip3009Authorization, type Erc1271Support,
} from './x402-eip3009.js';
import {
  isSolanaLocalMode,
  getSolanaAddress,
  solanaWalletRecord,
  localSolBalance,
  localSplBalance,
  localSolTransfer,
  localSplTransfer,
  resolveSolanaRpc,
  mintDecimalsStrict,
} from './local-solana.js';

/** True when either chain family is running non-custodially. */
function anyLocalMode(): boolean {
  return isLocalMode() || isSolanaLocalMode();
}

// ─── Configuration ──────────────────────────────────────────────

const API_BASE = process.env.AGENTWALLET_API_URL || 'https://hifriendbot.com/wp-json/agentwallet/v1';
const API_USER = process.env.AGENTWALLET_USER || '';
const API_PASS = process.env.AGENTWALLET_PASS || '';  // WordPress application password
const X402_WALLET_ID = process.env.AGENTWALLET_WALLET_ID || '';  // Wallet ID for x402 auto-pay
const DASHBOARD_URL = process.env.AGENTWALLET_DASHBOARD_URL || 'https://hifriendbot.com/wallet/';

// Basic credentials and 402 auto-pay decisions ride on this URL, so it must be
// https, or loopback for a local test server. Anything else is refused at start.
if (/^http:/i.test(API_BASE) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(API_BASE)) {
  throw new Error(`AGENTWALLET_API_URL must be https (got ${API_BASE}); plain http is allowed only for localhost.`);
}

// ─── API Helper ─────────────────────────────────────────────────

interface X402Accept {
  scheme: string;
  maxAmountRequired: string;
  payTo: string;
  network: string;
  requiredDecimals: number;
  asset?: string;
  extra?: { token?: string; name?: string };
}

interface X402Response {
  x402Version: number;
  accepts: X402Accept[];
  error: string;
}

/* ── Local-mode routing ──────────────────────────────────────────
   Translates the REST paths the tools already speak into in-process signing
   calls. Anything not listed here falls through to the hosted API, so
   non-custodial concerns (paywalls, billing, usage) still work if the operator
   has also configured credentials. */

const NOT_HANDLED = Symbol('not-handled');

function localChainId(body?: Record<string, unknown>, qs?: URLSearchParams): number {
  const fromBody = body?.chain_id;
  if (typeof fromBody === 'number') return fromBody;
  const fromQs = qs?.get('chain_id');
  if (fromQs) return parseInt(fromQs, 10);
  const fromEnv = (process.env.AGENTWALLET_CHAIN_ID || '').trim();
  if (fromEnv) return parseInt(fromEnv, 10);
  return 8453; // Base, matching the custodial default
}

/**
 * Refuse rather than silently hand the operation to someone else's signer.
 *
 * Reached when the operator is running non-custodially for one chain family but
 * has supplied no key for the other. Falling through to the hosted API here
 * would move funds onto a key they do not hold, while they believe they are in
 * self-custody. That is the single worst thing this server could do, so it
 * stops and says exactly which variable is missing.
 */
function refuseMissingLocalKey(family: 'solana' | 'evm'): never {
  const wanted = family === 'solana'
    ? 'AGENTWALLET_SOLANA_KEY (or AGENTWALLET_SOLANA_KEYFILE)'
    : 'AGENTWALLET_PRIVATE_KEY (or AGENTWALLET_KEYFILE)';
  throw new Error(
    `This is a ${family === 'solana' ? 'Solana' : 'EVM'} operation and no local ${family === 'solana' ? 'Solana' : 'EVM'} key is configured, ` +
    `but this server is running in local signing mode. Refusing rather than routing it through the hosted ` +
    `custodial signer while you believe you hold the keys. Set ${wanted} to sign it here, or unset the other ` +
    `local key variables to use the hosted path for everything.`
  );
}

async function routeLocally(
  path: string,
  method: string,
  body?: Record<string, unknown>
): Promise<unknown | typeof NOT_HANDLED> {
  const [rawPath, rawQs = ''] = path.split('?');
  const qs = new URLSearchParams(rawQs);

  // POST /wallets/{id}/send
  if (method === 'POST' && /^\/wallets\/[^/]+\/send$/.test(rawPath)) {
    const chainId = localChainId(body, qs);
    const solanaOp = SOLANA_CHAIN_IDS.has(chainId) || Boolean(body?.token_mint);

    if (solanaOp) {
      if (!isSolanaLocalMode()) refuseMissingLocalKey('solana');
      const to = String(body?.to || '');
      const value = String(body?.value ?? '0');
      if (body?.token_mint) {
        return localSplTransfer(
          String(body.token_mint),
          to,
          value,
          Number(body.token_decimals ?? 6),
          chainId
        );
      }
      return localSolTransfer(to, value, chainId);
    }

    if (!isLocalMode()) refuseMissingLocalKey('evm');

    const to = String(body?.to || '');
    const value = BigInt(String(body?.value ?? '0'));
    const data = String(body?.data || '');
    if (!/^0x[a-fA-F0-9]{40}$/.test(to)) {
      throw new Error(`Local mode expects an EVM address, got "${to}".`);
    }
    const hasData = data && data !== '0x';
    return localSend(chainId, to as `0x${string}`, value, hasData ? (data as `0x${string}`) : undefined);
  }

  // POST /wallets/{id}/x402/authorize  (x402 "exact": EIP-3009 authorization, signed here, broadcast by nobody)
  if (method === 'POST' && /^\/wallets\/[^/]*\/x402\/authorize$/.test(rawPath)) {
    if (!isLocalMode()) refuseMissingLocalKey('evm');
    const chainId = localChainId(body, qs);
    return localSignAuthorization(
      chainId,
      String(body?.asset || '') as `0x${string}`,
      { name: String(body?.name || ''), version: String(body?.version || '') },
      {
        from: getLocalAddress(),
        to: String(body?.to || '') as `0x${string}`,
        value: String(body?.value ?? '0'),
        validAfter: String(body?.valid_after ?? '0'),
        validBefore: String(body?.valid_before ?? '0'),
        nonce: String(body?.nonce || '') as `0x${string}`,
      },
    );
  }

  // POST /wallets/{id}/x402/permit2  (x402 "upto": Permit2 max-authorization, signed here)
  if (method === 'POST' && /^\/wallets\/[^/]*\/x402\/permit2$/.test(rawPath)) {
    if (!isLocalMode()) refuseMissingLocalKey('evm');
    const chainId = localChainId(body, qs);
    return localSignPermit2Upto(chainId, {
      from: getLocalAddress(),
      permitted: { token: String(body?.asset || '') as `0x${string}`, amount: String(body?.amount ?? '0') },
      spender: String(body?.spender || '') as `0x${string}`,
      nonce: String(body?.nonce ?? '0'),
      deadline: String(body?.deadline ?? '0'),
      witness: { to: String(body?.to || '') as `0x${string}`, facilitator: String(body?.facilitator || '') as `0x${string}`, validAfter: String(body?.valid_after ?? '0') },
    });
  }

  // POST /eth-call  (read-only; answered from the local RPC so pure self-custody needs no hosted credentials)
  if (method === 'POST' && rawPath === '/eth-call') {
    if (!isLocalMode()) return NOT_HANDLED;
    return localEthCall(localChainId(body, qs), String(body?.to || '') as `0x${string}`, String(body?.data || '0x') as `0x${string}`);
  }

  // POST /eth-get-code  (read-only; the payer's account code, checked for an EIP-7702 delegation before an x402 authorization)
  if (method === 'POST' && rawPath === '/eth-get-code') {
    if (!isLocalMode()) return NOT_HANDLED;
    return localGetCode(localChainId(body, qs), String(body?.address || '') as `0x${string}`);
  }

  // GET /wallets/{id}/balance
  if (method === 'GET' && /^\/wallets\/[^/]*\/balance$/.test(rawPath)) {
    const chainId = localChainId(body, qs);
    if (SOLANA_CHAIN_IDS.has(chainId)) {
      if (!isSolanaLocalMode()) refuseMissingLocalKey('solana');
      return localSolBalance(chainId);
    }
    if (!isLocalMode()) refuseMissingLocalKey('evm');
    return localNativeBalance(chainId);
  }

  // GET /wallets/{id}/token-balance
  if (method === 'GET' && /^\/wallets\/[^/]*\/token-balance$/.test(rawPath)) {
    const chainId = localChainId(body, qs);
    const token0 = qs.get('token') || qs.get('token_address') || '';
    if (SOLANA_CHAIN_IDS.has(chainId)) {
      if (!isSolanaLocalMode()) refuseMissingLocalKey('solana');
      return localSplBalance(token0, chainId);
    }
    if (!isLocalMode()) refuseMissingLocalKey('evm');
    const token = token0;
    if (!/^0x[a-fA-F0-9]{40}$/.test(token)) {
      throw new Error(`Local mode needs an EVM token address, got "${token}".`);
    }
    return localTokenBalance(chainId, token as `0x${string}`);
  }

  // POST /wallets/{id}/sign  (message signing only; tx signing goes through send)
  if (method === 'POST' && /^\/wallets\/[^/]*\/sign$/.test(rawPath)) {
    const message = body?.message;
    if (typeof message === 'string' && message) return localSignMessage(message);
    throw new Error(
      'Local mode signs messages in-process. For transactions use send_transaction, ' +
      'which signs and broadcasts locally in one step.'
    );
  }

  // Wallet listing and lookup describe whichever local keys are configured.
  if (method === 'GET' && rawPath === '/wallets') {
    const wallets = [];
    if (isLocalMode()) wallets.push(localWalletRecord());
    if (isSolanaLocalMode()) wallets.push(solanaWalletRecord());
    return { wallets };
  }
  if (method === 'GET' && /^\/wallets\/[^/]+$/.test(rawPath)) {
    return isLocalMode() ? localWalletRecord() : solanaWalletRecord();
  }

  if (method === 'POST' && rawPath === '/wallets') {
    throw new Error(
      'Local signing mode uses the single key you supplied, so there is nothing to create. ' +
      'Generate another key yourself and run a second instance with a different ' +
      'AGENTWALLET_PRIVATE_KEY, or unset it to create hosted wallets.'
    );
  }

  if (/^\/wallets\/[^/]*\/(pause|unpause)$/.test(rawPath) || (method === 'DELETE' && /^\/wallets\/[^/]+$/.test(rawPath))) {
    throw new Error(
      'Pause, unpause and delete are custodial controls: they work by refusing to sign on the server. ' +
      'In local mode the key is yours, so nothing can freeze it. Stop the process or move the funds.'
    );
  }

  return NOT_HANDLED;
}

/**
 * Make an API call. If the response is 402 and auto-pay is configured,
 * automatically pay via x402 and retry the request.
 */
async function api(path: string, method = 'GET', body?: Record<string, unknown>, extraHeaders?: Record<string, string>): Promise<unknown> {
  /* Local mode intercepts here rather than inside each tool. Routing at the
     single choke point every funds operation already passes through means no
     tool can quietly stay custodial because someone forgot to update it. */
  if (anyLocalMode()) {
    let handled: unknown;
    try {
      handled = await routeLocally(path, method, body);
    } catch (e) {
      throw new Error(redactRpcSecrets(e)); // viem puts the RPC URL, key and all, in its messages
    }
    if (handled !== NOT_HANDLED) return handled;
  }

  const url = `${API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...extraHeaders,
  };

  if (API_USER && API_PASS) {
    headers['Authorization'] = 'Basic ' + Buffer.from(`${API_USER}:${API_PASS}`).toString('base64');
  }

  // The API host has no reason to send a wallet operation elsewhere: a
  // redirect is refused instead of followed, so a request body is never
  // replayed to another origin and another origin's answer is never returned
  // as the API's (2026-10-04 audit).
  const options: RequestInit = { method, headers, redirect: 'manual' };
  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(url, options);
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`The AgentWallet API host answered ${path} with a redirect (HTTP ${res.status}); refusing to follow it.`);
  }
  const text = await res.text();
  if (text.length > API_MAX_RESPONSE_CHARS) throw new Error(`The AgentWallet API host returned an oversized response (${text.length} characters); refusing to parse it.`);
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw new Error(`The AgentWallet API host returned a non-JSON response (HTTP ${res.status}).`); }

  // A 402 from the API host is paid automatically only for a HOSTED wallet the
  // operator named with AGENTWALLET_WALLET_ID. In local mode the host is not a
  // custodian and must never be able to make the local key sign: a 402 is
  // returned as an error and the agent can call pay_x402 explicitly, which
  // reports what it does (2026-10-04 audit).
  if (res.status === 402 && !extraHeaders?.['X-PAYMENT'] && !extraHeaders?.['X-AGW-SKIP-X402']) {
    if (anyLocalMode()) {
      throw new Error(`The AgentWallet API host asked for payment on ${path}; nothing is paid automatically in local mode. If you trust it, call pay_x402 with that URL so the payment is explicit and reported.`);
    }
    if (X402_WALLET_ID) return handleX402Payment(data as X402Response, path, method, body);
  }

  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(error);
  }

  return data;
}

/**
 * Resolve an asset's decimals from a source the paying party controls, never
 * from the 402 response.
 *
 * Order: known-asset registry first (offline, works in local self-custody mode
 * where there may be no reachable API), then the token contract's own
 * decimals() via eth_call. If neither answers we refuse rather than guess,
 * because guessing is exactly what let a hostile endpoint inflate the cap.
 */
const decimalsCache = new Map<string, number>();

async function resolveTrustedDecimals(chainId: number, token: string): Promise<number> {
  const key = `${chainId}:${token.toLowerCase()}`;
  const cached = decimalsCache.get(key);
  if (typeof cached === 'number') return cached;

  const known = lookupTrustedDecimals(chainId, token);
  if (known !== null) {
    decimalsCache.set(key, known);
    return known;
  }

  if (isSolanaChain(chainId)) {
    throw new Error(
      `x402 blocked: cannot verify decimals for SPL mint ${token} on chain ${chainId}. ` +
      `Unknown mints are refused because the payment cap cannot be checked without trusted decimals.`
    );
  }

  // decimals() selector
  let onChain: number | null = null;
  try {
    const r = (await api('/eth-call', 'POST', {
      chain_id: chainId, to: token, data: '0x313ce567',
    }, { 'X-AGW-SKIP-X402': 'true' })) as { result?: string };
    const hex = (r?.result || '').replace(/^0x/, '');
    if (hex && /^[0-9a-fA-F]+$/.test(hex)) {
      const n = parseInt(hex, 16);
      if (Number.isInteger(n) && n >= 0 && n <= 36) onChain = n;
    }
  } catch {
    onChain = null; // fall through to the refusal below
  }

  if (onChain === null) {
    throw new Error(
      `x402 blocked: could not resolve on-chain decimals for ${token} on chain ${chainId}. ` +
      `The payment cap cannot be enforced without them, so the payment was refused.`
    );
  }

  decimalsCache.set(key, onChain);
  return onChain;
}

/**
 * Handle x402 auto-payment: pay on-chain, then retry the original request
 */
async function handleX402Payment(
  x402Data: X402Response,
  originalPath: string,
  originalMethod: string,
  originalBody?: Record<string, unknown>
): Promise<unknown> {
  const accepts = x402Data.accepts;
  if (!accepts || accepts.length === 0) {
    throw new Error('402 Payment Required but no payment options available.');
  }

  // Only an "exact" requirement can be settled by a transfer. An upto offer
  // names the MAXIMUM of a usage authorization; paying that maximum upfront
  // hands the endpoint the whole ceiling instead of what was used (2026-09-28
  // report). Such offers are refused here, before any wallet call; pay_x402
  // settles them with a Permit2 authorization. A missing scheme is our own
  // legacy paywall shape and means exact.
  const accept = accepts.find((a) => !a.scheme || a.scheme === 'exact');
  if (!accept) {
    throw new Error(
      `x402 auto-pay: no "exact" payment option was offered (schemes: ${accepts.map((a) => a.scheme || '?').join(', ')}); ` +
      `an upto maximum is not paid upfront. Use pay_x402 for this endpoint.`
    );
  }
  const payTo = String(accept.payTo || '');

  // Determine chain_id from network string (CAIP-2, plain name, or raw ID)
  const network = accept.network || '';
  const chainId = resolveChainId(network);
  if (chainId === null) throw new Error(`x402 auto-pay: unknown network "${network}" in the payment requirements; refusing to guess a chain.`);
  if (isSolanaChain(chainId) ? !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(payTo) : !/^0x[0-9a-fA-F]{40}$/.test(payTo)) {
    throw new Error(`x402 auto-pay: payTo "${payTo}" is not a valid address for chain ${chainId}.`);
  }

  // x402 maxAmountRequired is ALREADY in base/atomic units (e.g. "10000" =
  // 0.01 USDC at 6 decimals) and must be used directly. The previous code ran
  // it through parseUnits(), which re-scaled it by 10**decimals and overpaid by
  // that factor (1,000,000x for USDC). deriveX402Payment uses it directly (like
  // the pay_x402 tool) and enforces a hard ceiling so a malformed or malicious
  // 402 response cannot drain the wallet. AGENTWALLET_MAX_AUTOPAY is in
  // human-readable units of the asset; default 1.
  const maxAutopay = autopayEnvCap();
  const assetForDecimals = accept.asset || accept.extra?.token || '';
  const policy = autopayAssetAllowed(chainId, assetForDecimals);
  if (!policy.allowed) throw new Error(policy.reason as string);
  const trustedDecimals = assetForDecimals
    ? await resolveTrustedDecimals(chainId, assetForDecimals)
    : nativeDecimals(chainId); // native asset: 18 on EVM (wei), 9 on Solana (lamports)
  const { tokenAddress, rawAmount, decimals } = deriveX402Payment(accept, maxAutopay, trustedDecimals);

  // Send payment using our wallet (with X-AGW-SKIP-X402 to prevent recursion)
  let txHash: string;
  try {
    if (tokenAddress) {
      // ERC-20/SPL token transfer
      const isSOL = isSolanaChain(chainId);
      const sendResult = await api(
        `/wallets/${X402_WALLET_ID}/send`,
        'POST',
        isSOL
          ? { chain_id: chainId, to: payTo, value: rawAmount, token_mint: tokenAddress, token_decimals: decimals }
          : { chain_id: chainId, to: tokenAddress, value: '0', data: buildErc20TransferData(payTo, rawAmount) },
        { 'X-AGW-SKIP-X402': 'true' }
      ) as { tx_hash?: string; signature?: string };
      txHash = sendResult.tx_hash || sendResult.signature || '';
    } else {
      // Native transfer
      const sendResult = await api(
        `/wallets/${X402_WALLET_ID}/send`,
        'POST',
        { chain_id: chainId, to: payTo, value: rawAmount },
        { 'X-AGW-SKIP-X402': 'true' }
      ) as { tx_hash?: string; signature?: string };
      txHash = sendResult.tx_hash || sendResult.signature || '';
    }
  } catch (e) {
    throw new Error(`x402 auto-pay failed: ${(e as Error).message}. Original error: ${x402Data.error}`);
  }

  if (!txHash) {
    throw new Error('x402 auto-pay: no transaction hash returned.');
  }

  // Build X-PAYMENT header (base64-encoded JSON proof)
  const proof = {
    x402Version: 1,
    scheme: 'exact',
    network: network,
    payload: { txHash },
  };
  const paymentHeader = Buffer.from(JSON.stringify(proof)).toString('base64');

  // Wait briefly for tx confirmation (EVM ~2s, Solana ~6s)
  const waitMs = isSolanaChain(chainId) ? 8000 : 3000;
  await new Promise(resolve => setTimeout(resolve, waitMs));

  // Retry original request with payment proof
  return api(originalPath, originalMethod, originalBody, { 'X-PAYMENT': paymentHeader });
}

/**
 * Build ERC-20 transfer(address,uint256) calldata
 */
function buildErc20TransferData(to: string, amount: string): string {
  // transfer(address,uint256) selector = 0xa9059cbb
  const addressPadded = to.slice(2).toLowerCase().padStart(64, '0');
  const amountHex = BigInt(amount).toString(16).padStart(64, '0');
  return '0xa9059cbb' + addressPadded + amountHex;
}

function jsonResponse(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

// ─── Solana Helpers ───────────────────────────────────────────────

function isSolanaChain(chainId: number): boolean {
  return SOLANA_CHAIN_IDS.has(chainId);
}

/**
 * Validate an address — accepts both EVM (0x...) and Solana (Base58).
 */
function isValidAddress(address: string): boolean {
  // EVM: 0x + 40 hex chars
  if (/^0x[a-fA-F0-9]{40}$/.test(address)) return true;
  // Solana: 32-44 chars, Base58 alphabet (no 0, O, I, l)
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) return true;
  return false;
}

// ─── Guard helpers ──────────────────────────────────────────────

/** Request headers the caller may not set on pay_x402: Host would rename the TLS peer, the rest belong to the client. */
const FORBIDDEN_REQUEST_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'expect', 'te', 'trailer', 'keep-alive']);

/** Authorizations signed in this process, keyed by endpoint and requirement, kept until they expire. */
const signingInFlight = new Map<string, Promise<void>>();
const signedPayments = new Map<string, {
  headerName: string; paymentHeader: string; txHash: string | null;
  authorization: Eip3009Authorization | null; uptoAuth: UptoPermit2Authorization | null; payer: string | null; until: number;
}>();

function looksLikeTxHash(v: unknown): v is string {
  return typeof v === 'string' && (/^0x[0-9a-fA-F]{64}$/.test(v) || /^[1-9A-HJ-NP-Za-km-z]{86,88}$/.test(v));
}

function assertPayTo(chainId: number, payTo: unknown): void {
  const p = String(payTo ?? '');
  const ok = isSolanaChain(chainId) ? /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(p) : /^0x[0-9a-fA-F]{40}$/.test(p);
  if (!ok) throw new Error(`x402: payTo "${p}" is not a valid address for chain ${chainId}.`);
}

/** A URL with credentials in its path or query (Alchemy/Infura style keys) reduced to its origin for display. */
function redactUrl(u: string): string {
  try {
    const p = new URL(u);
    return p.pathname !== '/' || p.search ? `${p.origin}/…` : p.origin;
  } catch { return u; }
}
const API_MAX_RESPONSE_CHARS = 8 * 1024 * 1024;
/* Error text from the local signing path with every URL reduced to its origin
   and viem's "URL:" / "Request body:" lines dropped: an RPC endpoint carries
   its API key in the path or query, and a tool result is the agent's context
   and the client's log (2026-10-04 audit). */
function redactRpcSecrets(err: unknown): string {
  const e = err as { shortMessage?: string; details?: string; message?: string };
  let msg = e?.shortMessage ? [e.shortMessage, e.details].filter(Boolean).join(' ') : String(e?.message ?? err);
  msg = msg.split(/\r?\n/).filter(l => !/^\s*(URL|Request body|Request Arguments|Raw Call Arguments)\s*:/i.test(l)).join('\n').trim();
  return msg.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)\]]+/gi, (u) => redactUrl(u));
}

/**
 * Decimals to scale a human amount by. Always the token's own value (registry,
 * then decimals() on chain); a caller-supplied value must agree or the call
 * is refused, because "18" for USDC scales the amount by a trillion.
 */
async function verifiedDecimals(chainId: number, token: string, given?: number): Promise<number> {
  let trusted: number | null = null;
  if (isSolanaChain(chainId)) {
    // The mint itself says how many decimals it has; a caller's value only
    // ever confirms it (2026-10-04 audit: the substituted byte could not catch
    // an amount already scaled by a wrong guess).
    trusted = await mintDecimalsStrict(token, chainId);
    if (trusted === null) throw new Error(`Could not read the decimals of mint ${token} from the chain; refusing to guess the scale of the amount.`);
  } else {
    trusted = await resolveTrustedDecimals(chainId, token);
  }
  if (given !== undefined && given !== trusted) {
    throw new Error(`decimals ${given} was passed but ${token} has ${trusted} decimals; refusing to scale the amount by the wrong factor.`);
  }
  return trusted;
}

/** Cap variables are read at send time; a typo must fail at startup, not after funding. */
function validateGuardEnv(): void {
  parseDecimalPins(process.env.AGENTWALLET_TOKEN_DECIMALS); // throws on a malformed pin
  for (const name of ['AGENTWALLET_MAX_TX_NATIVE', 'AGENTWALLET_MAX_TX_TOKEN', 'AGENTWALLET_MAX_TX_SOL', 'AGENTWALLET_MAX_AUTOPAY']) {
    const raw = process.env[name];
    const v = (raw || '').trim();
    // Set but blank is a typo, not "no cap": refuse to start rather than run uncapped.
    if (raw !== undefined && v === '') throw new Error(`${name} is set but blank. Set it to a number or unset it.`);
    if (v && !/^\d+(\.\d+)?$/.test(v)) throw new Error(`${name} must be a decimal number, got "${v}".`);
  }
  for (const e of parseAutopayAssets(process.env.AGENTWALLET_AUTOPAY_ASSETS)) {
    if (e.asset !== 'native' && !/^0x[0-9a-f]{40}$/.test(e.asset) && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(e.asset)) {
      throw new Error(`AGENTWALLET_AUTOPAY_ASSETS entry "${e.asset}" is not "native", an EVM address or an SPL mint (optionally prefixed "chainId:").`);
    }
  }
  const t = (process.env.AGENTWALLET_X402_MAX_TIMEOUT || '').trim();
  if (t && (!/^\d+$/.test(t) || Number(t) < 60 || Number(t) > 31_536_000)) {
    throw new Error(`AGENTWALLET_X402_MAX_TIMEOUT must be a whole number of seconds between 60 and 31536000, got "${t}".`);
  }
}

// ─── EVM Helpers ──────────────────────────────────────────────────

/**
 * Convert a human-readable amount (e.g. "0.1") to raw units string given decimals.
 * Uses BigInt for precision — no floating-point errors.
 */
function parseUnits(amount: string, decimals: number): string {
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`Invalid amount "${amount}". Must be a positive number (e.g. "0.1" or "100").`);
  }
  const [whole, frac = ''] = amount.split('.');
  // More fractional digits than the token has cannot be sent; truncating would
  // move a different amount than the one echoed back to the caller.
  if (frac.length > decimals) throw new Error(`Amount "${amount}" has ${frac.length} decimal places but the token has ${decimals}.`);
  const raw = BigInt(whole + frac.padEnd(decimals, '0'));
  return raw.toString();
}

/**
 * Format raw units to human-readable string given decimals.
 */
function formatUnits(raw: string, decimals: number): string {
  const padded = raw.padStart(decimals + 1, '0');
  const whole = padded.slice(0, padded.length - decimals) || '0';
  const frac = padded.slice(padded.length - decimals);
  // Trim trailing zeros but keep at least one decimal
  const trimmed = frac.replace(/0+$/, '') || '0';
  return `${whole}.${trimmed}`;
}

/**
 * Pad an address to 32 bytes (64 hex chars) for ABI encoding.
 */
function padAddress(address: string): string {
  // An over-long "address" would shift every later calldata word (the amount
  // among them) and the EVM would decode whatever landed in the first 32 bytes.
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`Not an EVM address: "${address}".`);
  return address.slice(2).toLowerCase().padStart(64, '0');
}

/**
 * Encode a uint256 as 32 bytes hex (64 chars).
 */
function encodeUint256(value: string): string {
  const v = BigInt(value);
  if (v < 0n || v > (1n << 256n) - 1n) throw new Error(`Amount ${value} does not fit in uint256.`);
  return v.toString(16).padStart(64, '0');
}

// ─── Server ──────────────────────────────────────────────────────

// ─── x402 Network Mapping ──────────────────────────────────────

/**
 * Resolve an x402 network identifier to a chain ID: plain names ("base"),
 * CAIP-2 ("eip155:8453", "solana:<genesis prefix>") and raw ids ("8453").
 * The table and the parsing live in x402-payment.ts so they can be tested.
 */
function resolveChainId(network: string): number | null {
  return resolveNetworkChainId(network);
}

// ─── Server ──────────────────────────────────────────────────────

/**
 * Destination address shape, EVM or Solana.
 *
 * The contract-address params were regex-guarded but the DESTINATION on every
 * transfer tool was a bare z.string(), so a truncated or mistyped address went
 * straight into a signed transaction. On-chain sends are irreversible, and the
 * chain will happily accept any well-formed address, so the cheapest place to
 * catch a malformed one is before it is signed. This does not validate the
 * EIP-55 checksum, only the shape; a wrong-but-well-formed address is still the
 * caller's responsibility.
 */
const AddressSchema = z.string().regex(
  /^(0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/,
  'Must be a 0x-prefixed 40-hex EVM address or a base58 Solana address'
);

const server = new McpServer(
  {
    name: 'agentwallet',
    version: '1.13.5',
  },
  {
    instructions: `AgentWallet gives AI agents their own blockchain wallets. ${anyLocalMode()
      ? 'This server runs in LOCAL (self-custody) mode: the operator supplied the key, signing happens in this process, and the only spend guards are the AGENTWALLET_MAX_TX_* environment caps. There is no server-side pause, daily limit or approval email; pause_wallet, unpause_wallet and delete_wallet are refused.'
      : 'Private keys are encrypted server-side and never exposed: agents sign and broadcast transactions without ever touching raw keys.'}

## Getting Started
1. Call list_wallets to see existing wallets, or create_wallet to make a new one.
2. Fund the wallet by sending tokens to its address from an external source.
3. Use transfer (native tokens) or transfer_token (ERC-20/SPL tokens) to send funds.

## Supported Chains
- **EVM chains:** Ethereum (1), Base (8453), Arbitrum (42161), Optimism (10), Polygon (137), Avalanche (43114), BSC (56), Zora (7777777), PulseChain (369)
- **Solana:** Mainnet (900), Devnet (901), Testnet (902)
- Call get_chains for the full list with native tokens and stablecoin contract addresses.

## EVM vs Solana
- **Addresses:** EVM uses 0x-prefixed hex (42 chars). Solana uses Base58 (32-44 chars).
- **Native tokens:** EVM = ETH/POL/BNB/etc (18 decimals, wei). Solana = SOL (9 decimals, lamports).
- **Token standards:** EVM uses ERC-20. Solana uses SPL tokens.
- **EVM-only tools:** approve_token, get_allowance, wrap_eth, unwrap_eth, call_contract, get_token_info. These do not work on Solana.
- **Works on both:** create_wallet, transfer, transfer_token, send_transaction, sign_transaction, get_balance, get_token_balance.

## Common Workflows

### Send native tokens (ETH, SOL, etc.)
Use the transfer tool with a human-readable amount (e.g. "0.1" ETH). It auto-converts to wei/lamports.

### Send ERC-20 or SPL tokens
Use transfer_token. You need: wallet_id, token contract address, recipient, amount, chain_id, and decimals (6 for USDC, 18 for most ERC-20s). Call get_chains to find stablecoin addresses.

### Interact with DeFi (EVM only)
1. Check allowance with get_allowance.
2. If needed, call approve_token to let the DeFi contract spend your tokens.
3. Use send_transaction with the contract's calldata to execute the interaction.

### Wrap/unwrap native tokens (EVM only)
Use wrap_eth to convert ETH → WETH (required by many DeFi protocols). Use unwrap_eth to convert back.

### Read on-chain data (EVM only)
Use call_contract for gas-free read-only calls (eth_call). Provide ABI-encoded calldata.

## x402 Payments — Paying for Resources
The pay_x402 tool handles the full x402 payment flow automatically:
1. Fetches the URL.
2. If the server returns HTTP 402, parses the payment requirements.
3. Pays on-chain using your wallet.
4. Retries the request with proof of payment.
Always set max_payment to prevent overspending (e.g. "1.00" for max 1 USDC).

## x402 Paywalls — Accepting Payments
Create paywalls to charge other agents for accessing your resources:
1. create_paywall — set price, token, chain, and the resource URL to protect.
2. Share the access URL. Clients that pay on-chain get the resource; others get HTTP 402.
3. list_paywalls and get_paywall_payments to track revenue.
4. get_x402_revenue for aggregate stats across all paywalls.

## Wallet Security
- ${anyLocalMode() ? 'pause_wallet does not exist in local mode: revoke the key (rotate it and move the funds) if the process is compromised.' : 'Use pause_wallet to immediately freeze a wallet if compromised. No transactions can be signed while paused.'}
- Use unpause_wallet to resume operations.
- Use delete_wallet to permanently disable a wallet.
- ${anyLocalMode() ? 'Spend limits are the AGENTWALLET_MAX_TX_NATIVE / _TOKEN / _SOL / _AUTOPAY caps the operator set; run wallet_mode to see them. Unset means no limit.' : 'Wallets have server-enforced spending limits.'}

## Tool Selection Guide
| Goal | Tool |
|------|------|
| Send ETH/SOL/native tokens | transfer |
| Send USDC/ERC-20/SPL tokens | transfer_token |
| Check native balance | get_balance |
| Check token balance | get_token_balance |
| Look up token details | get_token_info (EVM only) |
| Approve DeFi spending | approve_token (EVM only) |
| Check approval amount | get_allowance (EVM only) |
| Read smart contract | call_contract (EVM only) |
| Custom transaction | send_transaction |
| Sign without broadcasting | sign_transaction |
| Pay for x402 resource | pay_x402 |
| Charge for your resource | create_paywall |
| Check usage/billing | get_usage |`,
  },
);

// ─── Tool: create_wallet ─────────────────────────────────────────

server.tool(
  'create_wallet',
  'Create a new EVM or Solana wallet. Returns the wallet ID and address. ' +
    (anyLocalMode() ? 'In local mode this reports the key already configured; no wallet is created remotely.' : 'Private key is encrypted server-side and never exposed.'),
  {
    label: z.string().default('').describe('Friendly name for the wallet'),
    chain_id: z.number().int().default(8453).describe('Default chain ID (1=Ethereum, 8453=Base, 42161=Arbitrum, 10=Optimism, 137=Polygon, 43114=Avalanche, 56=BSC, 7777777=Zora, 369=PulseChain, 900=Solana, 901=Solana Devnet)'),
  },
  async ({ label, chain_id }) => {
    const data = await api('/wallets', 'POST', { label, chain_id });
    return jsonResponse(data);
  },
);

// ─── Tool: list_wallets ──────────────────────────────────────────

server.tool(
  'list_wallets',
  'List all wallets owned by the authenticated user. ' +
    'Returns wallet IDs, addresses, labels, chain IDs, and status.',
  {},
  async () => {
    const data = await api('/wallets');
    return jsonResponse(data);
  },
);

// ─── Tool: get_wallet ────────────────────────────────────────────

server.tool(
  'get_wallet',
  'Get details for a specific wallet by ID. ' +
    'Returns address, label, chain, spending limits, and pause status.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
  },
  async ({ wallet_id }) => {
    const data = await api(`/wallets/${wallet_id}`);
    return jsonResponse(data);
  },
);

// ─── Tool: get_balance ───────────────────────────────────────────

server.tool(
  'get_balance',
  'Get the native token balance for a wallet on a specific chain. ' +
    'Returns balance in both wei (or lamports for Solana) and human-readable format.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    chain_id: z.number().int().optional().describe('Chain ID to check (defaults to wallet\'s default chain)'),
  },
  async ({ wallet_id, chain_id }) => {
    const params = chain_id ? `?chain_id=${chain_id}` : '';
    const data = await api(`/wallets/${wallet_id}/balance${params}`);
    return jsonResponse(data);
  },
);

// ─── Tool: sign_transaction ──────────────────────────────────────

server.tool(
  'sign_transaction',
  'Sign a transaction with a wallet\'s private key. ' +
    'For EVM: returns signed raw transaction hex. For Solana: returns base64 signed transaction. ' +
    'Does NOT broadcast — use send_transaction for sign + broadcast.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    to: AddressSchema.describe('Destination address (0x-prefixed for EVM, Base58 for Solana)'),
    chain_id: z.number().int().optional().describe('Chain ID (defaults to wallet\'s default)'),
    value: z.string().regex(/^\d+$/, 'decimal integer string').default('0').describe('Value in wei/lamports (decimal integer string; no hex, no decimals)'),
    data: z.string().regex(/^(0x([0-9a-fA-F]{2})*)?$/, '0x-prefixed even-length hex').default('').describe('Hex-encoded calldata (0x-prefixed) for EVM contract calls'),
    gas_limit: z.string().optional().describe('Gas limit — EVM only (auto-estimated if omitted)'),
    max_fee: z.string().optional().describe('Max fee per gas in wei — EVM only (auto if omitted)'),
    priority_fee: z.string().optional().describe('Max priority fee per gas in wei — EVM only (auto if omitted)'),
    token_mint: z.string().optional().describe('SPL token mint address — Solana only (for SPL token transfers)'),
    token_decimals: z.number().int().min(0).max(36).optional().describe('SPL token decimals, Solana only (6 for USDC)'),
  },
  async ({ wallet_id, to, chain_id, value, data, gas_limit, max_fee, priority_fee, token_mint, token_decimals }) => {
    // Validate address format
    if (!isValidAddress(to)) {
      throw new Error(`Invalid address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const body: Record<string, unknown> = { to, value };
    if (chain_id) body.chain_id = chain_id;
    // Without a chain id the SPL fields were silently dropped and the server
    // fell back to a native transfer of the same number, to the same address.
    if (token_mint && !chain_id) throw new Error('token_mint needs an explicit Solana chain_id (900 mainnet, 901 devnet).');

    if (isSolanaChain(chain_id ?? 0)) {
      // Solana-specific params
      if (token_mint) body.token_mint = token_mint;
      if (token_decimals !== undefined) body.token_decimals = token_decimals;
    } else {
      // EVM-specific params
      body.data = data;
      if (gas_limit) body.gas_limit = gas_limit;
      if (max_fee) body.max_fee = max_fee;
      if (priority_fee) body.priority_fee = priority_fee;
    }

    const result = await api(`/wallets/${wallet_id}/sign`, 'POST', body);
    return jsonResponse(result);
  },
);

// ─── Tool: send_transaction ──────────────────────────────────────

server.tool(
  'send_transaction',
  'Sign and broadcast a transaction. ' +
    'Returns the transaction hash (EVM) or signature (Solana) on success. ' +
    (anyLocalMode() ? 'Signed in this process with the local key and broadcast via the configured RPC.' : 'The transaction is signed server-side and broadcast via RPC.'),
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    to: AddressSchema.describe('Destination address (0x-prefixed for EVM, Base58 for Solana)'),
    chain_id: z.number().int().optional().describe('Chain ID (defaults to wallet\'s default)'),
    value: z.string().regex(/^\d+$/, 'decimal integer string').default('0').describe('Value in wei/lamports (decimal integer string; no hex, no decimals)'),
    data: z.string().regex(/^(0x([0-9a-fA-F]{2})*)?$/, '0x-prefixed even-length hex').default('').describe('Hex-encoded calldata (0x-prefixed) for EVM contract calls'),
    gas_limit: z.string().optional().describe('Gas limit — EVM only (auto-estimated if omitted)'),
    max_fee: z.string().optional().describe('Max fee per gas in wei — EVM only (auto if omitted)'),
    priority_fee: z.string().optional().describe('Max priority fee per gas in wei — EVM only (auto if omitted)'),
    token_mint: z.string().optional().describe('SPL token mint address — Solana only (for SPL token transfers)'),
    token_decimals: z.number().int().min(0).max(36).optional().describe('SPL token decimals, Solana only (6 for USDC)'),
  },
  async ({ wallet_id, to, chain_id, value, data, gas_limit, max_fee, priority_fee, token_mint, token_decimals }) => {
    // Validate address format
    if (!isValidAddress(to)) {
      throw new Error(`Invalid address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const body: Record<string, unknown> = { to, value };
    if (chain_id) body.chain_id = chain_id;
    // Without a chain id the SPL fields were silently dropped and the server
    // fell back to a native transfer of the same number, to the same address.
    if (token_mint && !chain_id) throw new Error('token_mint needs an explicit Solana chain_id (900 mainnet, 901 devnet).');

    if (isSolanaChain(chain_id ?? 0)) {
      // Solana-specific params
      if (token_mint) body.token_mint = token_mint;
      if (token_decimals !== undefined) body.token_decimals = token_decimals;
    } else {
      // EVM-specific params
      body.data = data;
      if (gas_limit) body.gas_limit = gas_limit;
      if (max_fee) body.max_fee = max_fee;
      if (priority_fee) body.priority_fee = priority_fee;
    }

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', body);
    return jsonResponse(result);
  },
);

// ─── Tool: transfer ─────────────────────────────────────────────

server.tool(
  'transfer',
  'Send native tokens (ETH, AVAX, BNB, POL, PLS, SOL) to an address. ' +
    'Specify the amount in human-readable format (e.g. "0.1" for 0.1 ETH). ' +
    'The amount is converted to wei/lamports automatically. Signs and broadcasts the transaction.',
  {
    wallet_id: z.number().int().describe('Wallet ID to send from'),
    to: AddressSchema.describe('Destination address (0x-prefixed for EVM, Base58 for Solana)'),
    amount: z.string().describe('Amount to send in human-readable format (e.g. "0.1" for 0.1 ETH)'),
    chain_id: z.number().int().describe('Chain ID (1=Ethereum, 8453=Base, 42161=Arbitrum, 10=Optimism, 137=Polygon, 43114=Avalanche, 56=BSC, 7777777=Zora, 369=PulseChain, 900=Solana, 901=Solana Devnet)'),
  },
  async ({ wallet_id, to, amount, chain_id }) => {
    // Validate address format
    if (!isValidAddress(to)) {
      throw new Error(`Invalid address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    // SOL uses 9 decimals (lamports), EVM native tokens use 18 decimals (wei)
    const decimals = isSolanaChain(chain_id) ? 9 : 18;
    const valueRaw = parseUnits(amount, decimals);

    const body: Record<string, unknown> = {
      to,
      value: valueRaw,
      chain_id,
    };
    if (!isSolanaChain(chain_id)) {
      body.data = '';
    }

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', body);

    return jsonResponse({
      ...(result as Record<string, unknown>),
      amount,
      chain_id,
    });
  },
);

// ─── Tool: get_token_balance ────────────────────────────────────

server.tool(
  'get_token_balance',
  'Get the ERC-20 or SPL token balance for a wallet on a specific chain. ' +
    'Returns the raw balance and human-readable balance. ' +
    'Use get_chains to find stablecoin addresses for each chain.',
  {
    wallet_id: z.number().int().describe('Wallet ID to check'),
    token: z.string().describe('Token address (0x-prefixed ERC-20 contract for EVM, Base58 mint for Solana)'),
    chain_id: z.number().int().describe('Chain ID to check on'),
    decimals: z.number().int().min(0).max(36).optional().describe('Token decimals. Taken from the response or the token contract when omitted'),
  },
  async ({ wallet_id, token, chain_id, decimals }) => {
    // Validate token address format
    if (!isValidAddress(token)) {
      throw new Error(`Invalid token address "${token}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const params = `?chain_id=${chain_id}&token=${token}`;
    const data = await api(`/wallets/${wallet_id}/token-balance${params}`) as { balance_raw?: string; balance_formatted?: string; balance?: string; decimals?: number };

    // Solana API returns balance_formatted + decimals directly
    if (isSolanaChain(chain_id) && data.balance_formatted !== undefined) {
      return jsonResponse({
        ...data,
        balance: data.balance_formatted,
        decimals: data.decimals ?? decimals ?? null,
      });
    }

    // The response's own decimals (local mode reads them from the contract) win
    // over the caller's guess; a guess of 18 used to reformat a 1 USDC balance
    // as 0.000000000001. When nothing supplies them, resolve them ourselves.
    let trusted: number | null = typeof data.decimals === 'number' ? data.decimals : null;
    if (trusted === null) {
      if (typeof decimals === 'number') trusted = decimals;
      else if (!isSolanaChain(chain_id)) trusted = await resolveTrustedDecimals(chain_id, token);
    }
    if (trusted === null) throw new Error('Could not determine the token decimals; pass decimals explicitly.');
    const warning = typeof decimals === 'number' && typeof data.decimals === 'number' && decimals !== data.decimals
      ? `decimals ${decimals} was passed but the token reports ${data.decimals}; the token's value was used.` : undefined;

    return jsonResponse({
      ...data,
      balance: data.balance ?? formatUnits(data.balance_raw || '0', trusted),
      decimals: trusted,
      ...(warning ? { warning } : {}),
    });
  },
);

// ─── Tool: transfer_token ───────────────────────────────────────

server.tool(
  'transfer_token',
  'Send ERC-20 tokens (EVM) or SPL tokens (Solana) to an address. ' +
    'Specify the amount in human-readable format (e.g. "100" for 100 USDC). ' +
    'Signs and broadcasts the transaction. Use get_chains to find stablecoin addresses.',
  {
    wallet_id: z.number().int().describe('Wallet ID to send from'),
    token: z.string().describe('Token address (0x-prefixed ERC-20 contract for EVM, Base58 mint for Solana)'),
    to: AddressSchema.describe('Recipient address (0x-prefixed for EVM, Base58 for Solana)'),
    amount: z.string().describe('Amount in human-readable format (e.g. "100" for 100 USDC)'),
    chain_id: z.number().int().describe('Chain ID'),
    decimals: z.number().int().min(0).max(36).optional().describe('Token decimals. Resolved from the registry or the token contract when omitted; if given, it must match'),
  },
  async ({ wallet_id, token, to, amount, chain_id, decimals: givenDecimals }) => {
    // Validate addresses
    if (!isValidAddress(token)) {
      throw new Error(`Invalid token address "${token}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }
    if (!isValidAddress(to)) {
      throw new Error(`Invalid recipient address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const decimals = await verifiedDecimals(chain_id, token, givenDecimals);
    const rawAmount = parseUnits(amount, decimals);
    let result: unknown;

    if (isSolanaChain(chain_id)) {
      // Solana SPL transfer — the server handles ATA derivation + instruction building
      result = await api(`/wallets/${wallet_id}/send`, 'POST', {
        to,
        value: rawAmount,
        token_mint: token,
        token_decimals: decimals,
        chain_id,
      });
    } else {
      // EVM ERC-20 transfer(address, uint256) calldata
      const calldata = '0xa9059cbb' + padAddress(to) + encodeUint256(rawAmount);
      result = await api(`/wallets/${wallet_id}/send`, 'POST', {
        to: token,       // Send TX to the token contract
        value: '0',      // No native value for token transfers
        data: calldata,
        chain_id,
      });
    }

    return jsonResponse({
      ...(result as Record<string, unknown>),
      token,
      recipient: to,
      amount,
      decimals,
    });
  },
);

// ─── Tool: call_contract ────────────────────────────────────────

server.tool(
  'call_contract',
  'Execute a read-only call against a smart contract (eth_call). ' +
    'Returns the raw hex result. Does not cost gas or modify state. ' +
    'Useful for reading on-chain data like token balances, prices, positions.',
  {
    chain_id: z.number().int().describe('Chain ID'),
    to: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Contract address'),
    data: z.string().describe('ABI-encoded calldata (0x-prefixed hex)'),
  },
  async ({ chain_id, to, data }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('call_contract is not supported on Solana. Use Solana-specific RPC methods instead.');
    }
    const result = await api('/eth-call', 'POST', { chain_id, to, data });
    return jsonResponse(result);
  },
);

// ─── Tool: approve_token ────────────────────────────────────────

server.tool(
  'approve_token',
  'Approve a spender contract to transfer ERC-20 tokens on your behalf. ' +
    'Required before interacting with any DeFi protocol (DEXs, lending, etc.). ' +
    'Use amount "max" for unlimited approval, or specify an exact amount.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token contract address'),
    spender: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Contract address to approve as spender'),
    amount: z.string().describe('Amount to approve in human-readable format (e.g. "1000"), or "max" for unlimited'),
    chain_id: z.number().int().describe('Chain ID'),
    decimals: z.number().int().min(0).max(36).optional().describe('Token decimals. Resolved from the registry or the token contract when omitted; if given, it must match'),
  },
  async ({ wallet_id, token, spender, amount, chain_id, decimals: givenDecimals }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('approve_token is not supported on Solana. Solana SPL tokens do not use ERC-20 style approvals.');
    }
    // approve(address spender, uint256 amount) — selector: 0x095ea7b3
    let rawAmount: string;
    if (amount.toLowerCase() === 'max') {
      rawAmount = (BigInt(2) ** BigInt(256) - BigInt(1)).toString();
    } else {
      rawAmount = parseUnits(amount, await verifiedDecimals(chain_id, token, givenDecimals));
    }
    const calldata = '0x095ea7b3' + padAddress(spender) + encodeUint256(rawAmount);

    // Asset risk rides along with the approval (issue #13). It never blocks; it is the
    // caller's call. Skipped for Permit2, which only moves what a signature allows.
    let risk: unknown = null;
    if (spender.toLowerCase() !== PERMIT2_ADDRESS.toLowerCase() && process.env.AGENTWALLET_TOKEN_RISK !== '0') {
      try { risk = await assessTokenRisk(chain_id, token, (to, data) => ethCallHex(chain_id, to, data)); } catch { risk = null; }
    }

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', {
      to: token,
      value: '0',
      data: calldata,
      chain_id,
    });

    return jsonResponse({
      ...(result as Record<string, unknown>),
      token,
      spender,
      amount: amount.toLowerCase() === 'max' ? 'unlimited' : amount,
      risk,
    });
  },
);

// ─── Tool: get_allowance ────────────────────────────────────────

server.tool(
  'get_allowance',
  'Check how many ERC-20 tokens a spender is approved to transfer. ' +
    'Returns the allowance in both raw and human-readable format. ' +
    'Use this to check if an approval is needed before a DeFi transaction.',
  {
    wallet_id: z.number().int().describe('Wallet ID (used to determine the owner address)'),
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token contract address'),
    spender: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Spender contract address to check'),
    chain_id: z.number().int().describe('Chain ID'),
    decimals: z.number().int().min(0).max(36).optional().describe('Token decimals. Resolved from the registry or the token contract when omitted; if given, it must match'),
  },
  async ({ wallet_id, token, spender, chain_id, decimals: givenDecimals }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('get_allowance is not supported on Solana. Solana SPL tokens do not use ERC-20 style allowances.');
    }
    // First get the wallet address
    const wallet = await api(`/wallets/${wallet_id}`) as { address: string };

    // allowance(address owner, address spender) — selector: 0xdd62ed3e
    const calldata = '0xdd62ed3e' + padAddress(wallet.address) + padAddress(spender);

    const result = await api('/eth-call', 'POST', { chain_id, to: token, data: calldata }) as { result: string };

    // Parse exactly one uint256 word: a hostile token returning more bytes must
    // not turn into a 512-bit "allowance".
    const rawHex = String(result?.result || '').replace(/^0x/, '').slice(0, 64);
    if (rawHex && !/^[0-9a-fA-F]+$/.test(rawHex)) throw new Error('allowance() returned non-hex data.');
    const raw = BigInt('0x' + (rawHex || '0')).toString();
    const decimals = await verifiedDecimals(chain_id, token, givenDecimals);
    const maxUint256 = (BigInt(2) ** BigInt(256) - BigInt(1)).toString();

    return jsonResponse({
      token,
      spender,
      allowance_raw: raw,
      allowance: raw === maxUint256 ? 'unlimited' : formatUnits(raw, decimals),
      is_unlimited: raw === maxUint256,
      decimals,
    });
  },
);

// ─── WETH / Wrapped Native Token addresses ──────────────────────


// ─── Tool: wrap_eth ─────────────────────────────────────────────

server.tool(
  'wrap_eth',
  'Wrap native tokens (ETH, AVAX, BNB, POL, PLS) into their wrapped ERC-20 version (WETH, WAVAX, etc.). ' +
    'Required for most DeFi protocols that use ERC-20 tokens instead of raw native tokens. ' +
    'Specify amount in human-readable format (e.g. "0.5" for 0.5 ETH).',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    amount: z.string().describe('Amount to wrap in human-readable format (e.g. "0.5")'),
    chain_id: z.number().int().describe('Chain ID'),
  },
  async ({ wallet_id, amount, chain_id }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('wrap_eth is not supported on Solana. Solana does not use wrapped native tokens like WETH.');
    }
    const wrapped = WRAPPED_NATIVE[chain_id];
    if (!wrapped) {
      throw new Error(`No wrapped native token configured for chain ${chain_id}`);
    }

    // WETH deposit() payable — selector: 0xd0e30db0
    const valueWei = parseUnits(amount, 18);

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', {
      to: wrapped.address,
      value: valueWei,
      data: '0xd0e30db0',
      chain_id,
    });

    return jsonResponse({
      ...(result as Record<string, unknown>),
      wrapped_token: wrapped.symbol,
      wrapped_address: wrapped.address,
      amount,
    });
  },
);

// ─── Tool: unwrap_eth ───────────────────────────────────────────

server.tool(
  'unwrap_eth',
  'Unwrap wrapped tokens (WETH, WAVAX, WBNB, etc.) back to native tokens. ' +
    'Specify amount in human-readable format (e.g. "0.5" for 0.5 WETH).',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    amount: z.string().describe('Amount to unwrap in human-readable format (e.g. "0.5")'),
    chain_id: z.number().int().describe('Chain ID'),
  },
  async ({ wallet_id, amount, chain_id }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('unwrap_eth is not supported on Solana. Solana does not use wrapped native tokens like WETH.');
    }
    const wrapped = WRAPPED_NATIVE[chain_id];
    if (!wrapped) {
      throw new Error(`No wrapped native token configured for chain ${chain_id}`);
    }

    // WETH withdraw(uint256) — selector: 0x2e1a7d4d
    const rawAmount = parseUnits(amount, 18);
    const calldata = '0x2e1a7d4d' + encodeUint256(rawAmount);

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', {
      to: wrapped.address,
      value: '0',
      data: calldata,
      chain_id,
    });

    return jsonResponse({
      ...(result as Record<string, unknown>),
      unwrapped_token: wrapped.symbol,
      amount,
    });
  },
);

// ─── Tool: get_token_info ───────────────────────────────────────

/**
 * Decode an ABI-encoded string return value from hex.
 * Handles malformed data gracefully — returns empty string on any parsing failure.
 */
function decodeAbiString(hex: string): string {
  try {
    const clean = hex.replace('0x', '');
    if (clean.length < 128) return ''; // offset + length minimum
    // First 32 bytes = offset, next 32 bytes at that offset = length
    const offset = parseInt(clean.slice(0, 64), 16) * 2;
    if (isNaN(offset) || offset + 64 > clean.length) return '';
    const length = parseInt(clean.slice(offset, offset + 64), 16);
    if (isNaN(length) || length === 0) return '';
    const dataHex = clean.slice(offset + 64, offset + 64 + length * 2);
    const pairs = dataHex.match(/.{2}/g);
    if (!pairs) return '';
    // Convert hex to UTF-8
    const bytes = new Uint8Array(pairs.map(b => parseInt(b, 16)));
    // Attacker-controlled text: keep it short and printable so a token cannot
    // smuggle kilobytes of instructions or terminal escapes into the agent's context.
    return new TextDecoder().decode(bytes).replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, 64);
  } catch {
    return '';
  }
}

server.tool(
  'get_token_info',
  'Get the name, symbol, and decimals of any ERC-20 token by its contract address. ' +
    'Useful for discovering token details before transfers or approvals.',
  {
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token contract address'),
    chain_id: z.number().int().describe('Chain ID'),
  },
  async ({ token, chain_id }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('get_token_info is not supported on Solana. Use Solana token metadata programs to query SPL token details.');
    }
    // Make 3 parallel eth_call requests: name(), symbol(), decimals()
    const [nameResult, symbolResult, decimalsResult] = await Promise.all([
      api('/eth-call', 'POST', { chain_id, to: token, data: '0x06fdde03' }).catch(() => ({ result: '0x' })),
      api('/eth-call', 'POST', { chain_id, to: token, data: '0x95d89b41' }).catch(() => ({ result: '0x' })),
      api('/eth-call', 'POST', { chain_id, to: token, data: '0x313ce567' }).catch(() => ({ result: '0x' })),
    ]) as { result: string }[];

    const name = decodeAbiString(nameResult.result);
    const symbol = decodeAbiString(symbolResult.result);
    const decimalsHex = String(decimalsResult?.result || '').replace(/^0x/, '').slice(0, 64);
    const parsedDecimals = /^[0-9a-fA-F]+$/.test(decimalsHex) ? Number(BigInt('0x' + decimalsHex)) : NaN;
    const decimals = Number.isInteger(parsedDecimals) && parsedDecimals >= 0 && parsedDecimals <= 255 ? parsedDecimals : null;

    return jsonResponse({
      token,
      chain_id,
      name: name || 'Unknown',
      symbol: symbol || 'Unknown',
      decimals,
    });
  },
);

// ─── x402 "exact" helpers ────────────────────────────────────────

/** The paying address: the local key in self-custody mode, else the hosted wallet record. */
async function payerAddress(walletId: number): Promise<string> {
  const w = (await api(`/wallets/${walletId}`, 'GET', undefined, { 'X-AGW-SKIP-X402': 'true' })) as { address?: string; wallet_address?: string };
  const a = String(w?.address || w?.wallet_address || '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error(`x402: could not resolve the EVM address of wallet ${walletId} (got "${a}").`);
  return a;
}

type PayerDelegation = { delegate: string; erc1271: Erc1271Support; warning: string };

/**
 * Best-effort look at the payer's account code. An EIP-7702 delegated EOA whose delegate
 * does not implement ERC-1271 is declined by facilitators that check code before recovering
 * the signer, with an error that reads like a signature fault (issue #9). Nothing is refused
 * here: the authorization costs nothing to sign and other facilitators accept it. The result
 * carries the warning so the agent can explain a signature-shaped rejection. A lookup failure
 * (a hosted server without the route, RPC trouble) reports nothing rather than blocking the payment.
 */
async function payerDelegation(chainId: number, payer: string): Promise<PayerDelegation | null> {
  try {
    const r = (await api('/eth-get-code', 'POST', { chain_id: chainId, address: payer }, { 'X-AGW-SKIP-X402': 'true' })) as { code?: string };
    const delegate = parseEip7702Delegation(r?.code);
    if (!delegate) return null;
    let erc1271: Erc1271Support = 'unknown';
    try {
      const probe = (await api('/eth-call', 'POST', { chain_id: chainId, to: payer, data: erc1271ProbeCalldata() }, { 'X-AGW-SKIP-X402': 'true' })) as { result?: string };
      erc1271 = classifyErc1271Probe(probe?.result);
    } catch { erc1271 = 'unknown'; }
    const warning = erc1271 === 'no'
      ? `Payer ${payer} is an EIP-7702 delegated account (delegate ${delegate}) and the delegate does not answer ERC-1271 isValidSignature. ` +
        `Facilitators that check account code before recovering the signer decline this authorization with a signature error. ` +
        `Pay from a plain EOA, or clear the delegation, for reliable x402 settlement.`
      : `Payer ${payer} is an EIP-7702 delegated account (delegate ${delegate}); a facilitator may verify the authorization through ERC-1271 on the delegate.`;
    return { delegate, erc1271, warning };
  } catch {
    return null;
  }
}

async function ethCallHex(chainId: number, to: string, data: string): Promise<string> {
  const r = (await api('/eth-call', 'POST', { chain_id: chainId, to, data }, { 'X-AGW-SKIP-X402': 'true' })) as { result?: string };
  return String(r?.result || '');
}

/**
 * The token's EIP-712 domain. Order: what the 402 declared (extra.name/version,
 * which is what the reference client requires), then a short list of USDC
 * deployments we know, then the contract's own name()/version(). A wrong
 * domain produces a signature that recovers to a stranger, so we refuse
 * rather than guess.
 */
async function resolveTokenDomain(chainId: number, asset: string, extra?: X402Requirement['extra']): Promise<{ name: string; version: string }> {
  if (extra?.name && extra?.version) return { name: String(extra.name), version: String(extra.version) };
  const known = knownTokenDomain(chainId, asset);
  if (known) return known;
  let name = '', version = '';
  try {
    name = decodeAbiString(await ethCallHex(chainId, asset, '0x06fdde03'));    // name()
    version = decodeAbiString(await ethCallHex(chainId, asset, '0x54fd4d50')); // version()
  } catch { /* refused below */ }
  if (!name || !version) {
    throw new Error(
      `x402: cannot determine the EIP-712 domain for token ${asset} on chain ${chainId}: the endpoint sent no ` +
      `extra.name/extra.version and the contract did not answer name()/version(). Refused rather than signed with a guessed domain.`,
    );
  }
  return { name, version };
}

/** Text an endpoint wrote, bounded so it cannot flood the agent's context. */
function serverText(s: unknown): string | null {
  if (s === undefined || s === null) return null;
  const t = String(s);
  return t.length > 300 ? t.slice(0, 300) + '…' : t;
}

/** Sign the authorization with whichever custody mode is active (local key, or the hosted signer). */
async function signAuthorization(
  walletId: number, chainId: number, asset: string, domain: { name: string; version: string }, auth: Eip3009Authorization, approvalId?: string | null,
): Promise<string> {
  const r = (await api(`/wallets/${walletId}/x402/authorize`, 'POST', {
    chain_id: chainId, asset, name: domain.name, version: domain.version,
    to: auth.to, value: auth.value, valid_after: auth.validAfter, valid_before: auth.validBefore, nonce: auth.nonce,
    ...(approvalId ? { approval_id: approvalId } : {}),
  }, { 'X-AGW-SKIP-X402': 'true' })) as { signature?: string; error?: string };
  const sig = String(r?.signature || '');
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) {
    throw new Error(`x402: the wallet did not return a valid authorization signature${r?.error ? ` (${r.error})` : ''}.`);
  }
  return sig;
}

/** Sign a Permit2 upto authorization with whichever custody mode is active. */
async function signPermit2(walletId: number, chainId: number, auth: UptoPermit2Authorization, approvalId?: string | null): Promise<string> {
  const r = (await api(`/wallets/${walletId}/x402/permit2`, 'POST', {
    chain_id: chainId, asset: auth.permitted.token, amount: auth.permitted.amount, spender: auth.spender, permit2: PERMIT2_ADDRESS,
    nonce: auth.nonce, deadline: auth.deadline, to: auth.witness.to, facilitator: auth.witness.facilitator, valid_after: auth.witness.validAfter,
    ...(approvalId ? { approval_id: approvalId } : {}),
  }, { 'X-AGW-SKIP-X402': 'true' })) as { signature?: string; error?: string };
  const sig = String(r?.signature || '');
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Error(`x402 upto: the wallet did not return a valid Permit2 signature${r?.error ? ` (${r.error})` : ''}.`);
  return sig;
}

// ─── Tool: pay_x402 ─────────────────────────────────────────────

server.tool(
  'pay_x402',
  'Handle an x402 payment flow. Fetches a URL, and if the server returns HTTP 402 Payment Required, ' +
    'parses the payment requirements (v1 body or v2 PAYMENT-REQUIRED header), signs an EIP-3009 ' +
    'TransferWithAuthorization for the "exact" scheme (no gas, nothing broadcast by the payer), and retries ' +
    'the request with the payment header. AgentWallet paywalls are paid by on-chain transfer instead. ' +
    'The "upto" scheme is settled with a Permit2 authorization bounded by the cap. Returns the final response and the settlement ' +
    'receipt. Supports the x402 open payment standard (https://x402.org). max_payment can only lower the operator\'s cap for one call.',
  {
    url: z.string().url().describe('The URL to access (will handle 402 payment if required)'),
    wallet_id: z.number().int().describe('Wallet ID to pay from'),
    method: z.string().default('GET').describe('HTTP method (GET, POST, PUT, DELETE)'),
    headers: z.string().optional().describe(
      'Optional JSON string of additional request headers. Credentials placed here ' +
        '(Authorization, Cookie, API keys) are sent only to the origin in `url`; if the ' +
        'endpoint redirects to a different origin they are dropped, not forwarded.',
    ),
    body: z.string().optional().describe('Optional request body for POST/PUT requests'),
    max_payment: z.string().optional().describe(
      'Maximum payment in human-readable format (e.g. "1.00" for 1 USDC). ' +
        'Lowers the operator\'s AGENTWALLET_MAX_AUTOPAY ceiling (default "1") for this one call; ' +
        'it can never raise it, and a value above the ceiling is ignored and reported as max_payment_ignored.',
    ),
    prefer_chain: z.number().int().optional().describe(
      'Preferred chain ID if the server accepts payment on multiple chains ' +
        '(e.g. 8453 for Base, 1 for Ethereum)',
    ),
    request_approval: z.boolean().optional().describe(
      'Hosted wallets only. When the payment exceeds the cap, email the wallet owner an approve/deny link ' +
        'instead of refusing, and return an approval_id to retry with. Default true unless AGENTWALLET_APPROVALS=0.',
    ),
    approval_id: z.string().optional().describe(
      'An approval id from an earlier over-cap attempt. Once the owner has approved it, pass it here to make that one payment.',
    ),
    fresh_authorization: z.boolean().optional().describe(
      'Sign a new authorization even if one for the same endpoint, amount and recipient is still valid. By default a repeat call ' +
        'within the validity window re-sends the earlier signature (same nonce, so it cannot settle twice) instead of paying again.',
    ),
  },
  async ({ url, wallet_id, method, headers: headersJson, body: reqBody, max_payment, prefer_chain, request_approval, approval_id, fresh_authorization }) => {
    // Build request headers
    const reqHeaders: Record<string, string> = { Accept: 'application/json' };
    if (headersJson) {
      let parsed: unknown;
      try { parsed = JSON.parse(headersJson); } catch { parsed = null; }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Invalid headers JSON. Must be a JSON object (e.g. {"Authorization": "Bearer ..."}).');
      }
      for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
        const name = k.toLowerCase();
        // Host would replace the TLS server name; the rest are hop-by-hop or framing headers the client owns.
        if (FORBIDDEN_REQUEST_HEADERS.has(name) || name.startsWith('proxy-') || name.startsWith(':')) {
          throw new Error(`Header "${k}" cannot be set by the caller.`);
        }
        if (typeof v !== 'string') throw new Error(`Header "${k}" must be a string.`);
        reqHeaders[k] = v;
      }
    }

    // Validate URL: canonicalizes IP literals (including IPv4-mapped IPv6) and
    // resolves DNS names, rejecting any private/internal destination. An early
    // check here gives a clear error before any request is built; safeFetch
    // below re-validates every hop and pins each connection to the addresses it
    // validated, so DNS cannot be rebound between the check and the connect.
    await assertPublicUrl(url);

    // Step 1: Make initial request
    const reqOptions: RequestInit = {
      method,
      headers: reqHeaders,
      signal: AbortSignal.timeout(30_000), // 30s timeout
    };
    if (reqBody && method !== 'GET') {
      reqOptions.body = reqBody;
      if (!reqHeaders['Content-Type']) reqHeaders['Content-Type'] = 'application/json';
    }

    const initialRes = await safeFetch(url, reqOptions);

    // If not 402, return the response as-is (no payment needed)
    if (initialRes.status !== 402) {
      const text = await initialRes.text();
      let parsed: unknown;
      try { parsed = JSON.parse(text); } catch { parsed = text; }
      return jsonResponse({
        status: initialRes.status,
        payment_required: false,
        response: parsed,
      });
    }

    // Step 2: Requirements come from the PAYMENT-REQUIRED header (v2) or the JSON body (v1).
    // A 402 that arrived through a cross-origin redirect cannot be paid here: the
    // payment header would be stripped on the same hop and the money would go
    // to whoever the redirecting server named. The agent should call the final URL.
    const servedFrom = finalUrlOf(initialRes, url); // recorded by safeFetch itself, never read from a header the server could set
    if (new URL(servedFrom).origin !== new URL(url).origin) {
      return jsonResponse({ status: 402, payment_required: true, payment_made: false,
        error: `The endpoint redirected to another origin (${new URL(servedFrom).origin}) before asking for payment. Call pay_x402 with that URL directly if you trust it.`,
        final_url: servedFrom });
    }
    const initialText = await initialRes.text();
    let initialBody: unknown = null;
    try { initialBody = JSON.parse(initialText); } catch { initialBody = null; }
    const paymentInfo = parsePaymentRequired(n => initialRes.headers.get(n), initialBody);
    if (!paymentInfo || !Array.isArray(paymentInfo.accepts) || paymentInfo.accepts.length === 0) {
      throw new Error(
        '402 response carried no x402 payment requirements (no PAYMENT-REQUIRED header and no "accepts" array in the body). ' +
        'This server may not support x402.',
      );
    }
    const x402Version = Number(paymentInfo.x402Version) || 1;
    const accepts = paymentInfo.accepts as X402Requirement[];

    // Step 3: Pick an option this client can sign: exact (EIP-3009) first, then a signable upto (Permit2).
    const picked = pickOption(accepts, resolveChainId, prefer_chain);
    if (!picked.option || !picked.chainId) {
      return jsonResponse({
        status: 402,
        payment_required: true,
        payment_made: false,
        error: picked.reason,
        offered: accepts.map(a => ({ scheme: a.scheme, network: a.network, amount: requiredAmount(a), asset: a.asset ?? a.extra?.token ?? null })),
      });
    }
    const option = picked.option;
    const chainId = picked.chainId;
    const isUpto = option.scheme === 'upto';
    const rawAmount = normalizeRawAmount(requiredAmount(option)); // "0010000" and "10000" are one amount

    // Decimals come from the registry or the token contract, NEVER from the 402
    // body. The endpoint controls what it declares, so trusting it would let a
    // hostile server inflate the cap and misreport the amount shown to the agent.
    const tokenAddress = option.asset || option.extra?.token || '';
    const trustedDecimals = tokenAddress
      ? await resolveTrustedDecimals(chainId, tokenAddress)
      : nativeDecimals(chainId); // 18 on EVM (wei), 9 on Solana (lamports)
    if (typeof option.requiredDecimals === 'number') assertDeclaredDecimals(option.requiredDecimals, trustedDecimals);
    const amount = formatUnits(rawAmount, trustedDecimals);
    const tokenLabel = assetLabel(chainId, tokenAddress); // never the 402's own label
    const skip = { 'X-AGW-SKIP-X402': 'true' };
    assertPayTo(chainId, option.payTo);

    // Step 3b: Can this asset be priced at all? The cap is in dollars; native
    // ETH or an arbitrary token is refused unless the operator allowlisted it.
    const assetPolicy = autopayAssetAllowed(chainId, tokenAddress);
    if (!assetPolicy.allowed) {
      return jsonResponse({
        status: 402, payment_required: true, payment_made: false,
        required_amount: amount, token: tokenLabel, token_address: tokenAddress || null, network: option.network, chain_id: chainId, pay_to: option.payTo,
        error: assetPolicy.reason,
      });
    }

    // Step 4: Hard per-payment cap, ALWAYS applied. If the caller omits max_payment
    // we fall back to AGENTWALLET_MAX_AUTOPAY (default "1"). Above the cap a hosted
    // wallet can ask its owner instead of refusing: an approval is created, the
    // owner gets approve/deny links by email, and the agent retries with the id.
    // For upto the cap applies to the MAXIMUM the seller may settle.
    // max_payment can only lower the operator's ceiling; an agent-chosen number
    // above it is ignored and reported, because the agent is what the cap bounds.
    const { cap: effectiveMax, source: capSource, clamped } = effectiveAutopayCap(max_payment);
    let approvalUsed: string | null = null;
    if (!isWithinCap(rawAmount, trustedDecimals, effectiveMax)) {
      const overCap = {
        status: 402, payment_required: true, payment_made: false,
        required_amount: amount, max_allowed: effectiveMax, cap_source: capSource, token: tokenLabel,
        ...(clamped ? { max_payment_ignored: `max_payment ${max_payment} exceeds the operator ceiling AGENTWALLET_MAX_AUTOPAY=${effectiveMax}; only the operator can raise it.` } : {}),
        network: option.network, chain_id: chainId, pay_to: option.payTo, description: option.description,
      };
      const wantApproval = request_approval ?? (process.env.AGENTWALLET_APPROVALS !== '0');
      if (approval_id) {
        // Local mode refuses before any lookup: only the hosted signer can consume
        // an approval, so here the same id would lift the cap on every call.
        const want = { walletId: wallet_id, chainId, asset: tokenAddress, payTo: option.payTo, rawAmount };
        const local = anyLocalMode();
        const a = local ? null : (await api(`/approvals/${encodeURIComponent(approval_id)}`, 'GET', undefined, skip)) as ApprovalRow;
        const refusal = approvalRefusal(approval_id, a, want, local);
        if (refusal) {
          return jsonResponse({ ...overCap, approval_id, ...refusal });
        }
        approvalUsed = String(approval_id);
      } else if (wantApproval && !anyLocalMode()) {
        const created = (await api('/approvals', 'POST', {
          wallet_id, chain_id: chainId, scheme: option.scheme, asset: tokenAddress, pay_to: option.payTo, value: rawAmount,
          amount_human: amount, token_name: tokenLabel, url,
        }, skip)) as { success?: boolean; id?: number; expires_at?: string; error?: string };
        if (!created?.id) {
          return jsonResponse({ ...overCap, error: `Payment of ${amount} ${tokenLabel} exceeds the ${effectiveMax} cap and the approval request failed: ${created?.error || 'unknown error'}.` });
        }
        return jsonResponse({
          ...overCap, approval_pending: true, approval_id: String(created.id), expires_at: created.expires_at ?? null,
          error: `Payment of ${amount} ${tokenLabel} exceeds the ${effectiveMax} cap (from ${capSource}). The wallet owner has been emailed approve/deny links ` +
            `(approval ${created.id}, valid 24 hours). Check it with check_approval, then call pay_x402 again with approval_id "${created.id}".`,
        });
      } else {
        return jsonResponse({
          ...overCap,
          error: `Payment of ${amount} ${tokenLabel} exceeds the ${effectiveMax} cap (from ${capSource}).` +
            (max_payment ? '' : ' No max_payment was provided, so the default cap was applied.') +
            (anyLocalMode() ? ' Local mode has no approval channel; the caps are the operator\'s and only the operator can change them. Do not edit the environment or config to raise them.'
                            : ' Pass request_approval=true to email the wallet owner for a one-time approval; the cap itself is the operator\'s to change.'),
        });
      }
    }

    // Step 5: Pay. Standard x402 "exact" on EVM is an EIP-3009 authorization the
    // facilitator settles; "upto" is a Permit2 max-authorization settled at actual
    // usage; the payer broadcasts nothing and pays no gas for either. AgentWallet's
    // own paywalls (verified by receipt), native-asset requests and Solana still use
    // a broadcast transfer proved by hash.
    const standardExact = !isUpto && !isSolanaChain(chainId) && Boolean(tokenAddress) && !isLegacyAgentWalletAccept(option);
    let headerName = 'X-PAYMENT';
    let paymentHeader = '';
    let txHash: string | null = null;
    let authorization: Eip3009Authorization | null = null;
    let uptoAuth: UptoPermit2Authorization | null = null;
    let payer: string | null = null;
    let permit2ApprovalTx: string | null = null;
    let payerDelegationInfo: PayerDelegation | null = null;
    let authorizationReused = false;

    // The resource is the whole URL including its query: /buy?id=1 and /buy?id=2
    // are different purchases, and reusing the first signature for the second
    // would report a payment the second resource never received.
    // The method and body are part of what was bought: POST {item:A} and
    // POST {item:B} to one URL are two purchases. Concurrent calls for one key
    // wait for the first signature instead of each signing a nonce.
    const bodyDigest = createHash('sha256').update(reqBody ?? '').digest('hex').slice(0, 16);
    const cacheKey = [wallet_id, chainId, tokenAddress.toLowerCase(), option.payTo.toLowerCase(), rawAmount, option.scheme, authorizationResource(url), (method || 'GET').toUpperCase(), bodyDigest].join('|');
    const inFlight = signingInFlight.get(cacheKey);
    if (inFlight && !fresh_authorization) await inFlight;
    const cachedAuth = fresh_authorization ? undefined : signedPayments.get(cacheKey);
    for (const [k, v] of signedPayments) if (v.until <= Date.now()) signedPayments.delete(k);
    let releaseSigning: () => void = () => {};
    if (!(cachedAuth && cachedAuth.until > Date.now())) {
      const mine = new Promise<void>(r => { releaseSigning = r; });
      // Released when the signature is cached, or after 30 s if this call throws first, so a failure never wedges the key.
      signingInFlight.set(cacheKey, Promise.race([mine, new Promise<void>(r => setTimeout(r, 30_000).unref())]));
    }

    if (cachedAuth && cachedAuth.until > Date.now()) {
      // Same endpoint, same requirement, still inside the window: re-send the
      // earlier signature. Its nonce is single-use, so a server that already
      // settled it cannot settle it again, and one that never did now can.
      ({ headerName, paymentHeader, txHash, authorization, uptoAuth, payer } = cachedAuth);
      authorizationReused = true;
    } else if (isUpto) {
      payer = await payerAddress(wallet_id);
      payerDelegationInfo = await payerDelegation(chainId, payer);
      const allowance = decodeUint(await ethCallHex(chainId, tokenAddress, permit2AllowanceCalldata(payer)));
      if (allowance < BigInt(rawAmount)) {
        if (process.env.AGENTWALLET_PERMIT2_AUTO_APPROVE === '1' && assetPolicy.via === 'stablecoin') {
          // Approve exactly this payment's maximum, never unlimited (2026-10-04 audit).
          const r = (await api(`/wallets/${wallet_id}/send`, 'POST', { to: tokenAddress, value: '0', data: permit2ApproveCalldata(rawAmount), chain_id: chainId }, skip)) as { tx_hash?: string };
          permit2ApprovalTx = String(r?.tx_hash || '');
          await new Promise(res => setTimeout(res, 4000));
        } else {
          return jsonResponse({
            status: 402, payment_required: true, payment_made: false, permit2_approval_needed: true,
            token: tokenLabel, token_address: tokenAddress, chain_id: chainId, payer, permit2: PERMIT2_ADDRESS,
            error: `This endpoint uses the x402 "upto" scheme, which settles through Permit2. Wallet ${payer} has not approved ` +
              `${tokenLabel} to Permit2 on chain ${chainId}. Call approve_permit2 once for this token (a normal transaction that needs gas), ` +
              `or set AGENTWALLET_PERMIT2_AUTO_APPROVE=1, then call pay_x402 again.`,
          });
        }
      }
      uptoAuth = buildUptoAuthorization(payer, option);
      const signature = await signPermit2(wallet_id, chainId, uptoAuth, approvalUsed);
      const payload = buildPaymentPayloadRaw(x402Version, option, uptoPayload(uptoAuth, signature), paymentInfo.resource, paymentInfo.extensions);
      const h = paymentHeaderFor(x402Version, payload);
      headerName = h.name;
      paymentHeader = h.value;
    } else if (standardExact) {
      payer = await payerAddress(wallet_id);
      payerDelegationInfo = await payerDelegation(chainId, payer);
      const domain = await resolveTokenDomain(chainId, tokenAddress, option.extra);
      authorization = buildAuthorization(payer, option);
      const signature = await signAuthorization(wallet_id, chainId, tokenAddress, domain, authorization, approvalUsed);
      const payload = buildPaymentPayload(x402Version, option, authorization, signature, paymentInfo.resource, paymentInfo.extensions);
      const h = paymentHeaderFor(x402Version, payload);
      headerName = h.name;
      paymentHeader = h.value;
    } else {
      let txResult: Record<string, unknown>;
      if (isSolanaChain(chainId)) {
        txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', tokenAddress
          ? { to: option.payTo, value: rawAmount, token_mint: tokenAddress, token_decimals: trustedDecimals, chain_id: chainId }
          : { to: option.payTo, value: rawAmount, chain_id: chainId })) as Record<string, unknown>;
      } else if (tokenAddress) {
        const calldata = '0xa9059cbb' + padAddress(option.payTo) + encodeUint256(rawAmount);
        txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', { to: tokenAddress, value: '0', data: calldata, chain_id: chainId })) as Record<string, unknown>;
      } else {
        txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', { to: option.payTo, value: rawAmount, data: '', chain_id: chainId })) as Record<string, unknown>;
      }
      txHash = String(txResult.tx_hash || txResult.signature || '');
      if (!txHash) throw new Error('x402: the payment transaction returned no hash.');
      paymentHeader = Buffer.from(JSON.stringify({ x402Version, scheme: option.scheme, network: option.network, payload: { txHash } })).toString('base64');
    }
    if (!authorizationReused) {
      const until = authorization ? Number(authorization.validBefore) * 1000
        : uptoAuth ? Number(uptoAuth.deadline) * 1000
        : Date.now() + maxAuthWindowSeconds() * 1000; // a broadcast transfer: the hash stays valid, re-sending it never pays twice
      signedPayments.set(cacheKey, { headerName, paymentHeader, txHash, authorization, uptoAuth, payer, until });
    }
    releaseSigning();
    signingInFlight.delete(cacheKey);

    // Step 6: Retry with the payment header and read the settlement receipt.
    const retryHeaders = { ...reqHeaders, [headerName]: paymentHeader };
    const retryOptions: RequestInit = {
      method,
      headers: retryHeaders,
      signal: AbortSignal.timeout(30_000),
    };
    if (reqBody && method !== 'GET') {
      retryOptions.body = reqBody;
    }

    const retryRes = await safeFetch(url, retryOptions);
    const retryText = await retryRes.text();
    let retryParsed: unknown;
    try { retryParsed = JSON.parse(retryText); } catch { retryParsed = retryText; }
    const settlement = parseSettlement(n => retryRes.headers.get(n));
    // A second 402 means the facilitator declined (unfunded payer, expired window, bad domain...). v2 servers
    // put the reason in a fresh PAYMENT-REQUIRED header, v1 servers in the body; surface it instead of {}.
    let retryError: string | null = null;
    const retryServedFrom = finalUrlOf(retryRes, url);
    const retryCrossOrigin = new URL(retryServedFrom).origin !== new URL(url).origin;
    if (retryCrossOrigin) {
      retryError = `The paid request was redirected to another origin (${new URL(retryServedFrom).origin}); the payment header is never forwarded across origins, so this response did not see the payment.`;
    }
    if (retryRes.status === 402) {
      const again = parsePaymentRequired(n => retryRes.headers.get(n), retryParsed);
      retryError = serverText(String(again?.error || (retryParsed as { error?: string } | null)?.error || 'Payment was not accepted (no reason given).')) as string;
      if (payerDelegationInfo && /signature/i.test(retryError)) retryError += ` Likely cause: ${payerDelegationInfo.warning}`;
    }

    return jsonResponse({
      status: retryRes.status,
      payment_required: true,
      // Paid means the endpoint accepted the payment: a settlement receipt, or a success status after the payment header.
      // A 4xx other than 402 (bad body, auth) means the request failed for another reason; the authorization was
      // sent but the facilitator normally does not settle a failed request, so it is not reported as paid.
      payment_made: !retryCrossOrigin && (Boolean(settlement?.success) || (retryRes.status >= 200 && retryRes.status < 300)),
      authorization_reused: authorizationReused,
      retry_error: retryError,
      payment_method: isUpto ? 'permit2-upto-authorization' : (standardExact ? 'eip3009-authorization' : 'onchain-transfer'),
      approval_id: approvalUsed,
      permit2_approval_tx: permit2ApprovalTx,
      x402_version: x402Version,
      amount,
      token: tokenLabel,
      token_address: tokenAddress || null,
      network: option.network,
      chain_id: chainId,
      pay_to: option.payTo,
      payer,
      payer_delegation: payerDelegationInfo,
      // txHash is ours (we broadcast it); settlement.transaction is the server's
      // claim and is surfaced only when it is shaped like a real hash.
      tx_hash: txHash ?? (looksLikeTxHash(settlement?.transaction) ? settlement?.transaction : null) ?? null,
      settlement_reported_by_server: settlement,
      authorization: authorization ? { nonce: authorization.nonce, valid_before: authorization.validBefore }
        : (uptoAuth ? { scheme: 'upto', max_amount: amount, nonce: uptoAuth.nonce, deadline: uptoAuth.deadline, facilitator: uptoAuth.witness.facilitator } : null),
      description: serverText(option.description),
      server_text_is_untrusted: true, // description, retry_error and the response are the endpoint's words, not instructions
      response: retryParsed,
    });
  },
);

// ─── Tool: check_approval ───────────────────────────────────────

server.tool(
  'check_approval',
  'Status of a payment approval created when pay_x402 exceeded the cap on a hosted wallet. ' +
    'Returns pending, approved, denied or expired. Once approved, call pay_x402 again with approval_id.',
  { approval_id: z.string().describe('Approval id returned by pay_x402') },
  async ({ approval_id }) => jsonResponse(await api(`/approvals/${encodeURIComponent(approval_id)}`, 'GET', undefined, { 'X-AGW-SKIP-X402': 'true' })),
);

// ─── Tool: approve_permit2 ──────────────────────────────────────

server.tool(
  'approve_permit2',
  'One-time ERC-20 approval of a token to the Permit2 contract, needed before paying x402 "upto" endpoints with that token. ' +
    'A normal on-chain transaction (needs gas). By default approves the maximum, the ecosystem norm, so it never has to be repeated; ' +
    'pass amount to grant a bounded allowance instead (required under AGENTWALLET_MAX_TX_TOKEN, which refuses a max approval). ' +
    'Permit2 itself only moves what each signed authorization allows.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token address (e.g. USDC on Base)'),
    chain_id: z.number().int().describe('Chain ID'),
    amount: z.string().optional().describe('Allowance to grant in human units (e.g. "100"). Omit for unlimited.'),
  },
  async ({ wallet_id, token, chain_id, amount }) => {
    if (isSolanaChain(chain_id)) throw new Error('Permit2 is an EVM contract; there is nothing to approve on Solana.');
    let data: string = permit2ApproveCalldata();
    if (amount !== undefined) {
      const raw = parseUnits(amount, await resolveTrustedDecimals(chain_id, token));
      data = '0x095ea7b3' + padAddress(PERMIT2_ADDRESS) + encodeUint256(raw);
    }
    const result = (await api(`/wallets/${wallet_id}/send`, 'POST', { to: token, value: '0', data, chain_id })) as Record<string, unknown>;
    return jsonResponse({ ...result, token, spender: PERMIT2_ADDRESS, amount: amount ?? 'unlimited', note: 'Permit2 only transfers what a signed authorization allows; the allowance itself moves nothing.' });
  },
);

// ─── Tool: check_token_risk ─────────────────────────────────────

server.tool(
  'check_token_risk',
  'Assess an ERC-20 token before approving or swapping it: honeypot, taxes, owner powers, verified source, ' +
    'holder concentration, DEX liquidity. Uses GoPlus Security (free, no key) with an on-chain fallback. ' +
    'A warning for the caller to weigh, never a block.',
  {
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token contract address'),
    chain_id: z.number().int().describe('Chain ID'),
  },
  async ({ token, chain_id }) => jsonResponse({ token, chain_id, risk: await assessTokenRisk(chain_id, token, (to, data) => ethCallHex(chain_id, to, data)) }),
);

// ─── Tool: get_usage ─────────────────────────────────────────────

server.tool(
  'get_usage',
  'Get the current month\'s usage statistics. ' +
    'Returns operations count, tier info, remaining quota, and fees.',
  {},
  async () => {
    const data = await api('/usage');
    return jsonResponse(data);
  },
);

// ─── Tool: buy_verification_credits ─────────────────────────────

server.tool(
  'buy_verification_credits',
  'Buy x402 verification credits with USDC on-chain. ' +
    'Paywall owners need credits to process verifications beyond the free tier (1,000/month) ' +
    'when they don\'t have Stripe billing configured. ' +
    'Returns 402 payment instructions — pay on-chain and retry with proof.',
  {
    count: z.number().int().min(100).default(1000)
      .describe('Number of verification credits to purchase (min 100, default 1000)'),
  },
  async ({ count }) => {
    const data = await api('/billing/verification-credits', 'POST', { count });
    return jsonResponse(data);
  },
);

// ─── Tool: pause_wallet ──────────────────────────────────────────

server.tool(
  'pause_wallet',
  'Emergency pause a wallet. No transactions can be signed while paused.',
  {
    wallet_id: z.number().int().describe('Wallet ID to pause'),
  },
  async ({ wallet_id }) => {
    const data = await api(`/wallets/${wallet_id}/pause`, 'POST');
    return jsonResponse(data);
  },
);

// ─── Tool: unpause_wallet ────────────────────────────────────────

server.tool(
  'unpause_wallet',
  'Resume a paused wallet so transactions can be signed again.',
  {
    wallet_id: z.number().int().describe('Wallet ID to unpause'),
  },
  async ({ wallet_id }) => {
    const data = await api(`/wallets/${wallet_id}/unpause`, 'POST');
    return jsonResponse(data);
  },
);

// ─── Tool: get_chains ────────────────────────────────────────────

server.tool(
  'get_chains',
  'List all supported chains (EVM + Solana) with their chain IDs, native tokens, ' +
    'stablecoins, and RPC configuration status.',
  {},
  async () => {
    const data = await api('/chains');
    return jsonResponse(data);
  },
);

// ─── Tool: delete_wallet ─────────────────────────────────────────

server.tool(
  'delete_wallet',
  'Delete (soft-delete) a wallet. The wallet will no longer appear in listings ' +
    'and cannot be used for transactions.',
  {
    wallet_id: z.number().int().describe('Wallet ID to delete'),
  },
  async ({ wallet_id }) => {
    const data = await api(`/wallets/${wallet_id}`, 'DELETE');
    return jsonResponse(data);
  },
);

// ─── Tool: create_paywall ────────────────────────────────────────

server.tool(
  'create_paywall',
  'Create an x402 paywall that charges agents/clients for accessing a resource. ' +
    'Returns a public access URL that returns HTTP 402 until paid. ' +
    'Agents pay on-chain, then retry with proof to get the content.',
  {
    wallet_id: z.number().int().describe('Wallet ID to receive payments'),
    name: z.string().describe('Human-readable paywall name (e.g. "Premium API Access")'),
    description: z.string().default('').describe('Description shown in the 402 response'),
    amount: z.string().describe('Price in human-readable format (e.g. "0.01" for 0.01 USDC)'),
    token_type: z.enum(['erc20', 'spl', 'native']).default('erc20').describe('"erc20" for EVM stablecoins, "spl" for Solana SPL tokens, "native" for ETH/SOL/POL/etc.'),
    token_address: z.string().default('').describe('Token contract address (ERC-20 for EVM, SPL mint Base58 for Solana). Required if token_type is "erc20" or "spl". Use get_chains to find stablecoin addresses.'),
    token_decimals: z.number().int().min(0).max(36).optional().describe('Token decimals. Defaults to the chain native decimals for "native", else 6 (USDC); set it for any other token'),
    token_name: z.string().default('USDC').describe('Token display name (e.g. "USDC", "ETH")'),
    chain_id: z.number().int().default(8453).describe('Chain ID for payments (8453=Base, 1=Ethereum, etc.)'),
    resource_url: z.string().url().describe('URL of the protected resource to serve after payment verification'),
    resource_mime: z.string().default('application/json').describe('MIME type of the resource (e.g. "application/json", "text/plain")'),
  },
  async ({ wallet_id, name, description, amount, token_type, token_address, token_decimals, token_name, chain_id, resource_url, resource_mime }) => {
    // Convert human-readable amount to raw token units. A native paywall used
    // to default to 6 decimals and price 0.01 ETH as 10000 wei.
    if (token_decimals === undefined) token_decimals = token_type === 'native' ? nativeDecimals(chain_id) : (lookupTrustedDecimals(chain_id, token_address) ?? 6);
    const rawAmount = parseUnits(amount, token_decimals);

    const data = await api('/x402/paywalls', 'POST', {
      wallet_id,
      name,
      description,
      amount: rawAmount,
      token_type,
      token_address,
      token_decimals,
      token_name,
      chain_id,
      resource_url,
      resource_mime,
    });

    return jsonResponse({
      ...(data as Record<string, unknown>),
      price: `${amount} ${token_name}`,
      chain_id,
    });
  },
);

// ─── Tool: list_paywalls ────────────────────────────────────────

server.tool(
  'list_paywalls',
  'List all your x402 paywalls. Returns paywall IDs, names, pricing, ' +
    'access URLs, payment counts, and revenue totals.',
  {
    page: z.number().int().default(1).describe('Page number'),
    per_page: z.number().int().min(1).max(100).default(50).describe('Results per page (max 100)'),
  },
  async ({ page, per_page }) => {
    const data = await api(`/x402/paywalls?page=${page}&per_page=${per_page}`);
    return jsonResponse(data);
  },
);

// ─── Tool: get_paywall ──────────────────────────────────────────

server.tool(
  'get_paywall',
  'Get details for a specific x402 paywall by ID. ' +
    'Returns pricing, access URL, payment stats, and configuration.',
  {
    paywall_id: z.number().int().describe('Paywall ID'),
  },
  async ({ paywall_id }) => {
    const data = await api(`/x402/paywalls/${paywall_id}`);
    return jsonResponse(data);
  },
);

// ─── Tool: update_paywall ───────────────────────────────────────

server.tool(
  'update_paywall',
  'Update an x402 paywall configuration. ' +
    'Can change price, resource URL, active status, or any other field.',
  {
    paywall_id: z.number().int().describe('Paywall ID to update'),
    name: z.string().optional().describe('New paywall name'),
    description: z.string().optional().describe('New description'),
    amount: z.string().optional().describe('New price in human-readable format (e.g. "0.05")'),
    token_decimals: z.number().int().min(0).max(36).optional().describe('Token decimals. Read from the paywall itself when omitted'),
    resource_url: z.string().url().optional().describe('New resource URL'),
    resource_mime: z.string().optional().describe('New MIME type'),
    is_active: z.boolean().optional().describe('Enable (true) or disable (false) the paywall'),
  },
  async ({ paywall_id, name, description, amount, token_decimals, resource_url, resource_mime, is_active }) => {
    const body: Record<string, unknown> = {};
    if (name !== undefined) body.name = name;
    if (description !== undefined) body.description = description;
    if (resource_url !== undefined) body.resource_url = resource_url;
    if (resource_mime !== undefined) body.resource_mime = resource_mime;
    if (is_active !== undefined) body.is_active = is_active;

    // Convert human-readable amount to raw if provided
    if (amount !== undefined) {
      let decimals = token_decimals;
      if (decimals === undefined) {
        const existing = (await api(`/x402/paywalls/${paywall_id}`)) as { token_decimals?: number | string };
        const d = Number(existing?.token_decimals);
        if (!Number.isInteger(d) || d < 0 || d > 36) throw new Error('Could not read the paywall decimals; pass token_decimals with the new amount.');
        decimals = d;
      }
      body.amount = parseUnits(amount, decimals);
    }

    const data = await api(`/x402/paywalls/${paywall_id}`, 'PUT', body);
    return jsonResponse(data);
  },
);

// ─── Tool: delete_paywall ───────────────────────────────────────

server.tool(
  'delete_paywall',
  'Delete an x402 paywall. The access URL will return 404 after deletion.',
  {
    paywall_id: z.number().int().describe('Paywall ID to delete'),
  },
  async ({ paywall_id }) => {
    const data = await api(`/x402/paywalls/${paywall_id}`, 'DELETE');
    return jsonResponse(data);
  },
);

// ─── Tool: get_paywall_payments ─────────────────────────────────

server.tool(
  'get_paywall_payments',
  'Get payment history for a specific x402 paywall. ' +
    'Returns verified payments with TX hashes, payer addresses, amounts, and timestamps.',
  {
    paywall_id: z.number().int().describe('Paywall ID'),
    page: z.number().int().default(1).describe('Page number'),
    per_page: z.number().int().min(1).max(100).default(20).describe('Results per page (max 100)'),
  },
  async ({ paywall_id, page, per_page }) => {
    const data = await api(`/x402/paywalls/${paywall_id}/payments?page=${page}&per_page=${per_page}`);
    return jsonResponse(data);
  },
);

// ─── Tool: get_x402_revenue ─────────────────────────────────────

server.tool(
  'get_x402_revenue',
  'Get aggregate x402 revenue statistics across all your paywalls. ' +
    'Returns total payments and revenue broken down by chain and token.',
  {},
  async () => {
    const data = await api('/x402/revenue');
    return jsonResponse(data);
  },
);

// ─── Tool: wallet_mode ──────────────────────────────────────────

server.tool(
  'wallet_mode',
  'Report whether this server is signing locally (self-custody, the private key never leaves this machine) ' +
    'or through the hosted AgentWallet API (custodial). Use this to verify custody before moving funds.',
  {},
  async () => {
    if (!anyLocalMode()) {
      return jsonResponse({
        mode: 'custodial',
        custody: 'agentwallet',
        signing: 'AgentWallet servers hold an encrypted key and sign on your behalf.',
        api_base: redactUrl(API_BASE),
        client_guards: {
          autopay_cap_usd: autopayEnvCap(),
          autopay_assets: (process.env.AGENTWALLET_AUTOPAY_ASSETS || '').trim() || 'registry stablecoins only',
          x402_max_timeout_seconds: maxAuthWindowSeconds(),
          note: 'These bound pay_x402 on hosted wallets too; the hosted signer adds its own pause, daily limit and approval checks.',
        },
        to_self_custody:
          'Set AGENTWALLET_PRIVATE_KEY for EVM and/or AGENTWALLET_SOLANA_KEY for Solana, then restart. ' +
          'Use export_wallet_key first if you want to carry an existing hosted wallet across.',
      });
    }

    const report: Record<string, unknown> = {
      mode: 'local',
      custody: 'self',
      signing: 'Signed in this process. Keys are never sent to AgentWallet or anyone else.',
      max_autopay: process.env.AGENTWALLET_MAX_AUTOPAY || '1',
      autopay_assets: process.env.AGENTWALLET_AUTOPAY_ASSETS || 'registry stablecoins only',
      x402_max_timeout_seconds: maxAuthWindowSeconds(),
      per_tx_cap_token: process.env.AGENTWALLET_MAX_TX_TOKEN || 'not set (ERC-20 and SPL transfers are uncapped)',
      allow_unknown_token_calls: process.env.AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS === '1',
      token_decimals_pins: parseDecimalPins(process.env.AGENTWALLET_TOKEN_DECIMALS).size,
    };

    if (isLocalMode()) {
      let rpc = 'default public endpoint';
      try {
        rpc = resolveRpcUrl(parseInt(process.env.AGENTWALLET_CHAIN_ID || '8453', 10));
      } catch { /* chain has no default; not worth failing the report over */ }
      report.evm = {
        address: getLocalAddress(),
        rpc_endpoint: redactUrl(rpc),
        per_tx_cap_native: process.env.AGENTWALLET_MAX_TX_NATIVE || 'not set',
      };
    } else {
      report.evm = 'no local EVM key. EVM operations are refused, not sent to the hosted signer.';
    }

    if (isSolanaLocalMode()) {
      let rpc = 'default public endpoint';
      try { rpc = resolveSolanaRpc(900); } catch { /* fall through to the default label */ }
      report.solana = {
        address: getSolanaAddress(),
        rpc_endpoint: redactUrl(rpc),
        per_tx_cap_sol: process.env.AGENTWALLET_MAX_TX_SOL || 'not set',
        per_tx_cap_token: process.env.AGENTWALLET_MAX_TX_TOKEN || 'not set (SPL transfers are uncapped; AGENTWALLET_MAX_TX_SOL does not cover them)',
      };
    } else {
      report.solana = 'no local Solana key. Solana operations are refused, not sent to the hosted signer.';
    }

    return jsonResponse(report);
  },
);

// ─── Tool: export_wallet_key ────────────────────────────────────

server.tool(
  'export_wallet_key',
  'Explain how to export the private key of a hosted (custodial) AgentWallet so it can be moved ' +
    'to self-custody or any other wallet. Export itself is deliberately human-gated and is not ' +
    'performed by this tool.',
  {
    wallet_id: z.number().int().optional().describe('Hosted wallet ID to export'),
  },
  async ({ wallet_id }) => {
    if (anyLocalMode()) {
      return jsonResponse({
        exportable: true,
        mode: 'local',
        note:
          'You are already in self-custody. The keys are the ones you supplied via AGENTWALLET_PRIVATE_KEY, ' +
          'AGENTWALLET_SOLANA_KEY or their KEYFILE variants, and this server keeps no copy beyond this process.',
      });
    }

    return jsonResponse({
      exportable: true,
      mode: 'custodial',
      how: `Sign in at ${DASHBOARD_URL} and use Export key on the wallet. ` +
        'The key is shown once and the export is logged.',
      wallet_id: wallet_id ?? 'all wallets are exportable',
      why_not_here:
        'Export is gated behind a browser login rather than the API key on purpose. An API key can ' +
        'spend within your limits; if it could also export keys, a leaked key would mean instant total loss. ' +
        'Your funds stay portable either way: nothing here is locked in.',
      after_export:
        'Set AGENTWALLET_PRIVATE_KEY to the exported key and restart to run non-custodially, ' +
        'or import it into any wallet you like.',
    });
  },
);

// ─── Start ──────────────────────────────────────────────────────

async function main() {
  validateGuardEnv();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  /* stderr, so it never corrupts the stdio JSON-RPC stream. Announcing custody
     at startup means an operator sees which mode they are in without asking. */
  if (anyLocalMode()) {
    try {
      const parts: string[] = [];
      if (isLocalMode()) parts.push(`EVM ${getLocalAddress()}`);
      if (isSolanaLocalMode()) parts.push(`Solana ${getSolanaAddress()}`);
      console.error(`AgentWallet MCP: LOCAL signing mode. ${parts.join(', ')}. Keys never leave this machine.`);
      if (!(process.env.AGENTWALLET_MAX_TX_TOKEN || '').trim()) console.error('AgentWallet MCP: warning, AGENTWALLET_MAX_TX_TOKEN is not set; ERC-20 and SPL transfers have no per-transaction ceiling.');
    } catch (e) {
      console.error(`AgentWallet MCP: local signing configured but a key could not be loaded: ${(e as Error).message}`);
      process.exit(1);
    }
  } else {
    console.error('AgentWallet MCP: custodial mode via ' + redactUrl(API_BASE) + '. Run wallet_mode for details.');
  }
}

main().catch((error) => {
  console.error('AgentWallet MCP server failed to start:', error);
  process.exit(1);
});
