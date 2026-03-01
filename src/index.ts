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

// ─── Configuration ──────────────────────────────────────────────

const API_BASE = process.env.AGENTWALLET_API_URL || 'https://hifriendbot.com/wp-json/agentwallet/v1';
const API_USER = process.env.AGENTWALLET_USER || '';
const API_PASS = process.env.AGENTWALLET_PASS || '';  // WordPress application password
const X402_WALLET_ID = process.env.AGENTWALLET_WALLET_ID || '';  // Wallet ID for x402 auto-pay

// ─── API Helper ─────────────────────────────────────────────────

interface X402Accept {
  scheme: string;
  maxAmountRequired: string;
  payTo: string;
  network: string;
  requiredDecimals: number;
  extra?: { token?: string; name?: string };
}

interface X402Response {
  x402Version: number;
  accepts: X402Accept[];
  error: string;
}

/**
 * Make an API call. If the response is 402 and auto-pay is configured,
 * automatically pay via x402 and retry the request.
 */
async function api(path: string, method = 'GET', body?: Record<string, unknown>, extraHeaders?: Record<string, string>): Promise<unknown> {
  const url = `${API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...extraHeaders,
  };

  if (API_USER && API_PASS) {
    headers['Authorization'] = 'Basic ' + Buffer.from(`${API_USER}:${API_PASS}`).toString('base64');
  }

  const options: RequestInit = { method, headers };
  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(url, options);
  const data = await res.json();

  // Handle 402 Payment Required — auto-pay if wallet configured
  if (res.status === 402 && X402_WALLET_ID && !extraHeaders?.['X-PAYMENT']) {
    return handleX402Payment(data as X402Response, path, method, body);
  }

  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(error);
  }

  return data;
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

  const accept = accepts[0]; // Use first option
  const tokenAddress = accept.extra?.token || '';
  const amount = accept.maxAmountRequired;
  const payTo = accept.payTo;
  const decimals = accept.requiredDecimals || 6;

  // Determine chain_id from network string (CAIP-2, plain name, or raw ID)
  const network = accept.network || '';
  const chainId = resolveChainId(network) ?? 8453;

  // Convert human-readable amount to raw (e.g. "0.01" with 6 decimals = "10000")
  const rawAmount = parseUnits(amount, decimals);

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

const SOLANA_CHAIN_IDS = new Set([900, 901, 902]);

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
  const fracPadded = frac.slice(0, decimals).padEnd(decimals, '0');
  const raw = BigInt(whole + fracPadded);
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
  return address.slice(2).toLowerCase().padStart(64, '0');
}

/**
 * Encode a uint256 as 32 bytes hex (64 chars).
 */
function encodeUint256(value: string): string {
  const hex = BigInt(value).toString(16);
  return hex.padStart(64, '0');
}

// ─── Server ──────────────────────────────────────────────────────

// ─── x402 Network Mapping ──────────────────────────────────────

const X402_NETWORKS: Record<string, number> = {
  'ethereum': 1,
  'base': 8453,
  'base-sepolia': 84532,
  'polygon': 137,
  'arbitrum': 42161,
  'optimism': 10,
  'bsc': 56,
  'avalanche': 43114,
  'zora': 7777777,
  'pulsechain': 369,
  'solana': 900,
  'solana-devnet': 901,
};

// Solana genesis hash prefixes for CAIP-2
const SOLANA_GENESIS: Record<number, string> = {
  900: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',  // mainnet-beta
  901: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1',  // devnet
};

/**
 * Resolve an x402 network identifier to a chain ID.
 * Supports plain names ("base"), CAIP-2 format ("eip155:8453"), and raw chain IDs ("8453").
 */
function resolveChainId(network: string): number | null {
  const lower = network.toLowerCase();
  if (X402_NETWORKS[lower]) return X402_NETWORKS[lower];
  const caipMatch = network.match(/^eip155:(\d+)$/);
  if (caipMatch) return parseInt(caipMatch[1], 10);
  // Solana CAIP-2: solana:<genesis_prefix>
  const solanaMatch = network.match(/^solana:(.+)$/);
  if (solanaMatch) {
    for (const [chainId, genesis] of Object.entries(SOLANA_GENESIS)) {
      if (solanaMatch[1] === genesis) return parseInt(chainId, 10);
    }
  }
  const num = parseInt(network, 10);
  if (!isNaN(num) && num > 0) return num;
  return null;
}

// ─── Server ──────────────────────────────────────────────────────

const server = new McpServer({
  name: 'agentwallet',
  version: '1.7.0',
});

// ─── Tool: create_wallet ─────────────────────────────────────────

server.tool(
  'create_wallet',
  'Create a new EVM or Solana wallet. Returns the wallet ID and address. ' +
    'Private key is encrypted server-side and never exposed.',
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
    to: z.string().describe('Destination address (0x-prefixed for EVM, Base58 for Solana)'),
    chain_id: z.number().int().optional().describe('Chain ID (defaults to wallet\'s default)'),
    value: z.string().default('0').describe('Value in wei/lamports (decimal string)'),
    data: z.string().default('').describe('Hex-encoded calldata (0x-prefixed) for EVM contract calls'),
    gas_limit: z.string().optional().describe('Gas limit — EVM only (auto-estimated if omitted)'),
    max_fee: z.string().optional().describe('Max fee per gas in wei — EVM only (auto if omitted)'),
    priority_fee: z.string().optional().describe('Max priority fee per gas in wei — EVM only (auto if omitted)'),
    token_mint: z.string().optional().describe('SPL token mint address — Solana only (for SPL token transfers)'),
    token_decimals: z.number().int().optional().describe('SPL token decimals — Solana only (6 for USDC)'),
  },
  async ({ wallet_id, to, chain_id, value, data, gas_limit, max_fee, priority_fee, token_mint, token_decimals }) => {
    // Validate address format
    if (!isValidAddress(to)) {
      throw new Error(`Invalid address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const body: Record<string, unknown> = { to, value };
    if (chain_id) body.chain_id = chain_id;

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
    'The transaction is signed server-side and broadcast via RPC.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    to: z.string().describe('Destination address (0x-prefixed for EVM, Base58 for Solana)'),
    chain_id: z.number().int().optional().describe('Chain ID (defaults to wallet\'s default)'),
    value: z.string().default('0').describe('Value in wei/lamports (decimal string)'),
    data: z.string().default('').describe('Hex-encoded calldata (0x-prefixed) for EVM contract calls'),
    gas_limit: z.string().optional().describe('Gas limit — EVM only (auto-estimated if omitted)'),
    max_fee: z.string().optional().describe('Max fee per gas in wei — EVM only (auto if omitted)'),
    priority_fee: z.string().optional().describe('Max priority fee per gas in wei — EVM only (auto if omitted)'),
    token_mint: z.string().optional().describe('SPL token mint address — Solana only (for SPL token transfers)'),
    token_decimals: z.number().int().optional().describe('SPL token decimals — Solana only (6 for USDC)'),
  },
  async ({ wallet_id, to, chain_id, value, data, gas_limit, max_fee, priority_fee, token_mint, token_decimals }) => {
    // Validate address format
    if (!isValidAddress(to)) {
      throw new Error(`Invalid address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const body: Record<string, unknown> = { to, value };
    if (chain_id) body.chain_id = chain_id;

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
    to: z.string().describe('Destination address (0x-prefixed for EVM, Base58 for Solana)'),
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
    decimals: z.number().int().default(18).describe('Token decimals (6 for USDC, 18 for most tokens)'),
  },
  async ({ wallet_id, token, chain_id, decimals }) => {
    // Validate token address format
    if (!isValidAddress(token)) {
      throw new Error(`Invalid token address "${token}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

    const params = `?chain_id=${chain_id}&token=${token}`;
    const data = await api(`/wallets/${wallet_id}/token-balance${params}`) as { balance_raw?: string; balance_formatted?: string; decimals?: number };

    // Solana API returns balance_formatted + decimals directly
    if (isSolanaChain(chain_id) && data.balance_formatted !== undefined) {
      return jsonResponse({
        ...data,
        balance: data.balance_formatted,
        decimals: data.decimals ?? decimals,
      });
    }

    // EVM: format from raw
    const balanceFormatted = formatUnits(data.balance_raw || '0', decimals);

    return jsonResponse({
      ...data,
      balance: balanceFormatted,
      decimals,
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
    to: z.string().describe('Recipient address (0x-prefixed for EVM, Base58 for Solana)'),
    amount: z.string().describe('Amount in human-readable format (e.g. "100" for 100 USDC)'),
    chain_id: z.number().int().describe('Chain ID'),
    decimals: z.number().int().default(18).describe('Token decimals (6 for USDC, 18 for most tokens)'),
  },
  async ({ wallet_id, token, to, amount, chain_id, decimals }) => {
    // Validate addresses
    if (!isValidAddress(token)) {
      throw new Error(`Invalid token address "${token}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }
    if (!isValidAddress(to)) {
      throw new Error(`Invalid recipient address "${to}". Use 0x-prefixed hex for EVM or Base58 for Solana.`);
    }

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
    decimals: z.number().int().default(18).describe('Token decimals (6 for USDC, 18 for most tokens)'),
  },
  async ({ wallet_id, token, spender, amount, chain_id, decimals }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('approve_token is not supported on Solana. Solana SPL tokens do not use ERC-20 style approvals.');
    }
    // approve(address spender, uint256 amount) — selector: 0x095ea7b3
    let rawAmount: string;
    if (amount.toLowerCase() === 'max') {
      rawAmount = (BigInt(2) ** BigInt(256) - BigInt(1)).toString();
    } else {
      rawAmount = parseUnits(amount, decimals);
    }
    const calldata = '0x095ea7b3' + padAddress(spender) + encodeUint256(rawAmount);

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
    decimals: z.number().int().default(18).describe('Token decimals (6 for USDC, 18 for most tokens)'),
  },
  async ({ wallet_id, token, spender, chain_id, decimals }) => {
    if (isSolanaChain(chain_id)) {
      throw new Error('get_allowance is not supported on Solana. Solana SPL tokens do not use ERC-20 style allowances.');
    }
    // First get the wallet address
    const wallet = await api(`/wallets/${wallet_id}`) as { address: string };

    // allowance(address owner, address spender) — selector: 0xdd62ed3e
    const calldata = '0xdd62ed3e' + padAddress(wallet.address) + padAddress(spender);

    const result = await api('/eth-call', 'POST', { chain_id, to: token, data: calldata }) as { result: string };

    // Parse uint256 result
    const rawHex = result.result.replace('0x', '');
    const raw = BigInt('0x' + (rawHex || '0')).toString();
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

const WRAPPED_NATIVE: Record<number, { address: string; symbol: string }> = {
  1:       { address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', symbol: 'WETH' },
  8453:    { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' },
  42161:   { address: '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', symbol: 'WETH' },
  10:      { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' },
  137:     { address: '0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270', symbol: 'WPOL' },
  56:      { address: '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', symbol: 'WBNB' },
  43114:   { address: '0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7', symbol: 'WAVAX' },
  7777777: { address: '0x4200000000000000000000000000000000000006', symbol: 'WETH' },
  369:     { address: '0xA1077a294dDE1B09bB078844df40758a5D0f9a27', symbol: 'WPLS' },
};

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
    return new TextDecoder().decode(bytes);
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
    const decimalsHex = decimalsResult.result.replace('0x', '');
    const decimals = decimalsHex ? parseInt(decimalsHex, 16) : 0;

    return jsonResponse({
      token,
      chain_id,
      name: name || 'Unknown',
      symbol: symbol || 'Unknown',
      decimals,
    });
  },
);

// ─── Tool: pay_x402 ─────────────────────────────────────────────

server.tool(
  'pay_x402',
  'Handle an x402 payment flow. Fetches a URL, and if the server returns HTTP 402 Payment Required, ' +
    'parses the payment requirements, executes the on-chain payment, and retries the request with ' +
    'proof of payment. Returns the final response. Supports the x402 open payment standard ' +
    '(https://x402.org). Set max_payment to prevent overspending.',
  {
    url: z.string().url().describe('The URL to access (will handle 402 payment if required)'),
    wallet_id: z.number().int().describe('Wallet ID to pay from'),
    method: z.string().default('GET').describe('HTTP method (GET, POST, PUT, DELETE)'),
    headers: z.string().optional().describe('Optional JSON string of additional request headers'),
    body: z.string().optional().describe('Optional request body for POST/PUT requests'),
    max_payment: z.string().optional().describe(
      'Maximum payment in human-readable format (e.g. "1.00" for 1 USDC). ' +
        'Rejects payments above this amount. Strongly recommended to prevent overspending.',
    ),
    prefer_chain: z.number().int().optional().describe(
      'Preferred chain ID if the server accepts payment on multiple chains ' +
        '(e.g. 8453 for Base, 1 for Ethereum)',
    ),
  },
  async ({ url, wallet_id, method, headers: headersJson, body: reqBody, max_payment, prefer_chain }) => {
    // Build request headers
    const reqHeaders: Record<string, string> = { Accept: 'application/json' };
    if (headersJson) {
      try {
        Object.assign(reqHeaders, JSON.parse(headersJson));
      } catch {
        throw new Error('Invalid headers JSON. Must be a JSON object (e.g. {"Authorization": "Bearer ..."}).');
      }
    }

    // Validate URL — block private IPs and cloud metadata endpoints
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '[::1]', '169.254.169.254', 'metadata.google.internal'];
    const blockedPrefixes = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
      '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
      '172.30.', '172.31.', '192.168.'];
    if (blockedHosts.includes(hostname) || blockedPrefixes.some(p => hostname.startsWith(p))) {
      throw new Error('URL points to a private/internal address. Only public URLs are allowed.');
    }
    if (urlObj.protocol !== 'https:') {
      throw new Error('Only HTTPS URLs are supported for x402 payments.');
    }

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

    const initialRes = await fetch(url, reqOptions);

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

    // Step 2: Parse x402 payment requirements from 402 response
    let paymentInfo: { x402Version?: number; accepts?: Array<Record<string, unknown>> };
    try {
      paymentInfo = await initialRes.json() as typeof paymentInfo;
    } catch {
      throw new Error('402 response body is not valid JSON. This server may not support x402.');
    }

    if (!paymentInfo.accepts || paymentInfo.accepts.length === 0) {
      throw new Error('402 response has no payment options in "accepts" array.');
    }

    // Step 3: Pick the best payment option
    type PaymentOption = {
      scheme: string; network: string; maxAmountRequired: string;
      payTo: string; requiredDecimals: number; description?: string;
      extra?: { name?: string; token?: string };
    };
    const options = paymentInfo.accepts as PaymentOption[];

    let option: PaymentOption;
    if (prefer_chain) {
      option = options.find(a => resolveChainId(a.network) === prefer_chain) || options[0];
    } else {
      option = options[0];
    }

    // Resolve the chain
    const chainId = resolveChainId(option.network);
    if (!chainId) {
      throw new Error(
        `Unsupported x402 network: "${option.network}". ` +
          `Supported: ${Object.keys(X402_NETWORKS).join(', ')}, or any CAIP-2 / numeric chain ID.`,
      );
    }

    // Calculate human-readable amount
    const amount = formatUnits(option.maxAmountRequired, option.requiredDecimals);

    // Step 4: Check spending limit
    if (max_payment) {
      const maxRaw = parseUnits(max_payment, option.requiredDecimals);
      if (BigInt(option.maxAmountRequired) > BigInt(maxRaw)) {
        return jsonResponse({
          status: 402,
          payment_required: true,
          payment_made: false,
          error: `Payment of ${amount} ${option.extra?.name || 'tokens'} exceeds your max_payment limit of ${max_payment}`,
          required_amount: amount,
          max_allowed: max_payment,
          token: option.extra?.name || 'native',
          network: option.network,
          chain_id: chainId,
          pay_to: option.payTo,
          description: option.description,
        });
      }
    }

    // Step 5: Execute payment
    let txResult: Record<string, unknown>;

    if (isSolanaChain(chainId)) {
      // Solana payment
      if (option.extra?.token) {
        // SPL token payment (e.g. USDC on Solana)
        txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', {
          to: option.payTo,
          value: option.maxAmountRequired,
          token_mint: option.extra.token,
          token_decimals: option.requiredDecimals,
          chain_id: chainId,
        })) as Record<string, unknown>;
      } else {
        // Native SOL payment
        txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', {
          to: option.payTo,
          value: option.maxAmountRequired,
          chain_id: chainId,
        })) as Record<string, unknown>;
      }
    } else if (option.extra?.token) {
      // EVM ERC-20 token payment (e.g. USDC)
      const calldata = '0xa9059cbb' + padAddress(option.payTo) + encodeUint256(option.maxAmountRequired);
      txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', {
        to: option.extra.token,
        value: '0',
        data: calldata,
        chain_id: chainId,
      })) as Record<string, unknown>;
    } else {
      // EVM native token payment (ETH, etc.)
      txResult = (await api(`/wallets/${wallet_id}/send`, 'POST', {
        to: option.payTo,
        value: option.maxAmountRequired,
        data: '',
        chain_id: chainId,
      })) as Record<string, unknown>;
    }

    // Solana returns 'signature', EVM returns 'tx_hash'
    const txHash = (txResult.tx_hash || txResult.signature) as string;

    // Step 6: Build x402 payment proof and retry
    const paymentProof = {
      x402Version: paymentInfo.x402Version || 1,
      scheme: option.scheme,
      network: option.network,
      payload: { txHash },
    };
    const paymentHeader = Buffer.from(JSON.stringify(paymentProof)).toString('base64');

    const retryHeaders = { ...reqHeaders, 'X-PAYMENT': paymentHeader };
    const retryOptions: RequestInit = {
      method,
      headers: retryHeaders,
      signal: AbortSignal.timeout(30_000),
    };
    if (reqBody && method !== 'GET') {
      retryOptions.body = reqBody;
    }

    const retryRes = await fetch(url, retryOptions);
    const retryText = await retryRes.text();
    let retryParsed: unknown;
    try { retryParsed = JSON.parse(retryText); } catch { retryParsed = retryText; }

    return jsonResponse({
      status: retryRes.status,
      payment_required: true,
      payment_made: true,
      amount,
      token: option.extra?.name || 'native',
      token_address: option.extra?.token || null,
      network: option.network,
      chain_id: chainId,
      pay_to: option.payTo,
      tx_hash: txHash,
      description: option.description,
      response: retryParsed,
    });
  },
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
    token_decimals: z.number().int().default(6).describe('Token decimals (6 for USDC, 18 for ETH/most tokens)'),
    token_name: z.string().default('USDC').describe('Token display name (e.g. "USDC", "ETH")'),
    chain_id: z.number().int().default(8453).describe('Chain ID for payments (8453=Base, 1=Ethereum, etc.)'),
    resource_url: z.string().url().describe('URL of the protected resource to serve after payment verification'),
    resource_mime: z.string().default('application/json').describe('MIME type of the resource (e.g. "application/json", "text/plain")'),
  },
  async ({ wallet_id, name, description, amount, token_type, token_address, token_decimals, token_name, chain_id, resource_url, resource_mime }) => {
    // Convert human-readable amount to raw token units
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
    per_page: z.number().int().default(50).describe('Results per page (max 100)'),
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
    token_decimals: z.number().int().optional().describe('Token decimals (needed if changing amount)'),
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
      const decimals = token_decimals ?? 6; // Default to USDC decimals
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
    per_page: z.number().int().default(20).describe('Results per page (max 100)'),
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

// ─── Start ──────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error('AgentWallet MCP server failed to start:', error);
  process.exit(1);
});
