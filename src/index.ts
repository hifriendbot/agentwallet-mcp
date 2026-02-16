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

// ─── API Helper ─────────────────────────────────────────────────

async function api(path: string, method = 'GET', body?: Record<string, unknown>): Promise<unknown> {
  const url = `${API_BASE}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Add basic auth if credentials provided
  if (API_USER && API_PASS) {
    headers['Authorization'] = 'Basic ' + Buffer.from(`${API_USER}:${API_PASS}`).toString('base64');
  }

  const options: RequestInit = { method, headers };
  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(url, options);
  const data = await res.json();

  if (!res.ok) {
    const error = (data as { error?: string }).error || `HTTP ${res.status}`;
    throw new Error(error);
  }

  return data;
}

function jsonResponse(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
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

const server = new McpServer({
  name: 'agentwallet',
  version: '1.2.0',
});

// ─── Tool: create_wallet ─────────────────────────────────────────

server.tool(
  'create_wallet',
  'Create a new EVM wallet. Returns the wallet ID and address. ' +
    'Private key is encrypted server-side and never exposed.',
  {
    label: z.string().default('').describe('Friendly name for the wallet'),
    chain_id: z.number().int().default(8453).describe('Default chain ID (1=Ethereum, 8453=Base, 42161=Arbitrum, 10=Optimism, 137=Polygon, 43114=Avalanche, 56=BSC, 7777777=Zora, 369=PulseChain)'),
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
    'Returns balance in both wei and human-readable format.',
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
  'Sign an EVM transaction with a wallet\'s private key. ' +
    'Returns the signed raw transaction hex (ready for manual broadcast). ' +
    'Does NOT broadcast — use send_transaction for sign + broadcast.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    to: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Destination address'),
    chain_id: z.number().int().optional().describe('Chain ID (defaults to wallet\'s default)'),
    value: z.string().default('0').describe('Value in wei (decimal string)'),
    data: z.string().default('').describe('Hex-encoded calldata (0x-prefixed) for contract calls'),
    gas_limit: z.string().optional().describe('Gas limit (auto-estimated if omitted)'),
    max_fee: z.string().optional().describe('Max fee per gas in wei (auto if omitted)'),
    priority_fee: z.string().optional().describe('Max priority fee per gas in wei (auto if omitted)'),
  },
  async ({ wallet_id, to, chain_id, value, data, gas_limit, max_fee, priority_fee }) => {
    const body: Record<string, unknown> = { to, value, data };
    if (chain_id) body.chain_id = chain_id;
    if (gas_limit) body.gas_limit = gas_limit;
    if (max_fee) body.max_fee = max_fee;
    if (priority_fee) body.priority_fee = priority_fee;

    const result = await api(`/wallets/${wallet_id}/sign`, 'POST', body);
    return jsonResponse(result);
  },
);

// ─── Tool: send_transaction ──────────────────────────────────────

server.tool(
  'send_transaction',
  'Sign and broadcast an EVM transaction. ' +
    'Returns the transaction hash on success. ' +
    'The transaction is signed server-side and broadcast via RPC.',
  {
    wallet_id: z.number().int().describe('Wallet ID'),
    to: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Destination address'),
    chain_id: z.number().int().optional().describe('Chain ID (defaults to wallet\'s default)'),
    value: z.string().default('0').describe('Value in wei (decimal string)'),
    data: z.string().default('').describe('Hex-encoded calldata (0x-prefixed) for contract calls'),
    gas_limit: z.string().optional().describe('Gas limit (auto-estimated if omitted)'),
    max_fee: z.string().optional().describe('Max fee per gas in wei (auto if omitted)'),
    priority_fee: z.string().optional().describe('Max priority fee per gas in wei (auto if omitted)'),
  },
  async ({ wallet_id, to, chain_id, value, data, gas_limit, max_fee, priority_fee }) => {
    const body: Record<string, unknown> = { to, value, data };
    if (chain_id) body.chain_id = chain_id;
    if (gas_limit) body.gas_limit = gas_limit;
    if (max_fee) body.max_fee = max_fee;
    if (priority_fee) body.priority_fee = priority_fee;

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', body);
    return jsonResponse(result);
  },
);

// ─── Tool: transfer ─────────────────────────────────────────────

server.tool(
  'transfer',
  'Send native tokens (ETH, AVAX, BNB, POL, PLS) to an address. ' +
    'Specify the amount in human-readable format (e.g. "0.1" for 0.1 ETH). ' +
    'The amount is converted to wei automatically. Signs and broadcasts the transaction.',
  {
    wallet_id: z.number().int().describe('Wallet ID to send from'),
    to: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Destination address'),
    amount: z.string().describe('Amount to send in human-readable format (e.g. "0.1" for 0.1 ETH)'),
    chain_id: z.number().int().describe('Chain ID (1=Ethereum, 8453=Base, 42161=Arbitrum, 10=Optimism, 137=Polygon, 43114=Avalanche, 56=BSC, 7777777=Zora, 369=PulseChain)'),
  },
  async ({ wallet_id, to, amount, chain_id }) => {
    // Convert human-readable to wei (18 decimals for all native tokens)
    const valueWei = parseUnits(amount, 18);

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', {
      to,
      value: valueWei,
      chain_id,
      data: '',
    });

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
  'Get the ERC-20 token balance for a wallet on a specific chain. ' +
    'Returns the raw balance and human-readable balance. ' +
    'Use get_chains to find stablecoin addresses for each chain.',
  {
    wallet_id: z.number().int().describe('Wallet ID to check'),
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token contract address'),
    chain_id: z.number().int().describe('Chain ID to check on'),
    decimals: z.number().int().default(18).describe('Token decimals (6 for USDC, 18 for most tokens)'),
  },
  async ({ wallet_id, token, chain_id, decimals }) => {
    const params = `?chain_id=${chain_id}&token=${token}`;
    const data = await api(`/wallets/${wallet_id}/token-balance${params}`) as { balance_raw: string };

    const balanceFormatted = formatUnits(data.balance_raw, decimals);

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
  'Send ERC-20 tokens (USDC, USDT, etc.) to an address. ' +
    'Specify the amount in human-readable format (e.g. "100" for 100 USDC). ' +
    'Signs and broadcasts the transaction. Use get_chains to find stablecoin addresses.',
  {
    wallet_id: z.number().int().describe('Wallet ID to send from'),
    token: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('ERC-20 token contract address'),
    to: z.string().regex(/^0x[a-fA-F0-9]{40}$/).describe('Recipient address'),
    amount: z.string().describe('Amount in human-readable format (e.g. "100" for 100 USDC)'),
    chain_id: z.number().int().describe('Chain ID'),
    decimals: z.number().int().default(18).describe('Token decimals (6 for USDC, 18 for most tokens)'),
  },
  async ({ wallet_id, token, to, amount, chain_id, decimals }) => {
    // Encode ERC-20 transfer(address, uint256) calldata
    const rawAmount = parseUnits(amount, decimals);
    const calldata = '0xa9059cbb' + padAddress(to) + encodeUint256(rawAmount);

    const result = await api(`/wallets/${wallet_id}/send`, 'POST', {
      to: token,       // Send TX to the token contract
      value: '0',      // No native value for token transfers
      data: calldata,
      chain_id,
    });

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
  'List all supported EVM chains with their chain IDs, native tokens, ' +
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

// ─── Start ──────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error('AgentWallet MCP server failed to start:', error);
  process.exit(1);
});
