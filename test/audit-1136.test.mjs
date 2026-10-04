/**
 * Regression tests from round 2 of the 2026-10-04 adversarial audit.
 *
 *  - NFT approval/transfer selectors are refused on a target that declines decimals()
 *  - payment_made follows the HTTP status and a server-reported failure
 *  - the tx-hash receipt flow is for the API host (and listed origins) only
 *  - accepts entries that are not requirements are dropped, not thrown on
 *  - a 0X-prefixed registry address is still the registry asset
 *  - non-EIP-3009 stablecoins are not "exact"-eligible
 *  - Permit2 address is per chain in the upto signer helpers
 *  - a pre-funded system account at the token-account address is created into
 *
 * Run with: node test/audit-1136.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { generatePrivateKey } from 'viem/accounts';
import { Keypair } from '@solana/web3.js';

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`  ok - ${name}`); };
const refused = async (name, fn, pattern) => { try { await fn(); } catch (e) { assert.match(e.message, pattern, `${name}: "${e.message}"`); passed++; console.log(`  ok - ${name}`); return; } throw new Error(`${name}: expected a refusal`); };

const { settlementVerdict, legacyReceiptAllowed, parsePaymentRequired, sanitizeRequired } = await import('../build/x402-eip3009.js');
const { assetSupportsExact, isStableAsset, lookupTrustedDecimals } = await import('../build/x402-payment.js');
const { permit2Address, permit2ApproveCalldata, permit2AllowanceCalldata } = await import('../build/x402-permit2.js');

ok('payment_made: a 402 on the paid retry is never "paid", whatever the settlement header says', () => {
  assert.deepStrictEqual(settlementVerdict(402, { success: true, transaction: '0x' + '44'.repeat(32) }, false), { payment_made: false, outcome: 'refused' });
  assert.deepStrictEqual(settlementVerdict(500, { success: true }, false), { payment_made: false, outcome: 'refused' });
  assert.deepStrictEqual(settlementVerdict(200, { success: false, errorReason: 'settlement_failed' }, false), { payment_made: false, outcome: 'server_reports_failure' });
  assert.deepStrictEqual(settlementVerdict(200, { success: 'true' }, false), { payment_made: true, outcome: 'paid' });
  assert.deepStrictEqual(settlementVerdict(200, null, false), { payment_made: true, outcome: 'paid' });
  assert.deepStrictEqual(settlementVerdict(200, { success: true }, true), { payment_made: false, outcome: 'not_delivered' });
});
ok('legacy receipt flow: API host and listed origins only', () => {
  const api = 'https://hifriendbot.com/wp-json/agentwallet/v1';
  assert.strictEqual(legacyReceiptAllowed('https://hifriendbot.com/x/paywall', api, undefined), true);
  assert.strictEqual(legacyReceiptAllowed('https://attacker.example/x', api, undefined), false);
  assert.strictEqual(legacyReceiptAllowed('https://shop.example/x', api, 'https://shop.example, https://other.example'), true);
  assert.strictEqual(legacyReceiptAllowed('not a url', api, undefined), false);
});
ok('accepts entries that are not requirements are dropped', () => {
  const r = parsePaymentRequired(() => null, { x402Version: 1, accepts: [null, 5, 'x', { scheme: 'exact', network: 'base', payTo: ['0x1'], maxAmountRequired: '5' }, { scheme: 'exact', network: 'base', payTo: '0x000000000000000000000000000000000000dEaD', maxAmountRequired: 10000, extra: { token: ['0x'], name: 'USD Coin' } }] });
  assert.strictEqual(r.accepts.length, 1);
  assert.strictEqual(r.accepts[0].maxAmountRequired, '10000');
  assert.deepStrictEqual(r.accepts[0].extra, { name: 'USD Coin' });
  const big = sanitizeRequired({ accepts: Array.from({ length: 500 }, () => ({ scheme: 'exact', network: 'base', payTo: '0x000000000000000000000000000000000000dEaD' })) });
  assert.strictEqual(big.accepts.length, 64);
});
ok('a 0X-prefixed registry address is still the registry asset', () => {
  const usdc = '0X833589fcd6edb6e08f4c7c32d4f71b54bda02913';
  assert.strictEqual(isStableAsset(8453, usdc), true);
  assert.strictEqual(lookupTrustedDecimals(8453, usdc), 6);
});
ok('USDT, DAI and USDbC are not exact-eligible; USDC is', () => {
  assert.strictEqual(assetSupportsExact(1, '0xdac17f958d2ee523a2206206994597c13d831ec7'), false);
  assert.strictEqual(assetSupportsExact(1, '0x6b175474e89094c44da98b954eedeac495271d0f'), false);
  assert.strictEqual(assetSupportsExact(8453, '0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca'), false);
  assert.strictEqual(assetSupportsExact(8453, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'), true);
  assert.strictEqual(assetSupportsExact(8453, '0x1111111111111111111111111111111111111111'), true, 'unknown assets are not refused here');
});
ok('Permit2 is per chain in the upto helpers', () => {
  assert.strictEqual(permit2Address(324).toLowerCase(), '0x0000000000225e31d15943971f47ad3022f714fa');
  assert.strictEqual(permit2Address(8453).toLowerCase(), '0x000000000022d473030f116ddee9f6b43ac78ba3');
  assert.ok(permit2ApproveCalldata('5', 324).includes('225e31d15943971f47ad3022f714fa'));
  assert.ok(permit2AllowanceCalldata('0x000000000000000000000000000000000000dEaD', 324).includes('225e31d15943971f47ad3022f714fa'));
  assert.throws(() => permit2ApproveCalldata('-1'), /not a uint256/);
  assert.throws(() => permit2ApproveCalldata((1n << 256n).toString()), /not a uint256/);
});

/* ── EVM: NFT selectors ───────────────────────────────────────── */
const rpcQueue = [];
const rpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const r = JSON.parse(b);
    const send = (payload) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: r.id, ...payload })); };
    if (r.method === 'eth_chainId') return send({ result: '0x2105' });
    if (r.method === 'eth_call') { const next = rpcQueue.shift(); return send(next ?? { error: { code: 3, message: 'execution reverted' } }); }
    send({ error: { code: -32601, message: `mock: ${r.method} not served` } });
  });
});
await new Promise(r => rpc.listen(0, '127.0.0.1', r));
process.env.AGENTWALLET_RPC_8453 = `http://127.0.0.1:${rpc.address().port}`;
process.env.AGENTWALLET_MAX_TX_TOKEN = '1';
process.env.AGENTWALLET_PRIVATE_KEY = generatePrivateKey();
const { localSend } = await import('../build/local-wallet.js');
const fresh20 = () => '0x' + Keypair.generate().publicKey.toBuffer().subarray(0, 20).toString('hex');
const ATT = '0'.repeat(24) + 'dead'.repeat(10);
try {
  await refused('setApprovalForAll to a collection that declines decimals() is refused', () => localSend(8453, fresh20(), 0n, '0xa22cb465' + ATT + '0'.repeat(63) + '1'), /NFT approval or transfer/);
  await refused('ERC-721 safeTransferFrom is refused', () => localSend(8453, fresh20(), 0n, '0x42842e0e' + ATT + ATT + '0'.repeat(63) + '1'), /NFT approval or transfer/);
  await refused('ERC-1155 safeTransferFrom is refused', () => localSend(8453, fresh20(), 0n, '0xf242432a' + ATT + ATT + '0'.repeat(64 * 3)), /NFT approval or transfer/);
  await refused('an unrelated selector on a non-token still passes the cap (stops at the nonce fetch)', () => localSend(8453, fresh20(), 0n, '0x12345678' + ATT), /eth_getTransactionCount|not served/);
} finally { rpc.close(); }

/* ── Solana: pre-funded ATA address ───────────────────────────── */
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const SYSTEM = '11111111111111111111111111111111';
const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const fresh = () => Keypair.generate().publicKey.toBase58();
const account = (owner, bytes, lamports = 1461600) => ({ data: [Buffer.from(bytes).toString('base64'), 'base64'], executable: false, lamports, owner, rentEpoch: 0, space: bytes.length });
const MINT = fresh(), WALLET = fresh();
let ataMode = 'empty';
const rentSizes = [];
const srpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const { id, method, params } = JSON.parse(b);
    const send = (p) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id, ...p })); };
    if (method === 'getGenesisHash') return send({ result: MAINNET_GENESIS });
    if (method === 'getAccountInfo') {
      if (params[0] === MINT && params[1]?.encoding === 'jsonParsed') return send({ result: { context: { slot: 1 }, value: { data: { program: 'spl-token', parsed: { type: 'mint', info: { decimals: 6, supply: '1', isInitialized: true, mintAuthority: null, freezeAuthority: null } }, space: 82 }, executable: false, lamports: 1461600, owner: TOKEN_PROGRAM, rentEpoch: 0, space: 82 } } });
      if (params[0] === MINT) return send({ result: { context: { slot: 1 }, value: account(TOKEN_PROGRAM, new Uint8Array(82)) } });
      if (params[0] === WALLET) return send({ result: { context: { slot: 1 }, value: account(SYSTEM, new Uint8Array(0)) } });
      if (ataMode === 'prefunded') return send({ result: { context: { slot: 1 }, value: account(SYSTEM, new Uint8Array(0), 890880) } });
      if (ataMode === 'foreign') return send({ result: { context: { slot: 1 }, value: account('Stake11111111111111111111111111111111111111', new Uint8Array(200)) } });
      return send({ result: { context: { slot: 1 }, value: null } });
    }
    if (method === 'getMinimumBalanceForRentExemption') { rentSizes.push(params[0]); return send({ result: (128 + params[0]) * 6960 }); }
    send({ error: { code: -32601, message: `mock: ${method} not served` } });
  });
});
await new Promise(r => srpc.listen(0, '127.0.0.1', r));
process.env.AGENTWALLET_SOLANA_KEY = JSON.stringify(Array.from(Keypair.generate().secretKey));
process.env.AGENTWALLET_SOLANA_RPC_900 = `http://127.0.0.1:${srpc.address().port}`;
delete process.env.AGENTWALLET_MAX_TX_TOKEN;
const { localSplTransfer } = await import('../build/local-solana.js');
try {
  ataMode = 'prefunded';
  await refused('a pre-funded system account at the token-account address is created into (stops at the blockhash)', () => localSplTransfer(MINT, WALLET, '1', 6, 900), /not served|blockhash/i);
  ok('the rent was asked for the real account size', () => { assert.deepStrictEqual(rentSizes, [165]); });
  // Since 1.13.10 the full rent is charged even for a pre-funded address: the node's lamports claim is not trusted (round 4).
  ataMode = 'prefunded'; process.env.AGENTWALLET_MAX_TX_SOL = '0.0015';
  await refused('the full rent is charged against the cap even when the node says the address is pre-funded', () => localSplTransfer(MINT, WALLET, '1', 6, 900), /exceeds AGENTWALLET_MAX_TX_SOL/);
  delete process.env.AGENTWALLET_MAX_TX_SOL;
  ataMode = 'foreign';
  await refused('an address occupied by another program still refuses', () => localSplTransfer(MINT, WALLET, '1', 6, 900), /occupied by an account owned by Stake/);
} finally { srpc.close(); }

console.log(`\naudit-1136: ${passed} passed`);
