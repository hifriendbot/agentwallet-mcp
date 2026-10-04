/**
 * Regression tests from the 2026-10-04 adversarial audit (pure and mock-RPC cases).
 *
 *  - the decimals probe treats JSON-RPC -32603 and an empty envelope as
 *    "could not ask", not as "the contract reverted" (fail closed)
 *  - Permit2 selectors aimed at an unknown contract are refused; zkSync's
 *    Permit2 is recognised
 *  - an out-of-range private key fails with a fixed message
 *  - network names inherited from Object.prototype are unknown
 *  - amounts are canonicalised; a signed window is never shorter than 60 s
 *  - AGENTWALLET_AUTOPAY_ASSETS entries can be chain-scoped
 *  - an approval's "used" must be exactly 0 or "0"
 *  - Solana: a caller's decimals must match the mint; program-data, buffer
 *    and lookup-table recipients are refused; an occupied token-account
 *    address refuses
 *
 * Run with: node test/audit-1135.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { generatePrivateKey } from 'viem/accounts';
import { Keypair } from '@solana/web3.js';

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`  ok - ${name}`); };
const okAsync = async (name, fn) => { await fn(); passed++; console.log(`  ok - ${name}`); };
const refused = async (name, fn, pattern) => { try { await fn(); } catch (e) { assert.match(e.message, pattern, `${name}: "${e.message}"`); passed++; console.log(`  ok - ${name}`); return; } throw new Error(`${name}: expected a refusal`); };

/* ── pure: x402 policy ─────────────────────────────────────────── */
const { resolveNetworkChainId, normalizeRawAmount, autopayAssetAllowed, approvalRefusal } = await import('../build/x402-payment.js');
const { buildAuthorization, MIN_WINDOW_SECONDS } = await import('../build/x402-eip3009.js');

ok('network names inherited from Object.prototype are unknown', () => {
  for (const n of ['constructor', '__proto__', 'hasownproperty', 'tostring', 'valueof']) assert.strictEqual(resolveNetworkChainId(n), null, n);
  assert.strictEqual(resolveNetworkChainId('base'), 8453);
  assert.strictEqual(resolveNetworkChainId('eip155:56'), 56);
  assert.strictEqual(resolveNetworkChainId('900abc'), null);
  assert.strictEqual(resolveNetworkChainId('0'), null);
});
ok('amounts are canonicalised before keying', () => {
  assert.strictEqual(normalizeRawAmount('0010000'), '10000');
  assert.strictEqual(normalizeRawAmount('10000'), '10000');
  assert.throws(() => normalizeRawAmount('1e3'), /invalid amount/);
});
ok('a 2-second window from the server is floored at 60 s', () => {
  delete process.env.AGENTWALLET_X402_MAX_TIMEOUT;
  const now = 1800000000;
  const a = buildAuthorization('0x0000000000000000000000000000000000000001', { scheme: 'exact', network: 'base', payTo: '0x000000000000000000000000000000000000dEaD', maxAmountRequired: '1', maxTimeoutSeconds: 2 }, now);
  assert.strictEqual(Number(a.validBefore) - now, MIN_WINDOW_SECONDS, String(Number(a.validBefore) - now));
  const b = buildAuthorization('0x0000000000000000000000000000000000000001', { scheme: 'exact', network: 'base', payTo: '0x000000000000000000000000000000000000dEaD', maxAmountRequired: '1', maxTimeoutSeconds: 300 }, now);
  assert.strictEqual(Number(b.validBefore) - now, 300, 'a sane window is honoured as before');
});
ok('allowlist entries can be scoped to a chain', () => {
  const WETH = '0x4200000000000000000000000000000000000006';
  process.env.AGENTWALLET_AUTOPAY_ASSETS = `8453:${WETH}`;
  assert.strictEqual(autopayAssetAllowed(8453, WETH).allowed, true);
  assert.strictEqual(autopayAssetAllowed(56, WETH).allowed, false);
  process.env.AGENTWALLET_AUTOPAY_ASSETS = WETH;
  assert.strictEqual(autopayAssetAllowed(56, WETH).allowed, true, 'a bare entry keeps the old any-chain meaning');
  assert.match(autopayAssetAllowed(56, '0x1111111111111111111111111111111111111111').reason, /Only the operator can change/);
  delete process.env.AGENTWALLET_AUTOPAY_ASSETS;
});
ok('an approval is unused only when used is exactly 0 or "0"', () => {
  const want = { walletId: 1, chainId: 8453, asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: '0x000000000000000000000000000000000000dEaD', rawAmount: '1' };
  const row = (used) => ({ status: 'approved', used, wallet_id: '1', chain_id: '8453', asset: want.asset.toLowerCase(), pay_to: want.payTo.toLowerCase(), value: '1' });
  assert.strictEqual(approvalRefusal('7', row(0), want, false), null);
  assert.strictEqual(approvalRefusal('7', row('0'), want, false), null);
  for (const v of [null, '', '  ', [], false, '0x0', undefined]) assert.ok(approvalRefusal('7', row(v), want, false), JSON.stringify(v));
});

/* ── EVM: key range, decimals probe, Permit2 ───────────────────── */
const rpcQueue = [];
const rpcLog = [];
const rpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const r = JSON.parse(b); rpcLog.push(r.method);
    const send = (payload, raw) => { res.setHeader('content-type', 'application/json'); res.end(raw ?? JSON.stringify({ jsonrpc: '2.0', id: r.id, ...payload })); };
    if (r.method === 'eth_chainId') return send({ result: '0x' + (CHAIN_ID).toString(16) });
    if (r.method === 'eth_call') { const next = rpcQueue.shift(); if (next) return send(next.payload, next.raw); return send({ result: '0x' + '0'.repeat(62) + '06' }); }
    send({ error: { code: -32601, message: `mock: ${r.method} not served` } });
  });
});
await new Promise(r => rpc.listen(0, '127.0.0.1', r));
let CHAIN_ID = 8453;
process.env.AGENTWALLET_RPC_8453 = `http://127.0.0.1:${rpc.address().port}`;
process.env.AGENTWALLET_RPC_324 = `http://127.0.0.1:${rpc.address().port}`;
process.env.AGENTWALLET_MAX_TX_TOKEN = '1';
process.env.AGENTWALLET_PRIVATE_KEY = generatePrivateKey();
const { localSend, classifyDecimalsError, getLocalAccount } = await import('../build/local-wallet.js');

const TOKEN = () => '0x' + Keypair.generate().publicKey.toBuffer().subarray(0, 20).toString('hex'); // a fresh address per case (the probe caches per address)
const BURN = '0x42966c68' + '0'.repeat(63) + '1'; // burn(uint256): calldata the cap cannot price
try {
  ok('classifyDecimalsError: only an explicit revert is "not a token"', () => {
    assert.strictEqual(classifyDecimalsError({ code: 3, message: 'execution reverted' }), 'not-a-token');
    assert.strictEqual(classifyDecimalsError({ code: -32000, message: 'execution reverted' }), 'not-a-token');
    assert.strictEqual(classifyDecimalsError({ code: -32603, message: 'Internal error' }), 'unreachable');
    assert.strictEqual(classifyDecimalsError({ code: -32603, message: 'VM Exception: revert', data: '0x' }), 'not-a-token');
    assert.strictEqual(classifyDecimalsError({ message: 'fetch failed' }), 'unreachable');
  });
  await refused('decimals() answered with JSON-RPC -32603 refuses unpriced calldata', async () => {
    // viem retries an "internal error" a few times before giving up; the node keeps answering it.
    for (let i = 0; i < 6; i++) rpcQueue.push({ payload: { error: { code: -32603, message: 'Internal error' } } });
    await localSend(8453, TOKEN(), 0n, BURN);
    rpcQueue.length = 0;
  }, /could not be reached to classify/);
  await refused('an empty JSON-RPC envelope refuses too', async () => {
    rpcQueue.push({ raw: '{}' });
    await localSend(8453, TOKEN(), 0n, BURN);
  }, /could not be reached to classify/);
  await refused('result "" refuses too', async () => {
    rpcQueue.push({ payload: { result: '' } });
    await localSend(8453, TOKEN(), 0n, BURN);
  }, /could not be reached to classify/);
  await refused('an explicit revert still means "not a token" and the call passes the cap (stops at the nonce fetch)', async () => {
    rpcQueue.push({ payload: { error: { code: 3, message: 'execution reverted' } } });
    await localSend(8453, TOKEN(), 0n, BURN);
  }, /eth_getTransactionCount|not served/);
  await refused("a Permit2 selector aimed at an unknown non-token contract is refused", async () => {
    rpcQueue.push({ payload: { error: { code: 3, message: 'execution reverted' } } });
    await localSend(8453, TOKEN(), 0n, '0x87517c45' + '0'.repeat(64 * 4));
  }, /Permit2 function aimed at/);
  CHAIN_ID = 324;
  await refused("zkSync Era's Permit2 deployment is guarded: approve(max) is refused under the cap", async () => {
    await localSend(324, '0x0000000000225e31D15943971F47aD3022F714Fa', 0n, '0x87517c45' + '0'.repeat(24) + '833589fcd6edb6e08f4c7c32d4f71b54bda02913' + '0'.repeat(24) + 'dead'.repeat(10) + '0'.repeat(24) + 'f'.repeat(40) + '0'.repeat(52) + 'f'.repeat(12));
  }, /AGENTWALLET_MAX_TX_TOKEN|Permit2/);
  CHAIN_ID = 8453;
  ok('an out-of-range private key fails with a fixed message that does not echo the key', () => {
    const bad = 'ff'.repeat(32);
    process.env.AGENTWALLET_PRIVATE_KEY = '0x' + bad;
    // getLocalAccount caches the first account it loads, so the bad key is tried in a fresh process.
    const out = execFileSync(process.execPath, ['-e', `process.env.AGENTWALLET_PRIVATE_KEY='0x${bad}'; import('./build/local-wallet.js').then(m => { try { m.getLocalAccount(); console.log('LOADED'); } catch (e) { console.log(e.message); } })`], { encoding: 'utf8' });
    assert.match(out, /outside the secp256k1 range/);
    assert.ok(!out.includes('115792089') && !out.includes(bad), out);
    process.env.AGENTWALLET_PRIVATE_KEY = generatePrivateKey();
  });
} finally {
  rpc.close();
}

/* ── Solana: decimals, recipients, occupied ATA ────────────────── */
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const SYSTEM = '11111111111111111111111111111111';
const BPF_UPGRADEABLE = 'BPFLoaderUpgradeab1e11111111111111111111111';
const LOOKUP_TABLE = 'AddressLookupTab1e1111111111111111111111111';
const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const fresh = () => Keypair.generate().publicKey.toBase58();
const account = (owner, bytes, executable = false) => ({ data: [Buffer.from(bytes).toString('base64'), 'base64'], executable, lamports: 1461600, owner, rentEpoch: 0, space: bytes.length });
const MINT9 = fresh(), PROGRAM_DATA = fresh(), TABLE = fresh(), WALLET = fresh();
const SOL_ACCOUNTS = {
  [MINT9]: account(TOKEN_PROGRAM, new Uint8Array(82)),
  [PROGRAM_DATA]: account(BPF_UPGRADEABLE, new Uint8Array(500)),
  [TABLE]: account(LOOKUP_TABLE, new Uint8Array(120)),
  [WALLET]: account(SYSTEM, new Uint8Array(0)),
};
let occupyAta = false;
const srpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const { id, method, params } = JSON.parse(b);
    const send = (p) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id, ...p })); };
    if (method === 'getGenesisHash') return send({ result: MAINNET_GENESIS });
    if (method === 'getAccountInfo') {
      const enc = params[1]?.encoding;
      if (params[0] === MINT9 && enc === 'jsonParsed') return send({ result: { context: { slot: 1 }, value: { data: { program: 'spl-token', parsed: { type: 'mint', info: { decimals: 9, supply: '1', isInitialized: true, mintAuthority: null, freezeAuthority: null } }, space: 82 }, executable: false, lamports: 1461600, owner: TOKEN_PROGRAM, rentEpoch: 0, space: 82 } } });
      if (SOL_ACCOUNTS[params[0]]) return send({ result: { context: { slot: 1 }, value: SOL_ACCOUNTS[params[0]] } });
      if (occupyAta) return send({ result: { context: { slot: 1 }, value: account(SYSTEM, new Uint8Array(0)) } }); // whatever else is asked for (the ATA) is a plain account
      return send({ result: { context: { slot: 1 }, value: null } });
    }
    if (method === 'getMinimumBalanceForRentExemption') return send({ result: (128 + params[0]) * 6960 });
    send({ error: { code: -32601, message: `mock: ${method} not served` } });
  });
});
await new Promise(r => srpc.listen(0, '127.0.0.1', r));
process.env.AGENTWALLET_SOLANA_KEY = JSON.stringify(Array.from(Keypair.generate().secretKey));
process.env.AGENTWALLET_SOLANA_RPC_900 = `http://127.0.0.1:${srpc.address().port}`;
delete process.env.AGENTWALLET_MAX_TX_TOKEN;
const { localSplTransfer, localSolTransfer, mintDecimalsStrict } = await import('../build/local-solana.js');
try {
  await okAsync('mintDecimalsStrict reads the mint', async () => { assert.strictEqual(await mintDecimalsStrict(MINT9, 900), 9); });
  await refused('a caller decimals of 12 on a 9-decimal mint refuses instead of being substituted', () => localSplTransfer(MINT9, fresh(), '1000000000000', 12, 900), /decimals 12 was passed but mint .* has 9 decimals/);
  await refused('a caller decimals of 6 on a 9-decimal mint refuses', () => localSplTransfer(MINT9, fresh(), '1000000', 6, 900), /decimals 6 was passed/);
  await refused('SPL send to a program-data account is refused', () => localSplTransfer(MINT9, PROGRAM_DATA, '1', 9, 900), /owned by program BPFLoaderUpgradeab1e/);
  await refused('SPL send to an address lookup table is refused', () => localSplTransfer(MINT9, TABLE, '1', 9, 900), /owned by program AddressLookupTab1e/);
  await refused('native SOL to a program-data account is refused', () => localSolTransfer(PROGRAM_DATA, '1', 900), /owned by program/);
  // 1.13.5 refused this; 1.13.6 corrects it: the associated-account program creates into a pre-funded system account (see audit-1136).
  await refused('a plain SOL-holding account at the token-account address is created into (stops at the blockhash)', async () => { occupyAta = true; try { await localSplTransfer(MINT9, WALLET, '1', 9, 900); } finally { occupyAta = false; } }, /not served|blockhash/i);
  await refused('a system-owned wallet still passes the guard (stops at the blockhash the mock does not serve)', () => localSplTransfer(MINT9, WALLET, '1', 9, 900), /not served|blockhash/i);
} finally {
  srpc.close();
}

console.log(`\naudit-1135: ${passed} passed`);
