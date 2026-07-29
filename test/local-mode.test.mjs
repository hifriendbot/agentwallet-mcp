/**
 * Local (non-custodial) mode end-to-end test.
 *
 * The point of these tests is not that the code runs. It is that the custody
 * claim is true. Every case here runs with AGENTWALLET_API_URL pointed at a
 * closed port, so if any funds path still reached for the hosted API the call
 * would fail loudly instead of passing quietly.
 *
 * Run: node test/local-mode.test.mjs
 */

import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { Keypair } from '@solana/web3.js';

/* Well-known throwaway key from the go-ethereum docs. Never used for funds. */
const TEST_KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const TEST_ADDRESS = '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23';
const DEAD_API = 'http://127.0.0.1:1'; // nothing listens here, by design

let passed = 0;
let failed = 0;

function check(name, fn) {
  try {
    fn();
    console.log(`  PASS  ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL  ${name}\n        ${e.message}`);
    failed++;
  }
}

/** Drive the server over stdio JSON-RPC, the same way a real MCP client does. */
function callTools(calls, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['build/index.js'], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => { err += d.toString(); });

    const send = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');

    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' },
    }});
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    calls.forEach((c, i) => send({ jsonrpc: '2.0', id: 100 + i, method: 'tools/call', params: c }));

    setTimeout(() => {
      child.kill();
      const responses = out.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      resolve({ responses, stderr: err });
    }, 12000);

    child.on('error', reject);
  });
}

const textOf = (resp) => {
  const c = resp?.result?.content?.[0]?.text;
  return c ? JSON.parse(c) : null;
};

console.log('\nLocal mode, with the hosted API pointed at a closed port\n');

const local = await callTools(
  [
    { name: 'wallet_mode', arguments: {} },
    { name: 'get_balance', arguments: { wallet_id: 1, chain_id: 8453 } },
    { name: 'list_wallets', arguments: {} },
    { name: 'get_token_balance', arguments: { wallet_id: 1, chain_id: 8453, token: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', decimals: 6 } },
    { name: 'export_wallet_key', arguments: {} },
    { name: 'transfer', arguments: { wallet_id: 1, to: TEST_ADDRESS, amount: '0.001', chain_id: 900 } },
  ],
  { AGENTWALLET_PRIVATE_KEY: TEST_KEY, AGENTWALLET_API_URL: DEAD_API },
);

const byId = (id) => local.responses.find((r) => r.id === id);

check('startup announces local mode on stderr', () => {
  assert.match(local.stderr, /LOCAL signing mode/);
  assert.match(local.stderr, new RegExp(TEST_ADDRESS));
});

check('wallet_mode reports self-custody and the right address', () => {
  const m = textOf(byId(100));
  assert.equal(m.mode, 'local');
  assert.equal(m.custody, 'self');
  assert.equal(m.evm.address, TEST_ADDRESS);
  assert.match(String(m.solana), /no local Solana key/);
});

check('native balance reads without touching the hosted API', () => {
  const b = textOf(byId(101));
  assert.equal(b.mode, 'local');
  assert.equal(b.address, TEST_ADDRESS);
  assert.ok(typeof b.balance_wei === 'string');
});

check('list_wallets returns the local key, not a server list', () => {
  const w = textOf(byId(102));
  assert.equal(w.wallets[0].custody, 'self');
  assert.equal(w.wallets[0].address, TEST_ADDRESS);
});

check('ERC-20 balance reads locally (proves ABI + RPC path)', () => {
  const t = textOf(byId(103));
  assert.equal(t.mode, 'local');
  assert.equal(t.symbol, 'USDC');
  assert.equal(t.decimals, 6);
});

check('export_wallet_key says you already hold the key', () => {
  const e = textOf(byId(104));
  assert.equal(e.mode, 'local');
  assert.equal(e.exportable, true);
});

check('Solana with no Solana key is refused, not sent to the custodial API', () => {
  const text = JSON.stringify(byId(105));
  assert.match(text, /no local Solana key is configured|Refusing/i);
});

console.log('\nSolana local mode, same closed-port conditions\n');

/* Deterministic throwaway keypair: seed of 32 bytes, all 0x07. Never funded. */
const solKp = Keypair.fromSeed(new Uint8Array(32).fill(7));
const SOL_SECRET = { key: JSON.stringify(Array.from(solKp.secretKey)), address: solKp.publicKey.toBase58() };

const sol = await callTools(
  [
    { name: 'wallet_mode', arguments: {} },
    { name: 'get_balance', arguments: { wallet_id: 1, chain_id: 900 } },
    { name: 'list_wallets', arguments: {} },
    { name: 'transfer', arguments: { wallet_id: 1, to: SOL_SECRET.address, amount: '0.001', chain_id: 1 } },
  ],
  { AGENTWALLET_SOLANA_KEY: SOL_SECRET.key, AGENTWALLET_PRIVATE_KEY: '', AGENTWALLET_API_URL: DEAD_API },
);

const solById = (id) => sol.responses.find((r) => r.id === id);

check('Solana key loads and is announced at startup', () => {
  assert.match(sol.stderr, /LOCAL signing mode/);
  assert.match(sol.stderr, new RegExp(SOL_SECRET.address));
});

check('wallet_mode reports the Solana address and no EVM key', () => {
  const m = textOf(solById(100));
  assert.equal(m.mode, 'local');
  assert.equal(m.solana.address, SOL_SECRET.address);
  assert.match(String(m.evm), /no local EVM key/);
});

check('SOL balance reads without the hosted API', () => {
  const b = textOf(solById(101));
  assert.equal(b.mode, 'local');
  assert.equal(b.address, SOL_SECRET.address);
  assert.ok(typeof b.balance_lamports === 'string');
});

check('list_wallets shows the Solana key only', () => {
  const w = textOf(solById(102));
  assert.equal(w.wallets.length, 1);
  assert.equal(w.wallets[0].wallet_type, 'solana');
});

check('EVM op with only a Solana key is refused, not sent to the hosted signer', () => {
  const text = JSON.stringify(solById(103));
  assert.match(text, /no local EVM key is configured|Refusing/i);
});

console.log('\nCustodial mode still behaves as before\n');

const custodial = await callTools(
  [{ name: 'wallet_mode', arguments: {} }],
  { AGENTWALLET_PRIVATE_KEY: '', AGENTWALLET_KEYFILE: '', AGENTWALLET_API_URL: DEAD_API },
);

check('custodial mode is reported when no key is set', () => {
  const m = textOf(custodial.responses.find((r) => r.id === 100));
  assert.equal(m.mode, 'custodial');
  assert.equal(m.custody, 'agentwallet');
});

check('custodial startup line names the API base', () => {
  assert.match(custodial.stderr, /custodial mode via/);
});

console.log('\nKey handling\n');

const badKey = await callTools(
  [{ name: 'wallet_mode', arguments: {} }],
  { AGENTWALLET_PRIVATE_KEY: 'not-a-key', AGENTWALLET_API_URL: DEAD_API },
);

check('an invalid key fails fast and never echoes the value', () => {
  assert.match(badKey.stderr, /Invalid private key|could not be loaded/);
  assert.doesNotMatch(badKey.stderr, /not-a-key/);
});

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
