/**
 * 1.14.0 Spend Policy: the policy file, the hash-chained ledger and its
 * budgets, the encrypted keyfile, x402 discovery, and the new tools over the
 * real stdio protocol with the hosted API pointed at a closed port.
 *
 * Run: node test/spend-policy.test.mjs
 */
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, appendFileSync, utimesSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';

const {
  parsePolicy, hostMatches, hostAllowed, recipientAllowed, targetAllowed, assetAllowed, toolAllowed, perHostRule, units, human, rawToUnits, loadPolicy, needsLedger,
} = await import('../build/policy.js');
const { Ledger } = await import('../build/ledger.js');
const { encryptKeyfile, decryptKeyfile, isEncryptedKeyfile, keyfilePassphrase, openKeyfile } = await import('../build/keyfile.js');
const { summarize, matches, discover } = await import('../build/discovery.js');

let passed = 0;
let failed = 0;
const check = (name, fn) => { try { fn(); passed++; console.log(`  PASS  ${name}`); } catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); } };
const checkAsync = async (name, fn) => { try { await fn(); passed++; console.log(`  PASS  ${name}`); } catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); } };

const dir = mkdtempSync(join(tmpdir(), 'agw-policy-'));
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const DEAD_API = 'http://127.0.0.1:1';
const DEAD_RPC = 'http://127.0.0.1:1';
const TEST_KEY = generatePrivateKey();
const TEST_ADDRESS = privateKeyToAccount(TEST_KEY).address;
const DEAD = '0x000000000000000000000000000000000000dEaD';
const OTHER = '0x1111111111111111111111111111111111111111';

console.log('\nPolicy parsing and matching\n');

check('a valid policy parses', () => {
  const p = parsePolicy(JSON.stringify({ version: 1, budget: { daily: '5', monthly: '50' }, hosts: { allow: ['api.example.com', '*.paid.example'] }, approval: { above: '0.5', max: '20' } }));
  assert.equal(p.budget.daily, '5');
});
check('an unknown key is refused (a misspelled budget must not run unbounded)', () => {
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, budgets: { daily: '5' } })), /Unrecognized key|budgets/);
});
check('a non-decimal budget is refused', () => {
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, budget: { daily: '5 USD' } })), /budget\.daily/);
});
check('an empty allow list is refused rather than refusing everything silently', () => {
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, hosts: { allow: [] } })), /hosts\.allow/);
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, recipients: { allow: [] } })), /recipients\.allow/);
});
check('approval.max below approval.above is refused', () => {
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, approval: { above: '5', max: '1' } })), /approval\.max/);
});
check('tools allow and deny together are refused', () => {
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, tools: { allow: ['pay_x402'], deny: ['transfer'] } })), /tools/);
});
check('host patterns: exact and wildcard subdomains only', () => {
  assert.equal(hostMatches('api.example.com', 'API.example.com'), true);
  assert.equal(hostMatches('*.example.com', 'api.example.com'), true);
  assert.equal(hostMatches('*.example.com', 'a.b.example.com'), true);
  assert.equal(hostMatches('*.example.com', 'example.com'), false, 'the apex is not a subdomain');
  assert.equal(hostMatches('*.example.com', 'notexample.com'), false);
});
check('deny beats allow; allow list closes everything else', () => {
  const p = { version: 1, hosts: { allow: ['*.example.com'], deny: ['evil.example.com'] } };
  assert.equal(hostAllowed(p, 'api.example.com').ok, true);
  assert.equal(hostAllowed(p, 'evil.example.com').ok, false);
  assert.equal(hostAllowed(p, 'other.org').ok, false);
  assert.equal(hostAllowed({ version: 1 }, 'anything.org').ok, true);
});
check('recipients: EVM compares case-insensitively, Solana exactly; contract targets see the deny list only', () => {
  const p = { version: 1, recipients: { allow: [DEAD.toLowerCase()], deny: [OTHER] } };
  assert.equal(recipientAllowed(p, DEAD).ok, true);
  assert.equal(recipientAllowed(p, OTHER).ok, false);
  assert.equal(recipientAllowed(p, '0x2222222222222222222222222222222222222222').ok, false);
  assert.equal(targetAllowed(p, '0x2222222222222222222222222222222222222222').ok, true);
  assert.equal(targetAllowed(p, OTHER).ok, false);
});
check('assets: chain-scoped and bare entries, native by name', () => {
  const p = { version: 1, assets: { allow: ['8453:' + USDC_BASE, 'native'] } };
  assert.equal(assetAllowed(p, 8453, USDC_BASE.toLowerCase()).ok, true);
  assert.equal(assetAllowed(p, 1, USDC_BASE).ok, false);
  assert.equal(assetAllowed(p, 8453, '').ok, true);
  assert.equal(assetAllowed(p, 8453, OTHER).ok, false);
});
check('tool allow and deny lists', () => {
  assert.equal(toolAllowed({ version: 1, tools: { allow: ['pay_x402'] } }, 'transfer'), false);
  assert.equal(toolAllowed({ version: 1, tools: { deny: ['transfer'] } }, 'transfer'), false);
  assert.equal(toolAllowed({ version: 1, tools: { deny: ['transfer'] } }, 'pay_x402'), true);
});
check('per_host rule lookup follows the same matching', () => {
  const p = { version: 1, per_host: { '*.example.com': { daily: '1', per_payment: '0.1' } } };
  assert.equal(perHostRule(p, 'api.example.com').per_payment, '0.1');
  assert.equal(perHostRule(p, 'example.com'), null);
});
check('fixed-point arithmetic: "1.50" and "1.5" agree, raw amounts scale by decimals', () => {
  assert.equal(units('1.50'), units('1.5'));
  assert.equal(human(units('0.000001')), '0.000001');
  assert.equal(human(rawToUnits('1000000', 6)), '1');
  assert.equal(human(rawToUnits('1500000000000000000', 18)), '1.5');
  assert.throws(() => units('1e3'), /Not a decimal/);
});
check('loadPolicy: no env means an empty policy; a budget needs a ledger next to the file', () => {
  const lp = loadPolicy({});
  assert.equal(lp.path, null);
  assert.equal(needsLedger({ version: 1, budget: { daily: '1' } }), true);
  assert.equal(needsLedger({ version: 1, hosts: { deny: ['x.com'] } }), false);
  const f = join(dir, 'p1.json');
  writeFileSync(f, JSON.stringify({ version: 1, budget: { daily: '1' } }));
  const l2 = loadPolicy({ AGENTWALLET_POLICY: f });
  assert.match(l2.ledgerPath, /agentwallet-ledger\.jsonl$/);
  assert.equal(l2.hash.length, 64);
  assert.equal(loadPolicy({ AGENTWALLET_POLICY: f, AGENTWALLET_LEDGER: join(dir, 'x.jsonl') }).ledgerPath, join(dir, 'x.jsonl'));
});

console.log('\nLedger: budgets, voids, chain integrity\n');

const spend = (over = {}) => ({ tool: 'pay_x402', mode: 'local', wallet: 'local', chainId: 8453, asset: USDC_BASE, assetLabel: 'USDC', raw: '2000000', decimals: 6, usd: '2', to: DEAD, host: 'api.example.com', resource: 'https://api.example.com/x', method: 'eip3009', ...over });
const limits = (over = {}) => ({ usd: { daily: '5', monthly: '50' }, native: undefined, host: null, unpriced: 'refuse', ...over });

const ledgerPath = join(dir, 'ledger.jsonl');
const L = new Ledger(ledgerPath);
check('a reservation under budget is written; the sums reflect it', () => {
  const seq = L.reserve(spend(), limits());
  assert.equal(seq, 1);
  assert.equal(human(L.spentUsd().daily), '2');
  assert.ok(existsSync(ledgerPath));
});
check('the daily budget bounds the SUM: a third 2-dollar spend under a 5-dollar day is refused', () => {
  L.reserve(spend(), limits());
  assert.throws(() => L.reserve(spend(), limits()), /daily budget of 5 would be exceeded: 4 already spent.*1 remaining/);
  assert.equal(L.check(spend({ raw: '1000000', usd: '1' }), limits()).ok, true, 'exactly the remainder fits');
});
check('a voided reservation gives the budget back', () => {
  L.void(2, 'signing failed in the test');
  assert.equal(human(L.spentUsd().daily), '2');
  assert.equal(L.check(spend(), limits()).ok, true);
});
check('per-host ceilings use the host sums', () => {
  const r = L.check(spend(), limits({ host: { pattern: 'api.example.com', daily: '3' } }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /per_host\["api.example.com"\] daily budget of 3/);
  assert.equal(L.check(spend({ host: 'other.example.com' }), limits({ host: { pattern: 'other.example.com', daily: '3' } })).ok, true);
});
check('an unpriced asset is refused under a budget unless the policy allows it, and never counted', () => {
  const r = L.check(spend({ asset: OTHER, assetLabel: OTHER, usd: null }), limits());
  assert.equal(r.ok, false);
  assert.match(r.reason, /not a registry stablecoin/);
  assert.equal(L.check(spend({ asset: OTHER, assetLabel: OTHER, usd: null }), limits({ unpriced: 'allow' })).ok, true);
});
check('native budgets are per chain in the coin\'s units', () => {
  const n = spend({ asset: '', assetLabel: 'ETH', raw: '20000000000000000', decimals: 18, usd: null });
  assert.equal(L.check(n, limits({ native: { daily: '0.01' } })).ok, false);
  assert.equal(L.check(n, limits({ native: { daily: '0.05' } })).ok, true);
});
check('settle folds the outcome into list_payments and the CSV export quotes safely', () => {
  L.settle(1, 'settled', 'ok');
  const rows = L.payments({ limit: 10 });
  assert.equal(rows[0].seq, 2);
  assert.equal(rows[0].outcome, 'void');
  assert.equal(rows[1].outcome, 'settled');
  const csv = L.csv();
  assert.match(csv.split('\r\n')[0], /^seq,ts,tool/);
  const L2 = new Ledger(join(dir, 'csv.jsonl'));
  L2.reserve(spend({ resource: '=HYPERLINK("x"),"y' }), limits());
  assert.match(L2.csv(), /"'=HYPERLINK\(""x""\),""y"/);
});
check('the chain survives a reload and refuses after tampering', () => {
  const again = new Ledger(ledgerPath);
  assert.equal(again.integrity, null);
  assert.equal(again.size(), L.size());
  assert.equal(human(again.spentUsd().daily), '2');
  const lines = readFileSync(ledgerPath, 'utf8').trim().split('\n');
  const e = JSON.parse(lines[0]);
  e.usd = '0.01'; // make the first spend look smaller
  writeFileSync(ledgerPath, [JSON.stringify(e), ...lines.slice(1)].join('\n') + '\n');
  const broken = new Ledger(ledgerPath);
  assert.match(broken.integrity, /chain broken at line 1/);
  const r = broken.check(spend(), limits());
  assert.equal(r.ok, false);
  assert.match(r.reason, /not intact/);
  assert.throws(() => broken.reserve(spend(), limits()), /not intact/);
});
check('windows roll: a spend 25 hours old is out of the day but in the month', () => {
  const p = join(dir, 'old.jsonl');
  const old = new Ledger(p);
  old.reserve(spend(), limits());
  const line = JSON.parse(readFileSync(p, 'utf8').trim());
  const now = Date.parse(line.ts) + 25 * 3600 * 1000;
  assert.equal(human(old.spentUsd(now).daily), '0');
  assert.equal(human(old.spentUsd(now).monthly), '2');
});

console.log('\n1.14.2: one budget across every process sharing the ledger (reported 2026-10-14)\n');

const sixty = () => spend({ raw: '600000', usd: '0.6' });
const oneDollar = () => limits({ usd: { total: '1' } });
check('two ledgers opened on one empty file before either spent: the second sees the first\'s spend and refuses the last dollar', () => {
  const p = join(dir, 'shared.jsonl');
  const A = new Ledger(p);
  const B = new Ledger(p);
  assert.equal(A.reserve(sixty(), oneDollar()), 1);
  assert.throws(() => B.reserve(sixty(), oneDollar()), /lifetime budget of 1 would be exceeded: 0\.6 already spent/);
  assert.equal(B.reserve(spend({ raw: '400000', usd: '0.4' }), oneDollar()), 2, 'the remainder fits and chains onto seq 1');
  assert.throws(() => A.reserve(spend({ raw: '10000', usd: '0.01' }), oneDollar()), /0 remaining/);
  assert.equal(human(A.spentUsd().total), '1');
  const fresh = new Ledger(p);
  assert.equal(fresh.integrity, null, 'no fork: one chain, two writers');
  assert.equal(fresh.size(), 2);
  assert.ok(!existsSync(p + '.lock'), 'the lock is released');
  B.void(2, 'the other process gave it back');
  assert.equal(A.check(spend({ raw: '400000', usd: '0.4' }), oneDollar()).ok, true, 'a void by one process is seen by the other');
});
check('a ledger file rewritten underneath a live process is refused, never forked', () => {
  const p = join(dir, 'rewritten.jsonl');
  const A = new Ledger(p);
  A.reserve(spend(), limits());
  writeFileSync(p, '');
  assert.throws(() => A.reserve(spend(), limits()), /rewritten underneath this process/);
  assert.match(A.integrity, /rewritten underneath/);
  assert.equal(A.check(spend(), limits()).ok, false);
});
check('a lock left by a dead process is cleared; a live lock is waited for, then refused with nothing signed', () => {
  const p = join(dir, 'locked.jsonl');
  const A = new Ledger(p, null, { lockWaitMs: 300 });
  writeFileSync(p + '.lock', '1 dead');
  const old = (Date.now() - 120_000) / 1000;
  utimesSync(p + '.lock', old, old);
  assert.equal(A.reserve(spend(), limits()), 1, 'a stale lock does not block');
  writeFileSync(p + '.lock', `${process.pid} live`);
  const t0 = Date.now();
  assert.throws(() => A.reserve(spend(), limits()), /locked by another agentwallet-mcp process .*Nothing was signed/);
  assert.ok(Date.now() - t0 >= 250, 'it waited for the lock');
  assert.equal(new Ledger(p).size(), 1, 'nothing was written while locked');
  unlinkSync(p + '.lock');
  assert.equal(A.reserve(spend(), limits()), 2);
});
await checkAsync('two OS processes released at the same instant: exactly one fits the last dollar and the chain stays intact', async () => {
  const p = join(dir, 'race.jsonl');
  const script = join(dir, 'race-child.mjs');
  writeFileSync(script, [
    `import { Ledger } from ${JSON.stringify(new URL('../build/ledger.js', import.meta.url).href)};`,
    `const L = new Ledger(process.argv[2]);`,
    `process.stdout.write('ready\\n');`,
    `process.stdin.once('data', () => {`,
    `  try { const seq = L.reserve(${JSON.stringify(sixty())}, ${JSON.stringify(oneDollar())}); console.log('RESERVED ' + seq); }`,
    `  catch (e) { console.log('REFUSED ' + e.message); }`,
    `  process.exit(0);`,
    `});`,
  ].join('\n'));
  const children = [0, 1].map(() => spawn(process.execPath, [script, p], { stdio: ['pipe', 'pipe', 'pipe'] }));
  const outs = ['', ''];
  const ready = children.map((c, i) => new Promise((res) => c.stdout.on('data', (d) => { outs[i] += d.toString(); if (outs[i].includes('ready')) res(); })));
  const exits = children.map((c) => new Promise((res) => c.on('exit', res)));
  await Promise.all(ready);
  for (const c of children) c.stdin.write('go\n');
  await Promise.all(exits);
  const results = outs.map((o) => o.split('\n').find((l) => /^(RESERVED|REFUSED)/.test(l)) || '(no result)');
  assert.equal(results.filter((r) => r.startsWith('RESERVED')).length, 1, results.join(' | '));
  assert.match(results.find((r) => r.startsWith('REFUSED')), /lifetime budget of 1 would be exceeded/);
  const after = new Ledger(p);
  assert.equal(after.integrity, null);
  assert.equal(after.size(), 1);
  assert.ok(!existsSync(p + '.lock'));
});

console.log('\nEncrypted keyfile\n');

check('round trip; wrong passphrase fails with a fixed message; the format is recognised', () => {
  const sealed = encryptKeyfile(TEST_KEY, 'correct horse battery', 'evm');
  assert.equal(isEncryptedKeyfile(sealed), true);
  assert.equal(isEncryptedKeyfile(TEST_KEY), false);
  assert.equal(decryptKeyfile(sealed, 'correct horse battery'), TEST_KEY);
  assert.throws(() => decryptKeyfile(sealed, 'wrong passphrase'), /wrong passphrase or a damaged file/);
  assert.ok(!sealed.includes(TEST_KEY.slice(2, 20)), 'the file never contains the key');
  assert.throws(() => encryptKeyfile(TEST_KEY, 'short'), /at least 8/);
});
check('passphrase sources: env, file, neither, both', () => {
  assert.equal(keyfilePassphrase({ AGENTWALLET_KEYFILE_PASSPHRASE: 'abc' }), 'abc');
  const f = join(dir, 'pass.txt');
  writeFileSync(f, 'from file\n');
  assert.equal(keyfilePassphrase({ AGENTWALLET_KEYFILE_PASSPHRASE_FILE: f }), 'from file');
  assert.throws(() => keyfilePassphrase({}), /no passphrase is configured/);
  assert.throws(() => keyfilePassphrase({ AGENTWALLET_KEYFILE_PASSPHRASE: 'a', AGENTWALLET_KEYFILE_PASSPHRASE_FILE: f }), /keep one/);
  assert.equal(openKeyfile('plain', {}), 'plain');
});

console.log('\nDiscovery\n');

const item = (resource, desc, amount = '20000') => ({ resource, description: desc, serviceName: 'svc', tags: ['weather'], lastUpdated: '2026-10-11T00:00:00Z', accepts: [{ scheme: 'exact', network: 'eip155:8453', amount, asset: USDC_BASE, payTo: DEAD }], extensions: { bazaar: { info: { input: { method: 'post' } } } } });
check('summarize re-prices from the registry, bounds text, drops non-https resources', () => {
  const s = summarize(item('https://api.example.com/weather', 'x'.repeat(1000)));
  assert.equal(s.prices[0].amount, '0.02');
  assert.equal(s.prices[0].asset, 'USDC');
  assert.equal(s.method, 'POST');
  assert.equal(s.description.length, 400);
  assert.equal(summarize({ resource: 'http://insecure.example/x' }), null);
  assert.equal(summarize(item('https://api.example.com/w', 'd', 'not-a-number')).prices[0].amount, null);
});
check('matches requires every word', () => {
  const s = summarize(item('https://api.example.com/weather', 'Hourly forecast'));
  assert.equal(matches(s, 'weather forecast'), true);
  assert.equal(matches(s, 'weather stock'), false);
});
await checkAsync('discover walks pages with a query and reports next_offset', async () => {
  const pages = {};
  for (let o = 0; o < 300; o += 100) pages[o] = { items: Array.from({ length: 100 }, (_, i) => item(`https://api.example.com/r${o + i}`, (o + i) % 50 === 0 ? 'rare bird' : 'common')), pagination: { total: 300 } };
  const fetched = [];
  const fetcher = async (url) => { fetched.push(url); return pages[Number(new URL(url).searchParams.get('offset'))]; };
  const r = await discover({ query: 'rare', limit: 3, offset: 0, fetcher });
  assert.equal(r.items.length, 3);
  assert.equal(fetched.length, 2);
  assert.equal(r.next_offset, 101);
  const r2 = await discover({ limit: 5, offset: 0, fetcher });
  assert.equal(r2.items.length, 5);
  assert.equal(r2.total, 300);
});

console.log('\nOver stdio: local mode, hosted API on a closed port, policy file loaded\n');

function callTools(calls, env, { listTools = false, waitMs = 9000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['build/index.js'], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.stderr.on('data', (d) => { err += d.toString(); });
    const send = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    if (listTools) send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    calls.forEach((c, i) => send({ jsonrpc: '2.0', id: 100 + i, method: 'tools/call', params: c }));
    const timer = setTimeout(() => { child.kill(); finish(null); }, waitMs);
    child.on('exit', (code) => { clearTimeout(timer); finish(code); });
    let done = false;
    function finish(code) {
      if (done) return; done = true;
      const responses = out.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      resolve({ responses, stderr: err, code });
    }
    child.on('error', reject);
  });
}
const textOf = (resp) => { const c = resp?.result?.content?.[0]?.text; return c ? JSON.parse(c) : null; };
const rawText = (resp) => resp?.result?.content?.[0]?.text ?? JSON.stringify(resp?.error ?? resp);

const policyFile = join(dir, 'policy.json');
const stdioLedger = join(dir, 'stdio-ledger.jsonl');
writeFileSync(policyFile, JSON.stringify({
  version: 1, name: 'test policy',
  budget: { daily: '5' },
  native_budget: { 8453: { daily: '0.01' } },
  hosts: { deny: ['denied.example.com'] },
  recipients: { deny: [OTHER] },
  tools: { deny: ['delete_wallet', 'create_paywall'] },
}, null, 2));
// AGENTWALLET_TOKEN_RISK=0: approve_token would otherwise ask GoPlus over the network before the policy runs.
const baseEnv = { AGENTWALLET_PRIVATE_KEY: TEST_KEY, AGENTWALLET_API_URL: DEAD_API, AGENTWALLET_RPC_8453: DEAD_RPC, AGENTWALLET_POLICY: policyFile, AGENTWALLET_LEDGER: stdioLedger, AGENTWALLET_MAX_TX_TOKEN: '100', AGENTWALLET_TOKEN_RISK: '0' };
const WETH_BASE = '0x4200000000000000000000000000000000000006';
const pad32 = (hex) => hex.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const approveCalldata = (spender, raw) => '0x095ea7b3' + pad32(spender) + BigInt(raw).toString(16).padStart(64, '0');
const transferCalldata = (to, raw) => '0xa9059cbb' + pad32(to) + BigInt(raw).toString(16).padStart(64, '0');

// Seed the ledger with a settled 4-dollar spend so the day has 1 dollar left before the server starts.
{
  const seed = new Ledger(stdioLedger);
  const s = seed.reserve(spend({ raw: '4000000', usd: '4', host: 'seed.example.com' }), limits());
  seed.settle(s, 'settled', null);
}

const run = await callTools([
  { name: 'spend_policy', arguments: {} },
  { name: 'wallet_mode', arguments: {} },
  { name: 'transfer_token', arguments: { wallet_id: 1, token: USDC_BASE, to: DEAD, amount: '2', chain_id: 8453 } },
  { name: 'transfer', arguments: { wallet_id: 1, to: OTHER, amount: '0.001', chain_id: 8453 } },
  { name: 'pay_x402', arguments: { url: 'https://denied.example.com/paid', wallet_id: 1 } },
  { name: 'quote_x402', arguments: { url: 'https://denied.example.com/paid' } },
  { name: 'transfer_token', arguments: { wallet_id: 1, token: USDC_BASE, to: DEAD, amount: '0.5', chain_id: 8453 } },
  { name: 'spend_policy', arguments: {} }, // placeholder so ids stay stable; list_payments runs in a second session below
  { name: 'export_receipts', arguments: { format: 'csv' } },
  { name: 'simulate_transaction', arguments: { wallet_id: 1, to: OTHER, value: '0.001', chain_id: 8453 } },
  { name: 'delete_wallet', arguments: { wallet_id: 1, confirm: 'DELETE' } },
  // 1.14.1: approvals and the native value of contract calls are spends (reported privately 2026-10-14).
  { name: 'approve_token', arguments: { wallet_id: 1, token: USDC_BASE, spender: DEAD, amount: 'max', chain_id: 8453 } },          // 111
  { name: 'approve_token', arguments: { wallet_id: 1, token: USDC_BASE, spender: DEAD, amount: '50', chain_id: 8453 } },           // 112
  { name: 'approve_token', arguments: { wallet_id: 1, token: USDC_BASE, spender: OTHER, amount: '0.5', chain_id: 8453 } },         // 113
  { name: 'approve_permit2', arguments: { wallet_id: 1, token: USDC_BASE, chain_id: 8453 } },                                       // 114
  { name: 'send_transaction', arguments: { wallet_id: 1, to: DEAD, value: '1000000000000000000', data: '0x12345678', chain_id: 8453 } }, // 115
  { name: 'wrap_eth', arguments: { wallet_id: 1, amount: '0.02', chain_id: 8453 } },                                                 // 116
  { name: 'wrap_eth', arguments: { wallet_id: 1, amount: '0.005', chain_id: 8453 } },                                                // 117
  { name: 'approve_token', arguments: { wallet_id: 1, token: USDC_BASE, spender: DEAD, amount: '0.25', chain_id: 8453 } },         // 118
  { name: 'simulate_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '0', data: approveCalldata(DEAD, (1n << 256n) - 1n), chain_id: 8453 } }, // 119
  { name: 'simulate_transaction', arguments: { wallet_id: 1, to: DEAD, value: '0.02', data: '0x12345678', chain_id: 8453 } },     // 120
  { name: 'send_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '0', data: '0x095ea7b3' + pad32(DEAD) + 'ff', chain_id: 8453 } }, // 121
  // 1.14.4: the native value carried on a classified token call is a spend too (reported privately 2026-10-23).
  { name: 'send_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '1000000000000000000', data: transferCalldata(DEAD, 1000n), chain_id: 8453 } }, // 122
  { name: 'send_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '2000000000000000', data: transferCalldata(DEAD, 1000n), chain_id: 8453 } },    // 123
  { name: 'simulate_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '1', data: transferCalldata(DEAD, 1000n), chain_id: 8453 } },                // 124
  { name: 'send_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '1000000000000000000', data: approveCalldata(DEAD, 1000n), chain_id: 8453 } },  // 125
], baseEnv, { listTools: true, waitMs: 15000 });
const byId = (id) => run.responses.find((r) => r.id === id);

check('tools/list omits the denied tools and includes the new ones', () => {
  const names = byId(2).result.tools.map((t) => t.name);
  assert.ok(!names.includes('delete_wallet'));
  assert.ok(!names.includes('create_paywall'));
  for (const n of ['quote_x402', 'discover_x402', 'list_payments', 'export_receipts', 'spend_policy', 'simulate_transaction', 'pay_x402', 'wallet_mode']) assert.ok(names.includes(n), n);
});
check('spend_policy reports the file, its hash, the seeded spend and the hidden tools', () => {
  const p = textOf(byId(100));
  assert.equal(p.policy.name, 'test policy');
  assert.equal(p.policy.sha256.length, 64);
  assert.equal(p.budgets.usd.daily.spent, '4');
  assert.equal(p.budgets.usd.daily.remaining, '1');
  assert.equal(p.ledger.integrity, 'intact');
  assert.deepEqual(p.tools_hidden_by_policy.sort(), ['create_paywall', 'delete_wallet']);
  assert.match(p.human_approval_channel, /no elicitation/);
});
check('wallet_mode names the policy', () => {
  assert.equal(textOf(byId(101)).spend_policy.name, 'test policy');
});
check('transfer_token above the remaining daily budget is refused before any RPC call', () => {
  const t = rawText(byId(102));
  assert.match(t, /daily budget of 5 would be exceeded: 4 already spent/);
  assert.ok(!/RPC node answered/.test(t), 'no RPC was contacted');
});
check('transfer to a denied recipient is refused', () => {
  assert.match(rawText(byId(103)), /policy denies recipient/);
});
check('pay_x402 to a denied host never contacts it', () => {
  const r = textOf(byId(104));
  assert.equal(r.policy_refusal, true);
  assert.match(r.error, /not contacted/);
});
check('quote_x402 to a denied host never contacts it either', () => {
  const r = textOf(byId(105));
  assert.equal(r.would_pay, false);
  assert.match(r.error, /policy denies host/);
});
// The SDK runs tool calls concurrently, so the ledger is read in a fresh session once the first has exited.
const second = await callTools([{ name: 'list_payments', arguments: { limit: 10 } }], baseEnv, { waitMs: 7000 });
check('a spend inside the budget is reserved, then voided when the dead RPC fails the send', () => {
  const t = rawText(byId(106));
  assert.match(t, /RPC node answered|fetch failed|ECONNREFUSED|Broadcast/i);
  const lp = textOf(second.responses.find((x) => x.id === 100));
  const mine = lp.payments.find((p) => p.amount === '0.5');
  assert.ok(mine, 'the 0.5 spend is on the ledger');
  assert.equal(mine.outcome, 'void');
  assert.equal(mine.tool, 'send');
  assert.equal(lp.persistent, true);
});
check('export_receipts returns CSV with the seeded row', () => {
  const csv = rawText(byId(108));
  assert.match(csv, /^seq,ts,tool/);
  assert.match(csv, /seed\.example\.com/);
});
check('simulate_transaction reports the policy refusal and signs nothing', () => {
  const s = textOf(byId(109));
  assert.equal(s.ok, false);
  assert.match(s.policy, /policy denies recipient/);
  assert.equal(s.signed, false);
});
check('a hidden tool cannot be called', () => {
  assert.match(JSON.stringify(byId(110)), /not found|Unknown tool|Tool delete_wallet/i);
});
check('the on-disk ledger chain is intact after the session and the void is recorded', () => {
  const after = new Ledger(stdioLedger);
  assert.equal(after.integrity, null);
  assert.equal(human(after.spentUsd().daily), '4');
});

console.log('\n1.14.1: approvals and contract calls with value are spends under the policy\n');

check('approve_token "max" is refused under a policy before any RPC call (reported 2026-10-14: approvals bypassed every budget)', () => {
  const t = rawText(byId(111));
  assert.match(t, /unlimited approval of USDC .* cannot be counted against any budget/);
  assert.match(t, /Nothing was signed/);
  assert.ok(!/RPC node answered|ECONNREFUSED/.test(t), 'no RPC was contacted');
});
check('a bounded approval above the remaining daily budget is refused by the budget', () => {
  assert.match(rawText(byId(112)), /daily budget of 5 would be exceeded/);
});
check('an approval to a denied address is refused: the spender is a recipient', () => {
  assert.match(rawText(byId(113)), /policy denies recipient/);
});
check('approve_permit2 with no amount is an unlimited approval and is refused under a policy', () => {
  assert.match(rawText(byId(114)), /unlimited approval of USDC/);
});
check('send_transaction with calldata AND native value counts the value against native_budget', () => {
  assert.match(rawText(byId(115)), /native_budget\.8453 daily budget of 0\.01 would be exceeded/);
});
check('wrap_eth above the native budget is refused (deposit() carries its amount as value)', () => {
  assert.match(rawText(byId(116)), /native_budget\.8453 daily budget of 0\.01 would be exceeded/);
});
check('simulate_transaction reports an unlimited approval as a policy refusal and signs nothing', () => {
  const s = textOf(byId(119));
  assert.equal(s.ok, false);
  assert.equal(s.moves.kind, 'approval');
  assert.equal(s.moves.to.toLowerCase(), DEAD.toLowerCase());
  assert.equal(s.moves.amount, 'unlimited');
  assert.match(s.policy, /unlimited approval/);
  assert.equal(s.signed, false);
});
check('simulate_transaction reports the native budget for a contract call with value', () => {
  const s = textOf(byId(120));
  assert.equal(s.ok, false);
  assert.equal(s.moves.kind, 'contract');
  assert.match(s.policy, /native_budget\.8453/);
});
check('truncated approve calldata is refused, not reclassified as a plain contract call', () => {
  assert.match(rawText(byId(121)), /calldata for approve is truncated/);
});
check('1.14.4: a transfer() call carrying 1 ETH is refused by native_budget, the token amount notwithstanding', () => {
  const t = rawText(byId(122));
  assert.match(t, /native_budget\.8453 daily budget of 0\.01 would be exceeded/);
  assert.ok(!/RPC node answered|fetch failed/i.test(t), 'refused before any RPC call');
});
check('1.14.4: a transfer() call carrying 0.002 ETH inside the budget reaches the signer (then fails on the dead RPC)', () => {
  const t = rawText(byId(123));
  assert.ok(!/policy/.test(t), t);
  assert.match(t, /RPC node answered|fetch failed|ECONNREFUSED|Broadcast|connect/i);
});
check('1.14.4: simulate_transaction reports the carried native value and the native_budget refusal', () => {
  const s = textOf(byId(124));
  assert.equal(s.ok, false);
  assert.equal(s.moves.kind, 'token');
  assert.match(s.moves.carried_native.amount, /^1(.0+)?$/);
  assert.equal(s.moves.carried_native.to.toLowerCase(), USDC_BASE.toLowerCase());
  assert.match(s.policy, /native_budget\.8453/);
});
check('1.14.4: an approve() call carrying 1 ETH is refused by native_budget too', () => {
  assert.match(rawText(byId(125)), /native_budget\.8453 daily budget of 0\.01 would be exceeded/);
});
const third = await callTools([{ name: 'list_payments', arguments: { limit: 20 } }], baseEnv, { waitMs: 7000 });
check('an approval and a wrap inside the budgets are reserved on the ledger (then voided by the dead RPC)', () => {
  const lp = textOf(third.responses.find((x) => x.id === 100));
  const appr = lp.payments.find((p) => p.method === 'approval' && p.amount === '0.25');
  assert.ok(appr, 'the 0.25 approval is on the ledger');
  assert.equal(appr.amount, '0.25');
  assert.equal(appr.usd, '0.25');
  assert.equal(appr.to.toLowerCase(), DEAD.toLowerCase());
  assert.equal(appr.asset.toLowerCase(), USDC_BASE.toLowerCase());
  assert.equal(appr.outcome, 'void');
  const wrap = lp.payments.find((p) => p.amount === '0.005');
  assert.ok(wrap, 'the 0.005 wrap is on the ledger');
  assert.equal(wrap.asset, '');
  assert.equal(wrap.method, 'native');
  assert.equal(wrap.to.toLowerCase(), WETH_BASE.toLowerCase());
  assert.equal(wrap.outcome, 'void');
  const after = new Ledger(stdioLedger);
  assert.equal(after.integrity, null);
});
check('1.14.4: a token call with carried value is two ledger lines, and a refused pair is released together', () => {
  const lp = textOf(third.responses.find((x) => x.id === 100));
  const nat = lp.payments.find((p) => p.asset === '' && p.amount === '0.002');
  assert.ok(nat, 'the carried 0.002 ETH is on the ledger as its own native line: ' + JSON.stringify(lp.payments));
  assert.equal(nat.method, 'native');
  assert.equal(nat.to.toLowerCase(), USDC_BASE.toLowerCase(), 'the native value goes to the token contract');
  assert.equal(nat.outcome, 'void');
  const tok = lp.payments.filter((p) => p.method === 'transfer' && p.amount === '0.001' && p.asset.toLowerCase() === USDC_BASE.toLowerCase());
  assert.equal(tok.length, 2, 'both transfer() calls put their token line on the ledger: ' + JSON.stringify(tok));
  const released = tok.find((p) => /released, the same call was refused: .*native_budget/.test(p.outcome_detail || ''));
  assert.ok(released, 'the token line of the refused 1 ETH call was released with the native refusal as its reason: ' + JSON.stringify(tok));
  assert.equal(released.outcome, 'void');
  const appr = lp.payments.find((p) => p.method === 'approval' && p.amount === '0.001');
  assert.ok(appr, 'the approval line of the refused approve()+1 ETH call is on the ledger');
  assert.equal(appr.outcome, 'void');
  assert.match(appr.outcome_detail, /released, the same call was refused: .*native_budget/);
  assert.equal(lp.payments.filter((p) => p.asset === '' && p.amount === '1').length, 0, 'the refused 1 ETH was never reserved');
});

console.log('\n1.14.2: hosted sign_transaction is the same spend as send (reported 2026-10-14)\n');

// Hosted mode: no local key, the API on a closed port. The policy must refuse before the API is ever contacted.
const hostedLedger = join(dir, 'hosted-ledger.jsonl');
const hostedEnv = { AGENTWALLET_API_URL: DEAD_API, AGENTWALLET_USER: 'u', AGENTWALLET_PASS: 'p', AGENTWALLET_POLICY: policyFile, AGENTWALLET_LEDGER: hostedLedger, AGENTWALLET_TOKEN_RISK: '0' };
const hosted = await callTools([
  { name: 'wallet_mode', arguments: {} },                                                                                                      // 100
  { name: 'sign_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '0', data: transferCalldata(OTHER, 100_000_000n), chain_id: 8453 } }, // 101
  { name: 'sign_transaction', arguments: { wallet_id: 1, to: OTHER, value: '5000000000000000000', chain_id: 8453 } },                       // 102
  { name: 'sign_transaction', arguments: { wallet_id: 1, to: DEAD, value: '20000000000000000', chain_id: 8453 } },                          // 103
  { name: 'sign_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '0', data: approveCalldata(DEAD, (1n << 256n) - 1n), chain_id: 8453 } }, // 104
  { name: 'sign_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '0', data: transferCalldata(DEAD, 100_000_000n), chain_id: 8453 } },  // 105
  { name: 'sign_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '0', data: transferCalldata(DEAD, 500_000n), chain_id: 8453 } },      // 106
], hostedEnv, { waitMs: 15000 });
const hid = (id) => hosted.responses.find((r) => r.id === id);
check('the session is hosted mode with the policy loaded', () => {
  const m = textOf(hid(100));
  assert.equal(m.mode, 'custodial', 'no local key: the hosted signer is the custodian');
  assert.equal(m.spend_policy.name, 'test policy');
});
check('sign_transaction of a 100 USDC transfer to a denied recipient is refused before the API is contacted', () => {
  const t = rawText(hid(101));
  assert.match(t, /policy denies recipient/);
  assert.ok(!/ECONNREFUSED|fetch failed/i.test(t), 'the API was never contacted');
});
check('sign_transaction of 5 ETH to a denied recipient is refused', () => {
  assert.match(rawText(hid(102)), /policy denies recipient/);
});
check('sign_transaction of native value above native_budget is refused', () => {
  assert.match(rawText(hid(103)), /native_budget\.8453 daily budget of 0\.01 would be exceeded/);
});
check('sign_transaction of an unlimited approve is refused under the policy', () => {
  assert.match(rawText(hid(104)), /unlimited approval of USDC/);
});
check('sign_transaction of a transfer above the daily budget is refused', () => {
  assert.match(rawText(hid(105)), /daily budget of 5 would be exceeded/);
});
check('a sign_transaction inside the policy is reserved on the ledger, then voided when the API cannot be reached', () => {
  const t = rawText(hid(106));
  assert.match(t, /ECONNREFUSED|fetch failed|Cannot reach|connect/i);
  assert.ok(!/policy/.test(t), t);
});
const hostedList = await callTools([{ name: 'list_payments', arguments: { limit: 10 } }], hostedEnv, { waitMs: 7000 });
check('the ledger names sign_transaction as the tool for that spend', () => {
  const lp = textOf(hostedList.responses.find((x) => x.id === 100));
  const mine = lp.payments.find((p) => p.amount === '0.5');
  assert.ok(mine, 'the 0.5 sign is on the ledger: ' + JSON.stringify(lp.payments));
  assert.equal(mine.tool, 'sign_transaction');
  assert.equal(mine.mode, 'hosted');
  assert.equal(mine.outcome, 'void');
  assert.equal(lp.payments.length, 1, 'the refused signs never reached the ledger');
  assert.equal(new Ledger(hostedLedger).integrity, null);
});

console.log('\n1.14.3: a refused local sign_transaction is voided, never counted (reported 2026-10-16)\n');

// Local mode refuses transaction signing on the sign route with a message that
// contains the word "broadcasts". The old test for "may already be live" was a
// case-insensitive regex over the message, so every refused sign stayed counted
// and ten refusals ate a whole day's native budget; the eleventh legitimate
// spend was then refused by the budget. Eleven refused signs must all get the
// local-mode refusal, none a budget refusal, and the ledger must void them all.
const signLedger = join(dir, 'local-sign-ledger.jsonl');
const signEnv = { ...baseEnv, AGENTWALLET_LEDGER: signLedger };
const tenthOfBudget = '1000000000000000'; // 0.001 ETH; native_budget for 8453 is 0.01 a day, so ten fill it
// Ten in one session (the SDK runs them concurrently, so all ten are reserved
// before the first void lands), then the eleventh alone in a fresh session,
// which is the reporter's sequence: ten failures, then the spend that used to
// be refused for a budget nothing had spent.
const signCall = { name: 'sign_transaction', arguments: { wallet_id: 1, to: DEAD, value: tenthOfBudget, chain_id: 8453 } };
const signs = await callTools(Array.from({ length: 10 }, () => signCall), signEnv, { waitMs: 15000 });
const eleventh = await callTools([signCall], signEnv, { waitMs: 8000 });
check('ten refused local sign_transaction calls all get the local-mode refusal, none a budget refusal', () => {
  for (let i = 0; i < 10; i++) {
    const t = rawText(signs.responses.find((r) => r.id === 100 + i));
    assert.match(t, /Local mode signs messages in-process/, t);
    assert.ok(!/budget/i.test(t), 'a refused sign consumed budget: ' + t);
  }
});
check('the eleventh, after ten failures worth a full day of budget, is still not refused by the budget', () => {
  const t = rawText(eleventh.responses.find((r) => r.id === 100));
  assert.match(t, /Local mode signs messages in-process/, t);
  assert.ok(!/budget/i.test(t), 'the failed signs consumed the budget: ' + t);
});
const signList = await callTools([{ name: 'list_payments', arguments: { limit: 20 } }, { name: 'spend_policy', arguments: {} }], signEnv, { waitMs: 7000 });
check('every refused sign is on the ledger as void and the native budget is untouched', () => {
  const lp = textOf(signList.responses.find((x) => x.id === 100));
  assert.equal(lp.payments.length, 11, JSON.stringify(lp.payments));
  for (const p of lp.payments) { assert.equal(p.tool, 'sign_transaction'); assert.equal(p.outcome, 'void', JSON.stringify(p)); }
  const sp = textOf(signList.responses.find((x) => x.id === 101));
  assert.equal(sp.budgets.native['8453'].daily.spent, '0');
  assert.equal(sp.budgets.native['8453'].daily.remaining, '0.01');
  assert.equal(new Ledger(signLedger).integrity, null);
});

// The other side of the same decision: a broadcast that failed after the signed
// bytes went to the node must still stay counted (outcome unknown), now by the
// marker on the error rather than by its wording.
const liveLedger = join(dir, 'live-ledger.jsonl');
const liveRpc = createServer((req, res) => {
  let b = ''; req.on('data', (c) => { b += c; });
  req.on('end', () => {
    const r = JSON.parse(b);
    const send = (p) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: r.id, ...p })); };
    switch (r.method) {
      case 'eth_chainId': return send({ result: '0x2105' });
      case 'eth_getCode': return send({ result: '0x' });
      case 'eth_getBalance': return send({ result: '0x' + (10n ** 18n).toString(16) });
      case 'eth_estimateGas': return send({ result: '0x5208' });
      case 'eth_maxPriorityFeePerGas': return send({ result: '0x3b9aca00' });
      case 'eth_gasPrice': return send({ result: '0x77359400' });
      case 'eth_getBlockByNumber': return send({ result: { number: '0x10', baseFeePerGas: '0x3b9aca00', gasLimit: '0x1c9c380', gasUsed: '0x0', timestamp: '0x1', hash: '0x' + '11'.repeat(32), parentHash: '0x' + '22'.repeat(32), transactions: [], miner: '0x' + '00'.repeat(20), nonce: '0x0000000000000000', difficulty: '0x0', extraData: '0x', logsBloom: '0x' + '00'.repeat(256), size: '0x0', stateRoot: '0x' + '33'.repeat(32), transactionsRoot: '0x' + '44'.repeat(32), receiptsRoot: '0x' + '55'.repeat(32), sha3Uncles: '0x' + '66'.repeat(32), totalDifficulty: '0x0', uncles: [] } });
      case 'eth_getTransactionCount': return send({ result: '0x5' });
      case 'eth_sendRawTransaction': return send({ error: { code: -32000, message: 'already known' } }); // the node had the bytes before it answered
      default: return send({ error: { code: -32601, message: `mock: ${r.method} not served` } });
    }
  });
});
await new Promise((r) => liveRpc.listen(0, '127.0.0.1', r));
const liveEnv = { ...baseEnv, AGENTWALLET_LEDGER: liveLedger, AGENTWALLET_RPC_8453: `http://127.0.0.1:${liveRpc.address().port}` };
const live = await callTools([{ name: 'transfer', arguments: { wallet_id: 1, to: DEAD, amount: '0.001', chain_id: 8453 } }], liveEnv, { waitMs: 15000 });
const liveList = await callTools([{ name: 'list_payments', arguments: { limit: 5 } }], liveEnv, { waitMs: 7000 });
// 1.14.4, the reporter's sequence: a transfer() carrying 0.006 ETH reaches the
// node (which says it may be live, so both lines stay counted); the same call
// again must be refused by native_budget, where before it went out uncounted
// as many times as the balance allowed.
const carryLedger = join(dir, 'carry-ledger.jsonl');
const carryEnv = { ...liveEnv, AGENTWALLET_LEDGER: carryLedger };
const carryCall = { name: 'send_transaction', arguments: { wallet_id: 1, to: USDC_BASE, value: '6000000000000000', data: transferCalldata(DEAD, 1000n), chain_id: 8453 } };
const carry1 = await callTools([carryCall], carryEnv, { waitMs: 15000 });
const carry2 = await callTools([carryCall], carryEnv, { waitMs: 15000 });
const carryList = await callTools([{ name: 'list_payments', arguments: { limit: 5 } }, { name: 'spend_policy', arguments: {} }], carryEnv, { waitMs: 7000 });
liveRpc.close();
check('1.14.4: the first transfer() carrying 0.006 ETH reaches the node and may be live', () => {
  assert.match(rawText(carry1.responses.find((r) => r.id === 100)), /MAY be live/);
});
check('1.14.4: the second identical call is refused by native_budget, the carried value having been counted', () => {
  const t = rawText(carry2.responses.find((r) => r.id === 100));
  assert.match(t, /native_budget\.8453 daily budget of 0\.01 would be exceeded: 0\.006 already spent/);
});
check('1.14.4: the ledger holds the native line and the token line of the first call, both unknown, and spend_policy shows 0.006 native spent', () => {
  const lp = textOf(carryList.responses.find((x) => x.id === 100));
  const nat = lp.payments.filter((p) => p.asset === '');
  assert.equal(nat.length, 1, JSON.stringify(lp.payments));
  assert.equal(nat[0].amount, '0.006');
  assert.equal(nat[0].outcome, 'unknown');
  assert.equal(nat[0].to.toLowerCase(), USDC_BASE.toLowerCase());
  const tok = lp.payments.filter((p) => p.asset !== '' && p.outcome === 'unknown');
  assert.equal(tok.length, 1, JSON.stringify(lp.payments));
  assert.equal(lp.payments.filter((p) => p.outcome === 'void').length, 1, 'the refused second call released its token line');
  const sp = textOf(carryList.responses.find((x) => x.id === 101));
  assert.equal(sp.budgets.native['8453'].daily.spent, '0.006', JSON.stringify(sp.budgets));
  assert.equal(new Ledger(carryLedger).integrity, null);
});
check('a send whose broadcast failed after the bytes reached the node says it may be live', () => {
  assert.match(rawText(live.responses.find((r) => r.id === 100)), /MAY be live/);
});
check('that spend stays on the ledger as unknown, not void', () => {
  const lp = textOf(liveList.responses.find((x) => x.id === 100));
  assert.equal(lp.payments.length, 1, JSON.stringify(lp.payments));
  assert.equal(lp.payments[0].tool, 'send');
  assert.equal(lp.payments[0].outcome, 'unknown', JSON.stringify(lp.payments[0]));
});

// Hosted mode, same distinction: a host that was never reached (the dead port
// above) voids the spend; a host that took the request and then dropped the
// connection may have signed and broadcast, so the spend stays counted.
const resetApi = createServer((req, res) => { req.on('data', () => {}); req.on('end', () => { res.socket.destroy(); }); });
await new Promise((r) => resetApi.listen(0, '127.0.0.1', r));
const resetLedger = join(dir, 'reset-ledger.jsonl');
const resetEnv = { ...hostedEnv, AGENTWALLET_API_URL: `http://127.0.0.1:${resetApi.address().port}`, AGENTWALLET_LEDGER: resetLedger };
const reset = await callTools([{ name: 'sign_transaction', arguments: { wallet_id: 1, to: DEAD, value: tenthOfBudget, chain_id: 8453 } }], resetEnv, { waitMs: 10000 });
const resetList = await callTools([{ name: 'list_payments', arguments: { limit: 5 } }], resetEnv, { waitMs: 7000 });
resetApi.close();
check('hosted: a connection the host dropped after taking the request says the transaction may be live', () => {
  assert.match(rawText(reset.responses.find((r) => r.id === 100)), /did not answer .* may be live/);
});
check('hosted: that spend stays on the ledger as unknown', () => {
  const lp = textOf(resetList.responses.find((x) => x.id === 100));
  assert.equal(lp.payments.length, 1, JSON.stringify(lp.payments));
  assert.equal(lp.payments[0].tool, 'sign_transaction');
  assert.equal(lp.payments[0].outcome, 'unknown', JSON.stringify(lp.payments[0]));
});

console.log('\nStartup refusals and the encrypted keyfile over stdio\n');

await checkAsync('a policy that does not parse stops the server', async () => {
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify({ version: 1, budgets: { daily: '1' } }));
  const r = await callTools([], { ...baseEnv, AGENTWALLET_POLICY: bad }, { waitMs: 6000 });
  assert.match(r.stderr, /policy field/);
  assert.notEqual(r.code, 0);
});
await checkAsync('a tampered ledger starts with a warning and refuses the spend', async () => {
  const t = join(dir, 'tampered.jsonl');
  const l = new Ledger(t);
  l.reserve(spend({ raw: '1000000', usd: '1' }), limits());
  appendFileSync(t, '{"seq":2,"kind":"void","ref":1,"prev":"junk","hash":"junk"}\n');
  const r = await callTools([{ name: 'transfer_token', arguments: { wallet_id: 1, token: USDC_BASE, to: DEAD, amount: '0.5', chain_id: 8453 } }], { ...baseEnv, AGENTWALLET_LEDGER: t }, { waitMs: 8000 });
  assert.match(r.stderr, /not intact/);
  assert.match(rawText(r.responses.find((x) => x.id === 100)), /not intact/);
});
await checkAsync('the CLI encrypts a keyfile and the server opens it with the passphrase', async () => {
  const plain = join(dir, 'plain.key');
  const sealed = join(dir, 'sealed.json');
  writeFileSync(plain, TEST_KEY + '\n');
  const out = execFileSync(process.execPath, ['build/index.js', 'encrypt-keyfile', plain, sealed], { env: { ...process.env, AGENTWALLET_KEYFILE_PASSPHRASE: 'test passphrase 1' }, stdio: ['ignore', 'pipe', 'pipe'] }).toString() + '';
  assert.ok(existsSync(sealed));
  assert.ok(isEncryptedKeyfile(readFileSync(sealed, 'utf8')));
  const env = { AGENTWALLET_KEYFILE: sealed, AGENTWALLET_KEYFILE_PASSPHRASE: 'test passphrase 1', AGENTWALLET_API_URL: DEAD_API };
  const r = await callTools([{ name: 'wallet_mode', arguments: {} }], env, { waitMs: 7000 });
  assert.equal(textOf(r.responses.find((x) => x.id === 100)).evm.address, TEST_ADDRESS);
  const wrong = await callTools([{ name: 'wallet_mode', arguments: {} }], { ...env, AGENTWALLET_KEYFILE_PASSPHRASE: 'not it, sorry' }, { waitMs: 7000 });
  assert.match(wrong.stderr, /could not be decrypted/);
  assert.ok(!wrong.stderr.includes(TEST_KEY.slice(2, 20)));
  const none = await callTools([{ name: 'wallet_mode', arguments: {} }], { AGENTWALLET_KEYFILE: sealed, AGENTWALLET_API_URL: DEAD_API }, { waitMs: 7000 });
  assert.match(none.stderr, /no passphrase is configured/);
  void out;
});
await checkAsync('an unknown AGENTWALLET_* name still refuses to start; the new names are known', async () => {
  const r = await callTools([], { ...baseEnv, AGENTWALLET_LEDGERR: 'x' }, { waitMs: 6000 });
  assert.match(r.stderr, /Unknown environment variable AGENTWALLET_LEDGERR/);
  const ok = await callTools([{ name: 'wallet_mode', arguments: {} }], { ...baseEnv, AGENTWALLET_WEBHOOK_URL: 'https://hooks.example.com/x', AGENTWALLET_WEBHOOK_SECRET: 's' }, { waitMs: 7000 });
  assert.equal(textOf(ok.responses.find((x) => x.id === 100)).mode, 'local');
});

console.log(`\nspend-policy: ${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
