/**
 * 1.14.0 Spend Policy: the policy file, the hash-chained ledger and its
 * budgets, the encrypted keyfile, x402 discovery, and the new tools over the
 * real stdio protocol with the hosted API pointed at a closed port.
 *
 * Run: node test/spend-policy.test.mjs
 */
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, appendFileSync } from 'node:fs';
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
  hosts: { deny: ['denied.example.com'] },
  recipients: { deny: [OTHER] },
  tools: { deny: ['delete_wallet', 'create_paywall'] },
}, null, 2));
const baseEnv = { AGENTWALLET_PRIVATE_KEY: TEST_KEY, AGENTWALLET_API_URL: DEAD_API, AGENTWALLET_RPC_8453: DEAD_RPC, AGENTWALLET_POLICY: policyFile, AGENTWALLET_LEDGER: stdioLedger, AGENTWALLET_MAX_TX_TOKEN: '100' };

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
