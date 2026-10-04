/**
 * Regression tests from the 2026-10-04 adversarial audit, hosted-path group.
 *
 *  - In LOCAL mode with hosted credentials also set, a 402 from the API host on
 *    a call that falls through to it (get_usage) used to run the internal
 *    auto-pay, which posted to /wallets//send with an empty wallet id; the
 *    local route accepted the empty id and the LOCAL KEY signed a transfer the
 *    agent never asked for. Now: the 402 comes back as an error naming
 *    pay_x402, nothing is signed, nothing reaches the RPC.
 *  - api() used to follow redirects from the API host with plain fetch; a 307
 *    replayed the request body to another origin and that origin's body came
 *    back as the API's answer. Now: any redirect from the host is refused.
 *  - RPC errors used to carry the RPC URL (API key included) into the tool
 *    result. Now: URLs are reduced to their origin.
 *  - A blank cap value used to mean "no cap". Now: the server refuses to start.
 *
 * Run with: node test/local-no-autopay.test.mjs
 */
import assert from 'node:assert';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { generatePrivateKey } from 'viem/accounts';

const ATTACKER = '0x00000000000000000000000000000000DEADBEEF';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

// Mock API host: 402 on /usage with a cap-sized USDC offer; 307 to another origin on /chains.
let apiSends = 0;
const other = createServer((req, res) => { let b = ''; req.on('data', c => b += c); req.on('end', () => { otherHits.push({ method: req.method, url: req.url, body: b }); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ reached: 'other-origin' })); }); });
const otherHits = [];
await new Promise(r => other.listen(0, '127.0.0.1', r));
const OTHER = `http://127.0.0.1:${other.address().port}`;
const api = createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    const json = (code, obj) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(obj)); };
    if (req.url.startsWith('/usage')) {
      if (req.headers['x-payment']) return json(200, { ok: true, served: 'after payment' });
      return json(402, { x402Version: 1, error: 'Payment Required', accepts: [{ scheme: 'exact', network: 'base', payTo: ATTACKER, asset: USDC, maxAmountRequired: '1000000', requiredDecimals: 6 }] });
    }
    if (req.url.startsWith('/chains')) { res.statusCode = 307; res.setHeader('location', OTHER + '/landed'); return res.end(); }
    if (req.method === 'POST' && /^\/wallets\/[^/]*\/send$/.test(req.url)) { apiSends++; return json(200, { tx_hash: '0x' + 'ab'.repeat(32) }); }
    json(404, { error: `mock: ${req.method} ${req.url} not served` });
  });
});
await new Promise(r => api.listen(0, '127.0.0.1', r));
const API_URL = `http://127.0.0.1:${api.address().port}`;

// Mock EVM RPC: answers chain id and reads, records any attempt to broadcast.
const rpcCalls = [];
const rpc = createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const r = JSON.parse(b); rpcCalls.push(r.method);
    const rep = (x) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: r.id, ...x })); };
    if (r.method === 'eth_chainId') return rep({ result: '0x2105' });
    if (r.method === 'eth_call') return rep({ result: '0x' + '0'.repeat(62) + '06' });
    if (r.method === 'eth_getBalance') return rep({ error: { code: -32601, message: 'The method eth_getBalance does not exist/is not available' } });
    rep({ error: { code: -32601, message: `mock: ${r.method} not served` } });
  });
});
await new Promise(r => rpc.listen(0, '127.0.0.1', r));
const RPC_URL = `http://127.0.0.1:${rpc.address().port}/v2/SECRET_API_KEY_123?key=QUERYSECRET`;

function run(tool, args, extraEnv = {}) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    for (const k of Object.keys(env)) if (k.startsWith('AGENTWALLET_')) delete env[k];
    Object.assign(env, {
      AGENTWALLET_API_URL: API_URL, AGENTWALLET_USER: 'u', AGENTWALLET_PASS: 'p',
      AGENTWALLET_PRIVATE_KEY: generatePrivateKey(), AGENTWALLET_RPC_8453: RPC_URL,
      AGENTWALLET_MAX_AUTOPAY: '1', AGENTWALLET_AUTOPAY_ASSETS: '', AGENTWALLET_MAX_TX_TOKEN: '5',
    }, extraEnv);
    const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d.toString(); });
    child.stderr.on('data', d => { err += d.toString(); });
    const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    send({ jsonrpc: '2.0', id: 100, method: 'tools/call', params: { name: tool, arguments: args } });
    const finish = (text, exit) => { clearInterval(timer); clearTimeout(limit); try { child.kill(); } catch {} resolve({ text, stderr: err, exit }); };
    child.on('exit', (code) => { if (code !== null && code !== 0) finish('', code); });
    const timer = setInterval(() => {
      const r = out.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).find(x => x && x.id === 100);
      if (r) finish(r.result?.content?.[0]?.text || JSON.stringify(r), 0);
    }, 100);
    const limit = setTimeout(() => finish(out, 'timeout'), 25_000);
  });
}

let passed = 0;
const ok = (name, cond, detail) => { if (!cond) throw new Error(`${name}: ${detail}`); passed++; console.log(`  ok - ${name}`); };
try {
  const usage = await run('get_usage', {});
  ok('a 402 from the API host in local mode is an error, not a payment', /nothing is paid automatically in local mode/.test(usage.text) && /pay_x402/.test(usage.text), usage.text.slice(0, 300));
  ok('the local key signed nothing', !rpcCalls.includes('eth_sendRawTransaction') && !rpcCalls.includes('eth_getTransactionCount'), rpcCalls.join(','));
  ok('the hosted send route was never called either', apiSends === 0, String(apiSends));

  const chains = await run('get_chains', {});
  ok('a redirect from the API host is refused', /redirect \(HTTP 307\)/.test(chains.text), chains.text.slice(0, 300));
  ok('nothing was replayed to the other origin', otherHits.length === 0, JSON.stringify(otherHits));

  const bal = await run('get_balance', { wallet_id: 1, chain_id: 8453 });
  ok('an RPC error reaches the agent', /eth_getBalance/.test(bal.text), bal.text.slice(0, 200));
  ok('but the RPC URL path key and query key do not', !bal.text.includes('SECRET_API_KEY_123') && !bal.text.includes('QUERYSECRET') && !bal.stderr.includes('SECRET_API_KEY_123'), bal.text.slice(0, 400));

  const blank = await run('get_usage', {}, { AGENTWALLET_MAX_TX_TOKEN: '   ' });
  ok('a blank cap value stops the server', blank.exit === 1 && /is set but blank/.test(blank.stderr), `exit ${blank.exit}: ${blank.stderr.slice(0, 200)}`);
} finally {
  api.close(); other.close(); rpc.close();
}
console.log(`\nlocal-no-autopay: ${passed} passed`);
