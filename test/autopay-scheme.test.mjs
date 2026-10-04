/**
 * Regression test for a 2026-09-28 finding: the internal auto-pay path (a 402
 * answered by the configured AgentWallet API host on an ordinary tool call,
 * not pay_x402) took the first offer without looking at its scheme, so an
 * `upto` maximum would have been paid upfront as a transfer. Now only an
 * `exact` offer is settled there, and anything else refuses before a wallet
 * call.
 *
 * A loopback HTTP server plays the API host: it answers the balance request
 * with a 402 until an X-PAYMENT header arrives, and records every /send.
 *
 * Run with: node test/autopay-scheme.test.mjs
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x000000000000000000000000000000000000dEaD';

let offer = null;
const sends = [];
let paidRetries = 0;
const api = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const json = (code, obj) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(obj)); };
    // Since 1.13.8 only the metered routes (POST /wallets, /sign, /send) are auto-paid: the
    // 402 is raised on the send itself; the payment transfer carries X-AGW-SKIP-X402.
    if (req.method === 'POST' && req.url === '/wallets/1/send') {
      if (req.headers['x-agw-skip-x402']) { sends.push(JSON.parse(body)); return json(200, { tx_hash: '0x' + 'ab'.repeat(32) }); }
      if (req.headers['x-payment']) { paidRetries++; return json(200, { tx_hash: '0x' + 'cd'.repeat(32), paid: true }); }
      return json(402, { x402Version: 1, error: 'Payment Required', accepts: [offer] });
    }
    if (req.url.startsWith('/wallets/1/balance')) {
      balance402s++;
      return json(402, { x402Version: 1, error: 'Payment Required', accepts: [offer] });
    }
    json(404, { error: `mock: ${req.method} ${req.url} not served` });
  });
});
await new Promise((r) => api.listen(0, '127.0.0.1', r));
const API_URL = `http://127.0.0.1:${api.address().port}`;

/** Drive the server over stdio, hosted mode, against the loopback API. */
let balance402s = 0;
function getBalance(tool = 'transfer') {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    for (const k of Object.keys(env)) if (k.startsWith('AGENTWALLET_')) delete env[k];
    Object.assign(env, {
      AGENTWALLET_API_URL: API_URL, AGENTWALLET_USER: 'test', AGENTWALLET_PASS: 'test',
      AGENTWALLET_WALLET_ID: '1', AGENTWALLET_MAX_AUTOPAY: '1',
    });
    const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d.toString(); });
    const send = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    send({ jsonrpc: '2.0', id: 100, method: 'tools/call', params: tool === 'get_balance'
      ? { name: 'get_balance', arguments: { wallet_id: 1, chain_id: 8453 } }
      : { name: 'transfer', arguments: { wallet_id: 1, chain_id: 8453, to: PAY_TO, amount: '0.001' } } });
    const timer = setInterval(() => {
      const responses = out.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      const r = responses.find((x) => x.id === 100);
      if (r) { clearInterval(timer); child.kill(); resolve(r.result?.content?.[0]?.text || JSON.stringify(r)); }
    }, 200);
    setTimeout(() => { clearInterval(timer); child.kill(); reject(new Error('no tool response in time; stdout was: ' + out.slice(0, 500))); }, 20000);
    child.on('error', reject);
  });
}

let passed = 0;
console.log('\nInternal auto-pay settles exact offers only\n');

offer = { scheme: 'upto', network: 'base', asset: USDC_BASE, payTo: PAY_TO, maxAmountRequired: '1000000', requiredDecimals: 6 };
{
  const text = await getBalance();
  assert.equal(sends.length, 0, `an upto offer must not produce a transfer; sends were ${JSON.stringify(sends)}`);
  assert.match(text, /no "exact" payment option|upto maximum is not paid upfront/, `unexpected tool text: ${text.slice(0, 300)}`);
  passed++;
  console.log('  ok - an upto offer from the API host is refused before any wallet call');
}

offer = { scheme: 'exact', network: 'base', asset: USDC_BASE, payTo: PAY_TO, maxAmountRequired: '1000000', requiredDecimals: 6 };
{
  const text = await getBalance();
  assert.equal(sends.length, 1, 'an exact offer under the cap is settled with one transfer');
  const amountWord = String(sends[0].data).slice(10 + 64, 10 + 128);
  assert.equal(BigInt('0x' + amountWord), 1000000n, 'the transfer carries the checked amount');
  assert.equal(sends[0].to.toLowerCase(), USDC_BASE.toLowerCase());
  assert.equal(paidRetries, 1, 'the request is retried once with the payment proof');
  assert.match(text, /"paid":\s*true/, `unexpected tool text: ${text.slice(0, 300)}`);
  assert.match(text, /"autopay_payment"/, `the result must report the automatic payment: ${text.slice(0, 300)}`);
  assert.match(text, /"amount": "1(\.0)?"/, `the reported amount: ${text.slice(0, 400)}`);
  passed++;
  console.log('  ok - control: an exact offer still settles, the original request is retried with proof, and the payment is reported');
}

{
  const before = sends.length;
  const text = await getBalance('get_balance');
  assert.equal(balance402s, 1, 'the read was attempted once');
  assert.equal(sends.length, before, `a 402 on a read must not be paid; sends were ${JSON.stringify(sends.slice(before))}`);
  assert.match(text, /a route the hosted billing does not meter; nothing was paid/, `unexpected tool text: ${text.slice(0, 300)}`);
  passed++;
  console.log('  ok - a 402 on a read route (get_balance) is reported, never paid (round 3)');
}

offer = { scheme: 'exact', network: 'base', asset: USDC_BASE, payTo: PAY_TO, maxAmountRequired: '5000000', requiredDecimals: 6 };
{
  const before = sends.length;
  const text = await getBalance();
  assert.equal(sends.length, before, 'an exact offer above the cap is not paid');
  assert.match(text, /exceeds the AGENTWALLET_MAX_AUTOPAY cap/, `unexpected tool text: ${text.slice(0, 300)}`);
  passed++;
  console.log('  ok - control: the cap still applies to exact offers');
}

api.close();
console.log(`\n${passed} passed\n`);
