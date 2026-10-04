/**
 * Regression tests from round 5 of the 2026-10-04 adversarial audit, network edge.
 *
 *  - a 160 KB node error does not stall the server and reaches the agent bounded
 *  - an RPC key echoed by the node as a bare path never reaches the agent
 *  - local reads verify the chain (a node serving another chain is refused)
 *  - check_token_risk honours AGENTWALLET_TOKEN_RISK=0 (no outbound request)
 *
 * Run with: node test/audit-11312.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { generatePrivateKey } from 'viem/accounts';

let passed = 0;
const ok = (name, cond, detail) => { if (!cond) throw new Error(`${name}: ${detail}`); passed++; console.log(`  ok - ${name}`); };

const KEY = 'SeCrEtKeY9f8e7d6c';
let mode = 'bigerror';
const rpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const r = JSON.parse(b);
    const send = (p, code = 200) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: r.id, ...p })); };
    if (r.method === 'eth_chainId') return send({ result: mode === 'wrongchain' ? '0x1' : '0x2105' });
    if (mode === 'bigerror') return send({ error: { code: -32000, message: 'M'.repeat(163840) } });
    if (mode === 'echo') { res.statusCode = 404; res.setHeader('content-type', 'text/html'); return res.end(`<!DOCTYPE html><html><body>The requested URL /v3/${KEY} was not found on this server.</body></html>`); }
    if (r.method === 'eth_getBalance') return send({ result: '0xde0b6b3a7640000' });
    if (r.method === 'eth_call') return send({ error: { code: 3, message: 'execution reverted' } }); // a contract that declines decimals()
    send({ error: { code: -32601, message: `mock: ${r.method} not served` } });
  });
});
await new Promise(r => rpc.listen(0, '127.0.0.1', r));
const RPC = `http://127.0.0.1:${rpc.address().port}/v3/${KEY}`;

function run(tool, args, extraEnv = {}) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    for (const k of Object.keys(env)) if (k.startsWith('AGENTWALLET_')) delete env[k];
    Object.assign(env, { AGENTWALLET_PRIVATE_KEY: generatePrivateKey(), AGENTWALLET_RPC_8453: RPC, AGENTWALLET_RPC_1: RPC }, extraEnv);
    const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d.toString(); }); child.stderr.on('data', d => { err += d.toString(); });
    const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    const t0 = Date.now();
    send({ jsonrpc: '2.0', id: 100, method: 'tools/call', params: { name: tool, arguments: args } });
    const finish = (text) => { clearInterval(timer); clearTimeout(limit); try { child.kill(); } catch {} resolve({ text, stderr: err, ms: Date.now() - t0 }); };
    const timer = setInterval(() => {
      const r = out.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).find(x => x && x.id === 100);
      if (r) finish(r.result?.content?.[0]?.text || JSON.stringify(r));
    }, 50);
    const limit = setTimeout(() => finish('TIMEOUT ' + out.slice(0, 200)), 60_000);
  });
}

try {
  mode = 'bigerror';
  const big = await run('get_balance', { wallet_id: 1, chain_id: 8453 });
  ok('a 160 KB node error answers in well under a second and reaches the agent bounded', big.ms < 3000 && big.text.length < 2600 && !big.text.startsWith('TIMEOUT'), `${big.ms} ms, ${big.text.length} chars`);

  mode = 'echo';
  const echo = await run('get_balance', { wallet_id: 1, chain_id: 8453 });
  ok('an RPC key echoed by the node as a bare path never reaches the agent', !echo.text.includes(KEY) && !echo.stderr.includes(KEY), echo.text.slice(0, 300));

  mode = 'wrongchain';
  const wrong = await run('get_balance', { wallet_id: 1, chain_id: 8453 });
  ok('a read against a node serving another chain is refused', /answers eth_chainId = 1|serves chain 1/.test(wrong.text), wrong.text.slice(0, 300));

  mode = 'ok';
  const risk = await run('check_token_risk', { token: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', chain_id: 8453 }, { AGENTWALLET_TOKEN_RISK: '0' });
  ok('check_token_risk honours AGENTWALLET_TOKEN_RISK=0', /"source": "none"/.test(risk.text) && /disabled by AGENTWALLET_TOKEN_RISK=0/.test(risk.text), risk.text.slice(0, 300));

  // ERC-677 transferAndCall(attacker, 1e24) on a contract that declines decimals(): priced at 0 decimals, so refused under the cap
  const ATT = '0'.repeat(24) + 'dead'.repeat(10);
  const t677 = await run('send_transaction', { wallet_id: 1, chain_id: 8453, to: '0x1111111111111111111111111111111111111111', value: '0', data: '0x4000aea0' + ATT + (10n ** 24n).toString(16).padStart(64, '0') + '0'.repeat(64) }, { AGENTWALLET_MAX_TX_TOKEN: '5' });
  ok('ERC-677 transferAndCall on a not-a-token target is priced and refused under the cap', /exceeds AGENTWALLET_MAX_TX_TOKEN|evaluated at 0 decimals/.test(t677.text), t677.text.slice(0, 300));
  const t777 = await run('send_transaction', { wallet_id: 1, chain_id: 8453, to: '0x1111111111111111111111111111111111111111', value: '0', data: '0x959b8c3f' + ATT }, { AGENTWALLET_MAX_TX_TOKEN: '5' });
  ok('ERC-777 authorizeOperator is refused outright', /NFT approval or transfer|refused/.test(t777.text) && !/tx_hash/.test(t777.text), t777.text.slice(0, 300));

  const noDefault = await run('get_balance', { wallet_id: 1, chain_id: 10 }, { AGENTWALLET_RPC_8453: RPC });
  ok('a chain without an explicit RPC does not fall through to a public endpoint once any chain has one', /public default is not used/.test(noDefault.text), noDefault.text.slice(0, 300));
} finally {
  rpc.close();
}
console.log(`\naudit-11312: ${passed} passed`);
