/**
 * Live x402 driver: runs pay_x402 through the real stdio MCP server in local
 * self-custody mode against a public endpoint and prints the tool result.
 *
 *   node test/x402-live.mjs <url> [method] [json-body] [max_payment]
 *
 * Environment: AGENTWALLET_PRIVATE_KEY (defaults to a zero-balance throwaway key,
 * in which case a spec-compliant facilitator answers "insufficient funds": that
 * still proves the payment header and signature were accepted, which is the
 * point). Not part of `npm test`; it touches the network.
 */
import { spawn } from 'node:child_process';

const [url, method = 'GET', body = '', maxPayment = '1'] = process.argv.slice(2);
if (!url) { console.error('usage: node test/x402-live.mjs <url> [method] [json-body] [max_payment]'); process.exit(2); }

const TEST_KEY = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'; // go-ethereum docs key, never funded

const env = {
  ...process.env,
  AGENTWALLET_PRIVATE_KEY: process.env.AGENTWALLET_PRIVATE_KEY || TEST_KEY,
  AGENTWALLET_API_URL: process.env.AGENTWALLET_API_URL || 'http://127.0.0.1:1',
  AGENTWALLET_MAX_AUTOPAY: maxPayment,
};

const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let out = '', err = '';
child.stdout.on('data', d => { out += d.toString(); });
child.stderr.on('data', d => { err += d.toString(); });
const send = m => child.stdin.write(JSON.stringify(m) + '\n');

send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'live', version: '1' } } });
send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
const args = { url, wallet_id: 1, method, max_payment: maxPayment };
if (body) args.body = body;
send({ jsonrpc: '2.0', id: 100, method: 'tools/call', params: { name: 'pay_x402', arguments: args } });

setTimeout(() => {
  child.kill();
  const responses = out.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const r = responses.find(x => x.id === 100);
  if (!r) { console.log('no response; stderr:\n' + err); process.exit(1); }
  const text = r.result?.content?.[0]?.text;
  try { console.log(JSON.stringify(JSON.parse(text), null, 2)); } catch { console.log(text || JSON.stringify(r, null, 2)); }
  if (err.trim()) console.log('\nstderr:\n' + err);
}, 45000);
