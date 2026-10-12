/**
 * Live checks for 1.14.0 (network; not part of npm test):
 *  - discover_x402 against the real Bazaar
 *  - quote_x402 against a real x402 endpoint (nothing signed)
 *  - approval.above with a client that declares elicitation: the server asks,
 *    the client declines, nothing is signed
 * Run: node test/live-1140.mjs
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generatePrivateKey } from 'viem/accounts';

const dir = mkdtempSync(join(tmpdir(), 'agw-live-'));
const policy = join(dir, 'policy.json');
writeFileSync(policy, JSON.stringify({ version: 1, name: 'live', budget: { daily: '1' }, approval: { above: '0.001', timeout_seconds: 60 } }));
const env = { ...process.env, AGENTWALLET_PRIVATE_KEY: generatePrivateKey(), AGENTWALLET_API_URL: 'http://127.0.0.1:1', AGENTWALLET_POLICY: policy };
delete env.AGENTWALLET_KEYFILE;

const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
let buf = '';
const pending = new Map();
let elicited = null;
child.stdout.on('data', d => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.method === 'elicitation/create') {
      elicited = m.params;
      console.log('SERVER ASKED:\n' + m.params.message.split('\n').map(l => '   ' + l).join('\n'));
      send({ jsonrpc: '2.0', id: m.id, result: { action: 'accept', content: { approve: false } } });
      continue;
    }
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  }
});
child.stderr.on('data', d => process.stderr.write('[stderr] ' + d));
const send = m => child.stdin.write(JSON.stringify(m) + '\n');
const call = (id, name, args, ms = 90000) => new Promise(res => {
  const t = setTimeout(() => { pending.delete(id); res({ timeout: true }); }, ms);
  pending.set(id, m => { clearTimeout(t); res(m); });
  send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
});
const text = m => { try { return JSON.parse(m.result.content[0].text); } catch { return m; } };

send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: { elicitation: {} }, clientInfo: { name: 'live', version: '1' } } });
send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
await new Promise(r => setTimeout(r, 1500));

const d = text(await call(10, 'discover_x402', { query: 'weather', limit: 3 }));
console.log('discover_x402:', JSON.stringify({ scanned: d.scanned, total: d.total, next_offset: d.next_offset, first: d.items?.[0] }, null, 1).slice(0, 1200));

const q = text(await call(11, 'quote_x402', { url: 'https://api.ozdreamtools.de/api/holidays', method: 'POST', body: JSON.stringify({ year: 2026, state: 'BY' }) }));
console.log('quote_x402:', JSON.stringify(q, null, 1).slice(0, 1500));

const p = text(await call(12, 'pay_x402', { url: 'https://api.ozdreamtools.de/api/holidays', method: 'POST', body: JSON.stringify({ year: 2026, state: 'BY' }), wallet_id: 1 }));
console.log('pay_x402 with approval.above and a declining human:', JSON.stringify({ human_approval: p.human_approval, payment_made: p.payment_made, error: p.error }, null, 1));
console.log('elicitation request seen by the client:', Boolean(elicited));

const sp = text(await call(13, 'spend_policy', {}));
console.log('spend_policy.human_approval_channel:', sp.human_approval_channel, '| ledger entries:', sp.ledger.entries);
child.kill();
