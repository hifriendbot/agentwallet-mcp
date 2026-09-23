/**
 * x402 Payer Report driver: pays a list of endpoints once each through the real
 * stdio MCP server (hosted or local mode, from the environment) and writes a
 * results table. Usage:
 *   node test/pay-bazaar.mjs <urls.json> <out.json> [max_payment] [wallet_id]
 * urls.json: [{url, method?, body?}]
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';

const [listFile, outFile, maxPayment = '0.01', walletId = '14'] = process.argv.slice(2);
const list = JSON.parse(fs.readFileSync(listFile, 'utf8'));
const env = { ...process.env, AGENTWALLET_MAX_AUTOPAY: maxPayment, AGENTWALLET_APPROVALS: '0' };
const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
const pending = new Map();
let buf = '';
child.stdout.on('data', d => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    try { const m = JSON.parse(line); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } } catch {}
  }
});
child.stderr.on('data', () => {});
const send = m => child.stdin.write(JSON.stringify(m) + '\n');
const call = (id, name, args, ms = 60000) => new Promise(res => {
  const t = setTimeout(() => { pending.delete(id); res({ timeout: true }); }, ms);
  pending.set(id, m => { clearTimeout(t); res(m); });
  send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
});

send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'payer-report', version: '1' } } });
send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
await new Promise(r => setTimeout(r, 1500));

const results = [];
let id = 100;
for (const e of list) {
  id++;
  const args = { url: e.url, wallet_id: Number(walletId), method: e.method || 'GET', max_payment: maxPayment };
  if (e.body) args.body = typeof e.body === 'string' ? e.body : JSON.stringify(e.body);
  const m = await call(id, 'pay_x402', args);
  let r = {};
  if (m.timeout) r = { error: 'timeout' };
  else if (m.error) r = { error: m.error.message };
  else if (m.result?.isError) r = { error: String(m.result.content?.[0]?.text || '').slice(0, 300) };
  else { try { r = JSON.parse(m.result.content[0].text); } catch { r = { error: 'unparseable' }; } }
  const row = {
    url: e.url, method: args.method, status: r.status ?? null, payment_required: r.payment_required ?? null, payment_made: r.payment_made ?? null,
    amount: r.amount ?? null, token: r.token ?? null, network: r.network ?? null, method_used: r.payment_method ?? null,
    tx: r.tx_hash ?? r.settlement?.transaction ?? null, error: r.error ?? r.retry_error ?? null,
  };
  results.push(row);
  console.log(`${row.payment_made ? 'PAID ' : (row.payment_required === false ? 'FREE ' : 'FAIL ')} ${row.status ?? '-'} ${row.amount ?? ''} ${e.url} ${row.tx ? row.tx.slice(0, 18) : (row.error ? String(row.error).slice(0, 90) : '')}`);
  fs.writeFileSync(outFile, JSON.stringify(results, null, 1));
  await new Promise(r => setTimeout(r, Number(process.env.PAY_PACE_MS || 0)));
}
child.kill();
const paid = results.filter(r => r.payment_made);
console.log(`\n${paid.length} paid, ${results.filter(r => r.payment_required === false).length} free, ${results.length - paid.length - results.filter(r => r.payment_required === false).length} failed`);
