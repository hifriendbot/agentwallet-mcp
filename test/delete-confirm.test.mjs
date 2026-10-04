/**
 * delete_wallet names the wallet it deletes (2026-10-04 audit, server finding F3).
 *
 * A leaked API key used to be enough to destroy a wallet key with one DELETE.
 * The server now asks for confirm = the wallet address; the tool reads the
 * wallet first and sends that address, and refuses to delete when the wallet
 * cannot be read. Hosted mode only: local mode refuses delete outright.
 *
 * Run with: node test/delete-confirm.test.mjs
 */
import assert from 'node:assert';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';

const ADDRESS = '0x1234567890AbcdEF1234567890aBcdef12345678';
const hits = [];
const api = createServer((req, res) => {
  let body = '';
  req.on('data', c => body += c);
  req.on('end', () => {
    hits.push({ method: req.method, url: req.url, body });
    const json = (code, obj) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(obj)); };
    if (req.method === 'GET' && req.url === '/wallets/7') return json(200, { id: 7, wallet_address: ADDRESS, chain_id: 8453 });
    if (req.method === 'GET' && req.url === '/wallets/8') return json(404, { error: 'Wallet not found or access denied.' });
    if (req.method === 'DELETE' && req.url === '/wallets/7') {
      let parsed = null; try { parsed = JSON.parse(body); } catch {}
      if (!parsed || String(parsed.confirm).toLowerCase() !== ADDRESS.toLowerCase()) return json(400, { error: 'confirm must be the wallet address of wallet #7; nothing was deleted.' });
      return json(200, { deleted: true });
    }
    json(404, { error: `mock: ${req.method} ${req.url} not served` });
  });
});
await new Promise(r => api.listen(0, '127.0.0.1', r));

function run(tool, args) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    for (const k of Object.keys(env)) if (k.startsWith('AGENTWALLET_')) delete env[k];
    Object.assign(env, { AGENTWALLET_API_URL: `http://127.0.0.1:${api.address().port}`, AGENTWALLET_USER: 'u', AGENTWALLET_PASS: 'p' });
    const child = spawn(process.execPath, ['build/index.js'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', d => { out += d.toString(); });
    child.stderr.on('data', () => {});
    const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    send({ jsonrpc: '2.0', id: 100, method: 'tools/call', params: { name: tool, arguments: args } });
    const finish = (text) => { clearInterval(timer); clearTimeout(limit); try { child.kill(); } catch {} resolve(text); };
    const timer = setInterval(() => {
      const r = out.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).find(x => x && x.id === 100);
      if (r) finish(r.result?.content?.[0]?.text || JSON.stringify(r));
    }, 100);
    const limit = setTimeout(() => finish(out), 25_000);
  });
}

let passed = 0;
const ok = (name, cond, detail) => { if (!cond) throw new Error(`${name}: ${detail}`); passed++; console.log(`  ok - ${name}`); };
try {
  const t = await run('delete_wallet', { wallet_id: 7 });
  ok('delete_wallet reads the wallet, then deletes with confirm = its address', /"deleted": ?true/.test(t), t.slice(0, 300));
  const del = hits.find(h => h.method === 'DELETE');
  ok('the DELETE carried the address', del && JSON.parse(del.body).confirm === ADDRESS, JSON.stringify(del));
  ok('the read came first', hits[0].method === 'GET' && hits[0].url === '/wallets/7', JSON.stringify(hits.map(h => h.method + ' ' + h.url)));

  hits.length = 0;
  const miss = await run('delete_wallet', { wallet_id: 8 });
  ok('an unreadable wallet is not deleted', !hits.some(h => h.method === 'DELETE') && /not found|could not be read|nothing was deleted/i.test(miss), miss.slice(0, 300));
} finally {
  api.close();
}
console.log(`\ndelete-confirm: ${passed} passed`);
