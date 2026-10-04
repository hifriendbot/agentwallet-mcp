/**
 * Regression tests from round 4 of the 2026-10-04 adversarial audit.
 *
 *  - a leading space in AGENTWALLET_API_URL no longer defeats the https-only check
 *  - a misspelled AGENTWALLET_* name and a malformed AGENTWALLET_MAX_AUTOPAY_PER_HOUR refuse to start
 *  - an unknown tool argument is an error that names it
 *  - max_payment is validated before any network activity
 *  - Solana: the SPL cap is evaluated at the decimals the instruction carries (decimals-flip)
 *  - Solana: the signature reported is the one computed here, and a node answering another is called out
 *
 * Run with: node test/audit-11310.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { Keypair, Transaction } from '@solana/web3.js';
import bs58 from 'bs58';
import { WebSocketServer } from 'ws';

let passed = 0;
const ok = (name, cond, detail) => { if (!cond) throw new Error(`${name}: ${detail}`); passed++; console.log(`  ok - ${name}`); };

/** Start the server with env and either call a tool or just watch it exit. */
function run(env, call) {
  return new Promise((resolve) => {
    const e = { ...process.env };
    for (const k of Object.keys(e)) if (k.startsWith('AGENTWALLET_')) delete e[k];
    Object.assign(e, env);
    const child = spawn(process.execPath, ['build/index.js'], { env: e, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', d => { out += d.toString(); });
    child.stderr.on('data', d => { err += d.toString(); });
    const send = (m) => { try { child.stdin.write(JSON.stringify(m) + '\n'); } catch {} };
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
    send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
    if (call) send({ jsonrpc: '2.0', id: 100, method: 'tools/call', params: { name: call.name, arguments: call.args } });
    const finish = (text, exit) => { clearInterval(timer); clearTimeout(limit); try { child.kill(); } catch {} resolve({ text, stderr: err, exit }); };
    child.on('exit', (code) => { if (code !== null && code !== 0) finish('', code); });
    const timer = setInterval(() => {
      const r = out.split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).find(x => x && x.id === (call ? 100 : 1));
      if (r) finish(call ? (r.result?.content?.[0]?.text || JSON.stringify(r)) : 'initialized', 0);
    }, 100);
    const limit = setTimeout(() => finish(out, 'timeout'), 25_000);
  });
}

const hosted = { AGENTWALLET_API_URL: 'http://127.0.0.1:1', AGENTWALLET_USER: 'u', AGENTWALLET_PASS: 'p' };

{
  const r = await run({ ...hosted, AGENTWALLET_API_URL: ' http://127.0.0.2:1' });
  ok('a leading space does not slip plain http past the https check', r.exit !== 0 && /must be https/.test(r.stderr), `exit=${r.exit} stderr=${r.stderr.slice(0, 200)}`);
}
{
  const r = await run({ ...hosted, AGENTWALLET_MAX_TX_TOKENS: '5' });
  ok('a misspelled AGENTWALLET_* name refuses to start', r.exit !== 0 && /Unknown environment variable AGENTWALLET_MAX_TX_TOKENS/.test(r.stderr), `exit=${r.exit} stderr=${r.stderr.slice(0, 200)}`);
}
{
  const r = await run({ ...hosted, AGENTWALLET_MAX_AUTOPAY_PER_HOUR: 'abc' });
  ok('a malformed per-hour limit refuses to start', r.exit !== 0 && /MAX_AUTOPAY_PER_HOUR must be a whole number/.test(r.stderr), `exit=${r.exit} stderr=${r.stderr.slice(0, 200)}`);
}
{
  const r = await run({ ...hosted, AGENTWALLET_PRIVATE_KEY: '0x' + '11'.repeat(32), AGENTWALLET_KEYFILE: 'C:/nope' });
  ok('two EVM key sources refuse to start', r.exit !== 0 && /Both AGENTWALLET_PRIVATE_KEY and AGENTWALLET_KEYFILE/.test(r.stderr), `exit=${r.exit} stderr=${r.stderr.slice(0, 200)}`);
}
{
  const r = await run(hosted, { name: 'get_wallet', args: { wallet_id: 1, walet_id: 2 } });
  ok('an unknown tool argument is an error that names it', /walet_id/.test(r.text) && !/ECONNREFUSED|fetch failed/.test(r.text), r.text.slice(0, 300));
}
{
  const r = await run(hosted, { name: 'pay_x402', args: { url: 'https://paywall.example/x', wallet_id: 1, max_payment: 'abc' } });
  ok('max_payment is validated before any fetch', /nothing was fetched/.test(r.text), r.text.slice(0, 300));
}

/* ── Solana: decimals flip and signature mismatch ── */
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const SYSTEM = '11111111111111111111111111111111';
const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const payer = Keypair.generate();
const MINT = Keypair.generate().publicKey.toBase58(), WALLET = Keypair.generate().publicKey.toBase58();
const account = (owner, bytes, lamports = 1461600) => ({ data: [Buffer.from(bytes).toString('base64'), 'base64'], executable: false, lamports, owner, rentEpoch: 0, space: bytes.length });
let decimalsAnswers = [];
let fakeSignature = null;
const received = [];
const srpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const { id, method, params } = JSON.parse(b);
    const send = (p) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id, ...p })); };
    if (method === 'getGenesisHash') return send({ result: MAINNET_GENESIS });
    if (method === 'getAccountInfo') {
      if (params[0] === MINT && params[1]?.encoding === 'jsonParsed') {
        const d = decimalsAnswers.length > 1 ? decimalsAnswers.shift() : decimalsAnswers[0];
        return send({ result: { context: { slot: 1 }, value: { data: { program: 'spl-token', parsed: { type: 'mint', info: { decimals: d, supply: '1', isInitialized: true, mintAuthority: null, freezeAuthority: null } }, space: 82 }, executable: false, lamports: 1461600, owner: TOKEN_PROGRAM, rentEpoch: 0, space: 82 } } });
      }
      if (params[0] === MINT) return send({ result: { context: { slot: 1 }, value: account(TOKEN_PROGRAM, new Uint8Array(82)) } });
      if (params[0] === WALLET) return send({ result: { context: { slot: 1 }, value: account(SYSTEM, new Uint8Array(0)) } });
      return send({ result: { context: { slot: 1 }, value: null } });
    }
    if (method === 'getMinimumBalanceForRentExemption') return send({ result: (128 + params[0]) * 6960 });
    if (method === 'getLatestBlockhash') return send({ result: { context: { slot: 1 }, value: { blockhash: bs58.encode(Buffer.alloc(32, 7)), lastValidBlockHeight: 1000 } } });
    if (method === 'sendTransaction') {
      const tx = Transaction.from(Buffer.from(params[0], 'base64'));
      received.push(tx);
      return send({ result: fakeSignature ?? bs58.encode(tx.signature) });
    }
    if (method === 'getSignatureStatuses') return send({ result: { context: { slot: 1 }, value: [{ slot: 1, confirmations: 1, err: null, confirmationStatus: 'confirmed' }] } });
    if (method === 'getBlockHeight') return send({ result: 10 });
    send({ error: { code: -32601, message: `mock: ${method} not served` } });
  });
});
// web3.js confirms over a WebSocket on the HTTP port + 1, so both ports are chosen together.
let port = 0;
for (let attempt = 0; attempt < 20 && !port; attempt++) {
  const p = 30000 + Math.floor(Math.random() * 20000);
  try { await new Promise((res, rej) => { srpc.once('error', rej); srpc.listen(p, '127.0.0.1', () => { srpc.removeListener('error', rej); res(); }); }); port = p; } catch { /* taken, try another */ }
}
if (!port) throw new Error('no free port pair');
const wss = new WebSocketServer({ host: '127.0.0.1', port: port + 1 });
wss.on('connection', (socket) => {
  socket.on('message', (m) => {
    const { id, method } = JSON.parse(m.toString());
    if (method === 'signatureSubscribe') {
      socket.send(JSON.stringify({ jsonrpc: '2.0', id, result: 1 }));
      setTimeout(() => socket.send(JSON.stringify({ jsonrpc: '2.0', method: 'signatureNotification', params: { result: { context: { slot: 2 }, value: { err: null } }, subscription: 1 } })), 50);
    } else {
      socket.send(JSON.stringify({ jsonrpc: '2.0', id, result: true }));
    }
  });
});
const solEnv = { AGENTWALLET_SOLANA_KEY: JSON.stringify(Array.from(payer.secretKey)), AGENTWALLET_SOLANA_RPC_900: `http://127.0.0.1:${port}`, AGENTWALLET_MAX_TX_TOKEN: '100' };
try {
  decimalsAnswers = [6, 18, 6, 6, 6, 6];
  const flip = await run(solEnv, { name: 'transfer_token', args: { wallet_id: 1, chain_id: 900, token: MINT, to: WALLET, amount: '1000000', decimals: 6 } });
  // There is no separate cap-side read any more: the node's second answer (18) hits the strict check and refuses; a consistent 6 hits the cap.
  ok('decimals-flip: a 1,000,000-token send under a 100-token cap is refused whatever the node says on a second read', /exceeds AGENTWALLET_MAX_TX_TOKEN|has 18 decimals; refusing/.test(flip.text) && received.length === 0, flip.text.slice(0, 300));
  decimalsAnswers = [6];
  const honest = await run(solEnv, { name: 'transfer_token', args: { wallet_id: 1, chain_id: 900, token: MINT, to: WALLET, amount: '1000000', decimals: 6 } });
  ok('with consistent decimals the cap itself refuses', /exceeds AGENTWALLET_MAX_TX_TOKEN \(100, evaluated at 6 decimals\)/.test(honest.text) && received.length === 0, honest.text.slice(0, 300));

  decimalsAnswers = [6];
  fakeSignature = bs58.encode(Buffer.alloc(64, 9));
  const fake = await run(solEnv, { name: 'transfer_token', args: { wallet_id: 1, chain_id: 900, token: MINT, to: WALLET, amount: '1', decimals: 6 } });
  ok('a node answering a different signature is called out, with the real one', /was BROADCAST/.test(fake.text) && /different signature/.test(fake.text) && received.length === 1 && fake.text.includes(bs58.encode(received[0].signature)), fake.text.slice(0, 400));

  fakeSignature = null;
  const good = await run(solEnv, { name: 'transfer_token', args: { wallet_id: 1, chain_id: 900, token: MINT, to: WALLET, amount: '1', decimals: 6 } });
  ok('an honest node: the reported signature is the locally computed one', received.length === 2 && good.text.includes(bs58.encode(received[1].signature)), good.text.slice(0, 300));
} finally {
  srpc.close();
  wss.close();
}

console.log(`\naudit-11310: ${passed} passed`);
