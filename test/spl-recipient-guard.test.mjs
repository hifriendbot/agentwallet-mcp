/**
 * Regression tests for the Solana recipient guard (2026-10-02 report).
 *
 * assertRecipientIsWallet refused programs and token accounts, but it told a
 * token account by length (>= 165 bytes), so an 82-byte mint owned by the
 * token program passed as a wallet. An SPL send "to" a mint lands in
 * ATA(mint address, mint): gone for good, or sweepable by whoever kept that
 * mint's keypair. Ownership by a token program now refuses on its own.
 *
 * A local mock JSON-RPC server plays the cluster. Every refusal happens
 * before anything is signed; the two "passes the guard" cases stop at the
 * next step (the mint lookup) for the same reason.
 *
 * Run with: node test/spl-recipient-guard.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { Keypair } from '@solana/web3.js';

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const SYSTEM = '11111111111111111111111111111111';
const BPF_LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111';
const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

const fresh = () => Keypair.generate().publicKey.toBase58();
const account = (owner, bytes, executable = false) => ({
  data: [Buffer.from(bytes).toString('base64'), 'base64'],
  executable, lamports: 1461600, owner, rentEpoch: 0, space: bytes.length,
});

// Token-2022 with extensions: 165 bytes of base layout, then the account-type byte.
const t22 = (type) => { const b = new Uint8Array(200); b[165] = type; return b; };

const ADDR = {
  classicMint: fresh(), t22Mint: fresh(), tokenAccount: fresh(), t22TokenAccount: fresh(),
  oddTokenOwned: fresh(), program: fresh(), wallet: fresh(), unseen: fresh(),
};
const ACCOUNTS = {
  [ADDR.classicMint]: account(TOKEN_PROGRAM, new Uint8Array(82)),
  [ADDR.t22Mint]: account(TOKEN_2022, t22(1)),
  [ADDR.tokenAccount]: account(TOKEN_PROGRAM, new Uint8Array(165)),
  [ADDR.t22TokenAccount]: account(TOKEN_2022, t22(2)),
  [ADDR.oddTokenOwned]: account(TOKEN_PROGRAM, new Uint8Array(40)),
  [ADDR.program]: account(BPF_LOADER, new Uint8Array(36), true),
  [ADDR.wallet]: account(SYSTEM, new Uint8Array(0)),
  // ADDR.unseen and the USDC mint are deliberately absent: getAccountInfo answers null.
};

const calls = [];
const rpc = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const { id, method, params } = JSON.parse(body);
    calls.push(method);
    let result;
    if (method === 'getGenesisHash') result = MAINNET_GENESIS;
    else if (method === 'getAccountInfo') result = { context: { slot: 1 }, value: ACCOUNTS[params[0]] ?? null };
    else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32601, message: `mock: ${method} not served` } }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
  });
});
await new Promise((r) => rpc.listen(0, '127.0.0.1', r));

process.env.AGENTWALLET_SOLANA_KEY = JSON.stringify(Array.from(Keypair.generate().secretKey));
process.env.AGENTWALLET_SOLANA_RPC_900 = `http://127.0.0.1:${rpc.address().port}`;
delete process.env.AGENTWALLET_MAX_TX_TOKEN;
delete process.env.AGENTWALLET_MAX_TX_SOL;

const { localSplTransfer, localSolTransfer } = await import('../build/local-solana.js');

let passed = 0;
async function throws(name, fn, pattern) {
  try {
    await fn();
  } catch (e) {
    assert.match(e.message, pattern, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
    return;
  }
  throw new Error(`${name}: expected a refusal, but the call went through`);
}
const spl = (to) => () => localSplTransfer(USDC, to, '1000', 6, 900);
const sol = (to) => () => localSolTransfer(to, '1000', 900);

try {
  // The report: an 82-byte mint was shorter than the length gate and passed.
  await throws('SPL send to a classic mint is refused', spl(ADDR.classicMint), /token mint, not a wallet/);
  await throws('SPL send to a Token-2022 mint with extensions is refused as a mint', spl(ADDR.t22Mint), /token mint, not a wallet/);
  await throws('native SOL send to a mint is refused too', sol(ADDR.classicMint), /token mint, not a wallet/);

  // What the guard already did keeps working, with the same wording.
  await throws('SPL send to a token account is still refused', spl(ADDR.tokenAccount), /token account, not a wallet/);
  await throws('SPL send to a Token-2022 token account is still refused', spl(ADDR.t22TokenAccount), /token account, not a wallet/);
  await throws('SPL send to a program is still refused', spl(ADDR.program), /is a program, not a wallet/);

  // No length makes a token-program account a wallet.
  await throws('any other account the token program owns is refused', spl(ADDR.oddTokenOwned), /owned by the SPL token program/);

  // Ordinary recipients pass the guard. The mock has no USDC mint, so the send
  // stops at the very next step, which proves the guard let it through.
  await throws('a system-owned wallet passes the guard', spl(ADDR.wallet), /Mint .* not found on this cluster/);
  await throws('an address never seen on chain passes the guard', spl(ADDR.unseen), /Mint .* not found on this cluster/);

  assert.ok(!calls.includes('sendTransaction'), 'nothing may be broadcast in this test');
  assert.ok(!calls.includes('getLatestBlockhash'), 'no transaction may be assembled in this test');
  passed++;
  console.log('  ok - nothing was signed or broadcast');
} finally {
  rpc.close();
}

console.log(`\nspl-recipient-guard: ${passed} passed`);
