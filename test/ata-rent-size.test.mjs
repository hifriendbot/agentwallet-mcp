/**
 * Regression tests for the rent an SPL send is charged under AGENTWALLET_MAX_TX_SOL
 * (2026-10-02 report).
 *
 * When the recipient has no token account, the send creates one and the payer
 * funds its rent. That rent was checked against the SOL cap at the classic
 * 165-byte size, but a Token-2022 account is bigger: an account-type byte, an
 * ImmutableOwner entry on every associated account, and one entry per account
 * extension the mint requires. The size is now derived from the mint.
 *
 * Part 1 drives localSplTransfer against a mock cluster and checks the size the
 * rent was asked for, and that a cap sitting between the old estimate and the
 * real rent now refuses. Part 2 checks the size arithmetic directly. Nothing is
 * signed or broadcast: the mock serves no blockhash, so every send stops there.
 *
 * Run with: node test/ata-rent-size.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { Keypair } from '@solana/web3.js';

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022 = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';

/** A Token-2022 mint: 165 bytes of base layout, type byte 1, then the given [type, valueLength] entries. */
function mint2022(extensions) {
  const bytes = [...new Uint8Array(165), 1];
  for (const [type, len] of extensions) bytes.push(type & 0xff, type >> 8, len & 0xff, len >> 8, ...new Uint8Array(len));
  return Uint8Array.from(bytes);
}
const rentFor = (size) => (128 + size) * 6960; // lamports, the cluster's rent-exempt minimum
const fresh = () => Keypair.generate().publicKey.toBase58();
const account = (owner, bytes) => ({
  data: [Buffer.from(bytes).toString('base64'), 'base64'],
  executable: false, lamports: 1461600, owner, rentEpoch: 0, space: bytes.length,
});

// TransferFeeConfig, NonTransferable, TransferHook, Pausable: every mint
// extension that puts an extension on the token account.
const ALL_ACCOUNT_AFFECTING = [[1, 108], [9, 0], [14, 64], [26, 33]];

const MINTS = { classic: fresh(), plain2022: fresh(), loaded2022: fresh() };
const ACCOUNTS = {
  [MINTS.classic]: account(TOKEN_PROGRAM, new Uint8Array(82)),
  [MINTS.plain2022]: account(TOKEN_2022, new Uint8Array(82)),
  [MINTS.loaded2022]: account(TOKEN_2022, mint2022(ALL_ACCOUNT_AFFECTING)),
};

const calls = [];
const rentSizes = [];
const rpc = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const { id, method, params } = JSON.parse(body);
    calls.push(method);
    const send = (payload) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id, ...payload }));
    };
    if (method === 'getGenesisHash') return send({ result: MAINNET_GENESIS });
    if (method === 'getAccountInfo') return send({ result: { context: { slot: 1 }, value: ACCOUNTS[params[0]] ?? null } });
    if (method === 'getMinimumBalanceForRentExemption') { rentSizes.push(params[0]); return send({ result: rentFor(params[0]) }); }
    send({ error: { code: -32601, message: `mock: ${method} not served` } });
  });
});
await new Promise((r) => rpc.listen(0, '127.0.0.1', r));

process.env.AGENTWALLET_SOLANA_KEY = JSON.stringify(Array.from(Keypair.generate().secretKey));
process.env.AGENTWALLET_SOLANA_RPC_900 = `http://127.0.0.1:${rpc.address().port}`;
delete process.env.AGENTWALLET_MAX_TX_TOKEN;

const { localSplTransfer, associatedAccountSize } = await import('../build/local-solana.js');

/** Send to a fresh recipient under the given SOL cap; returns the message the send stopped with. */
async function send(mint, capSol) {
  if (capSol) process.env.AGENTWALLET_MAX_TX_SOL = capSol; else delete process.env.AGENTWALLET_MAX_TX_SOL;
  rentSizes.length = 0;
  try {
    await localSplTransfer(mint, fresh(), '1', 0, 900);
  } catch (e) {
    return e.message;
  }
  throw new Error('the mock serves no blockhash, so the send must stop before signing');
}

let passed = 0;
async function ok(name, fn) { await fn(); passed++; console.log(`  ok - ${name}`); }

try {
  /* ── Part 1: the cap sees the real rent ────────────────────────── */

  await ok('classic mint: rent is asked for 165 bytes', async () => {
    await send(MINTS.classic, null);
    assert.deepStrictEqual(rentSizes, [165]);
  });
  await ok('Token-2022 mint: rent is asked for 170 bytes, not 165', async () => {
    await send(MINTS.plain2022, null);
    assert.deepStrictEqual(rentSizes, [170]);
  });
  await ok('Token-2022 mint with extensions: rent is asked for 195 bytes', async () => {
    await send(MINTS.loaded2022, null);
    assert.deepStrictEqual(rentSizes, [195]);
  });

  // The report's shape: a cap above the 165-byte rent (0.00203928 SOL) but below
  // the real 195-byte rent (0.00224808 SOL). 1.13.2 let this through.
  await ok('a cap between the old estimate and the real rent now refuses', async () => {
    assert.match(await send(MINTS.loaded2022, '0.0021'), /exceeds AGENTWALLET_MAX_TX_SOL \(0\.0021 SOL\)/);
  });
  await ok('the same cap still allows a classic mint, whose rent it covers', async () => {
    assert.doesNotMatch(await send(MINTS.classic, '0.0021'), /AGENTWALLET_MAX_TX_SOL/);
  });
  await ok('a cap above the real rent allows the Token-2022 send', async () => {
    assert.doesNotMatch(await send(MINTS.loaded2022, '0.0023'), /AGENTWALLET_MAX_TX_SOL/);
  });
  await ok('nothing was broadcast', () => {
    assert.ok(!calls.includes('sendTransaction'));
  });

  /* ── Part 2: sizes ─────────────────────────────────────────────── */

  await ok('classic SPL: 165 whatever the mint data holds', () => {
    assert.strictEqual(associatedAccountSize(false, new Uint8Array(82)), 165);
  });
  await ok('Token-2022 mint with no extensions: 170 (type byte + ImmutableOwner)', () => {
    assert.strictEqual(associatedAccountSize(true, new Uint8Array(82)), 170);
  });
  await ok('transfer-fee mint: 182 (adds TransferFeeAmount)', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[1, 108]])), 182);
  });
  await ok('transfer-hook mint: 175 (adds TransferHookAccount)', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[14, 64]])), 175);
  });
  await ok('non-transferable and pausable mints: 174 each', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[9, 0]])), 174);
    assert.strictEqual(associatedAccountSize(true, mint2022([[26, 33]])), 174);
  });
  await ok('every account-affecting extension at once: 195, the largest real case', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022(ALL_ACCOUNT_AFFECTING)), 195);
  });
  await ok('mint-only extensions add nothing (confidential transfer, metadata, close authority)', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[4, 65], [18, 64], [3, 32], [19, 120]])), 170);
  });
  await ok('an extension newer than this release is over-counted, not ignored', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[40, 16]])), 170 + 4 + 64);
  });
  await ok('padding after the last entry and a stray trailing byte do not change the size', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[1, 108], [0, 0], [14, 64]])), 182);
    assert.strictEqual(associatedAccountSize(true, Uint8Array.from([...mint2022([[14, 64]]), 9])), 175);
  });
  await ok('the same extension listed twice is counted once', () => {
    assert.strictEqual(associatedAccountSize(true, mint2022([[1, 108], [1, 108]])), 182);
  });
} finally {
  rpc.close();
  delete process.env.AGENTWALLET_MAX_TX_SOL;
}

console.log(`\nata-rent-size: ${passed} passed`);
