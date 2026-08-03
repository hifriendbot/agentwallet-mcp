/**
 * Regression tests for the SPL side of AGENTWALLET_MAX_TX_TOKEN.
 *
 * AGENTWALLET_MAX_TX_SOL only ever bounded native SOL. localSplTransfer had no
 * guard at all, so USDC on Solana (the asset the x402 rail actually settles in)
 * left a local-mode wallet with no ceiling.
 *
 * Run with: node test/spl-cap.test.mjs
 */
import assert from 'node:assert';
import { Keypair } from '@solana/web3.js';

// A throwaway keypair. Never signs: every case is refused by the guard before
// any RPC call or signature.
process.env.AGENTWALLET_SOLANA_KEY = JSON.stringify(Array.from(Keypair.generate().secretKey));
process.env.AGENTWALLET_MAX_TX_TOKEN = '1';

const USDC = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'; // 6 decimals
const DEST = '11111111111111111111111111111111';
const { localSplTransfer } = await import('../build/local-solana.js');

let passed = 0;
async function blocked(name, raw, decimals, pattern) {
  try {
    await localSplTransfer(USDC, DEST, raw, decimals, 900);
    throw new Error(`${name}: expected the guard to block this`);
  } catch (e) {
    assert.match(e.message, pattern, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}

await blocked(
  'blocks a 1,000,000 USDC SPL transfer against a cap of 1',
  '1000000000000', 6, /AGENTWALLET_MAX_TX_TOKEN/
);

// The same trust boundary as the x402 bypass: a caller-supplied decimals value
// must not be able to widen the ceiling.
await blocked(
  'caller-supplied decimals cannot widen the cap',
  '1000000000000', 18, /evaluated at 6 decimals/
);

console.log(`\nspl-cap: ${passed} passed`);
