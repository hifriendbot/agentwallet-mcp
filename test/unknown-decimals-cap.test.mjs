/**
 * Regression test for AW-001: spending-cap bypass on tokens with fewer than
 * six decimals (reported privately, fixed in 1.10.5).
 *
 * The guard used to assume 6 decimals for any token outside the trusted
 * registry, on the stated belief that 6 was "the smallest in common use" and
 * therefore the tightest ceiling. It is not the smallest: GUSD and EURS use 2,
 * and some tokens use 0. For a token with d decimals, a ceiling evaluated at 6
 * is 10**(6-d) times too permissive, so a 2-decimal token could move 10,000x
 * the configured cap while the guard reported success.
 *
 * The fix resolves decimals from the trusted registry, then from the token's
 * own decimals() on chain, and falls back to 0. Zero is the only value that
 * cannot fail open: no token has fewer than 0 decimals, so a cap evaluated at 0
 * is never larger than the true one.
 *
 * This test pins the unresolvable case, which is what the reporter exploited:
 * an unknown token on an unreachable RPC must fail closed, not open.
 *
 * Run with: node test/unknown-decimals-cap.test.mjs
 */
import assert from 'node:assert';
import { encodeFunctionData, parseAbi } from 'viem';

const ABI = parseAbi(['function transfer(address,uint256) returns (bool)']);

// Not in the trusted registry, and the RPC below is deliberately dead, so
// decimals cannot be resolved from either source. This is the AW-001 path.
const UNKNOWN_TOKEN = '0x00000000000000000000000000000000000000AA';
const RECIP = '0x000000000000000000000000000000000000dEaD';
const CHAIN = 8453;

// Throwaway key, never used: the guard rejects before signing or any RPC call.
process.env.AGENTWALLET_PRIVATE_KEY = '0x' + '1'.repeat(64);
process.env.AGENTWALLET_MAX_TX_TOKEN = '10';
// Unreachable on purpose. If the guard ever needs this to fail closed, it is
// already wrong: an operator with a flaky RPC must not get a wider ceiling.
process.env[`AGENTWALLET_RPC_${CHAIN}`] = 'http://127.0.0.1:1/dead';

const { localSend } = await import('../build/local-wallet.js');

let passed = 0;

/**
 * 10,000,000 base units. Under the old code this passed a cap of 10, because
 * 10 evaluated at 6 decimals is exactly 10,000,000. Against a 2-decimal token
 * that is 100,000 real tokens, 10,000x the cap the operator set.
 */
{
  const data = encodeFunctionData({
    abi: ABI,
    functionName: 'transfer',
    args: [RECIP, 10000000n],
  });
  let msg = '';
  try {
    await localSend(CHAIN, UNKNOWN_TOKEN, 0n, data);
    throw new Error('AW-001: the guard let the low-decimal amount through');
  } catch (e) {
    msg = e.message;
  }
  assert.match(
    msg,
    /Blocked by local guard/,
    `AW-001: expected the local guard to block, got "${msg}"`
  );
  assert.match(
    msg,
    /evaluated at 0 decimals/,
    `AW-001: unresolvable decimals must evaluate the cap at 0, got "${msg}"`
  );
  passed++;
  console.log('  ok - blocks 10,000,000 base units of an unknown token against a cap of 10');
}

// The floor must still permit genuinely small movements, so the guard stays a
// ceiling rather than a blanket ban. At 0 decimals a cap of 10 means 10 base
// units, so 10 passes the guard and fails later at the dead RPC.
{
  const data = encodeFunctionData({
    abi: ABI,
    functionName: 'transfer',
    args: [RECIP, 10n],
  });
  let guardBlocked = false;
  try {
    await localSend(CHAIN, UNKNOWN_TOKEN, 0n, data);
  } catch (e) {
    guardBlocked = /Blocked by local guard/.test(e.message);
  }
  assert.strictEqual(guardBlocked, false, 'an amount at the cap must not be blocked by the guard');
  passed++;
  console.log('  ok - allows an amount exactly at the cap');
}

// Negative control: a known 6-decimal token still uses its registry value, so
// the fix did not turn every cap into a 0-decimal cap.
{
  const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // Base USDC, 6 decimals
  const data = encodeFunctionData({
    abi: ABI,
    functionName: 'transfer',
    args: [RECIP, 5000000n], // 5 USDC, under the cap of 10
  });
  let guardBlocked = false;
  try {
    await localSend(CHAIN, USDC, 0n, data);
  } catch (e) {
    guardBlocked = /Blocked by local guard/.test(e.message);
  }
  assert.strictEqual(guardBlocked, false, 'a known 6-decimal token must keep its registry decimals');
  passed++;
  console.log('  ok - keeps registry decimals for a known token (5 USDC under a cap of 10)');
}

console.log(`\nunknown-decimals-cap: ${passed} passed`);
