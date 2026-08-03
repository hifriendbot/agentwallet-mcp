/**
 * Regression tests for AGENTWALLET_MAX_TX_TOKEN.
 *
 * The native per-transaction cap never saw ERC-20 movement: a token transfer is
 * `to = tokenContract, value = 0, amount in calldata`, so assertWithinNativeCap
 * compared 0 against the cap and always passed. In local mode there is no
 * server-side limit behind it, so a wallet holding USDC was effectively
 * uncapped even with AGENTWALLET_MAX_TX_NATIVE set.
 *
 * Run with: node test/token-cap.test.mjs
 */
import assert from 'node:assert';
import { encodeFunctionData, parseAbi } from 'viem';

const ABI = parseAbi([
  'function transfer(address,uint256) returns (bool)',
  'function approve(address,uint256) returns (bool)',
]);
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'; // Base USDC, 6 decimals
const RECIP = '0x000000000000000000000000000000000000dEaD';

// A throwaway key. Never used to sign: every blocked case below is rejected by
// the guard before any RPC call or signing happens.
process.env.AGENTWALLET_PRIVATE_KEY = '0x' + '1'.repeat(64);
process.env.AGENTWALLET_MAX_TX_TOKEN = '1';

const { localSend } = await import('../build/local-wallet.js');

let passed = 0;

async function blocked(name, amount, fn, pattern) {
  const data = encodeFunctionData({ abi: ABI, functionName: fn, args: [RECIP, amount] });
  try {
    await localSend(8453, USDC, 0n, data);
    throw new Error(`${name}: expected the guard to block this`);
  } catch (e) {
    assert.match(e.message, pattern, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}

await blocked(
  'blocks a 1,000,000 USDC transfer against a cap of 1',
  1000000000000n, 'transfer', /AGENTWALLET_MAX_TX_TOKEN/
);

await blocked(
  'blocks an oversized approval (an unbounded allowance is a drain vector)',
  2000000n, 'approve', /approval .* exceeds/
);

await blocked(
  'blocks a max-uint256 approval',
  (1n << 256n) - 1n, 'approve', /approval .* exceeds/
);

// Under the cap the guard must not be what stops it. Failing later at the RPC
// (this key holds nothing) proves the guard let it through.
{
  const data = encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [RECIP, 500000n] }); // 0.5 USDC
  let guardBlocked = false;
  try {
    await localSend(8453, USDC, 0n, data);
  } catch (e) {
    guardBlocked = /AGENTWALLET_MAX_TX_TOKEN|Blocked by local guard/.test(e.message);
  }
  assert.strictEqual(guardBlocked, false, 'a 0.5 USDC transfer must pass a cap of 1');
  passed++;
  console.log('  ok - allows a 0.5 USDC transfer under the cap of 1');
}

console.log(`\ntoken-cap: ${passed} passed`);
