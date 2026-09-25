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

// 2026-09-25 report: the selector table was an allowlist that returned early
// for anything it did not recognise, so these three went through uncapped.
const PERMIT2 = '0x000000000022D473030F116dDEE9F6B43aC78BA3';
const ABI2 = parseAbi([
  'function increaseAllowance(address,uint256) returns (bool)',
  'function approve(address,address,uint160,uint48)',
]);

async function blockedRaw(name, to, data, pattern) {
  try {
    await localSend(8453, to, 0n, data);
    throw new Error(`${name}: expected the guard to block this`);
  } catch (e) {
    assert.match(e.message, pattern, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}
async function notGuardBlocked(name, to, data) {
  let guardBlocked = false;
  try { await localSend(8453, to, 0n, data); }
  catch (e) { guardBlocked = /AGENTWALLET_MAX_TX_TOKEN|Blocked by local guard/.test(e.message); }
  assert.strictEqual(guardBlocked, false, `${name}: the guard must not be what stops this`);
  passed++;
  console.log(`  ok - ${name}`);
}

await blockedRaw(
  'blocks an oversized increaseAllowance (was uncapped)',
  USDC, encodeFunctionData({ abi: ABI2, functionName: 'increaseAllowance', args: [RECIP, 2000000n] }),
  /allowance increase .* exceeds/
);
await blockedRaw(
  'blocks an oversized direct Permit2 approve (was uncapped)',
  PERMIT2, encodeFunctionData({ abi: ABI2, functionName: 'approve', args: [USDC, RECIP, 2000000n, 0] }),
  /Permit2 approval .* exceeds/
);
await blockedRaw(
  'refuses calldata it cannot price when the target is a token contract',
  USDC, '0x12345678' + '0'.repeat(128),
  /not one AGENTWALLET_MAX_TX_TOKEN can price/
);
await blockedRaw(
  'refuses calldata it cannot price when the target is Permit2',
  PERMIT2, '0x12345678' + '0'.repeat(128),
  /not one AGENTWALLET_MAX_TX_TOKEN can price/
);
await notGuardBlocked(
  'allows an increaseAllowance under the cap',
  USDC, encodeFunctionData({ abi: ABI2, functionName: 'increaseAllowance', args: [RECIP, 500000n] })
);
await notGuardBlocked(
  'allows a Permit2 approve under the cap',
  PERMIT2, encodeFunctionData({ abi: ABI2, functionName: 'approve', args: [USDC, RECIP, 500000n, 0] })
);
await notGuardBlocked(
  'allows unpriced calldata to a non-token contract (it can only pull what was approved)',
  '0x4200000000000000000000000000000000000016', '0x12345678' + '0'.repeat(128) // Base L2ToL1MessagePasser, no decimals()
);
process.env.AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS = '1';
await notGuardBlocked(
  'AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1 lets unpriced token calldata through deliberately',
  USDC, '0x12345678' + '0'.repeat(128)
);
delete process.env.AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS;

console.log(`\ntoken-cap: ${passed} passed`);
