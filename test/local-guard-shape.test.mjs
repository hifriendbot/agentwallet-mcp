/**
 * Regression tests for the 2026-09-27 audit fixes in the EVM local guard:
 *
 *  - a truncated amount word REFUSES instead of returning (pre-0.5 Solidity
 *    zero-pads short calldata, so "let the node reject it" was wrong)
 *  - calldata must be even-length 0x hex before it reaches the guard or viem
 *  - sub-4-byte calldata aimed at a token is refused, not skipped
 *  - the EIP-3009 / Permit2 local signers refuse windows past the clamp
 *
 * All cases are rejected by the guard before any RPC call or signing.
 * Run with: node test/local-guard-shape.test.mjs
 */
import assert from 'node:assert';

process.env.AGENTWALLET_PRIVATE_KEY = '0x' + '2'.repeat(64);
process.env.AGENTWALLET_MAX_TX_TOKEN = '1';
delete process.env.AGENTWALLET_X402_MAX_TIMEOUT;

const { localSend, localSignAuthorization, localSignPermit2Upto } = await import('../build/local-wallet.js');

const WETH_MAINNET = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2'; // in the wrapped-native table, 18 decimals
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';        // Base USDC, 6 decimals, in the registry
const ATTACKER = '000000000000000000000000000000000000000000000000000000000000dead';

let passed = 0;
async function refused(name, chainId, to, data, pattern) {
  try {
    await localSend(chainId, to, 0n, data);
    throw new Error(`${name}: expected refusal`);
  } catch (e) {
    assert.match(e.message, pattern, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}

// transfer(address,uint256) with the amount word one byte short: WETH9 on
// mainnet would read it shifted left by 8 bits (256x). 1.12.6 returned here.
await refused('truncated amount word is refused, not allowed',
  8453, USDC, '0xa9059cbb' + ATTACKER + 'ff'.repeat(31), /truncated/);

await refused('truncated Permit2 token word is refused',
  8453, '0x000000000022D473030F116dDEE9F6B43aC78BA3', '0x87517c45' + 'ab'.repeat(20), /truncated/);

await refused('odd-length calldata is refused before the guard parses it',
  8453, USDC, '0xa9059cbb' + ATTACKER + '1', /even-length 0x hex/);

await refused('calldata without 0x is refused',
  8453, USDC, 'a9059cbb' + ATTACKER + '00'.repeat(32), /even-length 0x hex/);

await refused('sub-4-byte calldata aimed at a token is refused (fallback is unpriced)',
  8453, USDC, '0xa9', /not one AGENTWALLET_MAX_TX_TOKEN can price/);

// Signers: a window past the clamp is refused at the point of signature.
const now = Math.floor(Date.now() / 1000);
try {
  await localSignAuthorization(8453, USDC, { name: 'USD Coin', version: '2' }, {
    from: '0x0000000000000000000000000000000000000000', to: '0x' + ATTACKER.slice(24), value: '1',
    validAfter: String(now - 600), validBefore: String(now + 10 * 365 * 24 * 3600), nonce: '0x' + '11'.repeat(32),
  });
  throw new Error('expected refusal');
} catch (e) {
  assert.match(e.message, /validBefore is more than 3600 seconds/, e.message);
  passed++; console.log('  ok - EIP-3009 signer refuses a ten-year validBefore');
}
try {
  await localSignPermit2Upto(8453, {
    from: '0x0000000000000000000000000000000000000000',
    permitted: { token: USDC, amount: '1' }, spender: '0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002', nonce: '1',
    deadline: String(now + 86400 * 30), witness: { to: '0x' + ATTACKER.slice(24), facilitator: '0x00000000000000000000000000000000000000fa', validAfter: String(now - 600) },
  });
  throw new Error('expected refusal');
} catch (e) {
  assert.match(e.message, /deadline is more than 3600 seconds/, e.message);
  passed++; console.log('  ok - Permit2 signer refuses a thirty-day deadline');
}

console.log(`\nlocal-guard-shape: ${passed} passed`);
