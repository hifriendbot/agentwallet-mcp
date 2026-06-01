/**
 * Regression tests for x402 auto-pay amount/token derivation.
 *
 * Guards against the 2026-06-01 overpayment bug where maxAmountRequired (base
 * units per the x402 spec) was re-scaled via parseUnits, producing a
 * 10**decimals (1,000,000x for USDC) overpayment on the AGENTWALLET_WALLET_ID
 * auto-pay path. Run with: npm test
 */
import assert from 'node:assert';
import { deriveX402Payment } from '../build/x402-payment.js';

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }

// The core regression: a spec x402 USDC requirement is base units and must NOT
// be re-scaled. 0.01 USDC = "10000"; transfer must be "10000", not 10000000000.
ok('uses maxAmountRequired as base units (no re-scaling)', () => {
  const accept = { maxAmountRequired: '10000', requiredDecimals: 6, extra: { token: '0xUSDC' } };
  const r = deriveX402Payment(accept, '1');
  assert.strictEqual(r.rawAmount, '10000');
  assert.notStrictEqual(r.rawAmount, '10000000000'); // the old buggy value
  assert.strictEqual(r.tokenAddress, '0xUSDC');
});

// Standard `asset` field wins over the legacy extra.token.
ok('prefers standard asset field over extra.token', () => {
  const accept = { maxAmountRequired: '5000', requiredDecimals: 6, asset: '0xAsset', extra: { token: '0xLegacy' } };
  assert.strictEqual(deriveX402Payment(accept, '1').tokenAddress, '0xAsset');
});

// The hard cap blocks the over-limit (e.g. the would-be 10,000 USDC overpay).
ok('cap blocks an amount over AGENTWALLET_MAX_AUTOPAY', () => {
  const accept = { maxAmountRequired: '10000000000', requiredDecimals: 6 }; // 10,000 USDC
  assert.throws(() => deriveX402Payment(accept, '1'), /exceeds the AGENTWALLET_MAX_AUTOPAY cap/);
});

// A decimal sneaking into maxAmountRequired is rejected (must be base units).
ok('rejects non-integer maxAmountRequired', () => {
  const accept = { maxAmountRequired: '0.01', requiredDecimals: 6 };
  assert.throws(() => deriveX402Payment(accept, '1'), /expected an integer base-unit amount/);
});

// A normal micropayment under the cap is allowed unchanged.
ok('allows a normal micropayment under the cap', () => {
  const accept = { maxAmountRequired: '10000', requiredDecimals: 6 }; // 0.01 USDC, cap 1 USDC
  assert.strictEqual(deriveX402Payment(accept, '1').rawAmount, '10000');
});

console.log(`\nx402-payment: ${passed}/5 passed`);
