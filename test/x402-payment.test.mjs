/**
 * Regression tests for x402 auto-pay amount/token derivation.
 *
 * Guards against the 2026-06-01 overpayment bug where maxAmountRequired (base
 * units per the x402 spec) was re-scaled via parseUnits, producing a
 * 10**decimals (1,000,000x for USDC) overpayment on the AGENTWALLET_WALLET_ID
 * auto-pay path. Run with: npm test
 */
import assert from 'node:assert';
import {
  deriveX402Payment,
  isWithinCap,
  lookupTrustedDecimals,
  assertDeclaredDecimals,
} from '../build/x402-payment.js';

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }

// The core regression: a spec x402 USDC requirement is base units and must NOT
// be re-scaled. 0.01 USDC = "10000"; transfer must be "10000", not 10000000000.
ok('uses maxAmountRequired as base units (no re-scaling)', () => {
  const accept = { maxAmountRequired: '10000', requiredDecimals: 6, extra: { token: '0xUSDC' } };
  const r = deriveX402Payment(accept, '1', 6);
  assert.strictEqual(r.rawAmount, '10000');
  assert.notStrictEqual(r.rawAmount, '10000000000'); // the old buggy value
  assert.strictEqual(r.tokenAddress, '0xUSDC');
});

// Standard `asset` field wins over the legacy extra.token.
ok('prefers standard asset field over extra.token', () => {
  const accept = { maxAmountRequired: '5000', requiredDecimals: 6, asset: '0xAsset', extra: { token: '0xLegacy' } };
  assert.strictEqual(deriveX402Payment(accept, '1', 6).tokenAddress, '0xAsset');
});

// The hard cap blocks the over-limit (e.g. the would-be 10,000 USDC overpay).
ok('cap blocks an amount over AGENTWALLET_MAX_AUTOPAY', () => {
  const accept = { maxAmountRequired: '10000000000', requiredDecimals: 6 }; // 10,000 USDC
  assert.throws(() => deriveX402Payment(accept, '1', 6), /exceeds the AGENTWALLET_MAX_AUTOPAY cap/);
});

// A decimal sneaking into maxAmountRequired is rejected (must be base units).
ok('rejects non-integer maxAmountRequired', () => {
  const accept = { maxAmountRequired: '0.01', requiredDecimals: 6 };
  assert.throws(() => deriveX402Payment(accept, '1', 6), /expected an integer base-unit amount/);
});

// A normal micropayment under the cap is allowed unchanged.
ok('allows a normal micropayment under the cap', () => {
  const accept = { maxAmountRequired: '10000', requiredDecimals: 6 }; // 0.01 USDC, cap 1 USDC
  assert.strictEqual(deriveX402Payment(accept, '1', 6).rawAmount, '10000');
});

// ── isWithinCap: the shared cap the public pay_x402 tool uses ──────────────
// Guards the 2026-06-27 disclosure: pay_x402 with max_payment omitted must NOT
// authorize an unbounded payment. The tool falls back to AGENTWALLET_MAX_AUTOPAY
// (default "1"), so a malicious 402 returning 10,000 USDC is blocked.

ok('isWithinCap blocks a 10,000 USDC requirement at the default cap "1"', () => {
  // 10,000 USDC in base units at 6 decimals — the disclosure's malicious value.
  assert.strictEqual(isWithinCap('10000000000', 6, '1'), false);
});

ok('isWithinCap allows a 0.01 USDC micropayment at cap "1"', () => {
  assert.strictEqual(isWithinCap('10000', 6, '1'), true);
});

ok('isWithinCap allows exactly the cap (boundary)', () => {
  assert.strictEqual(isWithinCap('1000000', 6, '1'), true);  // 1.00 USDC == cap
  assert.strictEqual(isWithinCap('1000001', 6, '1'), false); // one base unit over
});

ok('isWithinCap honors a raised explicit cap', () => {
  // 10,000 USDC allowed only when the caller/env raises the cap to >= 10000.
  assert.strictEqual(isWithinCap('10000000000', 6, '10000'), true);
  assert.strictEqual(isWithinCap('10000000000', 6, '9999'), false);
});

ok('isWithinCap rejects a non-integer required amount', () => {
  assert.throws(() => isWithinCap('0.01', 6, '1'), /expected an integer base-unit amount/);
});

console.log(`\nx402-payment: ${passed}/10 passed`);

// ── 2026-08-02 disclosure: untrusted requiredDecimals bypassed the cap ──────
// A resource server controls requiredDecimals. When the cap was scaled with it,
// declaring 18 decimals for 6-decimal USDC turned a "1 USDC" cap into 10**18
// base units, so 1,000,000,000,000 units (1,000,000 USDC) passed a 1 USDC cap.
// Decimals now come from a trusted source and a mismatch fails closed.

ok('the reported bypass is blocked: forged 18 decimals on a 6-decimal asset', () => {
  const accept = {
    maxAmountRequired: '1000000000000',            // 1,000,000 USDC at 6 decimals
    requiredDecimals: 18,                          // the lie
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  };
  // trusted decimals for Base USDC is 6, so this must not be authorized
  assert.throws(() => deriveX402Payment(accept, '1', 6), /declared 18 decimals/);
});

ok('the same request is still blocked by the cap when decimals are honest', () => {
  const accept = { maxAmountRequired: '1000000000000', requiredDecimals: 6 };
  assert.throws(() => deriveX402Payment(accept, '1', 6), /exceeds the AGENTWALLET_MAX_AUTOPAY cap/);
});

ok('isWithinCap with trusted decimals rejects the forged amount', () => {
  // What the attacker wanted: evaluated at 18 it would have passed.
  assert.strictEqual(isWithinCap('1000000000000', 18, '1'), true);
  // What now happens: evaluated at the asset's real 6 decimals.
  assert.strictEqual(isWithinCap('1000000000000', 6, '1'), false);
});

ok('declared decimals matching trusted is accepted', () => {
  const accept = { maxAmountRequired: '10000', requiredDecimals: 6 };
  assert.strictEqual(deriveX402Payment(accept, '1', 6).rawAmount, '10000');
});

ok('absent requiredDecimals is allowed and uses the trusted value', () => {
  const accept = { maxAmountRequired: '10000' };
  const r = deriveX402Payment(accept, '1', 6);
  assert.strictEqual(r.rawAmount, '10000');
  assert.strictEqual(r.decimals, 6);
});

ok('malformed requiredDecimals is refused', () => {
  for (const bad of ['6', 6.5, -1, 999, NaN]) {
    assert.throws(
      () => assertDeclaredDecimals(bad, 6),
      /malformed requiredDecimals|declared/,
      `expected refusal for ${String(bad)}`
    );
  }
});

ok('0 declared against a 6-decimal asset is refused', () => {
  // Understating decimals shrinks the cap rather than inflating it, but a
  // mismatch still means the endpoint is lying about the asset. Fail closed.
  assert.throws(() => assertDeclaredDecimals(0, 6), /declared 0 decimals/);
});

ok('trusted registry returns real decimals for known assets', () => {
  assert.strictEqual(lookupTrustedDecimals(8453, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'), 6);
  assert.strictEqual(lookupTrustedDecimals(8453, '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'), 6); // case
  assert.strictEqual(lookupTrustedDecimals(1, '0x6B175474E89094C44Da98b954EedeAC495271d0F'), 18);   // DAI
  assert.strictEqual(lookupTrustedDecimals(8453, '0xdeadbeef'), null);   // unknown -> caller must resolve
  assert.strictEqual(lookupTrustedDecimals(99999, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'), null);
});

ok('SPL mints resolve from the trusted table', () => {
  assert.strictEqual(lookupTrustedDecimals(101, 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'), 6);
});

console.log(`\nx402-payment: ${passed} passed`);
