/**
 * Regression tests for the 2026-09-27 audit fixes in the x402 helpers:
 *
 *  - AGENTWALLET_MAX_AUTOPAY is a ceiling the agent's max_payment cannot raise
 *  - the cap prices registry stablecoins only; native / other assets need an
 *    explicit AGENTWALLET_AUTOPAY_ASSETS entry
 *  - the label shown to the agent never comes from the 402 body
 *  - authorization windows are clamped to AGENTWALLET_X402_MAX_TIMEOUT
 *
 * Run with: node test/x402-policy.test.mjs
 */
import assert from 'node:assert';

const {
  effectiveAutopayCap, autopayEnvCap, autopayAssetAllowed, assetLabel, nativeSymbol, isStableAsset, maxAuthWindowSeconds,
} = await import('../build/x402-payment.js');
const { buildAuthorization } = await import('../build/x402-eip3009.js');
const { buildUptoAuthorization } = await import('../build/x402-permit2.js');

const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const WETH = '0x4200000000000000000000000000000000000006';
const PAY_TO = '0x000000000000000000000000000000000000dEaD';
const FAC = '0x00000000000000000000000000000000000000fa';

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }

delete process.env.AGENTWALLET_MAX_AUTOPAY;
delete process.env.AGENTWALLET_AUTOPAY_ASSETS;
delete process.env.AGENTWALLET_X402_MAX_TIMEOUT;

ok('default ceiling is 1 and max_payment below it is honoured', () => {
  assert.deepStrictEqual(effectiveAutopayCap('0.25'), { cap: '0.25', source: 'max_payment', clamped: false });
  assert.deepStrictEqual(effectiveAutopayCap(undefined), { cap: '1', source: 'AGENTWALLET_MAX_AUTOPAY', clamped: false });
});
ok('max_payment above the ceiling is ignored, not obeyed (the agent cannot raise its own cap)', () => {
  assert.deepStrictEqual(effectiveAutopayCap('1000000'), { cap: '1', source: 'AGENTWALLET_MAX_AUTOPAY', clamped: true });
});
ok('operator ceiling applies and "1.50" equals "1.5"', () => {
  process.env.AGENTWALLET_MAX_AUTOPAY = '1.5';
  assert.deepStrictEqual(effectiveAutopayCap('1.50'), { cap: '1.50', source: 'max_payment', clamped: false });
  assert.deepStrictEqual(effectiveAutopayCap('1.51'), { cap: '1.5', source: 'AGENTWALLET_MAX_AUTOPAY', clamped: true });
  delete process.env.AGENTWALLET_MAX_AUTOPAY;
});
ok('a malformed ceiling or max_payment throws instead of reading as unlimited', () => {
  process.env.AGENTWALLET_MAX_AUTOPAY = '1e9';
  assert.throws(() => autopayEnvCap(), /decimal number/);
  delete process.env.AGENTWALLET_MAX_AUTOPAY;
  assert.throws(() => effectiveAutopayCap('0x10'), /decimal number/);
});

ok('registry stablecoins are priced by the dollar cap', () => {
  assert.strictEqual(isStableAsset(8453, USDC), true);
  assert.strictEqual(isStableAsset(8453, USDC.toLowerCase()), true);
  assert.deepStrictEqual(autopayAssetAllowed(8453, USDC), { allowed: true, via: 'stablecoin' });
  assert.strictEqual(autopayAssetAllowed(900, 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v').allowed, true);
});
ok('native ETH and non-stable tokens are refused by default (the report: "1" would have meant 1 ETH)', () => {
  const native = autopayAssetAllowed(8453, '');
  assert.strictEqual(native.allowed, false);
  assert.match(native.reason, /ETH/);
  assert.match(native.reason, /AGENTWALLET_AUTOPAY_ASSETS/);
  assert.strictEqual(autopayAssetAllowed(8453, WETH).allowed, false);
  assert.strictEqual(autopayAssetAllowed(900, '').allowed, false);
  assert.strictEqual(autopayAssetAllowed(8453, '0x1111111111111111111111111111111111111111').allowed, false);
});
ok('AGENTWALLET_AUTOPAY_ASSETS opts an asset or "native" in, case-insensitively for EVM', () => {
  process.env.AGENTWALLET_AUTOPAY_ASSETS = ` native , ${WETH.toUpperCase().replace('0X', '0x')} `;
  assert.deepStrictEqual(autopayAssetAllowed(8453, ''), { allowed: true, via: 'allowlist' });
  assert.deepStrictEqual(autopayAssetAllowed(8453, WETH), { allowed: true, via: 'allowlist' });
  assert.strictEqual(autopayAssetAllowed(8453, '0x1111111111111111111111111111111111111111').allowed, false);
  delete process.env.AGENTWALLET_AUTOPAY_ASSETS;
});

ok('labels come from the registry or the chain, never from the 402', () => {
  assert.strictEqual(assetLabel(8453, USDC), 'USDC');
  assert.strictEqual(assetLabel(8453, WETH), 'WETH');
  assert.strictEqual(assetLabel(8453, ''), 'ETH');
  assert.strictEqual(assetLabel(137, ''), 'POL');
  assert.strictEqual(assetLabel(900, ''), 'SOL');
  assert.strictEqual(nativeSymbol(424242), 'native');
  assert.strictEqual(assetLabel(8453, '0x1111111111111111111111111111111111111111'), '0x1111111111111111111111111111111111111111');
});

ok('authorization window is clamped to one hour by default', () => {
  assert.strictEqual(maxAuthWindowSeconds(), 3600);
  const req = { scheme: 'exact', network: 'base', maxAmountRequired: '1000000', asset: USDC, payTo: PAY_TO, maxTimeoutSeconds: 315360000 };
  const a = buildAuthorization(PAY_TO, req, 1800000000);
  assert.strictEqual(a.validBefore, String(1800000000 + 3600));
  const short = buildAuthorization(PAY_TO, { ...req, maxTimeoutSeconds: 60 }, 1800000000);
  assert.strictEqual(short.validBefore, '1800000060');
});
ok('Permit2 deadline is clamped the same way and AGENTWALLET_X402_MAX_TIMEOUT overrides', () => {
  process.env.AGENTWALLET_X402_MAX_TIMEOUT = '600';
  const upto = { scheme: 'upto', network: 'eip155:8453', amount: '500000', asset: USDC, payTo: PAY_TO, maxTimeoutSeconds: 86400, extra: { facilitatorAddress: FAC } };
  const u = buildUptoAuthorization(PAY_TO, upto, 1800000000);
  assert.strictEqual(u.deadline, String(1800000000 + 600));
  delete process.env.AGENTWALLET_X402_MAX_TIMEOUT;
});

console.log(`\nx402-policy: ${passed} passed`);
