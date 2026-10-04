/**
 * Regression tests from round 3 of the 2026-10-04 adversarial audit (pure parts).
 *
 *  - approvalRefusal binds the scheme: an "exact" approval does not cover an "upto" payment
 *  - approvalResourceUrl keeps origin and path only (no userinfo, query or fragment)
 *
 * The stdio-level behaviours (signing mutex, one live authorization per resource,
 * cache before the cap, approval refused on broadcast transfers) are driven by the
 * round-3 harnesses under the session scratchpad and recorded in SECURITY.md.
 *
 * Run with: node test/audit-1138.test.mjs
 */
import assert from 'node:assert';

const { approvalRefusal, approvalResourceUrl } = await import('../build/x402-payment.js');

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`  ok - ${name}`); };

const row = { status: 'approved', used: '0', wallet_id: '7', chain_id: '8453', asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', pay_to: '0x000000000000000000000000000000000000dead', value: '5000000', scheme: 'exact' };
const want = { walletId: 7, chainId: 8453, asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', payTo: '0x000000000000000000000000000000000000dEaD', rawAmount: '5000000' };

ok('an exact approval covers an exact payment', () => {
  assert.strictEqual(approvalRefusal('1', row, { ...want, scheme: 'exact' }, false), null);
});
ok('an exact approval does not cover an upto payment', () => {
  const r = approvalRefusal('1', row, { ...want, scheme: 'upto' }, false);
  assert.ok(r && /scheme/.test(r.error), JSON.stringify(r));
});
ok('a row without a scheme (older server) still matches', () => {
  const { scheme, ...old } = row;
  assert.strictEqual(approvalRefusal('1', old, { ...want, scheme: 'upto' }, false), null);
});
ok('approvalResourceUrl strips userinfo, query and fragment', () => {
  assert.strictEqual(approvalResourceUrl('https://shop.example/pay?id=1#x'), 'https://shop.example/pay');
  assert.strictEqual(approvalResourceUrl('https://coinbase.com@evil.example/pay'), 'https://evil.example/pay');
  assert.strictEqual(approvalResourceUrl('https://paywall.test\\@coinbase.com/pay'), 'https://paywall.test/@coinbase.com/pay');
});

console.log(`\naudit-1138: ${passed} passed`);
