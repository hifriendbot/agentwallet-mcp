/**
 * Regression tests for approval handling in pay_x402 (2026-10-02 report).
 *
 * An approval is single-use because the hosted signer marks it used when it
 * signs. In local mode the signature is made in-process and the server never
 * hears about it, so an approval_id looked up from the hosted account stayed
 * "unused" and lifted the cap on every call until it expired. The client check
 * also never compared the wallet. approvalRefusal() is the whole decision:
 *
 *  - local mode refuses any approval_id, before a lookup
 *  - a hosted approval must be approved, unused, and match wallet, chain,
 *    asset, recipient and amount
 *  - a missing or malformed field refuses rather than passes
 *
 * Run with: node test/approval-binding.test.mjs
 */
import assert from 'node:assert';

const { approvalRefusal } = await import('../build/x402-payment.js');

const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x000000000000000000000000000000000000dEaD';
const want = { walletId: 14, chainId: 8453, asset: USDC, payTo: PAY_TO, rawAmount: '5000000' };
// The server answers with strings (wpdb rows), lowercased addresses included.
const good = { status: 'approved', used: '0', wallet_id: '14', chain_id: '8453', asset: USDC.toLowerCase(), pay_to: PAY_TO.toLowerCase(), value: '5000000' };

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }

ok('a matching, approved, unused approval is accepted for a hosted wallet', () => {
  assert.strictEqual(approvalRefusal('7', good, want, false), null);
});

ok('an approval for more than the payment still covers it', () => {
  assert.strictEqual(approvalRefusal('7', { ...good, value: '9000000' }, want, false), null);
});

// The report: nothing consumes an approval when the signature is made locally.
ok('local mode refuses a perfectly good approval', () => {
  const r = approvalRefusal('7', good, want, true);
  assert.match(r.error, /cannot be used in local mode/);
});

ok('local mode refuses without needing the row at all', () => {
  const r = approvalRefusal('7', null, want, true);
  assert.match(r.error, /cannot be used in local mode/);
});

// The report: the wallet the owner approved was never compared.
ok('an approval for a different wallet is refused', () => {
  const r = approvalRefusal('7', { ...good, wallet_id: '15' }, want, false);
  assert.match(r.error, /does not cover this payment \(wallet,/);
});

ok('an approval with no wallet_id is refused', () => {
  const { wallet_id, ...row } = good;
  assert.match(approvalRefusal('7', row, want, false).error, /does not cover/);
});

ok('a used approval is refused', () => {
  const r = approvalRefusal('7', { ...good, used: '1' }, want, false);
  assert.match(r.error, /already used/);
  assert.strictEqual(r.approval_status, 'approved');
});

ok('a missing "used" field refuses instead of passing', () => {
  const { used, ...row } = good;
  assert.match(approvalRefusal('7', row, want, false).error, /already used/);
});

for (const status of ['pending', 'denied', 'expired']) {
  ok(`a ${status} approval is refused and reports its status`, () => {
    const r = approvalRefusal('7', { ...good, status }, want, false);
    assert.match(r.error, new RegExp(`is ${status}, not approved`));
    assert.strictEqual(r.approval_status, status);
  });
}

ok('an unknown approval (server error body) is refused', () => {
  const r = approvalRefusal('7', { error: 'Approval not found.' }, want, false);
  assert.match(r.error, /is unknown, not approved\. Approval not found\./);
  assert.strictEqual(r.approval_status, null);
});

ok('a different chain, asset or recipient is refused', () => {
  assert.match(approvalRefusal('7', { ...good, chain_id: '1' }, want, false).error, /does not cover/);
  assert.match(approvalRefusal('7', { ...good, asset: '0x' + '11'.repeat(20) }, want, false).error, /does not cover/);
  assert.match(approvalRefusal('7', { ...good, pay_to: '0x' + '22'.repeat(20) }, want, false).error, /does not cover/);
});

ok('a payment above the approved maximum is refused', () => {
  assert.match(approvalRefusal('7', { ...good, value: '4999999' }, want, false).error, /does not cover/);
});

ok('a missing or non-numeric approved value is refused, not thrown on', () => {
  const { value, ...row } = good;
  assert.match(approvalRefusal('7', row, want, false).error, /does not cover/);
  assert.match(approvalRefusal('7', { ...good, value: '5e6' }, want, false).error, /does not cover/);
});

console.log(`\napproval-binding: ${passed} passed`);
