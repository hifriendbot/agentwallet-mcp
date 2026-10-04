/**
 * Regression tests from round 3 of the 2026-10-04 adversarial audit, upto/EIP-712 group (pure parts).
 *
 *  - decodeAbiString refuses invalid UTF-8 and over-long names instead of returning a sanitised guess
 *  - sanitizeRequired lowercases all-uppercase addresses (not an EIP-55 checksum) and keeps mixed case
 *  - pickOption names an unknown network as the reason
 *
 * Run with: node test/audit-1139.test.mjs
 */
import assert from 'node:assert';

const { decodeAbiString, sanitizeRequired, pickOption } = await import('../build/x402-eip3009.js');

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`  ok - ${name}`); };

const abiString = (bytes) => '0x' + '20'.padStart(64, '0') + bytes.length.toString(16).padStart(64, '0') + Buffer.from(bytes).toString('hex').padEnd(Math.ceil(bytes.length / 32) * 64, '0');

ok('a valid name decodes', () => {
  assert.strictEqual(decodeAbiString(abiString(Buffer.from('USD Coin'))), 'USD Coin');
});
ok('invalid UTF-8 is refused, not replaced', () => {
  assert.strictEqual(decodeAbiString(abiString(Buffer.from([0xff, 0xfe, 0x00, 0xc0]))), '');
});
ok('a 257-byte name is refused, not truncated', () => {
  assert.strictEqual(decodeAbiString(abiString(Buffer.from('C'.repeat(257)))), '');
  assert.strictEqual(decodeAbiString(abiString(Buffer.from('C'.repeat(256)))), 'C'.repeat(256));
});
ok('all-uppercase addresses are lowercased; mixed case (a checksum) is kept', () => {
  const r = sanitizeRequired({ accepts: [
    { scheme: 'exact', network: 'base', payTo: '0x000000000000000000000000000000000000DEAD', asset: '0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913', extra: { token: '0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913' } },
    { scheme: 'exact', network: 'base', payTo: '0x000000000000000000000000000000000000dEaD', asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  ] });
  assert.strictEqual(r.accepts[0].payTo, '0x000000000000000000000000000000000000dead');
  assert.strictEqual(r.accepts[0].asset, '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913');
  assert.strictEqual(r.accepts[0].extra.token, '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913');
  assert.strictEqual(r.accepts[1].payTo, '0x000000000000000000000000000000000000dEaD');
  assert.strictEqual(r.accepts[1].asset, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
});
ok('an unknown network is named as the reason', () => {
  const r = pickOption([{ scheme: 'upto', network: 'zksync-era', payTo: '0x000000000000000000000000000000000000dead', asset: '0x1111111111111111111111111111111111111111', maxAmountRequired: '1', extra: { facilitatorAddress: '0x2222222222222222222222222222222222222222' } }], (n) => (n === 'base' ? 8453 : null));
  assert.strictEqual(r.option, null);
  assert.match(r.reason, /network\(s\) zksync-era are not ones this client knows/);
});

console.log(`\naudit-1139: ${passed} passed`);
