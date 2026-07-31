/**
 * Regression tests for the pay_x402 SSRF guard.
 * Models the private disclosure from ARC Security Research (2026-07-31) plus
 * the additional bypass classes found while verifying it.
 */
import assert from 'node:assert';
import { canonicalizeHost, isPrivateAddress, assertPublicUrl } from '../build/ssrf-guard.js';

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ok   ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
};
const ta = async (name, fn) => {
  try { await fn(); console.log(`  ok   ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
};
const rejects = async (url) => {
  try { await assertPublicUrl(url); }
  catch { return; }
  throw new Error(`expected rejection: ${url}`);
};
const allows = async (url) => { await assertPublicUrl(url); };

console.log('\nssrf-guard: canonicalization');
t('IPv4-mapped IPv6 unwraps to IPv4 (the reported bypass)', () => {
  assert.equal(canonicalizeHost('[::ffff:127.0.0.1]').ip, '127.0.0.1');
});
t('hex-spelled IPv4-mapped IPv6 unwraps (what Node actually produces)', () => {
  assert.equal(canonicalizeHost('[::ffff:7f00:1]').ip, '127.0.0.1');
});
t('metadata address via IPv4-mapped IPv6 unwraps', () => {
  assert.equal(canonicalizeHost('[::ffff:a9fe:a9fe]').ip, '169.254.169.254');
});
t('zone id is stripped from link-local', () => {
  assert.equal(canonicalizeHost('[fe80::1%eth0]').ip, 'fe80::1');
});

console.log('\nssrf-guard: private range detection');
for (const ip of ['127.0.0.1', '127.0.0.2', '127.255.255.254', '10.1.2.3', '172.16.0.1',
                  '172.31.255.255', '192.168.1.1', '169.254.169.254', '169.254.1.1',
                  '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
                  '::1', 'fd00::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:7f00:1']) {
  t(`private: ${ip}`, () => assert.equal(isPrivateAddress(ip), true));
}
for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700::1111']) {
  t(`public: ${ip}`, () => assert.equal(isPrivateAddress(ip), false));
}

console.log('\nssrf-guard: assertPublicUrl');
await ta('rejects the reported IPv4-mapped IPv6 loopback', () => rejects('https://[::ffff:127.0.0.1]:18443/'));
await ta('rejects cloud metadata via IPv4-mapped IPv6', () => rejects('https://[::ffff:169.254.169.254]/latest/meta-data/'));
await ta('rejects plain loopback', () => rejects('https://127.0.0.1/'));
await ta('rejects rest of 127/8', () => rejects('https://127.0.0.2/'));
await ta('rejects localhost by name', () => rejects('https://localhost/'));
await ta('rejects IPv6 loopback', () => rejects('https://[::1]/'));
await ta('rejects IPv6 unique-local', () => rejects('https://[fd00::1]/'));
await ta('rejects IPv6 link-local', () => rejects('https://[fe80::1]/'));
await ta('rejects link-local range, not just the metadata IP', () => rejects('https://169.254.1.1/'));
await ta('rejects carrier-grade NAT', () => rejects('https://100.64.0.1/'));
await ta('rejects cloud metadata by hostname', () => rejects('https://metadata.google.internal/'));
await ta('rejects decimal-encoded loopback', () => rejects('https://2130706433/'));
await ta('rejects http even when public', () => rejects('http://example.com/'));
await ta('allows an ordinary public host', () => allows('https://example.com/'));
await ta('allows a public IP literal', () => allows('https://8.8.8.8/'));

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
