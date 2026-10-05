// 1.13.16 regression: the payment header is bounded (round 8 echo bloat).
import assert from 'node:assert/strict';
import { buildPaymentPayloadRaw, paymentHeaderFor, MAX_PAYMENT_HEADER_BYTES } from '../build/x402-eip3009.js';

const req = { scheme: 'exact', network: 'eip155:8453', payTo: '0x' + '11'.repeat(20), asset: '0x' + '22'.repeat(20), maxAmountRequired: '1000000' };

// A normal v2 payload fits with room to spare.
const small = buildPaymentPayloadRaw(2, req, { signature: '0x' + 'ab'.repeat(65), authorization: {} }, { url: 'https://x.test/a' }, { 'payment-identifier': { info: { required: true } } });
const h = paymentHeaderFor(2, small);
assert.equal(h.name, 'PAYMENT-SIGNATURE');
assert.ok(h.value.length < 4096, 'small header stays small');

// Junk in outputSchema or extensions cannot become a multi-megabyte header.
const bloated = buildPaymentPayloadRaw(2, { ...req, outputSchema: { pad: 'x'.repeat(100_000) } }, { signature: '0x00' }, undefined, { pad: 'y'.repeat(100_000) });
assert.throws(() => paymentHeaderFor(2, bloated), /too large to echo/);
assert.equal(MAX_PAYMENT_HEADER_BYTES, 65536);

// v1 envelope never echoes the requirement at all.
const v1 = buildPaymentPayloadRaw(1, { ...req, outputSchema: { pad: 'x'.repeat(100_000) } }, { signature: '0x00' });
assert.ok(!('accepted' in v1));
assert.ok(paymentHeaderFor(1, v1).value.length < 1024);

console.log('audit-11316: ok');
