/**
 * x402 "exact" scheme via EIP-3009 (issue #7) and "upto" refusal (issue #6).
 *
 * Signs a real TransferWithAuthorization with a throwaway key and checks that
 * viem recovers the signer, so the typed data we send is the typed data the
 * facilitator will verify. Run with: npm test
 */
import assert from 'node:assert';
import { parseEip7702Delegation, erc1271ProbeCalldata, classifyErc1271Probe, ERC1271_MAGIC } from '../build/x402-eip3009.js';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyTypedData } from 'viem';
import {
  TRANSFER_WITH_AUTHORIZATION_TYPES,
  isLegacyAgentWalletAccept,
  requiredAmount,
  createNonce,
  buildAuthorization,
  typedDataFor,
  knownTokenDomain,
  decodeAbiString,
  buildPaymentPayload,
  paymentHeaderFor,
  parsePaymentRequired,
  parseSettlement,
  pickOption,
} from '../build/x402-eip3009.js';

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }
async function okAsync(name, fn) { await fn(); passed++; console.log(`  ok - ${name}`); }

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x1111111111111111111111111111111111111111';
const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'; // throwaway (Hardhat #1)
const chains = { base: 8453, 'eip155:8453': 8453, 'base-sepolia': 84532 };
const resolveChainId = (n) => chains[n] ?? (n.startsWith('eip155:') ? Number(n.slice(7)) : null);

const v1 = { scheme: 'exact', network: 'base', maxAmountRequired: '1000000', asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 60, resource: 'https://1f3d9.com/api/place', extra: { name: 'USD Coin', version: '2' } };
const v2 = { scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: USDC_BASE, payTo: PAY_TO, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } };
const legacy = { scheme: 'exact', network: 'base', maxAmountRequired: '10000', payTo: PAY_TO, requiredDecimals: 6, extra: { name: 'USDC', version: '1', token: USDC_BASE } };

ok('legacy AgentWallet paywalls are recognised by shape, standard ones are not', () => {
  assert.strictEqual(isLegacyAgentWalletAccept(legacy), true);
  assert.strictEqual(isLegacyAgentWalletAccept(v1), false);
  assert.strictEqual(isLegacyAgentWalletAccept(v2), false);
});

ok('required amount reads v1 maxAmountRequired and v2 amount', () => {
  assert.strictEqual(requiredAmount(v1), '1000000');
  assert.strictEqual(requiredAmount(v2), '10000');
});

ok('nonce is 32 random bytes', () => {
  const n = createNonce();
  assert.match(n, /^0x[0-9a-f]{64}$/);
  assert.notStrictEqual(n, createNonce());
});

ok('authorization window is now-600 to now+maxTimeoutSeconds, value is the raw amount', () => {
  const a = buildAuthorization('0x' + 'ab'.repeat(20), v1, 1_800_000_000, '0x' + '11'.repeat(32));
  assert.strictEqual(a.to, PAY_TO);
  assert.strictEqual(a.value, '1000000');
  assert.strictEqual(a.validAfter, '1799999400');
  assert.strictEqual(a.validBefore, '1800000060');
  assert.strictEqual(a.nonce, '0x' + '11'.repeat(32));
});

ok('authorization refuses a non-integer amount or a non-EVM payTo', () => {
  assert.throws(() => buildAuthorization('0x' + 'ab'.repeat(20), { ...v1, maxAmountRequired: '1.5' }), /invalid required amount/);
  assert.throws(() => buildAuthorization('0x' + 'ab'.repeat(20), { ...v1, payTo: 'notanaddress' }), /payTo is not an EVM address/);
});

await okAsync('signature over the typed data recovers to the signer (what the facilitator checks)', async () => {
  const account = privateKeyToAccount(KEY);
  const auth = buildAuthorization(account.address, v1, 1_800_000_000);
  const td = typedDataFor(8453, USDC_BASE, 'USD Coin', '2', auth);
  assert.strictEqual(td.primaryType, 'TransferWithAuthorization');
  assert.strictEqual(td.types, TRANSFER_WITH_AUTHORIZATION_TYPES);
  const signature = await account.signTypedData(td);
  assert.match(signature, /^0x[0-9a-f]{130}$/);
  assert.strictEqual(await verifyTypedData({ ...td, address: account.address, signature }), true);
  // A different domain version must NOT verify: this is the failure mode a guessed domain would hide.
  const wrong = typedDataFor(8453, USDC_BASE, 'USD Coin', '1', auth);
  assert.strictEqual(await verifyTypedData({ ...wrong, address: account.address, signature }), false);
});

ok('known token domains cover USDC on Base and are case-insensitive on the address', () => {
  assert.deepStrictEqual(knownTokenDomain(8453, USDC_BASE.toUpperCase().replace('0X', '0x')), { name: 'USD Coin', version: '2' });
  assert.deepStrictEqual(knownTokenDomain(84532, '0x036CbD53842c5426634e7929541eC2318f3dCF7e'), { name: 'USDC', version: '2' });
  assert.strictEqual(knownTokenDomain(8453, PAY_TO), null);
});

ok('decodeAbiString unpacks a name() return value', () => {
  const hex = '0x' + '20'.padStart(64, '0') + '8'.padStart(64, '0') + Buffer.from('USD Coin').toString('hex').padEnd(64, '0');
  assert.strictEqual(decodeAbiString(hex), 'USD Coin');
  assert.strictEqual(decodeAbiString('0x'), '');
});

ok('v1 payload and header: X-PAYMENT carrying scheme, network, signature and authorization', () => {
  const auth = buildAuthorization('0x' + 'ab'.repeat(20), v1, 1_800_000_000, '0x' + '22'.repeat(32));
  const payload = buildPaymentPayload(1, v1, auth, '0x' + 'cd'.repeat(65));
  assert.deepStrictEqual(Object.keys(payload).sort(), ['network', 'payload', 'scheme', 'x402Version']);
  assert.strictEqual(payload.x402Version, 1);
  assert.strictEqual(payload.network, 'base');
  assert.deepStrictEqual(payload.payload.authorization, auth);
  const h = paymentHeaderFor(1, payload);
  assert.strictEqual(h.name, 'X-PAYMENT');
  assert.deepStrictEqual(JSON.parse(Buffer.from(h.value, 'base64').toString('utf8')), payload);
});

ok('v2 payload and header: PAYMENT-SIGNATURE carrying resource, accepted and payload', () => {
  const auth = buildAuthorization('0x' + 'ab'.repeat(20), v2, 1_800_000_000, '0x' + '33'.repeat(32));
  const resource = { url: 'https://api.example.com/thing', description: 'a thing', mimeType: 'application/json' };
  const payload = buildPaymentPayload(2, v2, auth, '0x' + 'cd'.repeat(65), resource);
  assert.deepStrictEqual(Object.keys(payload).sort(), ['accepted', 'payload', 'resource', 'x402Version']);
  assert.strictEqual(payload.accepted, v2);
  assert.strictEqual(paymentHeaderFor(2, payload).name, 'PAYMENT-SIGNATURE');
});

ok('v2 payload echoes extensions and fills a payment-identifier id when the server asks for one', () => {
  const auth = buildAuthorization('0x' + 'ab'.repeat(20), v2, 1_800_000_000, '0x' + '44'.repeat(32));
  const ext = { 'payment-identifier': { info: { required: true }, schema: {} }, bazaar: { info: { input: { type: 'http' } } } };
  const payload = buildPaymentPayload(2, v2, auth, '0x' + 'cd'.repeat(65), undefined, ext);
  const id = payload.extensions['payment-identifier'].info.id;
  assert.match(id, /^[A-Za-z0-9_-]{16,128}$/);
  assert.strictEqual(payload.extensions['payment-identifier'].info.required, true);
  assert.deepStrictEqual(payload.extensions.bazaar, ext.bazaar);
  assert.strictEqual(ext['payment-identifier'].info.id, undefined); // input not mutated
  assert.strictEqual(buildPaymentPayload(2, v2, auth, '0x' + 'cd'.repeat(65)).extensions, undefined);
});

ok('parsePaymentRequired prefers the PAYMENT-REQUIRED header, falls back to a v1 body', () => {
  const v2Req = { x402Version: 2, resource: { url: 'https://api.example.com/x' }, accepts: [v2] };
  const encoded = Buffer.from(JSON.stringify(v2Req)).toString('base64');
  const fromHeader = parsePaymentRequired((n) => (n === 'PAYMENT-REQUIRED' ? encoded : null), null);
  assert.deepStrictEqual(fromHeader, v2Req);
  const fromBody = parsePaymentRequired(() => null, { x402Version: 1, accepts: [v1] });
  assert.strictEqual(fromBody.accepts[0], v1);
  assert.strictEqual(parsePaymentRequired(() => null, { error: 'nope' }), null);
});

ok('parseSettlement reads PAYMENT-RESPONSE, then X-PAYMENT-RESPONSE', () => {
  const s = { success: true, transaction: '0x' + 'ee'.repeat(32), network: 'eip155:8453', payer: PAY_TO };
  const b64 = Buffer.from(JSON.stringify(s)).toString('base64');
  assert.deepStrictEqual(parseSettlement((n) => (n === 'PAYMENT-RESPONSE' ? b64 : null)), s);
  assert.deepStrictEqual(parseSettlement((n) => (n === 'X-PAYMENT-RESPONSE' ? b64 : null)), s);
  assert.strictEqual(parseSettlement(() => null), null);
});

ok('pickOption chooses exact over upto and honours prefer_chain', () => {
  const upto = { ...v2, scheme: 'upto' };
  const sepolia = { ...v2, network: 'base-sepolia' };
  let r = pickOption([upto, v2], resolveChainId);
  assert.strictEqual(r.option, v2);
  assert.strictEqual(r.chainId, 8453);
  r = pickOption([v2, sepolia], resolveChainId, 84532);
  assert.strictEqual(r.option, sepolia);
});

ok('pickOption refuses an upto-only endpoint with a reason, never an upfront transfer (issue #6)', () => {
  const r = pickOption([{ ...v2, scheme: 'upto' }], resolveChainId);
  assert.strictEqual(r.option, null);
  assert.match(r.reason, /"upto" scheme/);
  assert.match(r.reason, /will not approximate/);
});

ok('pickOption reports unknown schemes', () => {
  const r = pickOption([{ ...v2, scheme: 'lightning' }], resolveChainId);
  assert.strictEqual(r.option, null);
  assert.match(r.reason, /lightning/);
});

ok('parseEip7702Delegation recognises a delegation designator and nothing else (issue #9)', () => {
  assert.strictEqual(parseEip7702Delegation('0xef01008a67b5020ee254ef48e3b6a04927f39baf7e408a'), '0x8a67b5020ee254ef48e3b6a04927f39baf7e408a');
  assert.strictEqual(parseEip7702Delegation('0xEF01008A67B5020EE254EF48E3B6A04927F39BAF7E408A'), '0x8a67b5020ee254ef48e3b6a04927f39baf7e408a');
  assert.strictEqual(parseEip7702Delegation('0x'), null);
  assert.strictEqual(parseEip7702Delegation(''), null);
  assert.strictEqual(parseEip7702Delegation(undefined), null);
  assert.strictEqual(parseEip7702Delegation('0x6080604052'), null);
  assert.strictEqual(parseEip7702Delegation('0xef01008a67b5020ee254ef48e3b6a04927f39baf7e408a00'), null);
});

ok('erc1271ProbeCalldata is a well-formed isValidSignature(bytes32,bytes) call', () => {
  const c = erc1271ProbeCalldata();
  assert.ok(c.startsWith(ERC1271_MAGIC));
  assert.strictEqual((c.length - 2) / 2, 4 + 32 + 32 + 32 + 96);
  assert.strictEqual(c.slice(10 + 64, 10 + 128), (64).toString(16).padStart(64, '0'));
  assert.strictEqual(c.slice(10 + 128, 10 + 192), (65).toString(16).padStart(64, '0'));
});

ok('classifyErc1271Probe: empty data means no interface, a 4-byte word means it exists, anything else is unknown', () => {
  assert.strictEqual(classifyErc1271Probe('0x'), 'no');
  assert.strictEqual(classifyErc1271Probe(''), 'no');
  assert.strictEqual(classifyErc1271Probe(undefined), 'no');
  assert.strictEqual(classifyErc1271Probe('0x1626ba7e' + '0'.repeat(56)), 'yes');
  assert.strictEqual(classifyErc1271Probe('0xffffffff' + '0'.repeat(56)), 'yes');
  assert.strictEqual(classifyErc1271Probe('0x01'), 'unknown');
  assert.strictEqual(classifyErc1271Probe('0x', true), 'unknown');
});

console.log(`\n${passed}/${passed} eip3009 tests passed`);
