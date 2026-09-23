/**
 * upto (Permit2) typed data and token-risk scoring, offline. Run with: npm test
 */
import assert from 'node:assert';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyTypedData } from 'viem';
import {
  PERMIT2_ADDRESS, X402_UPTO_PERMIT2_PROXY, UPTO_PERMIT2_WITNESS_TYPES,
  createPermit2Nonce, isUptoPayable, buildUptoAuthorization, uptoTypedData, uptoPayload,
  permit2AllowanceCalldata, permit2ApproveCalldata, decodeUint,
} from '../build/x402-permit2.js';
import { assessGoPlus } from '../build/token-risk.js';
import { pickOption } from '../build/x402-eip3009.js';

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }
async function okAsync(name, fn) { await fn(); passed++; console.log(`  ok - ${name}`); }

const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x1111111111111111111111111111111111111111';
const FAC = '0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf';
const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const resolveChainId = (n) => (n === 'eip155:8453' ? 8453 : null);
const upto = { scheme: 'upto', network: 'eip155:8453', amount: '500000', asset: USDC, payTo: PAY_TO, maxTimeoutSeconds: 120, extra: { facilitatorAddress: FAC } };
const exact = { scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: USDC, payTo: PAY_TO, maxTimeoutSeconds: 300, extra: { name: 'USD Coin', version: '2' } };

ok('constants match the coinbase/x402 reference', () => {
  assert.strictEqual(PERMIT2_ADDRESS, '0x000000000022D473030F116dDEE9F6B43aC78BA3');
  assert.strictEqual(X402_UPTO_PERMIT2_PROXY, '0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002');
  assert.deepStrictEqual(Object.keys(UPTO_PERMIT2_WITNESS_TYPES), ['PermitWitnessTransferFrom', 'TokenPermissions', 'Witness']);
});

ok('nonce is a decimal uint256 string', () => {
  const n = createPermit2Nonce();
  assert.match(n, /^\d+$/);
  assert.ok(BigInt(n) < 2n ** 256n);
});

ok('upto is payable only with a facilitator address and an asset', () => {
  assert.strictEqual(isUptoPayable(upto), true);
  assert.strictEqual(isUptoPayable({ ...upto, extra: {} }), false);
  assert.strictEqual(isUptoPayable({ ...upto, asset: undefined }), false);
});

ok('pickOption prefers exact over upto, accepts a signable upto alone, still refuses an unsignable one', () => {
  assert.strictEqual(pickOption([upto, exact], resolveChainId).option, exact);
  assert.strictEqual(pickOption([upto], resolveChainId).option, upto);
  const r = pickOption([{ ...upto, extra: {} }], resolveChainId);
  assert.strictEqual(r.option, null);
  assert.match(r.reason, /facilitatorAddress/);
});

ok('authorization binds token, max amount, proxy spender, payTo and facilitator', () => {
  const a = buildUptoAuthorization('0x' + 'ab'.repeat(20), upto, 1_800_000_000, '42');
  assert.strictEqual(a.permitted.token, USDC);
  assert.strictEqual(a.permitted.amount, '500000');
  assert.strictEqual(a.spender, X402_UPTO_PERMIT2_PROXY);
  assert.strictEqual(a.nonce, '42');
  assert.strictEqual(a.deadline, '1800000120');
  assert.deepStrictEqual(a.witness, { to: PAY_TO, facilitator: FAC, validAfter: '1799999400' });
  assert.throws(() => buildUptoAuthorization('0x' + 'ab'.repeat(20), { ...upto, extra: {} }), /facilitatorAddress/);
});

await okAsync('Permit2 witness signature recovers to the signer under the Permit2 domain', async () => {
  const account = privateKeyToAccount(KEY);
  const a = buildUptoAuthorization(account.address, upto, 1_800_000_000);
  const td = uptoTypedData(8453, a);
  assert.strictEqual(td.domain.name, 'Permit2');
  assert.strictEqual(td.domain.verifyingContract, PERMIT2_ADDRESS);
  const signature = await account.signTypedData(td);
  assert.strictEqual(await verifyTypedData({ ...td, address: account.address, signature }), true);
  const p = uptoPayload(a, signature);
  assert.strictEqual(p.signature, signature);
  assert.strictEqual(p.permit2Authorization, a);
});

ok('allowance and approve calldata target Permit2', () => {
  const owner = '0x' + 'ab'.repeat(20);
  assert.strictEqual(permit2AllowanceCalldata(owner), '0xdd62ed3e' + 'ab'.repeat(20).padStart(64, '0') + PERMIT2_ADDRESS.slice(2).toLowerCase().padStart(64, '0'));
  assert.strictEqual(permit2ApproveCalldata(), '0x095ea7b3' + PERMIT2_ADDRESS.slice(2).toLowerCase().padStart(64, '0') + 'f'.repeat(64));
  assert.strictEqual(decodeUint('0x' + '0'.repeat(63) + 'a'), 10n);
  assert.strictEqual(decodeUint('0x'), 0n);
});

ok('risk: a clean, widely held token scores low', () => {
  const r = assessGoPlus({ is_honeypot: '0', is_open_source: '1', holder_count: '10677188', buy_tax: '0', sell_tax: '0', is_in_dex: '1', holders: [{ percent: '0.05', is_contract: 1 }], trust_list: '1' });
  assert.strictEqual(r.level, 'low');
  assert.ok(r.score <= 5);
  assert.strictEqual(r.holder_count, 10677188);
});

ok('risk: a honeypot scores high with the flag named', () => {
  const r = assessGoPlus({ is_honeypot: '1', is_open_source: '1', holder_count: '12000' });
  assert.strictEqual(r.level, 'high');
  assert.ok(r.flags.includes('honeypot'));
});

ok('risk: closed source plus a 60 percent whale is medium-to-high, top holder reported', () => {
  const r = assessGoPlus({ is_open_source: '0', holder_count: '300', holders: [{ percent: '0.6', is_contract: 0, is_locked: 0 }] });
  assert.ok(r.flags.includes('closed_source') && r.flags.includes('top_holder_over_50pct'));
  assert.ok(r.level !== 'low');
  assert.strictEqual(r.top_holder_percent, 60);
});

console.log(`\n${passed}/${passed} permit2-risk tests passed`);
