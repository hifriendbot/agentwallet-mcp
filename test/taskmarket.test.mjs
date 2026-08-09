/**
 * Unit tests for the TaskMarket integration (src/taskmarket.ts).
 *
 * These cover the money-moving safety logic without touching the network:
 * base-unit conversion, the pinned x402 payment policy, the explicit
 * confirmation gate, and the hard spending cap. Run with:
 *   node test/taskmarket.test.mjs
 *
 * Network calls (searchTasks, getTask, listSubmissions, marketStats,
 * createTask) are exercised live in a separate integration script; see
 * scripts/taskmarket-live-check.mjs.
 */
import assert from 'node:assert';
import {
  baseUnitsToUsdc,
  usdcToBaseUnits,
  assertTaskMarketChallenge,
  TASKMARKET_PAYMENT_POLICY,
} from '../build/taskmarket.js';
import { createTask } from '../build/taskmarket.js';

let passed = 0;
function ok(name, fn) { fn(); passed++; console.log(`  ok - ${name}`); }
async function okAsync(name, fn) { await fn(); passed++; console.log(`  ok - ${name}`); }

const POLICY = TASKMARKET_PAYMENT_POLICY;
const REWARD = '2000000'; // 2 USDC in base units

// ── Unit conversion ─────────────────────────────────────────────

ok('baseUnitsToUsdc formats a whole-amount reward', () => {
  assert.strictEqual(baseUnitsToUsdc('2000000'), '2');
  assert.strictEqual(baseUnitsToUsdc('4500000'), '4.5');
});

ok('baseUnitsToUsdc handles sub-cent and empty values', () => {
  assert.strictEqual(baseUnitsToUsdc('1000'), '0.001');
  assert.strictEqual(baseUnitsToUsdc(null), '0');
  assert.strictEqual(baseUnitsToUsdc(''), '0');
  assert.strictEqual(baseUnitsToUsdc('abc'), '0');
});

ok('usdcToBaseUnits converts human USDC to base units', () => {
  assert.strictEqual(usdcToBaseUnits('2'), '2000000');
  assert.strictEqual(usdcToBaseUnits('0.5'), '500000');
  assert.strictEqual(usdcToBaseUnits('1.000000'), '1000000');
});

ok('usdcToBaseUnits rejects malformed amounts', () => {
  assert.throws(() => usdcToBaseUnits('-1'), /Invalid USDC amount/);
  assert.throws(() => usdcToBaseUnits('abc'), /Invalid USDC amount/);
  assert.throws(() => usdcToBaseUnits('1..2'), /Invalid USDC amount/);
});

// ── Pinned payment policy ───────────────────────────────────────

function goodChallenge(overrides = {}) {
  return {
    x402Version: 2,
    resource: { url: POLICY.resource },
    accepts: [{
      scheme: 'exact',
      network: POLICY.network,
      amount: REWARD,
      asset: POLICY.asset,
      payTo: POLICY.payTo,
      maxTimeoutSeconds: 300,
      extra: { name: 'USD Coin' },
      ...overrides,
    }],
  };
}

ok('accepts a challenge matching TaskMarket pinned policy', () => {
  const accept = assertTaskMarketChallenge(goodChallenge(), REWARD);
  assert.strictEqual(accept.payTo, POLICY.payTo);
});

ok('rejects a challenge on the wrong network', () => {
  assert.throws(
    () => assertTaskMarketChallenge(goodChallenge({ network: 'eip155:1' }), REWARD),
    /network/,
  );
});

ok('rejects a challenge with a foreign payee', () => {
  assert.throws(
    () => assertTaskMarketChallenge(goodChallenge({ payTo: '0x000000000000000000000000000000000000dEaD' }), REWARD),
    /payTo/,
  );
});

ok('rejects a challenge with a non-USDC asset', () => {
  assert.throws(
    () => assertTaskMarketChallenge(goodChallenge({ asset: '0x000000000000000000000000000000000000dEaD' }), REWARD),
    /asset/,
  );
});

ok('rejects a challenge whose resource URL is not the create endpoint', () => {
  assert.throws(
    () => assertTaskMarketChallenge({ ...goodChallenge(), resource: { url: 'https://evil.example/tasks' } }, REWARD),
    /resource/,
  );
});

ok('rejects a challenge whose quoted escrow differs from the requested reward', () => {
  assert.throws(
    () => assertTaskMarketChallenge(goodChallenge({ amount: '9999999' }), REWARD),
    /does not equal the requested reward/,
  );
});

ok('rejects a challenge with an excessive timeout', () => {
  assert.throws(
    () => assertTaskMarketChallenge(goodChallenge({ maxTimeoutSeconds: 3600 }), REWARD),
    /maxTimeoutSeconds/,
  );
});

ok('rejects a challenge with no accepts array', () => {
  assert.throws(
    () => assertTaskMarketChallenge({ accepts: [] }, REWARD),
    /without any payment options/,
  );
});

// ── Create gate: confirmation + spending cap ────────────────────

okAsync('create refuses without explicit confirmation, no payer called', async () => {
  let payerCalled = false;
  const result = await createTask({
    description: 'delegate this research',
    reward_usdc: '2',
    duration_hours: 48,
    tags: ['research'],
    confirm: false,
    max_reward_usdc: '5',
    payer: async () => { payerCalled = true; return { txHash: '0x' }; },
  });
  assert.strictEqual(result.status, 'refused');
  assert.match(result.reason, /confirm=true/);
  assert.strictEqual(payerCalled, false, 'no payment may be attempted without confirmation');
});

okAsync('create refuses when the reward exceeds the hard cap', async () => {
  let payerCalled = false;
  const result = await createTask({
    description: 'delegate this research',
    reward_usdc: '10',
    duration_hours: 48,
    tags: ['research'],
    confirm: true,
    max_reward_usdc: '5',
    payer: async () => { payerCalled = true; return { txHash: '0x' }; },
  });
  assert.strictEqual(result.status, 'refused');
  assert.match(result.reason, /exceeds the configured cap/);
  assert.strictEqual(payerCalled, false, 'no payment may be attempted over the cap');
});

okAsync('create validates description, duration, and tags before calling the network', async () => {
  await assert.rejects(
    createTask({
      description: '',
      reward_usdc: '1',
      duration_hours: 1,
      tags: ['x'],
      confirm: true,
      max_reward_usdc: '1',
      payer: async () => { throw new Error('payer must not be reached'); },
    }),
    /description must be between/,
  );
  await assert.rejects(
    createTask({
      description: 'ok',
      reward_usdc: '1',
      duration_hours: -1,
      tags: ['x'],
      confirm: true,
      max_reward_usdc: '1',
      payer: async () => { throw new Error('payer must not be reached'); },
    }),
    /duration_hours/,
  );
  await assert.rejects(
    createTask({
      description: 'ok',
      reward_usdc: '1',
      duration_hours: 1,
      tags: [],
      confirm: true,
      max_reward_usdc: '1',
      payer: async () => { throw new Error('payer must not be reached'); },
    }),
    /between 1 and 10 tags/,
  );
});

console.log(`\ntaskmarket tests: ${passed} passed, 0 failed`);
if (passed === 0) process.exit(1);
