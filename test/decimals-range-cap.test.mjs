/**
 * Regression test for the 2026-09-26 report: token-cap guard failed open for
 * unpriced calldata when the target's decimals() answered outside 0..36.
 *
 * The probe rejected out-of-range decimals (correct: an absurd value would
 * widen the ceiling) but reported that rejection with the same null it used
 * for "does not answer decimals() at all". The unpriced-calldata branch read
 * null as "not a token" and allowed the call. Two byte-identical ERC-20s that
 * differed only in the decimals immutable were blocked (18) and sent (77).
 *
 * The probe now reports four outcomes, and only "not a token" (the contract
 * reverted or returned nothing) may reach the allow branch. "Answered
 * nonsense" and "RPC unreachable" both refuse.
 *
 * A local JSON-RPC mock plays each kind of contract so the test needs no
 * network and no real chain.
 *
 * Run with: node test/decimals-range-cap.test.mjs
 */
import assert from 'node:assert';
import { createServer } from 'node:http';

const CHAIN = 8453;
// One address per case: the probe caches a usable decimals() answer per
// address, so reusing one would let the first answer decide every case.
let caseNo = 0;
const nextTarget = () => '0x' + (0xb0 + ++caseNo).toString(16).padStart(40, '0'); // not in the trusted registry
// The reporter's unpriced selector plus two words of arguments; the guard
// cannot price it, so classification of the target decides everything.
const UNPRICED = '0x62c06767' + '0'.repeat(128);

const word = (n) => '0x' + n.toString(16).padStart(64, '0');

/** How the mock answers eth_call; flipped per case below. */
let mode = 'decimals77';
const answers = {
  decimals77: () => ({ result: word(77) }),                       // a token with absurd decimals
  decimals255: () => ({ result: word(255) }),                     // uint8 max, still absurd
  decimals18: () => ({ result: word(18) }),                       // an ordinary token
  empty: () => ({ result: '0x' }),                                // no such function: a router, or an account
  short: () => ({ result: '0x1234' }),                            // answered, but not a uint8
  revert: () => ({ error: { code: 3, message: 'execution reverted', data: '0x' } }),
};

const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const rpc = JSON.parse(body);
    const reply = (extra) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, ...extra }));
    };
    if (rpc.method === 'eth_call') return reply(answers[mode]());
    if (rpc.method === 'eth_chainId') return reply({ result: '0x' + CHAIN.toString(16) });
    // Anything past the guard (nonce, gas, send) is refused so an allowed call
    // fails here, visibly, instead of being signed.
    reply({ error: { code: -32601, message: `mock: ${rpc.method} not served` } });
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const MOCK = `http://127.0.0.1:${server.address().port}/`;

// Throwaway key. Never signs: every case is decided by the guard or by the
// mock refusing to serve the transaction path.
process.env.AGENTWALLET_PRIVATE_KEY = '0x' + '1'.repeat(64);
process.env.AGENTWALLET_MAX_TX_TOKEN = '1';
process.env[`AGENTWALLET_RPC_${CHAIN}`] = MOCK;

const { localSend } = await import('../build/local-wallet.js');

let passed = 0;
const GUARD = /AGENTWALLET_MAX_TX_TOKEN|Blocked by local guard/;

async function refused(name, pattern) {
  const target = nextTarget();
  try {
    await localSend(CHAIN, target, 0n, UNPRICED);
    throw new Error(`${name}: expected the guard to refuse this`);
  } catch (e) {
    assert.match(e.message, GUARD, `${name}: not the guard: "${e.message}"`);
    assert.match(e.message, pattern, `${name}: unexpected reason: "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}

async function allowed(name) {
  const target = nextTarget();
  let guardBlocked = false;
  try { await localSend(CHAIN, target, 0n, UNPRICED); }
  catch (e) { guardBlocked = GUARD.test(e.message); }
  assert.strictEqual(guardBlocked, false, `${name}: the guard must not be what stops this`);
  passed++;
  console.log(`  ok - ${name}`);
}

// The report's discriminator: same calldata, same cap, only decimals() differs.
mode = 'decimals18';
await refused('refuses unpriced calldata to a token with decimals() = 18 (control)', /not one AGENTWALLET_MAX_TX_TOKEN can price/);
mode = 'decimals77';
await refused('refuses unpriced calldata to a token with decimals() = 77 (was allowed)', /not one AGENTWALLET_MAX_TX_TOKEN can price/);
mode = 'decimals255';
await refused('refuses unpriced calldata to a token with decimals() = 255', /not one AGENTWALLET_MAX_TX_TOKEN can price/);
mode = 'short';
await refused('refuses when decimals() answers data that is not a uint8', /not one AGENTWALLET_MAX_TX_TOKEN can price/);

// Contracts that demonstrably decline decimals() are not tokens; the call can
// only pull what an approval already allowed, so it passes the cap.
mode = 'empty';
await allowed('allows unpriced calldata when decimals() returns no data (a router)');
mode = 'revert';
await allowed('allows unpriced calldata when decimals() reverts (a router)');

// No answer at all is not evidence of anything. Refuse, and say why.
process.env[`AGENTWALLET_RPC_${CHAIN}`] = 'http://127.0.0.1:1/dead';
await refused('refuses unpriced calldata when the RPC is unreachable (cannot classify)', /could not be reached to classify/);
process.env[`AGENTWALLET_RPC_${CHAIN}`] = MOCK;

// The operator's explicit opt-out still works, and still applies only to
// unpriced calldata: a priced transfer against the 77-decimals token is
// evaluated at 0 decimals (the tightest ceiling) and blocked.
mode = 'decimals77';
process.env.AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS = '1';
await allowed('AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS=1 lets it through deliberately');
delete process.env.AGENTWALLET_ALLOW_UNKNOWN_TOKEN_CALLS;
{
  // transfer(0xdead, 2) on the 77-decimals token: 2 base units at 0 decimals is 2 > cap 1.
  const transfer = '0xa9059cbb' + '000000000000000000000000000000000000dEaD'.padStart(64, '0') + word(2).slice(2);
  try {
    await localSend(CHAIN, nextTarget(), 0n, transfer);
    throw new Error('expected the priced path to block this');
  } catch (e) {
    assert.match(e.message, /AGENTWALLET_MAX_TX_TOKEN/, `priced path: unexpected error "${e.message}"`);
    passed++;
    console.log('  ok - a priced transfer on the 77-decimals token is evaluated at 0 decimals and blocked');
  }
}

server.close();
console.log(`\ndecimals-range-cap: ${passed} passed`);
