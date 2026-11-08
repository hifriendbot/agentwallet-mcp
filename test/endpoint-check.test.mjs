/**
 * Endpoint check (policy `endpoint_check`): the index's answer becomes a
 * verdict, the verdict a refusal or not, and only the URL's origin and path
 * are sent. The index is a local HTTP double; nothing here reaches the network.
 *
 * Run: node test/endpoint-check.test.mjs
 */
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

const { checkedUrl, verdictFromAnswer, endpointRefusal, endpointVerdict, payToComparison } = await import('../build/endpoint-check.js');
const { parsePolicy } = await import('../build/policy.js');

let passed = 0;
let failed = 0;
const check = (name, fn) => { try { fn(); passed++; console.log(`  PASS  ${name}`); } catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); } };
const checkAsync = async (name, fn) => { try { await fn(); passed++; console.log(`  PASS  ${name}`); } catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); } };

const PAY_TO = '0x0E84dDEdAaE6A779c462C22a59F301EC31B6b808';
const OTHER = '0x000000000000000000000000000000000000dEaD';
const quote = { payTo: PAY_TO, chainId: 8453 };
const settled = { provider: 'settled' };
const answer = (over = {}) => ({ url: 'https://api.example.com/search', status: 'live', recommendation: 'pay', reasons: ['a real payment by Settled\'s scout came back with content'], pay_to: PAY_TO, network: 'eip155:8453', ...over });

check('only origin and path are sent: userinfo, query and fragment are dropped', () => {
  assert.equal(checkedUrl('https://user:pw@api.example.com:8443/v1/search?q=secret#frag'), 'https://api.example.com:8443/v1/search');
  assert.equal(checkedUrl('https://api.example.com/'), 'https://api.example.com/');
});

check('a pay answer is a pay verdict with the recipient compared', () => {
  const v = verdictFromAnswer('https://api.example.com/search', quote, 200, answer());
  assert.equal(v.recommendation, 'pay');
  assert.equal(v.pay_to_matches, true);
  assert.equal(v.endpoint_status, 'live');
  assert.equal(v.error, null);
  assert.equal(endpointRefusal(settled, v), null);
});

check('avoid refuses by default, with the index\'s reasons in the message', () => {
  const v = verdictFromAnswer('https://api.example.com/search', quote, 200, answer({ recommendation: 'avoid', reasons: ['the last real payment by Settled\'s scout came back without usable content'] }));
  const why = endpointRefusal(settled, v);
  assert.ok(why && /recommendation .* is avoid/.test(why), why);
  assert.ok(why.includes('without usable content'));
});

check('caution and unknown pass by default; the operator can refuse them', () => {
  for (const r of ['caution', 'unknown']) {
    const v = verdictFromAnswer('https://api.example.com/search', quote, 200, answer({ recommendation: r }));
    assert.equal(endpointRefusal(settled, v), null, r);
    assert.ok(endpointRefusal({ provider: 'settled', refuse: ['avoid', r] }, v), `${r} refused when listed`);
  }
});

check('a quote paying another recipient on the same chain is refused whatever the recommendation', () => {
  const v = verdictFromAnswer('https://api.example.com/search', { payTo: OTHER, chainId: 8453 }, 200, answer({ recommendation: 'pay' }));
  assert.equal(v.pay_to_matches, false);
  const why = endpointRefusal(settled, v);
  assert.ok(why && why.includes(OTHER) && why.includes(PAY_TO), why);
});

check('EVM addresses compare case-insensitively; another chain is not compared', () => {
  assert.equal(payToComparison({ payTo: PAY_TO.toLowerCase(), chainId: 8453 }, { payTo: PAY_TO, network: 'eip155:8453' }), true);
  assert.equal(payToComparison({ payTo: OTHER, chainId: 137 }, { payTo: PAY_TO, network: 'eip155:8453' }), null);
  assert.equal(payToComparison({ payTo: OTHER, chainId: 8453 }, { payTo: PAY_TO, network: 'base' }), false, 'a network name resolves too');
  assert.equal(payToComparison(quote, { payTo: null, network: 'eip155:8453' }), null);
  assert.equal(payToComparison(quote, { payTo: PAY_TO, network: 'made-up' }), null);
});

check('an index error allows by default and refuses under on_error "refuse"', () => {
  const used = verdictFromAnswer('https://api.example.com/search', quote, 429, { error: 'free_quota_exhausted', used_today: 25 });
  assert.equal(used.recommendation, 'error');
  assert.ok(used.error.includes('free_quota_exhausted'));
  assert.equal(endpointRefusal(settled, used), null);
  assert.ok(endpointRefusal({ provider: 'settled', on_error: 'refuse' }, used).includes('on_error'));
  const down = verdictFromAnswer('https://api.example.com/search', quote, 0, null);
  assert.equal(down.error, 'the index could not be reached');
  const odd = verdictFromAnswer('https://api.example.com/search', quote, 200, answer({ recommendation: 'buy now' }));
  assert.equal(odd.recommendation, 'error', 'a recommendation outside the four words is not trusted');
});

check('the index\'s text is bounded: at most 8 reasons of 300 characters', () => {
  const v = verdictFromAnswer('https://api.example.com/search', quote, 200, answer({ reasons: Array.from({ length: 12 }, (_, i) => `r${i} ` + 'x'.repeat(400)) }));
  assert.equal(v.reasons.length, 8);
  assert.ok(v.reasons.every(r => r.length === 301 && r.endsWith('…')));
  const noList = verdictFromAnswer('https://api.example.com/search', quote, 200, answer({ reasons: 'not a list' }));
  assert.deepEqual(noList.reasons, []);
});

check('the policy accepts endpoint_check and refuses a misspelled key inside it', () => {
  const p = parsePolicy(JSON.stringify({ version: 1, endpoint_check: { provider: 'settled', refuse: ['avoid', 'caution'], on_error: 'refuse', timeout_seconds: 5 } }));
  assert.deepEqual(p.endpoint_check.refuse, ['avoid', 'caution']);
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, endpoint_check: { provider: 'settled', refuses: ['avoid'] } })), /endpoint_check/);
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, endpoint_check: { provider: 'other' } })), /endpoint_check\.provider/);
  assert.throws(() => parsePolicy(JSON.stringify({ version: 1, endpoint_check: { provider: 'settled', refuse: ['pay'] } })), /endpoint_check\.refuse/);
});

// A local double of the index: records what it was asked, answers what the test says.
const asked = [];
let reply = { status: 200, body: answer() };
const server = createServer((req, res) => {
  asked.push(req.url);
  res.writeHead(reply.status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(reply.body));
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

await checkAsync('endpointVerdict asks /v1/free/check with the origin and path only', async () => {
  const v = await endpointVerdict({ provider: 'settled', base_url: base }, 'https://api.example.com/search?q=secret&key=abc', quote);
  assert.equal(asked.length, 1);
  assert.equal(asked[0], '/v1/free/check?url=' + encodeURIComponent('https://api.example.com/search'));
  assert.ok(!asked[0].includes('secret'));
  assert.equal(v.recommendation, 'pay');
  assert.equal(v.pay_to_matches, true);
});

await checkAsync('a 429 from the index is an error verdict, allowed by default', async () => {
  reply = { status: 429, body: { error: 'rate_limited' } };
  const v = await endpointVerdict({ provider: 'settled', base_url: base }, 'https://api.example.com/search', quote);
  assert.equal(v.recommendation, 'error');
  assert.equal(v.index_http_status, 429);
  assert.equal(endpointRefusal({ provider: 'settled', base_url: base }, v), null);
});

await checkAsync('an index that cannot be reached is an error verdict, not an exception', async () => {
  const v = await endpointVerdict({ provider: 'settled', base_url: 'http://127.0.0.1:1', timeout_seconds: 2 }, 'https://api.example.com/search', quote);
  assert.equal(v.recommendation, 'error');
  assert.equal(v.index_http_status, 0);
});

server.close();
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
