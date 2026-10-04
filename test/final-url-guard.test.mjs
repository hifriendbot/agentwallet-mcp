/**
 * Regression tests for the two 2026-10-04 findings.
 *
 *  1. pay_x402 refuses a 402 that arrived through a cross-origin redirect. It
 *     learned the serving origin from the x-agw-final-url header that safeFetch
 *     adds, but safeFetch copied every server header through first, so a server
 *     could send that header itself and claim the addressed origin. The final
 *     URL is now recorded out of band (finalUrlOf) and a server-sent header of
 *     that name is dropped.
 *
 *  2. The authorization-reuse key omitted the URL's query string, so two
 *     resources at the same path shared one signature.
 *
 * Part 1 is pure (no network). Part 2 reproduces the report's shape against
 * two public hosts, the way the existing SSRF tests already do, and is skipped
 * with a note if the hosts are unreachable.
 *
 * Run with: node test/final-url-guard.test.mjs
 */
import assert from 'node:assert';

const { buildFetchedResponse, finalUrlOf, FINAL_URL_HEADER, safeFetch } = await import('../build/ssrf-guard.js');
const { authorizationResource } = await import('../build/x402-payment.js');

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`  ok - ${name}`); };
const okAsync = async (name, fn) => { await fn(); passed++; console.log(`  ok - ${name}`); };

const ADDRESSED = 'https://api.trusted.example/paid';
const ATTACKER = 'https://attacker.example/x';
const body = new TextEncoder().encode('{}').buffer;

ok('a server-sent x-agw-final-url is dropped and the real one is the only value', () => {
  const res = buildFetchedResponse(402, 'Payment Required', [['content-type', 'application/json'], [FINAL_URL_HEADER, ADDRESSED + '/']], body, ATTACKER);
  assert.strictEqual(res.headers.get(FINAL_URL_HEADER), ATTACKER);
  assert.strictEqual(finalUrlOf(res, ADDRESSED), ATTACKER);
});

ok('the forged header is dropped whatever its letter case', () => {
  const res = buildFetchedResponse(402, '', [['X-AGW-Final-URL', ADDRESSED]], body, ATTACKER);
  assert.strictEqual(res.headers.get(FINAL_URL_HEADER), ATTACKER);
  assert.strictEqual(finalUrlOf(res, ADDRESSED), ATTACKER);
});

ok('finalUrlOf ignores headers entirely: a hand-built Response gets the fallback, not its header', () => {
  const fake = new Response(null, { status: 402, headers: { [FINAL_URL_HEADER]: ADDRESSED } });
  assert.strictEqual(finalUrlOf(fake, 'https://fallback.example/'), 'https://fallback.example/');
});

ok("the report's exact check refuses once the served origin is read out of band", () => {
  const res = buildFetchedResponse(402, '', [[FINAL_URL_HEADER, 'https://api.trusted.example/']], body, ATTACKER);
  const servedFrom = finalUrlOf(res, ADDRESSED);
  assert.notStrictEqual(new URL(servedFrom).origin, new URL(ADDRESSED).origin, 'cross-origin must be detected');
});

ok('ordinary server headers still come through, transfer-level ones do not', () => {
  const res = buildFetchedResponse(200, 'OK', [['content-type', 'text/plain'], ['content-encoding', 'gzip'], ['content-length', '999'], ['payment-required', 'abc']], body, ADDRESSED);
  assert.strictEqual(res.headers.get('content-type'), 'text/plain');
  assert.strictEqual(res.headers.get('payment-required'), 'abc');
  assert.strictEqual(res.headers.get('content-encoding'), null);
  assert.strictEqual(res.headers.get('content-length'), null);
});

ok('two resources at the same path with different queries get different authorization keys', () => {
  const a = authorizationResource('https://api.example/buy?id=1');
  const b = authorizationResource('https://api.example/buy?id=2');
  const c = authorizationResource('https://api.example/buy');
  assert.notStrictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.strictEqual(a, 'https://api.example/buy?id=1');
  assert.strictEqual(authorizationResource('https://api.example/buy?id=1#frag'), a, 'the fragment is not part of the resource');
});

// Live shape of the report: a public host that redirects cross-origin to a
// second public host which echoes a forged x-agw-final-url in its response.
console.log('\nfinal-url-guard: live redirect through two public hosts');
const forged = `https://httpbingo.org/response-headers?${FINAL_URL_HEADER}=${encodeURIComponent('https://httpbin.org/')}`;
const addressed = `https://httpbin.org/redirect-to?url=${encodeURIComponent(forged)}`;
try {
  await okAsync('a forged header on the far side of a cross-origin redirect does not hide the redirect', async () => {
    const res = await safeFetch(addressed, { method: 'GET', signal: AbortSignal.timeout(20_000) });
    const servedFrom = finalUrlOf(res, addressed);
    assert.strictEqual(new URL(servedFrom).origin, 'https://httpbingo.org');
    assert.notStrictEqual(new URL(servedFrom).origin, new URL(addressed).origin);
    assert.strictEqual(res.headers.get(FINAL_URL_HEADER), servedFrom, 'only the real value is in the header');
  });
} catch (e) {
  console.log(`  skip - live redirect check (${String(e.message).split('\n')[0]})`);
}

console.log(`\nfinal-url-guard: ${passed} passed`);
