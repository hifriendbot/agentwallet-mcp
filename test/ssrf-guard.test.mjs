/**
 * Regression tests for the pay_x402 SSRF guard.
 * Models the private disclosure from ARC Security Research (2026-07-31) plus
 * the additional bypass classes found while verifying it, the anonymous
 * DNS rebinding report (2026-08-02) closed by connection pinning, and the
 * cross-origin redirect credential leak reported by Arthur Kijkrittaya
 * (2026-09-08): safeFetch used to carry the caller's Authorization header to
 * whatever origin the first endpoint redirected to.
 */
import assert from 'node:assert';
import { createServer } from 'node:http';
import { Agent, fetch as undiciFetch } from 'undici';
import {
  canonicalizeHost,
  isPrivateAddress,
  assertPublicUrl,
  resolvePublicUrl,
  createPinnedLookup,
  safeFetch,
  sameOrigin,
  headersForRedirect,
} from '../build/ssrf-guard.js';

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

console.log('\nssrf-guard: validation returns the addresses to connect to');
await ta('an IP literal pins to itself with no DNS involved', async () => {
  const { addresses } = await resolvePublicUrl('https://8.8.8.8/');
  assert.deepEqual(addresses, [{ address: '8.8.8.8', family: 4 }]);
});
await ta('an IPv4-mapped literal pins to the unwrapped address', async () => {
  const { addresses } = await resolvePublicUrl('https://[::ffff:8.8.8.8]/');
  assert.deepEqual(addresses, [{ address: '8.8.8.8', family: 4 }]);
});
await ta('a public name returns at least one public address', async () => {
  const { addresses } = await resolvePublicUrl('https://example.com/');
  assert.ok(addresses.length > 0, 'expected at least one address');
  for (const a of addresses) assert.equal(isPrivateAddress(a.address), false);
});

console.log('\nssrf-guard: pinned lookup (the DNS rebinding fix)');
const callLookup = (fn, host, opts) => new Promise((res, rej) => {
  fn(host, opts, (err, a, family) => (err ? rej(err) : res({ a, family })));
});

await ta('a second resolution cannot change the address (the rebind attempt)', async () => {
  // "localhost" really does resolve to a private address on this machine, so if
  // anything consulted the resolver at connect time this would come back
  // 127.0.0.1. The pin is what makes that impossible.
  const pinned = createPinnedLookup([{ address: '93.184.216.34', family: 4 }]);
  const { a } = await callLookup(pinned, 'localhost', { all: true });
  assert.deepEqual(a, [{ address: '93.184.216.34', family: 4 }]);
});
await ta('a name that does not resolve at all still answers from the pin', async () => {
  const pinned = createPinnedLookup([{ address: '93.184.216.34', family: 4 }]);
  const { a, family } = await callLookup(pinned, 'no-such-host.invalid', {});
  assert.equal(a, '93.184.216.34');
  assert.equal(family, 4);
});
await ta('all:true yields the whole validated set, in order', async () => {
  const set = [{ address: '93.184.216.34', family: 4 }, { address: '2606:2800:220:1::1', family: 6 }];
  const pinned = createPinnedLookup(set);
  const { a } = await callLookup(pinned, 'example.com', { all: true });
  assert.deepEqual(a, set);
});
await ta('a family filter narrows the pin and never falls back to DNS', async () => {
  const pinned = createPinnedLookup([{ address: '93.184.216.34', family: 4 }]);
  await assert.rejects(() => callLookup(pinned, 'example.com', { family: 6, all: true }),
    e => e.code === 'ENOTFOUND');
});

console.log('\nssrf-guard: the pin reaches the socket');
await ta('undici connects to the pinned address, not to the hostname', async () => {
  const server = createServer((_req, res) => { res.writeHead(200); res.end('pinned-ok'); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  // The hostname is unresolvable on purpose: the only way this request can
  // succeed is if the connector honoured our lookup. That is the wiring the
  // whole fix depends on, so it is asserted rather than assumed.
  const agent = new Agent({ connect: { lookup: createPinnedLookup([{ address: '127.0.0.1', family: 4 }]) } });
  try {
    const res = await undiciFetch(`http://no-such-host.invalid:${port}/`, { dispatcher: agent });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'pinned-ok');
  } finally {
    await agent.destroy();
    await new Promise(r => server.close(r));
  }
});

console.log('\nssrf-guard: credentials do not follow a cross-origin redirect');
const SECRETS = {
  Authorization: 'Bearer SECRET',
  Cookie: 'session=SECRET',
  'Proxy-Authorization': 'Basic SECRET',
  'X-PAYMENT': 'SECRETPROOF',
  'X-Api-Key': 'SECRET',
  Accept: 'application/json',
  'Accept-Language': 'en',
  'User-Agent': 'agentwallet-test',
  'Content-Type': 'application/json',
};
const A = 'https://api.example.com/resource';
t('origin compares scheme, host and port', () => {
  assert.equal(sameOrigin(A, 'https://api.example.com/elsewhere?x=1'), true);
  assert.equal(sameOrigin(A, 'https://evil.example/'), false);
  assert.equal(sameOrigin(A, 'https://api.example.com:8443/resource'), false);
  assert.equal(sameOrigin(A, 'https://API.EXAMPLE.COM/resource'), true);
});
t('cross-origin redirect strips Authorization, Cookie, X-PAYMENT and custom headers (the report)', () => {
  const h = headersForRedirect(SECRETS, A, 'https://evil.example/collect', false);
  for (const k of ['Authorization', 'Cookie', 'Proxy-Authorization', 'X-PAYMENT', 'X-Api-Key']) {
    assert.equal(k in h, false, `${k} leaked across origins`);
  }
  assert.equal(JSON.stringify(h).includes('SECRET'), false, 'a secret value survived');
});
t('cross-origin redirect keeps only content negotiation headers', () => {
  const h = headersForRedirect(SECRETS, A, 'https://evil.example/collect', false);
  assert.deepEqual(Object.keys(h).sort(), ['Accept', 'Accept-Language', 'Content-Type', 'User-Agent']);
});
t('same host, different port is a different origin', () => {
  const h = headersForRedirect(SECRETS, A, 'https://api.example.com:8443/resource', false);
  assert.equal('Authorization' in h, false);
});
t('same-origin redirect keeps the credentials, as a browser would', () => {
  const h = headersForRedirect(SECRETS, A, 'https://api.example.com/v2/resource', false);
  assert.equal(h.Authorization, 'Bearer SECRET');
  assert.equal(h['X-PAYMENT'], 'SECRETPROOF');
  assert.equal(h['X-Api-Key'], 'SECRET');
});
t('a redirect that drops the body drops the body headers too, on either kind of hop', () => {
  const same = headersForRedirect(SECRETS, A, 'https://api.example.com/next', true);
  assert.equal('Content-Type' in same, false);
  assert.equal(same.Authorization, 'Bearer SECRET');
  const cross = headersForRedirect(SECRETS, A, 'https://evil.example/', true);
  assert.equal('Content-Type' in cross, false);
  assert.equal('Authorization' in cross, false);
});
t('header names are matched case-insensitively', () => {
  const h = headersForRedirect({ AUTHORIZATION: 'Bearer SECRET', accept: 'text/plain' }, A, 'https://evil.example/', false);
  assert.deepEqual(h, { accept: 'text/plain' });
});
t('accepts a Headers instance and an entries array as input', () => {
  const fromHeaders = headersForRedirect(new Headers({ Authorization: 'Bearer SECRET', Accept: 'x' }), A, 'https://evil.example/', false);
  assert.deepEqual(fromHeaders, { accept: 'x' });
  const fromArray = headersForRedirect([['Authorization', 'Bearer SECRET'], ['Accept', 'y']], A, 'https://evil.example/', false);
  assert.deepEqual(fromArray, { Accept: 'y' });
});
t('no headers at all is fine', () => {
  assert.deepEqual(headersForRedirect(undefined, A, 'https://evil.example/', true), {});
});

// Live reproduction of the report through the real safeFetch: httpbin
// redirects to a different origin that echoes the request headers back. Only
// a synthetic marker is sent. Skipped, not failed, if either service is down.
await ta('live: a cross-origin 302 does not carry the Authorization header (reporter\'s reproduction)', async () => {
  const marker = 'SYNTHETIC_MARKER_NOT_A_SECRET';
  const target = 'https://httpbin.org/redirect-to?url=' + encodeURIComponent('https://postman-echo.com/headers') + '&status_code=302';
  let res;
  try {
    res = await safeFetch(target, {
      headers: { Authorization: 'Bearer ' + marker, 'X-Audit-Marker': marker, Accept: 'application/json' },
      signal: AbortSignal.timeout(20_000),
    });
  } catch (e) {
    console.log(`       (skipped: ${e.message})`);
    return;
  }
  if (res.status !== 200) { console.log(`       (skipped: echo service answered ${res.status})`); return; }
  const text = await res.text();
  assert.equal(text.includes(marker), false, 'marker reached the second origin');
  assert.match(text, /postman-echo\.com/, 'expected the echo from the second origin');
});

console.log('\nssrf-guard: safeFetch still works against a real endpoint');
await ta('pinned https request completes with valid SNI and certificate', async () => {
  const res = await safeFetch('https://example.com/', { signal: AbortSignal.timeout(20_000) });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.length > 0, 'expected a response body');
});
await ta('safeFetch still refuses a private destination', async () => {
  await assert.rejects(() => safeFetch('https://127.0.0.1/'), /private\/internal/);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
