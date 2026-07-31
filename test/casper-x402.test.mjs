/**
 * Casper x402 and local-signing tests.
 *
 * Three things are load-bearing here and each has a test that fails loudly if
 * it regresses:
 *   1. mote math is exact — a sub-mote amount throws rather than truncating,
 *      because a silently rounded amount under-pays an invoice
 *   2. the facilitator client fails CLOSED — anything short of an explicit
 *      `true` is a payment failure, never a pass
 *   3. Casper is opt-in — with no key configured the server behaves exactly as
 *      it did before
 *
 * Run: node test/casper-x402.test.mjs
 */

import assert from 'node:assert';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';

import {
  blake2b256,
  csprToMotes,
  motesToCspr,
  parseCasperKey,
  isValidCasperPublicKey,
  accountHash,
  clBigNumber,
  buildTransferDeploy,
  buildCep18TransferDeploy,
  getCasperAddress,
  isCasperLocalMode,
  resolveCasperRpc,
  CASPER_MAINNET_CHAIN_ID,
  CASPER_TESTNET_CHAIN_ID,
} from '../build/local-casper.js';

import {
  isCasperNetwork,
  isCasperChain,
  resolveCasperChainId,
  selectCasperAccept,
  resolveCasperRequirement,
  isWithinCasperCap,
  buildCasperPayment,
  encodePaymentHeader,
  verifyPayment,
  settlePayment,
  facilitatorUrl,
} from '../build/casper-x402.js';

let passed = 0;
let failed = 0;

function ok(name, fn) {
  try {
    fn();
    console.log(`  ok - ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL - ${name}\n        ${e.message}`);
    failed++;
  }
}

async function okAsync(name, fn) {
  try {
    await fn();
    console.log(`  ok - ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL - ${name}\n        ${e.message}`);
    failed++;
  }
}

/* Throwaway keys, generated per run. Never used for funds. */
const ED_PEM = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' });
const SECP_PEM = generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).privateKey
  .export({ format: 'pem', type: 'sec1' });
const HEX_SECRET = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';

/* A well-formed testnet accept, used by most of the x402 cases below. */
const PAY_TO = '01' + 'ab'.repeat(32);
const WCSPR = 'cd'.repeat(32);
const ACCEPT = {
  scheme: 'exact',
  network: 'casper:casper-test',
  maxAmountRequired: '1500000000', // 1.5 wCSPR in motes
  payTo: PAY_TO,
  asset: WCSPR,
  extra: { name: 'wCSPR', decimals: 9 },
};

/* ── blake2b-256 ──────────────────────────────────────────────────────────
   Every Casper hash (deploy hash, body hash, account hash) rides on this, so
   it is checked against the published RFC 7693 vectors first. */

ok('blake2b256 matches the empty-input vector', () => {
  assert.strictEqual(
    blake2b256(Buffer.alloc(0)).toString('hex'),
    '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'
  );
});

ok('blake2b256 matches the "abc" vector', () => {
  assert.strictEqual(
    blake2b256(Buffer.from('abc')).toString('hex'),
    'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'
  );
});

ok('blake2b256 handles input longer than one 128-byte block', () => {
  const long = blake2b256(Buffer.alloc(300, 0x61));
  assert.strictEqual(long.length, 32);
  assert.notStrictEqual(long.toString('hex'), blake2b256(Buffer.alloc(0)).toString('hex'));
});

/* ── Mote math ────────────────────────────────────────────────────────────
   The hard requirement: exact integer math, and a throw rather than a silent
   truncation when an amount is finer than one mote. */

ok('csprToMotes converts whole CSPR exactly', () => {
  assert.strictEqual(csprToMotes('1'), 1000000000n);
  assert.strictEqual(csprToMotes('0'), 0n);
  assert.strictEqual(csprToMotes('2.5'), 2500000000n);
});

ok('csprToMotes keeps full precision on large amounts (no float drift)', () => {
  assert.strictEqual(csprToMotes('123456789.123456789'), 123456789123456789n);
});

ok('csprToMotes accepts exactly 9 decimals', () => {
  assert.strictEqual(csprToMotes('0.000000001'), 1n);
});

ok('csprToMotes THROWS on sub-mote precision instead of truncating', () => {
  assert.throws(() => csprToMotes('0.0000000001'), /sub-mote precision/);
  assert.throws(() => csprToMotes('1.1234567891'), /refusing to truncate/);
});

ok('csprToMotes tolerates trailing zeros beyond 9 decimals', () => {
  assert.strictEqual(csprToMotes('1.5000000000'), 1500000000n);
});

ok('csprToMotes rejects malformed amounts', () => {
  assert.throws(() => csprToMotes('-1'), /Invalid CSPR amount/);
  assert.throws(() => csprToMotes('abc'), /Invalid CSPR amount/);
  assert.throws(() => csprToMotes(''), /Invalid CSPR amount/);
});

ok('motesToCspr round-trips exactly', () => {
  assert.strictEqual(motesToCspr('1500000000'), '1.5');
  assert.strictEqual(motesToCspr('1'), '0.000000001');
  assert.strictEqual(motesToCspr('0'), '0.0');
  assert.strictEqual(csprToMotes(motesToCspr('123456789123456789')), 123456789123456789n);
});

/* ── Keys and addresses ──────────────────────────────────────────────── */

ok('parses an ed25519 PEM secret key into a 01-tagged public key', () => {
  const key = parseCasperKey(ED_PEM);
  assert.strictEqual(key.algo, 'ed25519');
  assert.strictEqual(key.publicKey.length, 33);
  assert.strictEqual(key.publicKey[0], 0x01);
});

ok('parses a secp256k1 PEM secret key into a 02-tagged compressed public key', () => {
  const key = parseCasperKey(SECP_PEM);
  assert.strictEqual(key.algo, 'secp256k1');
  assert.strictEqual(key.publicKey.length, 34);
  assert.strictEqual(key.publicKey[0], 0x02);
});

ok('parses a hex secret, defaulting to ed25519', () => {
  const key = parseCasperKey(HEX_SECRET);
  assert.strictEqual(key.algo, 'ed25519');
  assert.strictEqual(parseCasperKey('0x' + HEX_SECRET).publicKey.toString('hex'), key.publicKey.toString('hex'));
});

ok('parses a hex secret as secp256k1 when asked', () => {
  const key = parseCasperKey(HEX_SECRET, 'secp256k1');
  assert.strictEqual(key.algo, 'secp256k1');
  assert.strictEqual(key.publicKey.length, 34);
});

ok('rejects an unknown key algorithm hint', () => {
  assert.throws(() => parseCasperKey(HEX_SECRET, 'rsa'), /ed25519.*secp256k1/);
});

ok('rejects a hex secret of the wrong length', () => {
  assert.throws(() => parseCasperKey('abcd'), /32 bytes/);
});

ok('rejects garbage that is neither PEM nor hex', () => {
  assert.throws(() => parseCasperKey('not-a-key!'), /PEM secret key or a 32-byte hex secret/);
});

ok('validates Casper account public keys by tag and length', () => {
  assert.strictEqual(isValidCasperPublicKey('01' + 'ab'.repeat(32)), true);
  assert.strictEqual(isValidCasperPublicKey('02' + 'ab'.repeat(33)), true);
  assert.strictEqual(isValidCasperPublicKey('01' + 'ab'.repeat(33)), false); // ed25519, wrong length
  assert.strictEqual(isValidCasperPublicKey('03' + 'ab'.repeat(32)), false); // unknown tag
  assert.strictEqual(isValidCasperPublicKey('0xdeadbeef'), false);           // EVM-looking
  assert.strictEqual(isValidCasperPublicKey(''), false);
});

ok('accountHash produces a 32-byte hash and rejects bad keys', () => {
  assert.strictEqual(accountHash(PAY_TO).length, 32);
  assert.throws(() => accountHash('nope'), /Invalid Casper public key/);
});

/* ── CL serialization ─────────────────────────────────────────────────── */

ok('clBigNumber uses the length-prefixed little-endian U512 form', () => {
  assert.strictEqual(clBigNumber(0n).toString('hex'), '00');
  assert.strictEqual(clBigNumber(1n).toString('hex'), '0101');
  assert.strictEqual(clBigNumber(256n).toString('hex'), '020001');
  assert.strictEqual(clBigNumber(1000000000n).toString('hex'), '0400ca9a3b');
});

ok('clBigNumber refuses negative values', () => {
  assert.throws(() => clBigNumber(-1n), /cannot be negative/);
});

/* ── Deploy building (local signing) ─────────────────────────────────── */

ok('builds and signs a native transfer deploy with an ed25519 key', () => {
  process.env.AGENTWALLET_CASPER_KEY = ED_PEM;
  const deploy = buildTransferDeploy(PAY_TO, csprToMotes('2.5'), CASPER_TESTNET_CHAIN_ID, 100000000n);
  assert.match(deploy.hash, /^[0-9a-f]{64}$/);
  assert.strictEqual(deploy.header.chain_name, 'casper-test');
  assert.strictEqual(deploy.approvals.length, 1);
  // ed25519 signature is 1 tag byte + 64 bytes.
  assert.strictEqual(deploy.approvals[0].signature.length, 130);
  assert.strictEqual(deploy.approvals[0].signature.slice(0, 2), '01');
  assert.strictEqual(deploy.approvals[0].signer, getCasperAddress());
});

ok('rejects a non-Casper recipient when building a transfer', () => {
  assert.throws(
    () => buildTransferDeploy('0x2c7536E3605D9C16a7a3D7b1898e529396a65c23', 1n, CASPER_TESTNET_CHAIN_ID, 1n),
    /Invalid Casper recipient/
  );
});

ok('builds a CEP-18 (wCSPR) transfer deploy', () => {
  const deploy = buildCep18TransferDeploy(WCSPR, PAY_TO, 1500000000n, CASPER_TESTNET_CHAIN_ID, 1000000000n);
  assert.match(deploy.hash, /^[0-9a-f]{64}$/);
  assert.strictEqual(deploy.session.StoredContractByHash.entry_point, 'transfer');
  assert.strictEqual(deploy.session.StoredContractByHash.hash, WCSPR);
});

ok('rejects a CEP-18 contract hash of the wrong length', () => {
  assert.throws(() => buildCep18TransferDeploy('abcd', PAY_TO, 1n, CASPER_TESTNET_CHAIN_ID, 1n), /32 bytes/);
});

ok('deploy hashes differ between mainnet and testnet (chain name is bound in)', () => {
  const a = buildTransferDeploy(PAY_TO, 1n, CASPER_MAINNET_CHAIN_ID, 1n);
  const b = buildTransferDeploy(PAY_TO, 1n, CASPER_TESTNET_CHAIN_ID, 1n);
  assert.notStrictEqual(a.hash, b.hash);
});

/* ── Networks ─────────────────────────────────────────────────────────── */

ok('recognises the two Casper x402 networks and nothing else', () => {
  assert.strictEqual(resolveCasperChainId('casper:casper'), CASPER_MAINNET_CHAIN_ID);
  assert.strictEqual(resolveCasperChainId('casper:casper-test'), CASPER_TESTNET_CHAIN_ID);
  assert.strictEqual(resolveCasperChainId('CASPER:CASPER-TEST'), CASPER_TESTNET_CHAIN_ID);
  assert.strictEqual(resolveCasperChainId('eip155:8453'), null);
  assert.strictEqual(resolveCasperChainId('solana'), null);
  assert.strictEqual(isCasperNetwork('casper:casper'), true);
  assert.strictEqual(isCasperNetwork('base'), false);
  assert.strictEqual(isCasperChain(CASPER_MAINNET_CHAIN_ID), true);
  assert.strictEqual(isCasperChain(8453), false);
  assert.strictEqual(isCasperChain(900), false);
});

ok('resolves RPC endpoints, honouring AGENTWALLET_CASPER_RPC', () => {
  assert.match(resolveCasperRpc(CASPER_MAINNET_CHAIN_ID), /mainnet/);
  assert.match(resolveCasperRpc(CASPER_TESTNET_CHAIN_ID), /testnet/);
  process.env.AGENTWALLET_CASPER_RPC = 'https://rpc.example/rpc';
  assert.strictEqual(resolveCasperRpc(CASPER_MAINNET_CHAIN_ID), 'https://rpc.example/rpc');
  delete process.env.AGENTWALLET_CASPER_RPC;
});

/* ── accepts[] selection and requirement resolution ──────────────────── */

ok('selects the Casper option out of a mixed accepts[] array', () => {
  const accepts = [
    { scheme: 'exact', network: 'base', maxAmountRequired: '10000', payTo: '0xabc' },
    ACCEPT,
  ];
  assert.strictEqual(selectCasperAccept(accepts).network, 'casper:casper-test');
});

ok('returns null when the 402 offers no Casper option', () => {
  assert.strictEqual(selectCasperAccept([{ scheme: 'exact', network: 'base', maxAmountRequired: '1', payTo: '0x' }]), null);
  assert.strictEqual(selectCasperAccept([]), null);
});

ok('skips a Casper option using a scheme we cannot settle', () => {
  assert.strictEqual(selectCasperAccept([{ ...ACCEPT, scheme: 'upto' }]), null);
});

ok('prefers the requested Casper chain when several are offered', () => {
  const accepts = [ACCEPT, { ...ACCEPT, network: 'casper:casper' }];
  assert.strictEqual(selectCasperAccept(accepts, CASPER_MAINNET_CHAIN_ID).network, 'casper:casper');
  assert.strictEqual(selectCasperAccept(accepts, CASPER_TESTNET_CHAIN_ID).network, 'casper:casper-test');
});

ok('resolves a well-formed requirement without re-scaling the amount', () => {
  const req = resolveCasperRequirement(ACCEPT);
  assert.strictEqual(req.amountMotes, 1500000000n); // used as-is, base units
  assert.strictEqual(req.humanAmount, '1.5');
  assert.strictEqual(req.chainId, CASPER_TESTNET_CHAIN_ID);
  assert.strictEqual(req.asset, WCSPR);
  assert.strictEqual(req.decimals, 9);
});

ok('rejects a non-integer maxAmountRequired', () => {
  assert.throws(() => resolveCasperRequirement({ ...ACCEPT, maxAmountRequired: '1.5' }), /integer mote amount/);
});

ok('rejects a mismatched decimals declaration', () => {
  assert.throws(
    () => resolveCasperRequirement({ ...ACCEPT, extra: { decimals: 6 } }),
    /mismatched denomination/
  );
});

ok('rejects an invalid payTo', () => {
  assert.throws(() => resolveCasperRequirement({ ...ACCEPT, payTo: '0xdeadbeef' }), /invalid payTo/);
});

ok('rejects a 402 that omits the wCSPR contract hash', () => {
  assert.throws(() => resolveCasperRequirement({ ...ACCEPT, asset: undefined }), /CEP-18 contract hash/);
});

ok('accepts a hash- prefixed asset', () => {
  assert.strictEqual(resolveCasperRequirement({ ...ACCEPT, asset: `hash-${WCSPR}` }).asset, WCSPR);
});

/* ── Caps ─────────────────────────────────────────────────────────────── */

ok('isWithinCasperCap compares motes against a human CSPR cap', () => {
  assert.strictEqual(isWithinCasperCap('1500000000', '2'), true);
  assert.strictEqual(isWithinCasperCap('1500000000', '1.5'), true);   // exactly at the cap
  assert.strictEqual(isWithinCasperCap('1500000001', '1.5'), false);  // one mote over
  assert.strictEqual(isWithinCasperCap('10000000000000', '1'), false);
});

ok('isWithinCasperCap rejects a non-integer mote amount', () => {
  assert.throws(() => isWithinCasperCap('1.5', '2'), /expected an integer/);
});

/* ── Payment payload ─────────────────────────────────────────────────── */

ok('builds an x402 v2 payment payload carrying a signed deploy', () => {
  const payment = buildCasperPayment(ACCEPT, 2);
  assert.strictEqual(payment.x402Version, 2);
  assert.strictEqual(payment.scheme, 'exact');
  assert.strictEqual(payment.network, 'casper:casper-test');
  assert.strictEqual(payment.payload.amount, '1500000000');
  assert.strictEqual(payment.payload.to, PAY_TO);
  assert.strictEqual(payment.payload.asset, WCSPR);
  assert.strictEqual(payment.payload.from, getCasperAddress());
  assert.match(payment.payload.deployHash, /^[0-9a-f]{64}$/);
  assert.strictEqual(payment.payload.deploy.approvals.length, 1);
});

ok('encodes the payment header as base64 JSON', () => {
  const payment = buildCasperPayment(ACCEPT, 2);
  const decoded = JSON.parse(Buffer.from(encodePaymentHeader(payment), 'base64').toString('utf8'));
  assert.strictEqual(decoded.network, 'casper:casper-test');
  assert.strictEqual(decoded.payload.amount, '1500000000');
});

/* ── Facilitator client ──────────────────────────────────────────────── */

const FACILITATOR_DEFAULT = 'https://x402-facilitator.cspr.cloud';

ok('defaults to the Casper facilitator and honours the override', () => {
  delete process.env.AGENTWALLET_CASPER_FACILITATOR_URL;
  assert.strictEqual(facilitatorUrl(), FACILITATOR_DEFAULT);
  process.env.AGENTWALLET_CASPER_FACILITATOR_URL = 'http://127.0.0.1:9/';
  assert.strictEqual(facilitatorUrl(), 'http://127.0.0.1:9'); // trailing slash trimmed
  delete process.env.AGENTWALLET_CASPER_FACILITATOR_URL;
});

/** Stand up a fake facilitator that answers /verify and /settle with a script. */
function withFacilitator(handler, fn) {
  return new Promise((resolve, reject) => {
    const srv = createServer((req, res) => handler(req, res));
    srv.listen(0, '127.0.0.1', async () => {
      process.env.AGENTWALLET_CASPER_FACILITATOR_URL = `http://127.0.0.1:${srv.address().port}`;
      try {
        await fn();
        resolve();
      } catch (e) {
        reject(e);
      } finally {
        delete process.env.AGENTWALLET_CASPER_FACILITATOR_URL;
        srv.close();
      }
    });
  });
}

const json = (res, code, body) => {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
};

await okAsync('verify + settle succeed on an explicit true verdict', () =>
  withFacilitator((req, res) => {
    if (req.url === '/verify') return json(res, 200, { isValid: true, payer: PAY_TO });
    return json(res, 200, { success: true, transaction: 'ab'.repeat(32), network: 'casper:casper-test' });
  }, async () => {
    const payment = buildCasperPayment(ACCEPT, 2);
    const v = await verifyPayment(payment, ACCEPT);
    assert.strictEqual(v.ok, true);
    const s = await settlePayment(payment, ACCEPT);
    assert.strictEqual(s.ok, true);
    assert.strictEqual(s.transaction, 'ab'.repeat(32));
  }));

await okAsync('FAIL CLOSED: isValid false is a failure and carries the reason', () =>
  withFacilitator((req, res) => json(res, 200, { isValid: false, invalidReason: 'insufficient_funds' }), async () => {
    const v = await verifyPayment(buildCasperPayment(ACCEPT, 2), ACCEPT);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /insufficient_funds/);
  }));

await okAsync('FAIL CLOSED: a non-2xx facilitator response is a failure', () =>
  withFacilitator((req, res) => json(res, 500, { isValid: true }), async () => {
    const v = await verifyPayment(buildCasperPayment(ACCEPT, 2), ACCEPT);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /HTTP 500/);
  }));

await okAsync('FAIL CLOSED: a 200 with an unparseable body is a failure', () =>
  withFacilitator((req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('<html>gateway</html>'); }, async () => {
    const s = await settlePayment(buildCasperPayment(ACCEPT, 2), ACCEPT);
    assert.strictEqual(s.ok, false);
    assert.match(s.reason, /non-JSON body/);
  }));

await okAsync('FAIL CLOSED: a missing verdict field is a failure', () =>
  withFacilitator((req, res) => json(res, 200, { ok: 'sure' }), async () => {
    const v = await verifyPayment(buildCasperPayment(ACCEPT, 2), ACCEPT);
    assert.strictEqual(v.ok, false);
  }));

await okAsync('FAIL CLOSED: a truthy-but-not-true verdict is a failure', () =>
  withFacilitator((req, res) => json(res, 200, { isValid: 'true', success: 1 }), async () => {
    const payment = buildCasperPayment(ACCEPT, 2);
    assert.strictEqual((await verifyPayment(payment, ACCEPT)).ok, false);
    assert.strictEqual((await settlePayment(payment, ACCEPT)).ok, false);
  }));

await okAsync('FAIL CLOSED: an unreachable facilitator is a failure, not a throw', async () => {
  process.env.AGENTWALLET_CASPER_FACILITATOR_URL = 'http://127.0.0.1:1';
  const v = await verifyPayment(buildCasperPayment(ACCEPT, 2), ACCEPT);
  delete process.env.AGENTWALLET_CASPER_FACILITATOR_URL;
  assert.strictEqual(v.ok, false);
  assert.match(v.reason, /unreachable/);
});

/* ── Opt-in ───────────────────────────────────────────────────────────── */

ok('Casper stays completely off when no key is configured', () => {
  const saved = process.env.AGENTWALLET_CASPER_KEY;
  delete process.env.AGENTWALLET_CASPER_KEY;
  delete process.env.AGENTWALLET_CASPER_KEYFILE;
  assert.strictEqual(isCasperLocalMode(), false);
  process.env.AGENTWALLET_CASPER_KEY = saved;
  assert.strictEqual(isCasperLocalMode(), true);
});

ok('AGENTWALLET_CASPER_KEYFILE alone enables Casper mode', () => {
  const saved = process.env.AGENTWALLET_CASPER_KEY;
  delete process.env.AGENTWALLET_CASPER_KEY;
  process.env.AGENTWALLET_CASPER_KEYFILE = '/tmp/secret_key.pem';
  assert.strictEqual(isCasperLocalMode(), true);
  delete process.env.AGENTWALLET_CASPER_KEYFILE;
  process.env.AGENTWALLET_CASPER_KEY = saved;
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
