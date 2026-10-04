/**
 * Regression tests for two 2026-09-28 findings in the local token cap.
 *
 * 1. `increaseAllowance` was checked on the increment alone, so two calls
 *    that each fit under AGENTWALLET_MAX_TX_TOKEN could leave a standing
 *    allowance above it. Now the current allowance is read and the resulting
 *    total is checked; a failed read refuses.
 * 2. For a token outside the registry the RPC was the only source of
 *    decimals, and a false answer scaled amount and cap by the same factor.
 *    AGENTWALLET_TOKEN_DECIMALS pins the value ahead of the RPC.
 *
 * A loopback JSON-RPC mock answers decimals() and allowance(); anything past
 * the guard (nonce, gas, send) is refused so an allowed call fails there,
 * visibly, instead of being signed.
 *
 * Run with: node test/allowance-total-cap.test.mjs
 */
import assert from 'node:assert';
import { createServer } from 'node:http';
import { encodeFunctionData, parseAbi } from 'viem';

const CHAIN = 8453;
const ABI = parseAbi([
  'function increaseAllowance(address,uint256) returns (bool)',
  'function approve(address,uint256) returns (bool)',
  'function transfer(address,uint256) returns (bool)',
]);
const SPENDER = '0x000000000000000000000000000000000000dEaD';
let caseNo = 0;
const nextToken = () => '0x' + (0xc0 + ++caseNo).toString(16).padStart(40, '0'); // not in the trusted registry
const word = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');

/** What the mock says the current allowance is; flipped per case. */
let allowance = 0n;
let allowanceFails = false;
let decimals = 6;
const server = createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const rpc = JSON.parse(body);
    const reply = (extra) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, ...extra }));
    };
    if (rpc.method === 'eth_chainId') return reply({ result: '0x' + CHAIN.toString(16) });
    if (rpc.method === 'eth_call') {
      const data = String(rpc.params?.[0]?.data || '');
      if (data.startsWith('0x313ce567')) return reply({ result: word(decimals) });        // decimals()
      if (data.startsWith('0xdd62ed3e')) {                                                  // allowance(owner,spender)
        if (allowanceFails) return reply({ error: { code: -32000, message: 'mock: allowance unavailable' } });
        return reply({ result: word(allowance) });
      }
      return reply({ result: '0x' });
    }
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
const { parseDecimalPins } = await import('../build/x402-payment.js');

let passed = 0;
const GUARD = /AGENTWALLET_MAX_TX_TOKEN|Blocked by local guard/;

async function refused(name, token, data, pattern) {
  try {
    await localSend(CHAIN, token, 0n, data);
    throw new Error(`${name}: expected the guard to block this`);
  } catch (e) {
    assert.match(e.message, pattern, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}

async function passedGuard(name, token, data) {
  try {
    await localSend(CHAIN, token, 0n, data);
    throw new Error(`${name}: the mock should have refused the send`);
  } catch (e) {
    assert.doesNotMatch(e.message, GUARD, `${name}: the guard blocked it: "${e.message}"`);
    assert.match(e.message, /mock: .* not served/, `${name}: unexpected error "${e.message}"`);
    passed++;
    console.log(`  ok - ${name}`);
  }
}

console.log('\nincreaseAllowance is checked on the resulting total\n');

const inc = (n) => encodeFunctionData({ abi: ABI, functionName: 'increaseAllowance', args: [SPENDER, n] });
const approve = (n) => encodeFunctionData({ abi: ABI, functionName: 'approve', args: [SPENDER, n] });

allowance = 600000n;
await refused('a compliant increment on top of a compliant allowance refuses when the total exceeds the cap',
  nextToken(), inc(600000n), /standing allowance of 1200000 .* above AGENTWALLET_MAX_TX_TOKEN/);

allowance = 1000000n;
await refused('an allowance already at the cap refuses any increment',
  nextToken(), inc(1n), /standing allowance of 1000001/);

allowance = 300000n;
await passedGuard('an increment whose total stays within the cap passes the guard',
  nextToken(), inc(600000n));

allowanceFails = true;
await refused('an allowance that cannot be read refuses instead of assuming zero',
  nextToken(), inc(1n), /could not read the current allowance/);
allowanceFails = false;

allowance = 900000n;
await passedGuard('approve is absolute: it replaces the allowance, so no read and no sum',
  nextToken(), approve(600000n));

await refused('an oversized increment still refuses on its own',
  nextToken(), inc(2000000n), /standing allowance|exceeds/);

console.log('\nAGENTWALLET_TOKEN_DECIMALS pins decimals ahead of the RPC\n');

{
  const token = nextToken();
  decimals = 36; // the RPC lies: 36 decimals makes a 1-token cap 10^36 base units
  const transfer = encodeFunctionData({ abi: ABI, functionName: 'transfer', args: [SPENDER, 500000000000000000000000000000000000n] }); // 5e35
  // Until 1.13.10 the RPC's 36 priced the cap and this 5e35 transfer passed; since 1.13.11 an RPC answer above 18
  // is not trusted at all and the cap falls back to 0 decimals, so the same transfer refuses even without a pin.
  await refused('control: with no pin an RPC answer of 36 is not trusted and the transfer refuses at 0 decimals',
    token, transfer, /evaluated at 0 decimals/);

  const pinned = nextToken();
  process.env.AGENTWALLET_TOKEN_DECIMALS = `${CHAIN}:${pinned}=6`;
  await refused('pinned to 6 decimals, the same transfer refuses however the RPC answers',
    pinned, transfer, /evaluated at 6 decimals/);
  delete process.env.AGENTWALLET_TOKEN_DECIMALS;
  decimals = 6;
}

{
  const pins = parseDecimalPins(`${CHAIN}:${SPENDER}=6, EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v=6`);
  assert.equal(pins.get(`${CHAIN}:${SPENDER.toLowerCase()}`), 6);
  assert.equal(pins.get('spl:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'), 6);
  for (const bad of [`${SPENDER}=6`, `${CHAIN}:${SPENDER}=99`, 'nonsense', `${CHAIN}:0x1234=6`]) {
    assert.throws(() => parseDecimalPins(bad), /AGENTWALLET_TOKEN_DECIMALS/, `expected "${bad}" to be rejected`);
  }
  passed++;
  console.log('  ok - pins parse, and malformed pins are rejected at startup');
}

server.close();
console.log(`\n${passed} passed\n`);
