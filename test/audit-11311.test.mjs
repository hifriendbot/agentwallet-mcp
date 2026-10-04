/**
 * Regression tests from round 4 of the 2026-10-04 adversarial audit, local EVM group.
 *
 *  - a node answering an absurd priority fee or gas estimate cannot burn the balance: AGENTWALLET_MAX_FEE_NATIVE
 *  - caller gas_limit / max_fee / priority_fee are honoured (and bounded)
 *  - the reported hash is computed locally; a node answering another hash is called out
 *  - a token reporting decimals 2^20 does not hang the server (balance shown raw)
 *  - mainnet WETH is in the registry (a node saying 36 does not widen the cap); RPC decimals above 18 are refused
 *  - a plain-http RPC URL to a non-loopback host is refused
 *
 * Run with: node test/audit-11311.test.mjs
 */
import assert from 'node:assert';
import http from 'node:http';
import { generatePrivateKey } from 'viem/accounts';
import { parseTransaction, keccak256 } from 'viem';

let passed = 0;
const ok = (name, cond, detail) => { if (!cond) throw new Error(`${name}: ${detail}`); passed++; console.log(`  ok - ${name}`); };

// Mock node: chain 1 (so mainnet WETH applies), scripted answers.
const script = { tip: 10n ** 9n, estimateGas: 21000n, gasPrice: 2n * 10n ** 9n, baseFee: 10n ** 9n, decimals: 6, fakeHash: null };
const sent = [];
const rpc = http.createServer((req, res) => {
  let b = ''; req.on('data', c => b += c);
  req.on('end', () => {
    const r = JSON.parse(b);
    const send = (p) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: r.id, ...p })); };
    const hex = (n) => '0x' + n.toString(16);
    switch (r.method) {
      case 'eth_chainId': return send({ result: '0x1' });
      case 'eth_estimateGas': return send({ result: hex(script.estimateGas) });
      case 'eth_maxPriorityFeePerGas': return send({ result: hex(script.tip) });
      case 'eth_gasPrice': return send({ result: hex(script.gasPrice) });
      case 'eth_getBlockByNumber': return send({ result: { number: '0x10', baseFeePerGas: hex(script.baseFee), gasLimit: '0x1c9c380', gasUsed: '0x0', timestamp: '0x1', hash: '0x' + '11'.repeat(32), parentHash: '0x' + '22'.repeat(32), transactions: [], miner: '0x' + '00'.repeat(20), nonce: '0x0000000000000000', difficulty: '0x0', extraData: '0x', logsBloom: '0x' + '00'.repeat(256), size: '0x0', stateRoot: '0x' + '33'.repeat(32), transactionsRoot: '0x' + '44'.repeat(32), receiptsRoot: '0x' + '55'.repeat(32), sha3Uncles: '0x' + '66'.repeat(32), totalDifficulty: '0x0', uncles: [] } });
      case 'eth_getTransactionCount': return send({ result: '0x5' });
      case 'eth_call': {
        const data = String(r.params[0].data || '');
        if (data.startsWith('0x313ce567')) return send({ result: '0x' + script.decimals.toString(16).padStart(64, '0') });
        if (data.startsWith('0x70a08231')) return send({ result: '0x' + (10n ** 18n).toString(16).padStart(64, '0') });
        if (data.startsWith('0x95d89b41')) return send({ result: '0x' + '20'.padStart(64, '0') + '3'.padStart(64, '0') + Buffer.from('TKN').toString('hex').padEnd(64, '0') });
        return send({ error: { code: 3, message: 'execution reverted' } });
      }
      case 'eth_sendRawTransaction': { const tx = parseTransaction(r.params[0]); sent.push({ raw: r.params[0], tx }); return send({ result: script.fakeHash ?? keccak256(r.params[0]) }); }
      default: return send({ error: { code: -32601, message: `mock: ${r.method} not served` } });
    }
  });
});
await new Promise(r => rpc.listen(0, '127.0.0.1', r));
process.env.AGENTWALLET_RPC_1 = `http://127.0.0.1:${rpc.address().port}`;
process.env.AGENTWALLET_PRIVATE_KEY = generatePrivateKey();
process.env.AGENTWALLET_MAX_TX_NATIVE = '0.001';
delete process.env.AGENTWALLET_MAX_FEE_NATIVE;
const { localSend, localTokenBalance, resolveRpcUrl } = await import('../build/local-wallet.js');
const DEAD = '0x000000000000000000000000000000000000dEaD';
const refused = async (name, fn, pattern) => { try { await fn(); } catch (e) { assert.match(e.message, pattern, `${name}: "${e.message}"`); passed++; console.log(`  ok - ${name}`); return; } throw new Error(`${name}: expected a refusal`); };

try {
  // baseline: 21000 gas x (1.2 x 1 gwei + 1 gwei) is far under the 0.01 default cap
  const base = await localSend(1, DEAD, 10n ** 15n);
  ok('baseline transfer signs and reports the locally computed hash', sent.length === 1 && base.tx_hash === keccak256(sent[0].raw) && base.worst_case_fee !== undefined, JSON.stringify(base));

  script.tip = 47619n * 10n ** 9n;
  await refused('a 47,619 gwei priority fee from the node is refused by the fee cap before signing', () => localSend(1, DEAD, 10n ** 15n), /burn up to .* native in fees .* above AGENTWALLET_MAX_FEE_NATIVE/);
  ok('nothing was signed for it', sent.length === 1, String(sent.length));
  script.tip = 10n ** 9n;

  script.estimateGas = 30_000_000n;
  await refused('a 30M gas estimate from the node is refused by the fee cap', () => localSend(1, DEAD, 10n ** 15n), /above AGENTWALLET_MAX_FEE_NATIVE/);
  script.estimateGas = 21000n;

  const explicit = await localSend(1, DEAD, 10n ** 15n, undefined, { gas: '21000', maxFeePerGas: '2000000000', maxPriorityFeePerGas: '1000000000' });
  const tx = sent[sent.length - 1].tx;
  ok('caller gas parameters are honoured in the signed transaction', tx.gas === 21000n && tx.maxFeePerGas === 2000000000n && tx.maxPriorityFeePerGas === 1000000000n && explicit.max_fee_per_gas === '2000000000', JSON.stringify({ gas: String(tx.gas), max: String(tx.maxFeePerGas), tip: String(tx.maxPriorityFeePerGas) }));
  await refused('caller max_fee is bounded by the cap too', () => localSend(1, DEAD, 10n ** 15n, undefined, { gas: '21000', maxFeePerGas: '10000000000000000' }), /above AGENTWALLET_MAX_FEE_NATIVE/);

  process.env.AGENTWALLET_MAX_FEE_NATIVE = '0.00001';
  await refused('AGENTWALLET_MAX_FEE_NATIVE lowers the ceiling', () => localSend(1, DEAD, 10n ** 15n), /above AGENTWALLET_MAX_FEE_NATIVE \(0\.00001\)/);
  delete process.env.AGENTWALLET_MAX_FEE_NATIVE;

  script.fakeHash = '0x' + '11'.repeat(32);
  await refused('a node answering a different hash is called out as BROADCAST with the real hash', () => localSend(1, DEAD, 10n ** 15n), /was BROADCAST, but the node answered with a different hash/);
  script.fakeHash = null;

  script.decimals = 2 ** 20;
  const t0 = Date.now();
  const bal = await localTokenBalance(1, '0x1111111111111111111111111111111111111111');
  ok('a token reporting decimals 2^20 answers at once with the raw balance only', Date.now() - t0 < 5000 && bal.decimals === null && bal.balance === null && bal.balance_raw === (10n ** 18n).toString(), JSON.stringify(bal));

  // mainnet WETH: the node says 36, the registry says 18, so the cap is evaluated at 18
  process.env.AGENTWALLET_MAX_TX_TOKEN = '5';
  script.decimals = 36;
  const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';
  const transfer = (amountRaw) => '0xa9059cbb' + '0'.repeat(24) + DEAD.slice(2) + amountRaw.toString(16).padStart(64, '0');
  await refused('mainnet WETH is priced at 18 decimals whatever the node says', () => localSend(1, WETH, 0n, transfer(100000n * 10n ** 18n)), /exceeds.*AGENTWALLET_MAX_TX_TOKEN|evaluated at 18 decimals/);
  // The node says 36 for an unknown token: that answer is no longer trusted, so the cap falls back to 0 decimals
  // (6 raw units = 6 tokens > cap); trusting 36 would have read 6 raw units as 6e-36 tokens and allowed it.
  await refused('a non-registry token whose node-reported decimals exceed 18 is priced at 0 decimals, not the node\'s figure', () => localSend(1, '0x2222222222222222222222222222222222222222', 0n, transfer(6n)), /evaluated at 0 decimals/);
  delete process.env.AGENTWALLET_MAX_TX_TOKEN;

  process.env.AGENTWALLET_RPC_8453 = 'http://rpc.example.test/v1';
  ok('a plain-http RPC URL to a non-loopback host is refused', (() => { try { resolveRpcUrl(8453); return false; } catch (e) { return /must be https/.test(e.message); } })(), 'no refusal');
  delete process.env.AGENTWALLET_RPC_8453;
} finally {
  rpc.close();
}
console.log(`\naudit-11311: ${passed} passed`);
