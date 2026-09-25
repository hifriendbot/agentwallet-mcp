/**
 * Asks Coinbase's public x402 facilitator to verify a payment payload we built
 * and signed. With an unfunded throwaway key the expected answer is
 * "insufficient funds" (or similar), NOT an invalid-signature reason: that
 * proves the typed data, domain and header shape match what the facilitator
 * expects. Not part of `npm test`; it touches the network.
 *
 *   node test/facilitator-verify.mjs [facilitatorBase]   (default https://x402.org/facilitator)
 */
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { buildAuthorization, typedDataFor, buildPaymentPayload } from '../build/x402-eip3009.js';

const base = (process.argv[2] || 'https://x402.org/facilitator').replace(/\/$/, '');
const account = privateKeyToAccount(generatePrivateKey()); // fresh unfunded key per run, never a well-known one (issue #9)
const USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'; // USDC on Base Sepolia, the network the public facilitator serves
const CHAIN = 84532;

const requirementsV1 = {
  scheme: 'exact', network: 'base-sepolia', maxAmountRequired: '10000', resource: 'https://example.com/api/thing',
  description: 'facilitator probe', mimeType: 'application/json', outputSchema: {}, payTo: '0x1111111111111111111111111111111111111111',
  maxTimeoutSeconds: 300, asset: USDC, extra: { name: 'USDC', version: '2' },
};
const requirementsV2 = {
  scheme: 'exact', network: 'eip155:84532', amount: '10000', asset: USDC, payTo: '0x1111111111111111111111111111111111111111',
  maxTimeoutSeconds: 300, extra: { name: 'USDC', version: '2' },
};

async function probe(x402Version, req) {
  const auth = buildAuthorization(account.address, req);
  const signature = await account.signTypedData(typedDataFor(CHAIN, USDC, 'USDC', '2', auth));
  const paymentPayload = buildPaymentPayload(x402Version, req, auth, signature, { url: 'https://example.com/api/thing' });
  const res = await fetch(base + '/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ x402Version, paymentPayload, paymentRequirements: req }),
  });
  const text = await res.text();
  console.log(`v${x402Version} verify -> http ${res.status}: ${text.slice(0, 400)}`);
}

await probe(1, requirementsV1);
await probe(2, requirementsV2);
