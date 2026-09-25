/**
 * Asks Coinbase's public facilitator to verify an upto (Permit2) payload we built.
 * With an unfunded, unapproved throwaway key the expected answer is
 * permit2_allowance_required or insufficient funds, NOT an invalid-signature or
 * malformed-payload reason: that proves the typed data and envelope are right.
 * Not part of `npm test`; it touches the network.
 */
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { buildUptoAuthorization, uptoTypedData, uptoPayload } from '../build/x402-permit2.js';
import { buildPaymentPayloadRaw } from '../build/x402-eip3009.js';

const base = (process.argv[2] || 'https://x402.org/facilitator').replace(/\/$/, '');
const account = privateKeyToAccount(generatePrivateKey()); // fresh unfunded key per run (issue #9)
const supported = await (await fetch(base + '/supported')).json();
const kind = (supported.kinds || []).find(k => k.scheme === 'upto' && k.network === 'eip155:84532');
if (!kind) { console.log('facilitator does not advertise upto on Base Sepolia'); process.exit(1); }
const req = {
  scheme: 'upto', network: 'eip155:84532', amount: '50000', asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  payTo: '0x1111111111111111111111111111111111111111', maxTimeoutSeconds: 300,
  extra: { facilitatorAddress: kind.extra.facilitatorAddress },
};
const auth = buildUptoAuthorization(account.address, req);
const signature = await account.signTypedData(uptoTypedData(84532, auth));
const paymentPayload = buildPaymentPayloadRaw(2, req, uptoPayload(auth, signature), { url: 'https://example.com/api/thing' });
const res = await fetch(base + '/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: req }) });
console.log(`upto verify -> http ${res.status}: ${(await res.text()).slice(0, 400)}`);
