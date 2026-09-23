// Verifies a TransferWithAuthorization signature produced by the hosted PHP signer
// (AGW_EIP712) recovers to the wallet address. Usage: node test/verify-server-sig.mjs <json-file>
import fs from 'node:fs';
import { recoverTypedDataAddress } from 'viem';
import { TRANSFER_WITH_AUTHORIZATION_TYPES } from '../build/x402-eip3009.js';

const line = fs.readFileSync(process.argv[2], 'utf8').split('\n').find(l => l.trim().startsWith('{'));
const { from, signature, auth } = JSON.parse(line);
const recovered = await recoverTypedDataAddress({
  domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: TRANSFER_WITH_AUTHORIZATION_TYPES,
  primaryType: 'TransferWithAuthorization',
  message: { from: auth.from, to: auth.to, value: BigInt(auth.value), validAfter: BigInt(auth.validAfter), validBefore: BigInt(auth.validBefore), nonce: auth.nonce },
  signature,
});
const ok = recovered.toLowerCase() === from.toLowerCase();
console.log(ok ? `OK: server signature recovers to ${recovered}` : `MISMATCH: recovered ${recovered}, wallet ${from}`);
process.exit(ok ? 0 : 1);
