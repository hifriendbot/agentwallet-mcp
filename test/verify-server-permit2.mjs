// Verifies a Permit2 upto signature produced by the hosted PHP signer recovers to the wallet.
// Usage: node test/verify-server-permit2.mjs <json-file with {from, signature, auth, chain_id}>
import fs from 'node:fs';
import { recoverTypedDataAddress } from 'viem';
import { uptoTypedData } from '../build/x402-permit2.js';

const line = fs.readFileSync(process.argv[2], 'utf8').split('\n').find(l => l.trim().startsWith('{'));
const { from, signature, auth, chain_id } = JSON.parse(line);
const td = uptoTypedData(Number(chain_id), { ...auth, from });
const recovered = await recoverTypedDataAddress({ ...td, signature });
const ok = recovered.toLowerCase() === from.toLowerCase();
console.log(ok ? `OK: server Permit2 signature recovers to ${recovered}` : `MISMATCH: recovered ${recovered}, wallet ${from}`);
process.exit(ok ? 0 : 1);
