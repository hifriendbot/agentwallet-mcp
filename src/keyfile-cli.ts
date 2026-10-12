/**
 * `agentwallet-mcp encrypt-keyfile <plain-keyfile> <encrypted-keyfile>`
 *
 * Reads the plaintext key material, asks for a passphrase twice on the
 * terminal (or takes AGENTWALLET_KEYFILE_PASSPHRASE), writes the encrypted
 * file with mode 600, and prints the EVM address it controls when the
 * material is a hex key, so the operator can confirm it is the right one
 * before deleting the plaintext. Nothing is printed that could identify the
 * key itself.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { encryptKeyfile, decryptKeyfile, secretsEqual } from './keyfile.js';

function prompt(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) return reject(new Error('No terminal to ask for a passphrase on; set AGENTWALLET_KEYFILE_PASSPHRASE for this command instead.'));
    const muted = new Writable({ write(_c, _e, cb) { cb(); } });
    const rl = createInterface({ input: process.stdin, output: muted, terminal: true });
    process.stderr.write(question);
    rl.question('', (answer) => { rl.close(); process.stderr.write('\n'); resolve(answer); });
  });
}

export async function runEncryptKeyfile(args: string[]): Promise<void> {
  const [input, output] = args;
  if (!input || !output) {
    console.error('Usage: agentwallet-mcp encrypt-keyfile <plain-keyfile> <encrypted-keyfile>\n' +
      'The plaintext file holds an EVM hex key or a Solana key (id.json array, base58 or base64). The passphrase is asked for on the terminal, or taken from AGENTWALLET_KEYFILE_PASSPHRASE.');
    process.exitCode = 2;
    return;
  }
  if (existsSync(output)) { console.error(`Refusing to overwrite ${output}; choose a new path.`); process.exitCode = 2; return; }
  const material = readFileSync(input, 'utf8').trim();
  if (!material) { console.error(`${input} is empty.`); process.exitCode = 2; return; }
  const hex = material.replace(/^0x/, '');
  const family: 'evm' | 'solana' | undefined = /^[0-9a-fA-F]{64}$/.test(hex) ? 'evm' : material.startsWith('[') || /^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(material) || /^[A-Za-z0-9+/=]{80,100}$/.test(material) ? 'solana' : undefined;

  let pass = process.env.AGENTWALLET_KEYFILE_PASSPHRASE;
  if (pass === undefined) {
    pass = await prompt('Passphrase (not echoed): ');
    const again = await prompt('Again: ');
    if (!secretsEqual(pass, again)) { console.error('The passphrases differ; nothing written.'); process.exitCode = 2; return; }
  }
  const sealed = encryptKeyfile(material, pass, family);
  // Round-trip before writing: a file that cannot be opened is worse than none.
  if (decryptKeyfile(sealed, pass) !== material) throw new Error('Internal error: the encrypted file did not round-trip; nothing written.');
  writeFileSync(output, sealed, { mode: 0o600, flag: 'wx' });

  let address = '';
  if (family === 'evm') {
    const { privateKeyToAccount } = await import('viem/accounts');
    try { address = privateKeyToAccount(`0x${hex}`).address; } catch { address = ''; }
  }
  console.error(`Wrote ${output} (${family ?? 'unknown key type'}, scrypt + AES-256-GCM).` + (address ? ` It controls ${address}.` : '') +
    `\nPoint AGENTWALLET_KEYFILE${family === 'solana' ? ' or AGENTWALLET_SOLANA_KEYFILE' : ''} at it, set AGENTWALLET_KEYFILE_PASSPHRASE or AGENTWALLET_KEYFILE_PASSPHRASE_FILE, then delete ${input} once a test run shows the same address.`);
}
