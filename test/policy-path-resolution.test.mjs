/**
 * Regression: the policy file's directory and the ledger path beside it.
 *
 * Reported privately 2026-10-25 against 1.14.5: loadPolicy() found the
 * directory by stripping everything after the last slash, so a bare relative
 * filename (AGENTWALLET_POLICY=policy.json) was left whole and became the
 * directory. The default ledger path came out as
 * "policy.json/agentwallet-ledger.jsonl" and the Ledger constructor threw at
 * startup. Dot-relative and absolute spellings worked. Filesystem only: no
 * wallet, key, signature or network. Works on POSIX and Windows paths.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';
import { loadPolicy } from '../build/policy.js';
import { Ledger } from '../build/ledger.js';

const initialCwd = process.cwd();
const temp = mkdtempSync(join(tmpdir(), 'agentwallet-policy-path-'));
let pass = 0;
const budget = { version: 1, budget: { daily: '1' } };
try {
  process.chdir(temp);
  writeFileSync('policy.json', JSON.stringify(budget));
  writeFileSync('custom.json', JSON.stringify({ ...budget, ledger: 'custom-ledger.jsonl' }));
  writeFileSync('custom-abs.json', JSON.stringify({ ...budget, ledger: join(temp, 'abs-ledger.jsonl') }));
  writeFileSync('nobudget.json', JSON.stringify({ version: 1, hosts: { deny: ['example.com'] } }));
  mkdirSync('nested');
  writeFileSync('nested/policy.json', JSON.stringify(budget));
  writeFileSync('nested/custom.json', JSON.stringify({ ...budget, ledger: 'sub/ledger.jsonl' }));
  mkdirSync('nested/sub');

  // [label, env, expected ledger path (resolved against the working directory)]
  const cases = [
    ['bare filename, default ledger', { AGENTWALLET_POLICY: 'policy.json' }, join(temp, 'agentwallet-ledger.jsonl')],
    ['dot-relative filename, default ledger', { AGENTWALLET_POLICY: './policy.json' }, join(temp, 'agentwallet-ledger.jsonl')],
    ['absolute filename, default ledger', { AGENTWALLET_POLICY: join(temp, 'policy.json') }, join(temp, 'agentwallet-ledger.jsonl')],
    ['nested relative filename, default ledger', { AGENTWALLET_POLICY: 'nested/policy.json' }, join(temp, 'nested', 'agentwallet-ledger.jsonl')],
    ['bare filename, relative ledger field', { AGENTWALLET_POLICY: 'custom.json' }, join(temp, 'custom-ledger.jsonl')],
    ['nested filename, relative ledger field with a subdirectory', { AGENTWALLET_POLICY: 'nested/custom.json' }, join(temp, 'nested', 'sub', 'ledger.jsonl')],
    ['bare filename, absolute ledger field', { AGENTWALLET_POLICY: 'custom-abs.json' }, join(temp, 'abs-ledger.jsonl')],
    ['AGENTWALLET_LEDGER wins over the default', { AGENTWALLET_POLICY: 'policy.json', AGENTWALLET_LEDGER: join(temp, 'explicit.jsonl') }, join(temp, 'explicit.jsonl')],
    ['AGENTWALLET_LEDGER wins over the ledger field', { AGENTWALLET_POLICY: 'custom.json', AGENTWALLET_LEDGER: join(temp, 'explicit2.jsonl') }, join(temp, 'explicit2.jsonl')],
  ];
  for (const [label, env, expected] of cases) {
    const loaded = loadPolicy(env);
    assert.ok(loaded.ledgerPath, `${label}: a budget needs a ledger path`);
    // The bug: the filename itself used as the directory.
    assert.ok(!/policy\.json[\/]|custom\.json[\/]|custom-abs\.json[\/]/.test(loaded.ledgerPath), `${label}: ledger path "${loaded.ledgerPath}" treats the policy file as a directory`);
    assert.equal(resolve(loaded.ledgerPath), resolve(expected), `${label}: ledger path`);
    const ledger = new Ledger(loaded.ledgerPath); // threw ENOTDIR/ENOENT before the fix
    assert.equal(ledger.integrity, null, `${label}: ledger integrity`);
    assert.ok(existsSync(expected), `${label}: ledger file created at ${expected}`);
    assert.equal(loaded.path, env.AGENTWALLET_POLICY, `${label}: policy path reported as given`);
    pass++;
    console.log(`PASS: ${label} -> ${isAbsolute(loaded.ledgerPath) ? '<abs>' : loaded.ledgerPath}`);
  }

  // No budget, no ledger field, no env: no ledger at all, and a bare filename still loads.
  const none = loadPolicy({ AGENTWALLET_POLICY: 'nobudget.json' });
  assert.equal(none.ledgerPath, null);
  assert.equal(none.policy.hosts.deny[0], 'example.com');
  pass++;
  console.log('PASS: bare filename without a budget loads and names no ledger');

  // A missing file is still a clear error that names the file.
  assert.throws(() => loadPolicy({ AGENTWALLET_POLICY: 'missing.json' }), /AGENTWALLET_POLICY: could not read missing\.json/);
  pass++;
  console.log('PASS: a missing bare filename reports the file');
} finally {
  process.chdir(initialCwd);
  rmSync(temp, { recursive: true, force: true });
}
console.log(`policy-path-resolution: ${pass} cases passed`);
