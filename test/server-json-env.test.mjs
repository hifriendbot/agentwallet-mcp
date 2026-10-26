/**
 * server.json is the manifest MCP clients and the official registry configure
 * from. Reported privately 2026-10-26: it declared 28 of the 32 AGENTWALLET_*
 * names the code accepts, and the six missing ones were the entire spend
 * policy, ledger, webhook and keyfile-passphrase surface, so an operator
 * installing from the manifest never learned they existed. This test keeps
 * the manifest and KNOWN_ENV in step. Templated names such as
 * AGENTWALLET_RPC_<chainId> are documentation and are not in KNOWN_ENV.
 *
 * Run: node test/server-json-env.test.mjs
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const sj = JSON.parse(readFileSync(new URL('../server.json', import.meta.url), 'utf8'));
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const src = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8');
const m = /const KNOWN_ENV = new Set\(\[([^\]]*)\]\)/.exec(src);
assert.ok(m, 'KNOWN_ENV not found in src/index.ts');
const known = new Set([...m[1].matchAll(/"(AGENTWALLET_[A-Z_0-9]+)"/g)].map((x) => x[1]));
const vars = sj.packages.flatMap((p) => p.environmentVariables ?? []);
const declared = vars.map((e) => e.name);
const concrete = declared.filter((n) => !n.includes('<'));

let passed = 0;
const ok = (name, fn) => { fn(); passed++; console.log(`  ok - ${name}`); };

ok('every AGENTWALLET_* name the code accepts is declared in server.json', () => {
  const missing = [...known].filter((n) => !declared.includes(n)).sort();
  assert.deepEqual(missing, [], `missing from server.json: ${missing.join(', ')}`);
});
ok('server.json declares no concrete name the code does not accept', () => {
  const extra = concrete.filter((n) => !known.has(n)).sort();
  assert.deepEqual(extra, [], `in server.json but not in KNOWN_ENV: ${extra.join(', ')}`);
});
ok('no name is declared twice', () => {
  assert.equal(new Set(declared).size, declared.length);
});
ok('the secrets are marked isSecret and the paths are not', () => {
  const secrets = /^AGENTWALLET_(PASS|PRIVATE_KEY|SOLANA_KEY|WEBHOOK_SECRET|KEYFILE_PASSPHRASE)$/;
  for (const e of vars) assert.equal(Boolean(e.isSecret), secrets.test(e.name), `${e.name} isSecret should be ${secrets.test(e.name)}`);
});
ok('server.json carries the package version and name', () => {
  assert.equal(sj.version, pkg.version);
  for (const p of sj.packages) { assert.equal(p.version, pkg.version); assert.equal(p.identifier, pkg.name); }
  assert.equal(sj.name, pkg.mcpName);
});
ok('the server announces the package version', () => {
  const v = [...src.matchAll(/^\s+version: '(\d+\.\d+\.\d+)',$/gm)].map((x) => x[1]);
  assert.deepEqual(v, [pkg.version], `McpServer version strings in src/index.ts: ${v.join(', ')}`);
});

console.log(`\nserver-json-env: ${passed} passed\n`);
