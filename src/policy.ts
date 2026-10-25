/**
 * Spend policy: one JSON file that bounds what this process may sign.
 *
 * The per-transaction caps in the environment bound a single signature. They
 * cannot see sums, so 500 payments of 0.99 under a cap of 1 were allowed. A
 * policy adds rolling budgets (enforced through the ledger), host and recipient
 * lists, per-host limits, chain and asset lists, a human-approval threshold
 * (answered through MCP elicitation) and a tool allowlist.
 *
 * Everything here is pure: parsing, matching and arithmetic. Enforcement with
 * state lives in ledger.ts and index.ts. Amounts are decimal strings compared
 * as integers at 18 places so "1.50" and "1.5" agree and nothing is a float.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join } from 'node:path';
import { z } from 'zod';

const Dec = z.string().regex(/^\d+(\.\d+)?$/, 'a decimal number as a string, like "5" or "0.25"');
const Window = z.object({ daily: Dec.optional(), monthly: Dec.optional(), total: Dec.optional() }).strict();
const HostPattern = z.string().min(1).max(253).regex(/^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i, 'a hostname, or *.example.com for its subdomains');
const Address = z.string().regex(/^(0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/, 'an EVM address or a Solana address');
const AssetRef = z.string().regex(/^(\d+:)?(0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44}|native)$/, 'an address or mint, optionally prefixed "chainId:", or "native"');

export const PolicySchema = z.object({
  version: z.literal(1),
  name: z.string().max(80).optional(),
  /** Rolling budgets in stablecoin (dollar) units across every chain: x402 payments and stablecoin transfers. */
  budget: Window.optional(),
  /** Rolling budgets for the chain's own coin, keyed by chain id, in that coin's units. */
  native_budget: z.record(z.string().regex(/^\d+$/), Window).optional(),
  /** What to do with a spend the budget cannot price (a token outside the registry). Default refuse when a budget is set. */
  unpriced_spends: z.enum(['refuse', 'allow']).optional(),
  hosts: z.object({ allow: z.array(HostPattern).max(500).optional(), deny: z.array(HostPattern).max(500).optional() }).strict().optional(),
  /** Per-host ceilings for x402 payments, dollar units. */
  per_host: z.record(HostPattern, z.object({ daily: Dec.optional(), monthly: Dec.optional(), per_payment: Dec.optional() }).strict()).optional(),
  recipients: z.object({ allow: z.array(Address).max(1000).optional(), deny: z.array(Address).max(1000).optional() }).strict().optional(),
  chains: z.object({ allow: z.array(z.number().int().positive()).max(100).optional() }).strict().optional(),
  assets: z.object({ allow: z.array(AssetRef).max(500).optional() }).strict().optional(),
  /** Ask the human (MCP elicitation) above `above`; in local mode an accepted ask may admit up to `max`, above the per-payment cap. */
  approval: z.object({ above: Dec.optional(), max: Dec.optional(), timeout_seconds: z.number().int().min(30).max(3600).optional() }).strict().optional(),
  tools: z.object({ allow: z.array(z.string().regex(/^[a-z_0-9]+$/)).max(100).optional(), deny: z.array(z.string().regex(/^[a-z_0-9]+$/)).max(100).optional() }).strict().optional(),
  /** Ledger path; relative paths resolve against the policy file's directory. */
  ledger: z.string().min(1).max(1024).optional(),
}).strict();

export type Policy = z.infer<typeof PolicySchema>;

export const PRECISION = 18;
/** Decimal string to an integer at 18 places. */
export function units(v: string): bigint {
  if (!/^\d+(\.\d+)?$/.test(v)) throw new Error(`Not a decimal amount: "${String(v).slice(0, 40)}".`);
  const [whole, frac = ''] = v.split('.');
  if (frac.length > PRECISION) throw new Error(`Amount "${v}" has more than ${PRECISION} decimal places.`);
  return BigInt(whole + frac.padEnd(PRECISION, '0'));
}
/** Integer at 18 places back to a trimmed decimal string. */
export function human(u: bigint): string {
  const neg = u < 0n;
  const s = (neg ? -u : u).toString().padStart(PRECISION + 1, '0');
  const whole = s.slice(0, s.length - PRECISION);
  let frac = s.slice(s.length - PRECISION);
  let end = frac.length;
  while (end > 0 && frac[end - 1] === '0') end--;
  frac = frac.slice(0, end);
  return (neg ? '-' : '') + whole + (frac ? '.' + frac : '');
}
/** Raw base units of an asset to an 18-place integer (decimals must be 0..36). */
export function rawToUnits(raw: string, decimals: number): bigint {
  if (!/^\d+$/.test(raw)) throw new Error(`Not a raw amount: "${String(raw).slice(0, 40)}".`);
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) throw new Error(`decimals out of range: ${decimals}`);
  const r = BigInt(raw);
  return decimals <= PRECISION ? r * 10n ** BigInt(PRECISION - decimals) : r / 10n ** BigInt(decimals - PRECISION);
}

export const DAY_MS = 86_400_000;
export const MONTH_MS = 30 * DAY_MS;

export interface LoadedPolicy {
  policy: Policy;
  path: string | null;
  /** sha256 of the file bytes, so an operator can pin the policy they reviewed. */
  hash: string | null;
  ledgerPath: string | null;
}

/** An empty policy: nothing bounded beyond the environment caps. */
export const EMPTY: LoadedPolicy = { policy: { version: 1 }, path: null, hash: null, ledgerPath: null };

/** Parse a policy document. Throws with the field path on any mistake; an unknown key is a mistake (a misspelled budget must not run unbounded). */
export function parsePolicy(text: string): Policy {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch (e) { throw new Error(`policy is not JSON: ${(e as Error).message}`); }
  const r = PolicySchema.safeParse(raw);
  if (!r.success) {
    const first = r.error.issues[0];
    throw new Error(`policy field ${first.path.join('.') || '(root)'}: ${first.message}`);
  }
  const p = r.data;
  for (const [k, v] of Object.entries(p.native_budget || {})) if (!v.daily && !v.monthly && !v.total) throw new Error(`policy field native_budget.${k}: set daily, monthly or total.`);
  if (p.approval?.above && p.approval?.max && units(p.approval.max) < units(p.approval.above)) throw new Error('policy field approval.max: must be at least approval.above.');
  if (p.tools?.allow && p.tools?.deny) throw new Error('policy field tools: use allow or deny, not both.');
  if (p.hosts?.allow && p.hosts.allow.length === 0) throw new Error('policy field hosts.allow: an empty allow list would refuse every host; remove it or list hosts.');
  if (p.recipients?.allow && p.recipients.allow.length === 0) throw new Error('policy field recipients.allow: an empty allow list would refuse every recipient; remove it or list addresses.');
  return p;
}

/** Load the policy named by AGENTWALLET_POLICY (none set: EMPTY). The ledger path comes from AGENTWALLET_LEDGER, then the policy, then a default next to the policy when a budget needs one. */
export function loadPolicy(env: NodeJS.ProcessEnv = process.env): LoadedPolicy {
  const file = (env.AGENTWALLET_POLICY || '').trim();
  const ledgerEnv = (env.AGENTWALLET_LEDGER || '').trim();
  if (!file) return { ...EMPTY, ledgerPath: ledgerEnv || null };
  let text: string;
  try { text = readFileSync(file, 'utf8'); } catch (e) { throw new Error(`AGENTWALLET_POLICY: could not read ${file}: ${(e as Error).message}`); }
  const policy = parsePolicy(text);
  const hash = createHash('sha256').update(text).digest('hex');
  // The ledger lives beside the policy file. dirname() gives '.' for a bare
  // filename; a hand-rolled strip-after-last-slash left the filename itself as
  // the directory, so AGENTWALLET_POLICY=policy.json could not start (1.14.6).
  const dir = dirname(file);
  let ledgerPath: string | null = ledgerEnv || null;
  if (!ledgerPath && policy.ledger) ledgerPath = isAbsolute(policy.ledger) ? policy.ledger : join(dir, policy.ledger);
  if (!ledgerPath && needsLedger(policy)) ledgerPath = join(dir, 'agentwallet-ledger.jsonl');
  return { policy, path: file, hash, ledgerPath };
}

/** A budget is only meaningful across restarts, so it needs a file. */
export function needsLedger(p: Policy): boolean {
  return Boolean(p.budget || p.native_budget || (p.per_host && Object.values(p.per_host).some(h => h.daily || h.monthly)));
}

/* ── Matching ─────────────────────────────────────────────────────── */

/**
 * A DNS name as the policy compares, sums and records it: lowercase, without
 * the root label's trailing dot. "api.example.com." (and its %2E spelling)
 * names the same host as "api.example.com", TLS accepts either, and Node's URL
 * parser keeps the dot, so the raw hostname slipped past hosts.deny and
 * per_host (reported privately 2026-10-24, 1.14.5). IP literals pass through.
 */
export function canonicalHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[')) return h;
  while (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

/** The host of a URL as the policy sees it. */
export function hostOf(url: string): string {
  return canonicalHost(new URL(url).hostname);
}

export function hostMatches(pattern: string, host: string): boolean {
  const p = canonicalHost(pattern);
  const h = canonicalHost(host);
  if (p.startsWith('*.')) return h.endsWith(p.slice(1)) && h.length > p.length - 1;
  return p === h;
}

export function hostAllowed(p: Policy, host: string): { ok: true } | { ok: false; reason: string } {
  const deny = p.hosts?.deny?.find(x => hostMatches(x, host));
  if (deny) return { ok: false, reason: `policy denies host ${host} (hosts.deny "${deny}").` };
  if (p.hosts?.allow && !p.hosts.allow.some(x => hostMatches(x, host))) return { ok: false, reason: `policy does not allow host ${host}: it is not in hosts.allow. Only the operator can add it.` };
  return { ok: true };
}

function sameAddress(a: string, b: string): boolean {
  return /^0x/i.test(a) && /^0x/i.test(b) ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/** A funds destination (a transfer recipient, an x402 payTo) against the recipient lists. */
export function recipientAllowed(p: Policy, to: string): { ok: true } | { ok: false; reason: string } {
  if (p.recipients?.deny?.some(x => sameAddress(x, to))) return { ok: false, reason: `policy denies recipient ${to} (recipients.deny).` };
  if (p.recipients?.allow && !p.recipients.allow.some(x => sameAddress(x, to))) return { ok: false, reason: `policy does not allow recipient ${to}: it is not in recipients.allow. Only the operator can add it.` };
  return { ok: true };
}

/** A contract target (approve, wrap, arbitrary calldata): the deny list only; an allow list is about where funds go. */
export function targetAllowed(p: Policy, to: string): { ok: true } | { ok: false; reason: string } {
  if (p.recipients?.deny?.some(x => sameAddress(x, to))) return { ok: false, reason: `policy denies contract target ${to} (recipients.deny).` };
  return { ok: true };
}

export function chainAllowed(p: Policy, chainId: number): { ok: true } | { ok: false; reason: string } {
  if (p.chains?.allow && !p.chains.allow.includes(chainId)) return { ok: false, reason: `policy does not allow chain ${chainId}: it is not in chains.allow.` };
  return { ok: true };
}

/** asset '' means the chain's native coin. */
export function assetAllowed(p: Policy, chainId: number, asset: string): { ok: true } | { ok: false; reason: string } {
  if (!p.assets?.allow) return { ok: true };
  const want = asset ? asset : 'native';
  const hit = p.assets.allow.some(e => {
    const m = /^(?:(\d+):)?(.+)$/.exec(e)!;
    if (m[1] && Number(m[1]) !== chainId) return false;
    return m[2] === 'native' ? want === 'native' : sameAddress(m[2], want);
  });
  return hit ? { ok: true } : { ok: false, reason: `policy does not allow asset ${want} on chain ${chainId}: it is not in assets.allow.` };
}

export function perHostRule(p: Policy, host: string): { pattern: string; daily?: string; monthly?: string; per_payment?: string } | null {
  for (const [pattern, rule] of Object.entries(p.per_host || {})) if (hostMatches(pattern, host)) return { pattern, ...rule };
  return null;
}

export function toolAllowed(p: Policy, name: string): boolean {
  if (p.tools?.allow) return p.tools.allow.includes(name);
  if (p.tools?.deny) return !p.tools.deny.includes(name);
  return true;
}

/* ── Budget arithmetic (sums come from the ledger) ───────────────── */

export interface Spent { daily: bigint; monthly: bigint; total: bigint }
export interface BudgetLine { limit: string; spent: string; remaining: string }
export type BudgetReport = Partial<Record<'daily' | 'monthly' | 'total', BudgetLine>>;

export function budgetReport(w: { daily?: string; monthly?: string; total?: string } | undefined, spent: Spent): BudgetReport | null {
  if (!w) return null;
  const out: BudgetReport = {};
  for (const k of ['daily', 'monthly', 'total'] as const) {
    if (!w[k]) continue;
    const lim = units(w[k]!);
    out[k] = { limit: w[k]!, spent: human(spent[k]), remaining: human(lim - spent[k] < 0n ? 0n : lim - spent[k]) };
  }
  return out;
}

/** Stable summary for the agent and for the hash a human can compare against the file they reviewed. */
export function describePolicy(lp: LoadedPolicy): Record<string, unknown> {
  const p = lp.policy;
  return {
    loaded: Boolean(lp.path),
    path: lp.path,
    sha256: lp.hash,
    name: p.name ?? null,
    budget: p.budget ?? null,
    native_budget: p.native_budget ?? null,
    unpriced_spends: p.unpriced_spends ?? (p.budget ? 'refuse' : 'allow'),
    hosts: p.hosts ?? null,
    per_host: p.per_host ?? null,
    recipients: p.recipients ? { allow: p.recipients.allow?.length ?? null, deny: p.recipients.deny?.length ?? null } : null,
    chains: p.chains ?? null,
    assets: p.assets ?? null,
    approval: p.approval ?? null,
    tools: p.tools ?? null,
    ledger: lp.ledgerPath,
  };
}
