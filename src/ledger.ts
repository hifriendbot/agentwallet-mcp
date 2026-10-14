/**
 * The ledger: an append-only, hash-chained JSONL record of every spend this
 * process reserved, and what became of it.
 *
 * Budgets are enforced from it, so a reservation is written BEFORE the
 * signature exists: check and append happen in one synchronous step, which in
 * a single-threaded process means two concurrent calls cannot both fit the
 * last dollar. A reservation whose signing fails is voided by a later line;
 * the spend line itself is never edited, so the chain stays verifiable.
 *
 * Each line carries the sha256 of the previous line's hash plus its own body.
 * On load the chain is verified; a broken chain with a budget configured
 * refuses every spend until the operator looks at the file.
 */
import { appendFileSync, existsSync, readFileSync, openSync, closeSync } from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { DAY_MS, MONTH_MS, type Spent, units, rawToUnits, human } from './policy.js';

/** 'approval' is an ERC-20 allowance granted (approve, increaseAllowance, Permit2.approve): a spend the spender executes later, counted when granted. */
export type SpendMethod = 'eip3009' | 'permit2' | 'transfer' | 'native' | 'spl' | 'autopay' | 'approval';
export interface SpendEntry {
  seq: number;
  ts: string;
  kind: 'spend';
  tool: string;
  mode: 'local' | 'hosted';
  wallet: string;
  chain_id: number;
  /** '' for the chain's own coin. */
  asset: string;
  asset_label: string;
  /** Human units of the asset. */
  amount: string;
  raw: string;
  /** Dollar value as a decimal string when the asset is a registry stablecoin, else null (not counted toward the dollar budget). */
  usd: string | null;
  to: string;
  host: string | null;
  resource: string | null;
  method: SpendMethod;
  proof: { nonce?: string; tx_hash?: string } | null;
  prev: string;
  hash: string;
}
export interface FollowEntry {
  seq: number;
  ts: string;
  kind: 'void' | 'settle';
  ref: number;
  outcome: string;
  detail: string | null;
  prev: string;
  hash: string;
}
export type Entry = SpendEntry | FollowEntry;

const GENESIS = '0'.repeat(64);
const MAX_LINE = 16 * 1024;

function hashOf(prev: string, body: Record<string, unknown>): string {
  return createHash('sha256').update(prev + '\n' + JSON.stringify(body)).digest('hex');
}

export interface ReserveInput {
  tool: string; mode: 'local' | 'hosted'; wallet: string; chainId: number; asset: string; assetLabel: string;
  raw: string; decimals: number; usd: string | null; to: string; host: string | null; resource: string | null; method: SpendMethod;
  proof?: { nonce?: string; tx_hash?: string } | null;
}

export interface Limits {
  usd?: { daily?: string; monthly?: string; total?: string };
  native?: { daily?: string; monthly?: string; total?: string };
  host?: { pattern: string; daily?: string; monthly?: string } | null;
  unpriced: 'refuse' | 'allow';
}

export class Ledger {
  readonly path: string | null;
  private entries: Entry[] = [];
  private last = GENESIS;
  private seq = 0;
  /** null = intact; otherwise what broke. */
  integrity: string | null = null;
  private webhook: { url: string; secret: string } | null = null;

  constructor(path: string | null, webhook?: { url: string; secret: string } | null) {
    this.path = path;
    this.webhook = webhook ?? null;
    if (path) this.load();
  }

  private load(): void {
    if (!existsSync(this.path!)) {
      // Create it now so a permissions problem shows at startup, not at the first spend.
      closeSync(openSync(this.path!, 'a', 0o600));
      return;
    }
    const text = readFileSync(this.path!, 'utf8');
    const lines = text.split('\n').filter(l => l.trim());
    let prev = GENESIS;
    for (let i = 0; i < lines.length; i++) {
      let e: Entry;
      try { e = JSON.parse(lines[i]); } catch { this.integrity = `line ${i + 1} is not JSON`; break; }
      const { hash, ...body } = e as Entry & Record<string, unknown>;
      if (e.prev !== prev || hashOf(prev, body) !== hash) { this.integrity = `chain broken at line ${i + 1} (seq ${e.seq})`; break; }
      if (e.seq !== this.seq + 1) { this.integrity = `sequence gap at line ${i + 1}`; break; }
      this.entries.push(e);
      this.seq = e.seq;
      prev = hash;
    }
    this.last = prev;
  }

  private append(body: Omit<Entry, 'hash' | 'prev' | 'seq' | 'ts'> & Record<string, unknown>): Entry {
    if (this.integrity) throw new Error(`The ledger at ${this.path} is not intact (${this.integrity}); refusing to record or spend until the operator has looked at it.`);
    const full = { seq: this.seq + 1, ts: new Date().toISOString(), ...body, prev: this.last } as Omit<Entry, 'hash'>;
    const hash = hashOf(this.last, full as unknown as Record<string, unknown>);
    const entry = { ...full, hash } as Entry;
    const line = JSON.stringify(entry);
    if (line.length > MAX_LINE) throw new Error('ledger entry too large');
    if (this.path) appendFileSync(this.path, line + '\n', { mode: 0o600 });
    this.entries.push(entry);
    this.seq = entry.seq;
    this.last = hash;
    this.notify(entry);
    return entry;
  }

  private notify(entry: Entry): void {
    const w = this.webhook;
    if (!w) return;
    const body = JSON.stringify(entry);
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'User-Agent': 'agentwallet-mcp' };
    if (w.secret) headers['X-AgentWallet-Signature'] = 'sha256=' + createHmac('sha256', w.secret).update(body).digest('hex');
    // Fire and forget: a webhook must never delay or fail a signature.
    fetch(w.url, { method: 'POST', headers, body, redirect: 'manual', signal: AbortSignal.timeout(10_000) })
      .then(r => { if (!(r.status >= 200 && r.status < 300)) console.error(`[agentwallet] webhook answered HTTP ${r.status} for ledger seq ${entry.seq}`); })
      .catch(e => console.error(`[agentwallet] webhook failed for ledger seq ${entry.seq}: ${(e as Error).message.split('\n')[0]}`));
  }

  /** Spends not voided, newest last. */
  private liveSpends(): SpendEntry[] {
    const voided = new Set(this.entries.filter(e => e.kind === 'void').map(e => (e as FollowEntry).ref));
    return this.entries.filter((e): e is SpendEntry => e.kind === 'spend' && !voided.has(e.seq));
  }

  /** Dollar sums over rolling windows; nowMs for tests. */
  spentUsd(nowMs = Date.now(), host?: string): Spent {
    return this.sum(nowMs, e => (host === undefined || e.host === host) && e.usd !== null ? units(e.usd!) : 0n);
  }
  spentNative(chainId: number, nowMs = Date.now()): Spent {
    return this.sum(nowMs, e => e.chain_id === chainId && e.asset === '' ? rawToUnits(e.raw, nativeDecimalsOf(chainId)) : 0n);
  }
  private sum(nowMs: number, f: (e: SpendEntry) => bigint): Spent {
    const out: Spent = { daily: 0n, monthly: 0n, total: 0n };
    for (const e of this.liveSpends()) {
      const v = f(e);
      if (v === 0n) continue;
      const t = Date.parse(e.ts);
      out.total += v;
      if (nowMs - t < MONTH_MS) out.monthly += v;
      if (nowMs - t < DAY_MS) out.daily += v;
    }
    return out;
  }

  /** Would this spend fit every limit? The reason names the first it does not. */
  check(input: ReserveInput, limits: Limits, nowMs = Date.now()): { ok: true } | { ok: false; reason: string } {
    if (this.integrity) return { ok: false, reason: `The ledger at ${this.path} is not intact (${this.integrity}); every spend is refused until the operator has looked at it.` };
    const amount18 = rawToUnits(input.raw, input.decimals);
    if (input.asset === '') {
      const r = refusal(limits.native, this.spentNative(input.chainId, nowMs), amount18, `native_budget.${input.chainId}`);
      if (r) return { ok: false, reason: r };
    } else if (input.usd === null) {
      if (limits.unpriced === 'refuse' && (limits.usd || limits.host)) {
        return { ok: false, reason: `policy: ${input.assetLabel} on chain ${input.chainId} is not a registry stablecoin, so the dollar budget cannot count it; refused (set unpriced_spends to "allow" in the policy to let such spends through uncounted).` };
      }
    }
    if (input.usd !== null) {
      const usd18 = units(input.usd);
      const r = refusal(limits.usd, this.spentUsd(nowMs), usd18, 'budget');
      if (r) return { ok: false, reason: r };
      if (limits.host && input.host) {
        const h = refusal({ daily: limits.host.daily, monthly: limits.host.monthly }, this.spentUsd(nowMs, input.host), usd18, `per_host["${limits.host.pattern}"]`);
        if (h) return { ok: false, reason: h };
      }
    }
    return { ok: true };
  }

  /** Check and record in one synchronous step. Returns the spend's seq. */
  reserve(input: ReserveInput, limits: Limits): number {
    const c = this.check(input, limits);
    if (!c.ok) throw new Error(c.reason);
    const amount = human(rawToUnits(input.raw, input.decimals));
    const e = this.append({
      kind: 'spend', tool: input.tool, mode: input.mode, wallet: input.wallet, chain_id: input.chainId, asset: input.asset, asset_label: input.assetLabel,
      amount, raw: input.raw, usd: input.usd, to: input.to, host: input.host, resource: input.resource, method: input.method, proof: input.proof ?? null,
    });
    return e.seq;
  }

  /** The spend never happened (signing or broadcast failed before anything left this process). */
  void(ref: number, detail: string): void {
    try { this.append({ kind: 'void', ref, outcome: 'void', detail: detail.slice(0, 300) }); } catch (e) { console.error(`[agentwallet] ledger void failed: ${(e as Error).message}`); }
  }
  /** What the endpoint or chain said afterwards. Never throws: the payment already happened. */
  settle(ref: number, outcome: string, detail: string | null): void {
    try { this.append({ kind: 'settle', ref, outcome: outcome.slice(0, 40), detail: detail ? detail.slice(0, 300) : null }); } catch (e) { console.error(`[agentwallet] ledger settle failed: ${(e as Error).message}`); }
  }

  size(): number { return this.entries.length; }

  /** Spends newest first with their latest follow-up folded in. */
  payments(opts: { limit: number; host?: string; outcome?: string; since?: number }): Array<Record<string, unknown>> {
    const follow = new Map<number, FollowEntry>();
    for (const e of this.entries) if (e.kind !== 'spend') follow.set((e as FollowEntry).ref, e as FollowEntry);
    const out: Array<Record<string, unknown>> = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < opts.limit; i--) {
      const e = this.entries[i];
      if (e.kind !== 'spend') continue;
      if (opts.host !== undefined && e.host !== opts.host) continue;
      if (opts.since !== undefined && Date.parse(e.ts) < opts.since) continue;
      const f = follow.get(e.seq);
      const outcome = f ? f.outcome : 'signed';
      if (opts.outcome !== undefined && outcome !== opts.outcome) continue;
      const { prev: _p, hash: _h, kind: _k, ...rest } = e;
      out.push({ ...rest, outcome, outcome_detail: f?.detail ?? null, outcome_at: f?.ts ?? null });
    }
    return out;
  }

  /** CSV of every spend, oldest first. RFC 4180 quoting; a cell starting with = + - @ is prefixed so a spreadsheet cannot run it. */
  csv(since?: number, until?: number): string {
    const cols = ['seq', 'ts', 'tool', 'mode', 'wallet', 'chain_id', 'asset', 'asset_label', 'amount', 'usd', 'to', 'host', 'resource', 'method', 'proof', 'outcome', 'outcome_detail', 'outcome_at'];
    const rows = this.payments({ limit: Number.MAX_SAFE_INTEGER, since }).reverse().filter(r => until === undefined || Date.parse(String(r.ts)) <= until);
    const cell = (v: unknown) => {
      let s = v === null || v === undefined ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return [cols.join(','), ...rows.map(r => cols.map(c => cell(r[c])).join(','))].join('\r\n') + '\r\n';
  }

  /** JSONL of every spend, oldest first. */
  jsonl(since?: number, until?: number): string {
    return this.payments({ limit: Number.MAX_SAFE_INTEGER, since }).reverse().filter(r => until === undefined || Date.parse(String(r.ts)) <= until).map(r => JSON.stringify(r)).join('\n') + '\n';
  }
}

function refusal(w: { daily?: string; monthly?: string; total?: string } | undefined, spent: Spent, amount: bigint, what: string): string | null {
  if (!w) return null;
  for (const k of ['daily', 'monthly', 'total'] as const) {
    const lim = w[k];
    if (!lim) continue;
    const l = units(lim);
    if (spent[k] + amount > l) {
      const left = l - spent[k] < 0n ? 0n : l - spent[k];
      return `policy ${what} ${k === 'total' ? 'lifetime' : k} budget of ${lim} would be exceeded: ${human(spent[k])} already spent in the window, ${human(amount)} requested, ${human(left)} remaining. Nothing was signed. Only the operator can raise the budget.`;
    }
  }
  return null;
}

function nativeDecimalsOf(chainId: number): number {
  return chainId >= 900 && chainId <= 902 ? 9 : 18;
}
