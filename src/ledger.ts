/**
 * The ledger: an append-only, hash-chained JSONL record of every spend this
 * process reserved, and what became of it.
 *
 * Budgets are enforced from it, so a reservation is written BEFORE the
 * signature exists. Check and append happen in one step under an exclusive
 * lock file, after the file has been re-read and the chain re-verified, so
 * two concurrent calls cannot both fit the last dollar, whether they come
 * from one process or from several agentwallet-mcp processes sharing the
 * file (two MCP clients configured with the same wallet and ledger). A
 * reservation whose signing fails is voided by a later line; the spend line
 * itself is never edited, so the chain stays verifiable.
 *
 * Each line carries the sha256 of the previous line's hash plus its own body.
 * The chain is verified on every read; a broken chain with a budget
 * configured refuses every spend until the operator looks at the file, and a
 * file that no longer holds what this process wrote is refused the same way.
 */
import { appendFileSync, existsSync, readFileSync, openSync, closeSync, writeSync, unlinkSync, statSync } from 'node:fs';
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
/** How long a spend waits for another process to finish its own check-and-append. */
const LOCK_WAIT_MS = 10_000;
/** A lock older than this was left by a process that died holding it. */
const LOCK_STALE_MS = 30_000;
const sleeper = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms: number): void { Atomics.wait(sleeper, 0, 0, ms); }

function hashOf(prev: string, body: Record<string, unknown>): string {
  return createHash('sha256').update(prev + '\n' + JSON.stringify(body)).digest('hex');
}

interface Chain { entries: Entry[]; last: string; seq: number; integrity: string | null }

/** Parse and verify a ledger file's text. A trailing line without its newline is still being written by another process and is not read. */
function parseChain(text: string): Chain {
  const complete = text.endsWith('\n') || !text.includes('\n') && text.trim() === '' ? text : text.slice(0, text.lastIndexOf('\n') + 1);
  const lines = complete.split('\n').filter(l => l.trim());
  const out: Chain = { entries: [], last: GENESIS, seq: 0, integrity: null };
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let e: Entry;
    try { e = JSON.parse(lines[i]); } catch { out.integrity = `line ${i + 1} is not JSON`; break; }
    const { hash, ...body } = e as Entry & Record<string, unknown>;
    if (e.prev !== prev || hashOf(prev, body) !== hash) { out.integrity = `chain broken at line ${i + 1} (seq ${e.seq})`; break; }
    if (e.seq !== out.seq + 1) { out.integrity = `sequence gap at line ${i + 1}`; break; }
    out.entries.push(e);
    out.seq = e.seq;
    prev = hash;
  }
  out.last = prev;
  return out;
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

export interface LedgerOptions {
  /** Tests shorten the wait for a held lock. */
  lockWaitMs?: number;
}

export class Ledger {
  readonly path: string | null;
  private entries: Entry[] = [];
  private last = GENESIS;
  private seq = 0;
  /** null = intact; otherwise what broke. Refreshed from the file on every read. */
  integrity: string | null = null;
  private webhook: { url: string; secret: string } | null = null;
  private lockWaitMs = LOCK_WAIT_MS;

  constructor(path: string | null, webhook?: { url: string; secret: string } | null, opts?: LedgerOptions) {
    this.path = path;
    this.webhook = webhook ?? null;
    if (opts?.lockWaitMs !== undefined) this.lockWaitMs = opts.lockWaitMs;
    if (path) {
      // Create it now so a permissions problem shows at startup, not at the first spend.
      if (!existsSync(path)) closeSync(openSync(path, 'a', 0o600));
      this.sync();
    }
  }

  /**
   * Re-read the file so the sums include what every other process wrote.
   * The file must still begin with what this process has seen, line for
   * line; otherwise it was rewritten underneath us and nothing is adopted.
   */
  private sync(): void {
    if (!this.path) return;
    if (!existsSync(this.path)) { this.integrity = `the file was removed while this process was running (it held seq ${this.seq})`; return; }
    const c = parseChain(readFileSync(this.path, 'utf8'));
    const n = this.entries.length;
    if (c.entries.length < n || (n > 0 && c.entries[n - 1].hash !== this.last)) {
      this.integrity = c.integrity && c.entries.length < n ? c.integrity : `the file was rewritten underneath this process (it held seq ${this.seq} ending ${this.last.slice(0, 12)}, the file now ends at seq ${c.seq})`;
      return;
    }
    this.entries = c.entries;
    this.seq = c.seq;
    this.last = c.last;
    this.integrity = c.integrity;
  }

  /** Take the exclusive lock file; returns the release. A lock a dead process left behind is cleared after LOCK_STALE_MS. */
  private lock(): () => void {
    if (!this.path) return () => {};
    const lockPath = this.path + '.lock';
    const deadline = Date.now() + this.lockWaitMs;
    for (;;) {
      try {
        const fd = openSync(lockPath, 'wx', 0o600);
        try { writeSync(fd, `${process.pid} ${new Date().toISOString()}\n`); } finally { closeSync(fd); }
        return () => { try { unlinkSync(lockPath); } catch { /* already gone */ } };
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      }
      try {
        if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) { unlinkSync(lockPath); continue; }
      } catch { continue; /* released between the two calls */ }
      if (Date.now() >= deadline) {
        throw new Error(`The ledger at ${this.path} is locked by another agentwallet-mcp process (${lockPath}) that did not finish within ${this.lockWaitMs} ms. Nothing was signed. If no other process is running, remove the lock file.`);
      }
      sleepSync(5);
    }
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

  /** Dollar sums over rolling windows from a fresh read of the file; nowMs for tests. */
  spentUsd(nowMs = Date.now(), host?: string): Spent {
    this.sync();
    return this.sumUsd(nowMs, host);
  }
  spentNative(chainId: number, nowMs = Date.now()): Spent {
    this.sync();
    return this.sumNative(chainId, nowMs);
  }
  private sumUsd(nowMs: number, host?: string): Spent {
    return this.sum(nowMs, e => (host === undefined || e.host === host) && e.usd !== null ? units(e.usd!) : 0n);
  }
  private sumNative(chainId: number, nowMs: number): Spent {
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

  /** Would this spend fit every limit, given what every process has written so far? The reason names the first limit it does not. */
  check(input: ReserveInput, limits: Limits, nowMs = Date.now()): { ok: true } | { ok: false; reason: string } {
    this.sync();
    return this.evaluate(input, limits, nowMs);
  }

  private evaluate(input: ReserveInput, limits: Limits, nowMs: number): { ok: true } | { ok: false; reason: string } {
    if (this.integrity) return { ok: false, reason: `The ledger at ${this.path} is not intact (${this.integrity}); every spend is refused until the operator has looked at it.` };
    const amount18 = rawToUnits(input.raw, input.decimals);
    if (input.asset === '') {
      const r = refusal(limits.native, this.sumNative(input.chainId, nowMs), amount18, `native_budget.${input.chainId}`);
      if (r) return { ok: false, reason: r };
    } else if (input.usd === null) {
      if (limits.unpriced === 'refuse' && (limits.usd || limits.host)) {
        return { ok: false, reason: `policy: ${input.assetLabel} on chain ${input.chainId} is not a registry stablecoin, so the dollar budget cannot count it; refused (set unpriced_spends to "allow" in the policy to let such spends through uncounted).` };
      }
    }
    if (input.usd !== null) {
      const usd18 = units(input.usd);
      const r = refusal(limits.usd, this.sumUsd(nowMs), usd18, 'budget');
      if (r) return { ok: false, reason: r };
      if (limits.host && input.host) {
        const h = refusal({ daily: limits.host.daily, monthly: limits.host.monthly }, this.sumUsd(nowMs, input.host), usd18, `per_host["${limits.host.pattern}"]`);
        if (h) return { ok: false, reason: h };
      }
    }
    return { ok: true };
  }

  /** Re-read, check and record in one step under the lock. Returns the spend's seq. */
  reserve(input: ReserveInput, limits: Limits): number {
    const unlock = this.lock();
    try {
      this.sync();
      const c = this.evaluate(input, limits, Date.now());
      if (!c.ok) throw new Error(c.reason);
      const amount = human(rawToUnits(input.raw, input.decimals));
      const e = this.append({
        kind: 'spend', tool: input.tool, mode: input.mode, wallet: input.wallet, chain_id: input.chainId, asset: input.asset, asset_label: input.assetLabel,
        amount, raw: input.raw, usd: input.usd, to: input.to, host: input.host, resource: input.resource, method: input.method, proof: input.proof ?? null,
      });
      return e.seq;
    } finally { unlock(); }
  }

  /** A follow-up line, written under the lock after a fresh read so it chains onto whatever any process wrote last. */
  private follow(body: Omit<FollowEntry, 'hash' | 'prev' | 'seq' | 'ts'>): void {
    const unlock = this.lock();
    try { this.sync(); this.append(body as unknown as Omit<Entry, 'hash' | 'prev' | 'seq' | 'ts'> & Record<string, unknown>); } finally { unlock(); }
  }

  /** The spend never happened (signing or broadcast failed before anything left this process). */
  void(ref: number, detail: string): void {
    try { this.follow({ kind: 'void', ref, outcome: 'void', detail: detail.slice(0, 300) }); } catch (e) { console.error(`[agentwallet] ledger void failed: ${(e as Error).message}`); }
  }
  /** What the endpoint or chain said afterwards. Never throws: the payment already happened. */
  settle(ref: number, outcome: string, detail: string | null): void {
    try { this.follow({ kind: 'settle', ref, outcome: outcome.slice(0, 40), detail: detail ? detail.slice(0, 300) : null }); } catch (e) { console.error(`[agentwallet] ledger settle failed: ${(e as Error).message}`); }
  }

  size(): number { this.sync(); return this.entries.length; }

  /** Spends newest first with their latest follow-up folded in, from a fresh read. */
  payments(opts: { limit: number; host?: string; outcome?: string; since?: number }): Array<Record<string, unknown>> {
    this.sync();
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
