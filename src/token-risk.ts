/**
 * Asset risk before an approval or a swap. The wallet layer knows the amount;
 * it did not know the asset. This asks GoPlus Security's free token_security
 * endpoint (no key) and, when that is unavailable, falls back to what the
 * chain itself can tell us. Always a WARNING, never a block: the caller
 * decides. Requested in agentwallet-mcp issue #13.
 */
import { safeFetch } from './ssrf-guard.js';

export type RiskLevel = 'low' | 'medium' | 'high' | 'unknown';

export interface TokenRisk {
  level: RiskLevel;
  score: number;             // 0 (clean) to 100 (do not touch)
  flags: string[];
  notes: string[];
  source: 'goplus' | 'onchain' | 'none';
  holder_count?: number;
  top_holder_percent?: number;
  buy_tax?: number;
  sell_tax?: number;
}

const GOPLUS_CHAINS = new Set([1, 56, 137, 8453, 42161, 10, 43114, 324, 59144, 534352, 25, 250, 100, 1101, 5000, 81457, 204]);

function num(v: unknown): number | null {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v); return Number.isFinite(n) ? n : null;
}
function flag(v: unknown): boolean { return v === '1' || v === 1 || v === true; }

/** Turn a GoPlus token_security record into a verdict. Exported so it can be unit-tested offline. */
export function assessGoPlus(r: Record<string, unknown>): TokenRisk {
  const flags: string[] = []; const notes: string[] = []; let score = 0;
  const add = (cond: boolean, name: string, pts: number, note?: string) => { if (cond) { flags.push(name); score += pts; if (note) notes.push(note); } };
  add(flag(r.is_honeypot), 'honeypot', 100, 'GoPlus marks this token as a honeypot: it can be bought but not sold.');
  add(flag(r.fake_token), 'fake_token', 100, 'Flagged as an imitation of a known token.');
  add(flag(r.is_airdrop_scam), 'airdrop_scam', 80);
  add(flag(r.cannot_sell_all), 'cannot_sell_all', 60);
  add(flag(r.transfer_pausable), 'transfer_pausable', 30, 'The owner can pause transfers.');
  add(flag(r.is_blacklisted), 'blacklist', 30, 'The contract has a blacklist function.');
  add(flag(r.owner_change_balance), 'owner_change_balance', 80, 'The owner can change any balance.');
  add(flag(r.hidden_owner), 'hidden_owner', 40);
  add(flag(r.selfdestruct), 'selfdestruct', 40);
  add(flag(r.is_mintable), 'mintable', 15);
  add(flag(r.slippage_modifiable), 'tax_modifiable', 25, 'Buy/sell tax can be changed by the owner.');
  add(flag(r.personal_slippage_modifiable), 'personal_tax', 40, 'The owner can set a different tax for specific addresses.');
  add(flag(r.trading_cooldown), 'trading_cooldown', 10);
  add(flag(r.external_call), 'external_call', 15);
  add(r.is_open_source === '0', 'closed_source', 35, 'Contract source is not verified.');
  add(flag(r.is_proxy), 'proxy', 10, 'Upgradeable proxy: the logic can change.');
  const buy = num(r.buy_tax), sell = num(r.sell_tax);
  if (buy !== null && buy > 0.1) { flags.push('buy_tax_high'); score += 30; }
  if (sell !== null && sell > 0.1) { flags.push('sell_tax_high'); score += 40; }
  const holders = num(r.holder_count);
  if (holders !== null && holders < 50) { flags.push('few_holders'); score += 25; }
  let top = 0;
  const list = Array.isArray(r.holders) ? (r.holders as Array<Record<string, unknown>>) : [];
  for (const h of list) { const p = num(h.percent); if (p !== null && !flag(h.is_contract) && !flag(h.is_locked) && p > top) top = p; }
  if (top > 0.5) { flags.push('top_holder_over_50pct'); score += 40; }
  else if (top > 0.2) { flags.push('top_holder_over_20pct'); score += 15; }
  if (r.is_in_dex === '0') { flags.push('no_dex_liquidity'); score += 20; }
  if (flag(r.trust_list)) { notes.push('On GoPlus trust list (well-known token).'); score = Math.min(score, 5); }
  score = Math.min(100, score);
  const level: RiskLevel = score >= 60 ? 'high' : score >= 25 ? 'medium' : 'low';
  const out: TokenRisk = { level, score, flags, notes, source: 'goplus' };
  if (holders !== null) out.holder_count = holders;
  if (top) out.top_holder_percent = Math.round(top * 10000) / 100;
  if (buy !== null) out.buy_tax = buy;
  if (sell !== null) out.sell_tax = sell;
  return out;
}

/**
 * Assess a token. `ethCall` runs a read-only call and returns the hex result
 * (used for the on-chain fallback: does the contract answer name() and decimals()?).
 */
export async function assessTokenRisk(
  chainId: number,
  token: string,
  ethCall?: (to: string, data: string) => Promise<string>,
): Promise<TokenRisk> {
  const addr = token.toLowerCase();
  if (GOPLUS_CHAINS.has(chainId)) {
    try {
      const res = await safeFetch(`https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${addr}`, {
        method: 'GET', headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(12_000),
      });
      const j = (await res.json()) as { code?: number; result?: Record<string, Record<string, unknown>> };
      const rec = j?.result?.[addr];
      if (rec && Object.keys(rec).length > 0) return assessGoPlus(rec);
    } catch { /* fall through to on-chain */ }
  }
  if (ethCall) {
    try {
      const name = await ethCall(token, '0x06fdde03');
      const decimals = await ethCall(token, '0x313ce567');
      const answers = Boolean(name && name !== '0x') && Boolean(decimals && decimals !== '0x');
      return {
        level: answers ? 'unknown' : 'high', score: answers ? 50 : 90,
        flags: answers ? ['no_security_data'] : ['not_an_erc20'],
        notes: [answers ? 'No security data available for this chain or token; only basic ERC-20 shape was confirmed.' : 'Contract did not answer name() and decimals(); it may not be an ERC-20 token at all.'],
        source: 'onchain',
      };
    } catch { /* fall through */ }
  }
  return { level: 'unknown', score: 50, flags: ['no_security_data'], notes: ['No risk data could be fetched.'], source: 'none' };
}
