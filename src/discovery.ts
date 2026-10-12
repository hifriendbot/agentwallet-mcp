/**
 * x402 discovery: the Bazaar index of x402 resources published by the CDP
 * facilitator (public, no key). The agent can find a paid API by subject
 * instead of being handed a URL.
 *
 * Everything the index says is a seller's own words. Descriptions are
 * bounded and marked untrusted; prices are re-derived from the registry
 * (never the seller's decimals), and nothing here pays.
 */
import { safeFetch } from './ssrf-guard.js';
import { lookupTrustedDecimals, assetLabel, resolveNetworkChainId } from './x402-payment.js';

export const BAZAAR_URL = 'https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources';
const PAGE = 100;
const MAX_SCAN = 500;
const MAX_BYTES = 4 * 1024 * 1024;

export interface BazaarItem {
  resource: string;
  type?: string;
  description?: string;
  serviceName?: string;
  tags?: unknown;
  lastUpdated?: string;
  accepts?: Array<{ scheme?: string; network?: string; amount?: string; maxAmountRequired?: string; asset?: string; payTo?: string }>;
  extensions?: { bazaar?: { info?: { input?: { method?: string; type?: string; bodyType?: string; discoverable?: boolean }; output?: { type?: string } } } };
}

export interface DiscoveredResource {
  resource: string;
  method: string;
  service: string | null;
  description: string | null;
  prices: Array<{ amount: string | null; asset: string; network: string; chain_id: number | null; scheme: string }>;
  tags: string[];
  last_updated: string | null;
}

const cut = (v: unknown, n: number): string | null => v === undefined || v === null ? null : String(v).slice(0, n);

/** A raw item to the bounded shape the agent sees. */
export function summarize(it: BazaarItem): DiscoveredResource | null {
  if (!it || typeof it.resource !== 'string' || !/^https:\/\//i.test(it.resource)) return null;
  const prices = (Array.isArray(it.accepts) ? it.accepts : []).slice(0, 6).map(a => {
    const network = String(a?.network ?? '').slice(0, 60);
    const chainId = resolveNetworkChainId(network);
    const asset = String(a?.asset ?? '').slice(0, 80);
    const raw = String(a?.amount ?? a?.maxAmountRequired ?? '');
    let amount: string | null = null;
    if (chainId !== null && /^\d{1,40}$/.test(raw)) {
      const d = asset ? lookupTrustedDecimals(chainId, asset) : (chainId >= 900 ? 9 : 18);
      if (d !== null) amount = formatRaw(raw, d);
    }
    return { amount, asset: chainId !== null && asset ? assetLabel(chainId, asset) : (asset || 'native'), network, chain_id: chainId, scheme: String(a?.scheme ?? '').slice(0, 20) };
  });
  const tags = Array.isArray(it.tags) ? it.tags.slice(0, 10).map(t => String(t).slice(0, 40)) : [];
  return {
    resource: it.resource.slice(0, 500),
    method: String(it.extensions?.bazaar?.info?.input?.method ?? 'GET').toUpperCase().slice(0, 10),
    service: cut(it.serviceName, 120),
    description: cut(it.description, 400),
    prices, tags, last_updated: cut(it.lastUpdated, 40),
  };
}

function formatRaw(raw: string, decimals: number): string {
  const padded = raw.padStart(decimals + 1, '0');
  const whole = padded.slice(0, padded.length - decimals) || '0';
  let frac = padded.slice(padded.length - decimals);
  let end = frac.length;
  while (end > 0 && frac[end - 1] === '0') end--;
  frac = frac.slice(0, end);
  return frac ? `${whole}.${frac}` : whole;
}

/** Case-insensitive match of every query word against resource, service, description and tags. */
export function matches(r: DiscoveredResource, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const hay = [r.resource, r.service ?? '', r.description ?? '', ...r.tags].join(' ').toLowerCase();
  return words.every(w => hay.includes(w));
}

export interface DiscoverOptions { query?: string; limit: number; offset: number; chainId?: number; fetcher?: (url: string) => Promise<unknown> }

async function fetchPage(url: string): Promise<unknown> {
  const res = await safeFetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'agentwallet-mcp' }, signal: AbortSignal.timeout(20_000) });
  if (res.status !== 200) throw new Error(`The x402 index answered HTTP ${res.status}.`);
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new Error('The x402 index answered with more data than this client will read.');
  try { return JSON.parse(text); } catch { throw new Error('The x402 index answered with something other than JSON.'); }
}

/**
 * Walk the index from `offset`, keeping items that match. With no query one
 * page is enough; with one, up to MAX_SCAN items are read so the agent sees
 * matches rather than the first page's noise. `next_offset` continues the walk.
 */
export async function discover(opts: DiscoverOptions): Promise<{ items: DiscoveredResource[]; scanned: number; total: number | null; next_offset: number | null }> {
  const fetcher = opts.fetcher ?? fetchPage;
  const out: DiscoveredResource[] = [];
  let offset = opts.offset;
  let scanned = 0;
  let total: number | null = null;
  const want = Math.max(1, Math.min(50, opts.limit));
  while (out.length < want && scanned < MAX_SCAN) {
    const page = (await fetcher(`${BAZAAR_URL}?limit=${PAGE}&offset=${offset}`)) as { items?: unknown; pagination?: { total?: unknown } };
    const items = Array.isArray(page?.items) ? page.items as BazaarItem[] : [];
    if (typeof page?.pagination?.total === 'number') total = page.pagination.total;
    for (const it of items) {
      offset++;
      scanned++;
      const s = summarize(it);
      if (!s) continue;
      if (opts.chainId !== undefined && !s.prices.some(p => p.chain_id === opts.chainId)) continue;
      if (opts.query && !matches(s, opts.query)) continue;
      out.push(s);
      if (out.length >= want) break;
    }
    if (items.length < PAGE) { if (out.length < want) return { items: out, scanned, total, next_offset: null }; break; }
    if (!opts.query && opts.chainId === undefined) break;
  }
  return { items: out, scanned, total, next_offset: total !== null && offset >= total ? null : offset };
}
