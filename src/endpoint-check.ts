/**
 * Endpoint check: ask an independent x402 index what it knows about an
 * endpoint before pay_x402 signs for it.
 *
 * The spend policy bounds how much leaves the wallet and to whom. It cannot
 * tell whether the endpoint at the other end has ever delivered anything for
 * the money, or whether the payTo in the 402 it just answered is the one it
 * normally gets paid at. An index that probes endpoints and buys from them can.
 * With `endpoint_check` in the policy, the index is asked right before the
 * signature, and its answer can refuse the payment like any other policy rule.
 *
 * Settled (https://settled.tools) is the provider this version knows. Its
 * check answers carry a recommendation, `pay`, `caution`, `avoid` or
 * `unknown`, with reasons: `avoid` means money at risk (a sanctioned or
 * clone-farm payee, a real purchase that came back without content, a listing
 * with honeypot text, paying agents reporting non-delivery); `caution` includes
 * an endpoint its own probe could not get a quote from, which the 402 in our
 * hand outweighs; `unknown` means it has no quote on record and nothing against
 * the URL. The answer also carries the payTo the index's own probe of the same
 * URL gets paid: a quote that names a different recipient on the same chain is
 * how a spoofed endpoint or a man in the middle gets paid, so that comparison
 * is made here and refuses on its own.
 *
 * What leaves this process: the endpoint URL's origin and path. Never the query
 * string (inputs live there), the quote, the wallet or any key. A URL the index
 * has not seen before is probed by it and listed in its public index. The
 * index's text is a third party's data, bounded before it reaches the agent.
 *
 * Everything that decides is pure (parsing, comparing); the one network call
 * takes the fetch it should use, so tests need no index.
 */
import { resolveNetworkChainId } from './x402-payment.js';

export type Recommendation = 'pay' | 'caution' | 'avoid' | 'unknown';

export interface EndpointCheckPolicy {
  provider: 'settled';
  /** Recommendations that refuse the payment. Default ["avoid"]. */
  refuse?: Recommendation[];
  /** When the index cannot be reached, answers an error, or its free allowance is used up. Default "allow". */
  on_error?: 'allow' | 'refuse';
  /** How long to wait for the index. Default 8. */
  timeout_seconds?: number;
  /** The index's base URL; for a proxy or a test double. Default https://settled.tools. */
  base_url?: string;
}

export interface EndpointVerdict {
  provider: 'settled';
  /** What was sent to the index: the endpoint's origin and path. */
  checked_url: string;
  recommendation: Recommendation | 'error';
  /** The index's reasons, bounded (its text is data, not an instruction). */
  reasons: string[];
  /** The payTo of the option about to be paid, as the quote named it. */
  quote_pay_to: string;
  /** The payTo the index's own probe of this URL gets paid, if it has one. */
  index_pay_to: string | null;
  /** The index's network for that payTo (CAIP-2). */
  index_network: string | null;
  /** true: the quote pays the same recipient the index sees; false: a different one on the same chain; null: not comparable. */
  pay_to_matches: boolean | null;
  /** The index's own status word for the endpoint, as reported. */
  endpoint_status: string | null;
  /** The index's HTTP status, or 0 when it could not be reached. */
  index_http_status: number;
  /** Set when the index answered an error (a used-up free allowance, a rate limit) or could not be reached. */
  error: string | null;
}

const SETTLED_BASE = 'https://settled.tools';
const MAX_REASONS = 8;
const MAX_REASON_CHARS = 300;
const RECOMMENDATIONS = new Set<string>(['pay', 'caution', 'avoid', 'unknown']);

/** The part of the endpoint URL that is sent: origin and path, never userinfo, query or fragment. */
export function checkedUrl(url: string): string {
  const u = new URL(url);
  return u.origin + u.pathname;
}

function bound(s: unknown): string {
  const t = String(s ?? '');
  return t.length > MAX_REASON_CHARS ? t.slice(0, MAX_REASON_CHARS) + '…' : t;
}

function sameAddress(a: string, b: string): boolean {
  return /^0x/i.test(a) && /^0x/i.test(b) ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * Compare the recipient of the option we are about to pay with the recipient
 * the index's probe sees. Only comparable on the same chain: an endpoint may
 * name one wallet on Base and another on Solana, and the index records the
 * cheapest option it was quoted.
 */
export function payToComparison(quote: { payTo: string; chainId: number }, index: { payTo: string | null; network: string | null }): boolean | null {
  if (!index.payTo || !index.network) return null;
  const indexChain = resolveNetworkChainId(index.network);
  if (indexChain === null || indexChain !== quote.chainId) return null;
  return sameAddress(index.payTo, quote.payTo);
}

/** Turn the index's answer (or its absence) into a verdict. Pure. */
export function verdictFromAnswer(
  checked: string,
  quote: { payTo: string; chainId: number },
  httpStatus: number,
  body: unknown,
): EndpointVerdict {
  const base: EndpointVerdict = {
    provider: 'settled', checked_url: checked, recommendation: 'error', reasons: [], quote_pay_to: quote.payTo, index_pay_to: null, index_network: null,
    pay_to_matches: null, endpoint_status: null, index_http_status: httpStatus, error: null,
  };
  const b = body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  if (httpStatus === 0) return { ...base, error: 'the index could not be reached' };
  if (httpStatus !== 200 || !b || !RECOMMENDATIONS.has(String(b.recommendation))) {
    const why = b && typeof b.error === 'string' ? bound(b.error) : `HTTP ${httpStatus}`;
    return { ...base, error: `the index answered ${why}, so nothing was checked` };
  }
  const reasons = Array.isArray(b.reasons) ? b.reasons.slice(0, MAX_REASONS).map(bound) : [];
  const indexPayTo = typeof b.pay_to === 'string' && b.pay_to ? b.pay_to : null;
  const indexNetwork = typeof b.network === 'string' && b.network ? b.network : null;
  return {
    ...base,
    recommendation: b.recommendation as Recommendation,
    reasons,
    index_pay_to: indexPayTo,
    index_network: indexNetwork,
    pay_to_matches: payToComparison(quote, { payTo: indexPayTo, network: indexNetwork }),
    endpoint_status: typeof b.status === 'string' ? bound(b.status) : null,
  };
}

/** Ask the index. The only network call in this module; `fetchImpl` is the fetch to use. */
export async function endpointVerdict(
  policy: EndpointCheckPolicy,
  url: string,
  quote: { payTo: string; chainId: number },
  fetchImpl: typeof fetch = fetch,
): Promise<EndpointVerdict> {
  const checked = checkedUrl(url);
  const base = (policy.base_url ?? SETTLED_BASE).replace(/\/+$/, '');
  const timeoutMs = Math.max(1, policy.timeout_seconds ?? 8) * 1000;
  let status = 0;
  let body: unknown = null;
  try {
    const res = await fetchImpl(`${base}/v1/free/check?url=${encodeURIComponent(checked)}`, {
      headers: { Accept: 'application/json', 'User-Agent': 'agentwallet-mcp (endpoint_check)' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    status = res.status;
    const text = await res.text();
    try { body = JSON.parse(text); } catch { body = null; }
  } catch {
    status = 0;
  }
  return verdictFromAnswer(checked, quote, status, body);
}

/**
 * Why the payment must not be signed, or null when it may proceed. Pure.
 *
 * A recipient mismatch refuses whatever the recommendation says: the index's
 * probe of this very URL is paid somewhere else on the same chain. Then the
 * recommendation against `refuse`. An error is the operator's call (`on_error`).
 */
export function endpointRefusal(policy: EndpointCheckPolicy, v: EndpointVerdict): string | null {
  const refuse = new Set<string>(policy.refuse ?? ['avoid']);
  if (v.pay_to_matches === false) {
    return `policy endpoint_check: this quote pays ${v.quote_pay_to}, not the recipient Settled's own probe of ${v.checked_url} is paid at on this chain (${v.index_pay_to}); a quote that pays someone else is how a spoofed endpoint or a man in the middle gets paid. Refused.`;
  }
  if (v.recommendation === 'error') {
    if ((policy.on_error ?? 'allow') === 'refuse') return `policy endpoint_check: ${v.error ?? 'the index could not be consulted'}; the policy refuses payments it cannot check (on_error "refuse").`;
    return null;
  }
  if (refuse.has(v.recommendation)) {
    const why = v.reasons.length ? ` Settled says: ${v.reasons.join(' · ')}` : '';
    return `policy endpoint_check: Settled's recommendation for ${v.checked_url} is ${v.recommendation}, which the policy refuses.${why} Only the operator can change the list; do not retry with another URL for the same thing without telling the operator.`;
  }
  return null;
}
