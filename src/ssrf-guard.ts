/**
 * SSRF guard for outbound x402 requests.
 *
 * The original guard compared `new URL(url).hostname` against literal strings
 * and dotted-decimal prefixes. That missed every alternate spelling of a
 * private destination: IPv4-mapped IPv6 (`[::ffff:127.0.0.1]` parses to
 * `[::ffff:7f00:1]`), the rest of 127.0.0.0/8, IPv6 unique-local and
 * link-local, the whole 169.254.0.0/16 link-local range rather than only the
 * metadata address, and 100.64.0.0/10.
 *
 * This module canonicalizes the host into actual IP addresses and tests them
 * against numeric ranges, then resolves DNS names and applies the same test to
 * every answer, so a public name pointing at a private address is refused too.
 *
 * Validating a name is not enough on its own. If the request is then handed to
 * fetch() as a URL, the name is resolved a second time by the HTTP client, and
 * an attacker who controls the authoritative DNS can answer public for the
 * check and private for the connection. So `safeFetch` pins the connection to
 * the exact addresses that were validated: the resolver runs once, and the
 * socket is only allowed to reach an address from that answer. The hostname is
 * still used for the Host header and for TLS SNI and certificate validation,
 * so pinning is invisible to legitimate endpoints.
 *
 * Redirects are followed by hand, and a redirect to a different origin drops
 * every caller-supplied header except a short content-negotiation list. A
 * bearer token meant for api.example.com must not be replayed to whatever
 * host api.example.com chooses to redirect to.
 *
 * Reported privately by ARC Security Research, 2026-07-31 (spelling bypasses),
 * by an anonymous researcher, 2026-08-02 (the DNS rebinding race), and by
 * Arthur Kijkrittaya, 2026-09-08 (credentials surviving cross-origin redirects).
 */

import { isIP, type LookupFunction } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import { Agent, fetch as undiciFetch } from 'undici';

/** Hostnames that must never be reached regardless of what they resolve to. */
const BLOCKED_NAMES = new Set([
  'localhost',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
]);

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8 >>> 0) + v;
  }
  return n >>> 0;
}

function inV4Range(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(base);
  if (a === null || b === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (a & mask) === (b & mask);
}

/** Ranges that are never a legitimate x402 payment endpoint. */
const V4_BLOCKED = [
  '0.0.0.0/8',        // this network / unspecified
  '10.0.0.0/8',       // private
  '100.64.0.0/10',    // carrier-grade NAT
  '127.0.0.0/8',      // loopback, all of it
  '169.254.0.0/16',   // link-local, includes cloud metadata
  '172.16.0.0/12',    // private
  '192.0.0.0/24',     // IETF protocol assignments
  '192.168.0.0/16',   // private
  '198.18.0.0/15',    // benchmarking
  '224.0.0.0/4',      // multicast
  '240.0.0.0/4',      // reserved, includes 255.255.255.255
];

/** Expand an IPv6 literal (any spelling Node's isIP accepts) into eight 16-bit groups. */
export function expandIPv6(hostRaw: string): number[] | null {
  let h = hostRaw.toLowerCase();
  // A trailing dotted IPv4 (::ffff:1.2.3.4, ::1.2.3.4, 64:ff9b::1.2.3.4) is the last two groups.
  const dotted = h.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const v4 = ipv4ToInt(dotted[2]);
    if (v4 === null) return null;
    h = dotted[1] + (v4 >>> 16).toString(16) + ':' + (v4 & 0xffff).toString(16);
  }
  const halves = h.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

const embeddedV4 = (hi: number, lo: number) => [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join('.');
const zeroThrough = (g: number[], n: number) => g.slice(0, n).every(x => x === 0);

/**
 * Reduce a host to the IP address it actually denotes.
 * Strips IPv6 brackets and unwraps every IPv6 form that embeds an IPv4
 * address: IPv4-mapped (::ffff:a.b.c.d), IPv4-translated (::ffff:0:a.b.c.d)
 * and the deprecated IPv4-compatible form (::a.b.c.d, also spelled
 * ::7f00:1). The match is on the expanded groups, not on one spelling, so
 * 0:0:0:0:0:0:7f00:1 and ::7F00:1 canonicalize the same way. The compatible
 * form was reported as unclassified on 2026-09-25 (not reachable in practice,
 * modern stacks refuse to route ::/96, but a guard should not depend on that).
 */
export function canonicalizeHost(hostRaw: string): { ip: string | null; family: 0 | 4 | 6 } {
  let host = hostRaw.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const zone = host.indexOf('%');            // fe80::1%eth0
  if (zone !== -1) host = host.slice(0, zone);

  const fam = isIP(host);
  if (fam === 0) return { ip: null, family: 0 };
  if (fam === 4) return { ip: host, family: 4 };

  const g = expandIPv6(host);
  if (!g) return { ip: host, family: 6 };
  if (zeroThrough(g, 5) && g[5] === 0xffff) return { ip: embeddedV4(g[6], g[7]), family: 4 };            // ::ffff:a.b.c.d
  if (zeroThrough(g, 4) && g[4] === 0xffff && g[5] === 0) return { ip: embeddedV4(g[6], g[7]), family: 4 }; // ::ffff:0:a.b.c.d
  if (zeroThrough(g, 6) && !(g[6] === 0 && g[7] <= 1)) return { ip: embeddedV4(g[6], g[7]), family: 4 };  // ::a.b.c.d, but not :: or ::1
  return { ip: host, family: 6 };
}

/** True when the address is loopback, private, link-local, multicast or reserved. */
export function isPrivateAddress(ipRaw: string): boolean {
  const { ip, family } = canonicalizeHost(ipRaw);
  if (!ip) return false;

  if (family === 4) return V4_BLOCKED.some(c => inV4Range(ip, c));

  const g = expandIPv6(ip);
  if (!g) return true;                                              // isIP said IPv6 but it will not parse: refuse
  if (zeroThrough(g, 7) && g[7] <= 1) return true;                  // :: unspecified, ::1 loopback
  if ((g[0] & 0xfe00) === 0xfc00) return true;                      // fc00::/7 unique-local
  if ((g[0] & 0xffc0) === 0xfe80) return true;                      // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return true;                      // ff00::/8 multicast
  if (g[0] === 0x64 && g[1] === 0xff9b) return true;                // 64:ff9b::/96 NAT64
  if (g[0] === 0x2002) return true;                                 // 2002::/16 6to4
  if (g[0] === 0x2001 && g[1] === 0xdb8) return true;               // 2001:db8::/32 documentation
  return false;
}

/** An address that passed validation and is therefore allowed to be connected to. */
export type ValidatedAddress = { address: string; family: 4 | 6 };

/**
 * Validate `url` and return the exact set of addresses a connection to it is
 * allowed to use. DNS names are resolved once here; that single answer is both
 * what gets checked and what gets connected to, which is what removes the
 * time-of-check/time-of-use gap.
 *
 * Throws unless the URL is https and every address it denotes is public.
 */
export async function resolvePublicUrl(url: string): Promise<{ target: URL; addresses: ValidatedAddress[] }> {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new Error('Invalid URL.');
  }

  if (u.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are supported for x402 payments.');
  }

  const hostRaw = u.hostname.toLowerCase();
  const bare = hostRaw.startsWith('[') && hostRaw.endsWith(']') ? hostRaw.slice(1, -1) : hostRaw;
  if (BLOCKED_NAMES.has(bare)) {
    throw new Error('URL points to a private/internal address. Only public URLs are allowed.');
  }

  const { ip, family } = canonicalizeHost(hostRaw);
  if (family !== 0) {
    if (isPrivateAddress(ip as string)) {
      throw new Error('URL points to a private/internal address. Only public URLs are allowed.');
    }
    // An IP literal is never resolved, so there is nothing to rebind: the
    // socket layer connects to the literal we just checked.
    return { target: u, addresses: [{ address: ip as string, family }] };
  }

  // A name: every address it resolves to must be public.
  let answers: Array<{ address: string; family: number }>;
  try {
    answers = await dnsLookup(bare, { all: true });
  } catch {
    throw new Error(`Could not resolve host "${bare}".`);
  }
  if (!answers.length) throw new Error(`Could not resolve host "${bare}".`);

  const addresses: ValidatedAddress[] = [];
  for (const a of answers) {
    if (isPrivateAddress(a.address)) {
      throw new Error('URL resolves to a private/internal address. Only public URLs are allowed.');
    }
    addresses.push({ address: a.address, family: a.family === 6 ? 6 : 4 });
  }
  return { target: u, addresses };
}

/**
 * Throw unless `url` is an https URL pointing at a public destination.
 * Kept for callers that only want the check and not the resolved addresses.
 */
export async function assertPublicUrl(url: string): Promise<void> {
  await resolvePublicUrl(url);
}

type LookupCallback = (
  err: NodeJS.ErrnoException | null,
  addressOrList?: string | ValidatedAddress[],
  family?: number,
) => void;

/**
 * A drop-in replacement for dns.lookup that answers only from an already
 * validated set and never queries a resolver. Handing this to the socket layer
 * is what pins the connection: whatever the authoritative server says on a
 * second query cannot reach the socket.
 */
export function createPinnedLookup(addresses: ValidatedAddress[]) {
  const pinned = addresses.slice();
  return function pinnedLookup(_hostname: string, options: unknown, callback?: LookupCallback): void {
    const cb = (typeof options === 'function' ? options : callback) as LookupCallback;
    const opts = (typeof options === 'object' && options !== null ? options : {}) as {
      all?: boolean;
      family?: number;
    };

    let list = pinned;
    if (opts.family === 4 || opts.family === 6) {
      list = pinned.filter(a => a.family === opts.family);
    }

    queueMicrotask(() => {
      if (!list.length) {
        const err = new Error('No validated address is available for this host.') as NodeJS.ErrnoException;
        err.code = 'ENOTFOUND';
        cb(err);
        return;
      }
      if (opts.all) {
        cb(null, list.map(a => ({ address: a.address, family: a.family })));
        return;
      }
      cb(null, list[0].address, list[0].family);
    });
  };
}

/** Statuses whose Response must be constructed with a null body. */
const NULL_BODY_STATUS = new Set([101, 103, 204, 205, 304]);

/**
 * The only request headers that may travel to a different origin on a
 * redirect. Everything else the caller supplied (Authorization, Cookie,
 * X-PAYMENT, API keys under any custom name) is bound to the origin the caller
 * addressed and is dropped. An allow list is used rather than a deny list so a
 * secret under an unanticipated header name cannot slip through.
 */
const CROSS_ORIGIN_SAFE_HEADERS = new Set([
  'accept',
  'accept-language',
  'accept-encoding',
  'user-agent',
  'content-type',
]);

/** Headers that describe a request body and are wrong once the body is gone. */
const ENTITY_HEADERS = new Set(['content-type', 'content-length', 'content-encoding', 'transfer-encoding']);

/** True when two URLs share scheme, host and port (the web origin). */
export function sameOrigin(a: string, b: string): boolean {
  const ua = new URL(a);
  const ub = new URL(b);
  return ua.protocol === ub.protocol && ua.host === ub.host;
}

function headersToRecord(headers: HeadersInit | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  if (typeof (headers as Headers).forEach === 'function' && !Array.isArray(headers)) {
    (headers as Headers).forEach((v, k) => { out[k] = v; });
    return out;
  }
  if (Array.isArray(headers)) {
    for (const [k, v] of headers) out[k] = v;
    return out;
  }
  for (const [k, v] of Object.entries(headers as Record<string, string>)) out[k] = v;
  return out;
}

/**
 * Decide which request headers follow a redirect from `from` to `to`.
 *
 * Same origin: everything is kept, as a browser would. Different origin: only
 * CROSS_ORIGIN_SAFE_HEADERS survive. When the redirect also turned the request
 * into a body-less GET (`bodyDropped`), the entity headers go too, on either
 * kind of hop.
 */
export function headersForRedirect(
  headers: HeadersInit | undefined,
  from: string,
  to: string,
  bodyDropped: boolean,
): Record<string, string> {
  const crossOrigin = !sameOrigin(from, to);
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headersToRecord(headers))) {
    const name = k.toLowerCase();
    if (bodyDropped && ENTITY_HEADERS.has(name)) continue;
    if (crossOrigin && !CROSS_ORIGIN_SAFE_HEADERS.has(name)) continue;
    out[k] = v;
  }
  return out;
}

/**
 * fetch() that validates the target, and every redirect hop, against
 * resolvePublicUrl, and connects only to the addresses that validation
 * returned. Redirects are followed manually because the automatic follower
 * would happily land on a private address after a public first hop, and
 * because each hop needs its own resolve-then-pin cycle.
 *
 * Headers are re-derived on every redirect (see headersForRedirect): a hop to
 * another origin carries no credential the caller attached for the first one.
 *
 * The body is buffered so the pinned connection can be torn down before the
 * response is handed back.
 */
export async function safeFetch(url: string, options: RequestInit = {}, maxHops = 3): Promise<Response> {
  let current = url;
  let opts = options;

  for (let hop = 0; hop <= maxHops; hop++) {
    const { addresses } = await resolvePublicUrl(current);

    // One agent per hop, carrying that hop's pinned addresses. The hostname is
    // untouched, so Host and TLS SNI/certificate validation still use the name.
    const agent = new Agent({
      connect: { lookup: createPinnedLookup(addresses) as unknown as LookupFunction },
    });

    let status: number;
    let statusText: string;
    let headers: Array<[string, string]>;
    let body: ArrayBuffer | null;
    try {
      const res = await undiciFetch(current, {
        ...opts,
        redirect: 'manual',
        dispatcher: agent,
      } as Parameters<typeof undiciFetch>[1]);

      status = res.status;
      statusText = res.statusText;
      headers = [];
      for (const [k, v] of res.headers) {
        // The body below is already decoded, so the transfer-level description
        // of it would be wrong if carried over.
        if (k === 'content-encoding' || k === 'content-length') continue;
        headers.push([k, v]);
      }
      body = NULL_BODY_STATUS.has(status) ? null : await res.arrayBuffer();
    } finally {
      await agent.destroy();
    }

    const out = new Response(body, { status, statusText, headers });
    const isRedirect = status >= 300 && status < 400 && out.headers.has('location');
    if (!isRedirect) return out;

    const next = new URL(out.headers.get('location') as string, current).toString();
    // A redirected request must not replay the body or method blindly, and it
    // must not replay the caller's credentials to a different origin at all.
    const bodyDropped = status === 303
      || ((status === 301 || status === 302) && !!opts.method && opts.method !== 'GET');
    opts = { ...opts, headers: headersForRedirect(opts.headers, current, next, bodyDropped) };
    if (bodyDropped) {
      opts = { ...opts, method: 'GET', body: undefined };
    }
    current = next;
  }
  throw new Error('Too many redirects while contacting the x402 endpoint.');
}
