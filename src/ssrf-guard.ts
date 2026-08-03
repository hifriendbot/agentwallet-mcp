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
 * Reported privately by ARC Security Research, 2026-07-31 (spelling bypasses)
 * and by an anonymous researcher, 2026-08-02 (the DNS rebinding race).
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

/**
 * Reduce a host to the IP address it actually denotes.
 * Strips IPv6 brackets and unwraps IPv4-mapped and IPv4-compatible IPv6.
 */
export function canonicalizeHost(hostRaw: string): { ip: string | null; family: 0 | 4 | 6 } {
  let host = hostRaw.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const zone = host.indexOf('%');            // fe80::1%eth0
  if (zone !== -1) host = host.slice(0, zone);

  const fam = isIP(host);
  if (fam === 0) return { ip: null, family: 0 };
  if (fam === 4) return { ip: host, family: 4 };

  // IPv6: unwrap ::ffff:a.b.c.d and its hex spelling ::ffff:7f00:1
  const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return { ip: mapped[1], family: 4 };
  const hexMapped = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMapped) {
    const hi = parseInt(hexMapped[1], 16);
    const lo = parseInt(hexMapped[2], 16);
    return { ip: [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255].join('.'), family: 4 };
  }
  return { ip: host, family: 6 };
}

/** True when the address is loopback, private, link-local, multicast or reserved. */
export function isPrivateAddress(ipRaw: string): boolean {
  const { ip, family } = canonicalizeHost(ipRaw);
  if (!ip) return false;

  if (family === 4) return V4_BLOCKED.some(c => inV4Range(ip, c));

  const v6 = ip;
  if (v6 === '::' || v6 === '::1') return true;                 // unspecified, loopback
  if (/^f[cd][0-9a-f]{2}:/.test(v6)) return true;               // fc00::/7 unique-local
  if (/^fe[89ab][0-9a-f]:/.test(v6)) return true;               // fe80::/10 link-local
  if (/^ff[0-9a-f]{2}:/.test(v6)) return true;                  // ff00::/8 multicast
  if (/^(64:ff9b|2002):/.test(v6)) return true;                 // NAT64 / 6to4 translation
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
 * fetch() that validates the target, and every redirect hop, against
 * resolvePublicUrl, and connects only to the addresses that validation
 * returned. Redirects are followed manually because the automatic follower
 * would happily land on a private address after a public first hop, and
 * because each hop needs its own resolve-then-pin cycle.
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
    // A redirected request must not replay the body or method blindly.
    if (status === 303 || ((status === 301 || status === 302) && opts.method && opts.method !== 'GET')) {
      opts = { ...opts, method: 'GET', body: undefined };
    }
    current = next;
  }
  throw new Error('Too many redirects while contacting the x402 endpoint.');
}
