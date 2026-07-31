/**
 * SSRF guard for outbound x402 requests.
 *
 * The previous guard compared `new URL(url).hostname` against literal strings
 * and dotted-decimal prefixes. That misses every alternate spelling of a
 * private destination: IPv4-mapped IPv6 (`[::ffff:127.0.0.1]` parses to
 * `[::ffff:7f00:1]`), the rest of 127.0.0.0/8, IPv6 unique-local and
 * link-local, the whole 169.254.0.0/16 link-local range rather than only the
 * metadata address, and 100.64.0.0/10.
 *
 * This module canonicalizes the host into actual IP addresses and tests them
 * against numeric ranges, then resolves DNS names and applies the same test to
 * every answer, so a public name pointing at a private address is refused too.
 *
 * Reported privately by ARC Security Research, 2026-07-31.
 */

import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

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

/**
 * Throw unless `url` is an https URL pointing at a public destination.
 * DNS names are resolved and every answer is checked, so a public name that
 * maps to a private address is rejected.
 */
export async function assertPublicUrl(url: string): Promise<void> {
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
    return;
  }

  // A name: every address it resolves to must be public.
  let answers: Array<{ address: string }>;
  try {
    answers = await lookup(bare, { all: true });
  } catch {
    throw new Error(`Could not resolve host "${bare}".`);
  }
  if (!answers.length) throw new Error(`Could not resolve host "${bare}".`);
  for (const a of answers) {
    if (isPrivateAddress(a.address)) {
      throw new Error('URL resolves to a private/internal address. Only public URLs are allowed.');
    }
  }
}

/**
 * fetch() that validates the target, and every redirect hop, against
 * assertPublicUrl. Redirects are followed manually because the automatic
 * follower would happily land on a private address after a public first hop.
 */
export async function safeFetch(url: string, options: RequestInit = {}, maxHops = 3): Promise<Response> {
  let current = url;
  for (let hop = 0; hop <= maxHops; hop++) {
    await assertPublicUrl(current);
    const res = await fetch(current, { ...options, redirect: 'manual' });
    const isRedirect = res.status >= 300 && res.status < 400 && res.headers.has('location');
    if (!isRedirect) return res;

    const next = new URL(res.headers.get('location') as string, current).toString();
    // A redirected request must not replay the body or method blindly.
    if (res.status === 303 || ((res.status === 301 || res.status === 302) && options.method && options.method !== 'GET')) {
      options = { ...options, method: 'GET', body: undefined };
    }
    current = next;
  }
  throw new Error('Too many redirects while contacting the x402 endpoint.');
}
