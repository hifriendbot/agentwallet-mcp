/**
 * Marks an error thrown after a transaction may already have left this
 * process, so the ledger keeps the reservation counted instead of voiding it.
 *
 * The decision used to be a regex over the error text (/BROADCAST|MAY be live/i)
 * and misfired on any message that merely contained the word "broadcasts",
 * including the local-mode refusal of transaction signing, so every refused
 * sign_transaction consumed the budget for good (reported privately, 2026-10-16,
 * fixed in 1.14.3). A marker on the error object cannot misfire on wording.
 *
 * Symbol.for so the marker survives a duplicated module in the bundle; a plain
 * `instanceof` would not.
 */
const MARK = Symbol.for('agentwallet.maybeLive');

/** Mark `err` as thrown after the transaction may have gone out. Returns it. */
export function markMaybeLive<T extends object>(err: T): T {
  (err as unknown as Record<symbol, boolean>)[MARK] = true;
  return err;
}

/** Was this error thrown after the transaction may have gone out? */
export function isMaybeLive(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as Record<symbol, unknown>)[MARK] === true;
}

/** Copy the marker from `from` onto `to` (for errors re-thrown with a redacted message). */
export function carryMaybeLive<T extends object>(from: unknown, to: T): T {
  return isMaybeLive(from) ? markMaybeLive(to) : to;
}

/**
 * A fetch() rejection whose cause says the connection was never made: nothing
 * reached the host, so a reserved spend can be voided. Anything else (a timeout
 * waiting for the answer, a reset mid-request, an unknown cause) may have
 * reached the host, and a send there is treated as possibly live.
 */
export function connectionNeverMade(err: unknown): boolean {
  const e = err as { name?: string; cause?: { code?: string; name?: string; message?: string } };
  const code = e?.cause?.code ?? '';
  // fetch() refuses some requests before opening a socket (a blocked port such
  // as 1, an unsupported scheme, a URL it will not parse); undici reports those
  // as "fetch failed" with a bare-message cause and no errno.
  if (!code && /^(bad port|invalid url|unsupported scheme|unknown scheme|url scheme ".*" is not supported|fetch failed)$/i.test(e?.cause?.message ?? '')) return true;
  if (/^(ECONNREFUSED|ENOTFOUND|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|EADDRNOTAVAIL|UND_ERR_CONNECT_TIMEOUT|ERR_TLS_CERT_ALTNAME_INVALID|CERT_HAS_EXPIRED|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT_LOCALLY|ERR_INVALID_URL)$/.test(code)) return true;
  // Node's own TLS errors arrive as the cause with a name and no errno code.
  if (/^(ERR_TLS_|ERR_SSL_)/.test(code)) return true;
  return false;
}
