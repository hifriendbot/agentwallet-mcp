# Security

AgentWallet moves money on behalf of software. Everything below exists because of that.

## Report a vulnerability

Email **security@hifriendbot.com**. Do not open a public issue for anything exploitable.

We pay for real findings in USDC on Base, per the tiers published at https://hifriendbot.com/wallet/#security: $50 (low), $150 (medium), $500 (high or critical). Two researchers have been paid through this channel in 2026. We answer within three business days and credit you in the changelog unless you ask us not to.

## Disclosure history

| Date | Severity | Report | Fix |
| --- | --- | --- | --- |
| 2026-06-27 | High | `pay_x402` cap could be bypassed when `max_payment` was omitted (attacker-controlled `maxAmountRequired` reached the transfer) | 1.8.0: cap always enforced, shared `isWithinCap` helper, regression tests |
| 2026-07-26 | Medium | AgentWallet API keys were WordPress application passwords usable on any REST route, and key-management routes accepted them | Server: app passwords scoped to `/agentwallet/v1` only; key listing, reveal, mint and revoke require a browser session plus nonce |
| 2026-07-26 | Low | Daily spending limit could be enforced but never set | Server: `spending_limit_daily` on create, `PATCH /wallets/{id}`, dashboard control |
| 2026-08-12 | Medium | `upto` scheme settled as a full upfront transfer (overcharge relative to usage) | 1.11.0 refuses `upto`; 1.12.0 signs it correctly through Permit2 |
| 2026-08-19 | High (functional) | `exact` scheme sent a broadcast transfer instead of an EIP-3009 authorization; standard servers rejected every payment | 1.11.0: EIP-3009 `TransferWithAuthorization`, verified against Coinbase's facilitator and settled live on Base |
| 2026-09-26 | Medium | Token cap let unpriced calldata through when the target's `decimals()` answered outside 0..36: the probe reported "absurd answer" and "no answer" with the same null, and only "no answer" was meant to pass | 1.12.5: the probe reports usable, unusable, not-a-token and unreachable separately; only a contract that demonstrably declines `decimals()` passes, an unreachable RPC refuses, regression test with a mock RPC |

## What the code guarantees

**Self-custody is testable, not asserted.** `test/local-mode.test.mjs` runs every funds tool with the hosted API pointed at a closed port. If any path still reached a server, the test fails. Local keys are read once from the environment, never logged, never persisted, never included in an error message.

**Caps fail closed.** Token amounts are evaluated at trusted decimals (registry, then the contract), never at decimals the paying endpoint declares. Unknown tokens are refused rather than guessed. `AGENTWALLET_MAX_TX_TOKEN` covers `transfer`, `transferFrom`, `approve`, `increaseAllowance`, Permit2 `approve`, EIP-3009 authorizations and Permit2 maximums, because all of them let someone else move funds. Calldata the guard cannot price is refused when its target is a token contract or Permit2, rather than let through uncapped. A target counts as a token unless it demonstrably declines `decimals()` (reverts or returns nothing); an absurd answer, a malformed answer, or an unreachable RPC all refuse.

**The server signs one struct off-chain.** `POST /wallets/{id}/x402/authorize` rebuilds an EIP-3009 authorization from validated fields and signs that; it never signs caller-supplied typed data. Same for the Permit2 route. Both run the pause and token-cap checks a transfer gets.

**No SSRF from `pay_x402`.** URLs must be HTTPS; every hop is resolved once, checked against private ranges, and the connection is pinned to the validated addresses. Caller credentials are dropped on cross-origin redirects.

**Approvals are single-use and bound.** A human approval names one wallet, chain, asset, recipient and maximum; it expires in 24 hours and is consumed by exactly one signature.

## Dependencies

`npm audit` is run before every release. The SPL transfer path is hand-built to avoid `@solana/spl-token` and its `bigint-buffer` advisory. Remaining advisories, if any, are listed in the release notes with the reason they do not apply under stdio transport.
