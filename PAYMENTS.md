# Endpoints AgentWallet has paid

Real x402 payments made by `pay_x402`, with the settlement transaction. Add yours in a PR (endpoint, scheme, amount, tx).

| Date | Endpoint | Scheme | Amount | Chain | Settlement |
| --- | --- | --- | --- | --- | --- |
| 2026-09-23 | `POST https://api.ozdreamtools.de/api/holidays` (German public holidays by state) | x402 v2, `exact`, EIP-3009 | 0.02 USDC | Base | [0x9e53736330fec8cb8341e0f9425c508f6253430744c0c612ba1bc80081df6ea7](https://basescan.org/tx/0x9e53736330fec8cb8341e0f9425c508f6253430744c0c612ba1bc80081df6ea7) |

Notes from the runs:

- The payer wallet held 0 ETH. The facilitator paid the gas, which is the point of the `exact` scheme.
- Coinbase's public facilitator (`https://x402.org/facilitator`) returns `isValid: true` for AgentWallet's v1 and v2 payloads on Base Sepolia (`node test/facilitator-verify.mjs`).
- `node test/x402-live.mjs <url> [method] [body] [max_payment]` drives a real payment through the stdio MCP server in local self-custody mode.
