# Endpoints AgentWallet has paid

Real x402 payments made by `pay_x402`, with the settlement transaction. Add yours in a PR (endpoint, scheme, amount, tx).

| Date | Endpoint | Scheme | Amount | Chain | Settlement |
| --- | --- | --- | --- | --- | --- |
| 2026-09-23 | `POST https://api.ozdreamtools.de/api/holidays` (German public holidays by state) | x402 v2, `exact`, EIP-3009 | 0.02 USDC | Base | [0x9e53736330fec8cb8341e0f9425c508f6253430744c0c612ba1bc80081df6ea7](https://basescan.org/tx/0x9e53736330fec8cb8341e0f9425c508f6253430744c0c612ba1bc80081df6ea7) |
| 2026-09-23 | `POST https://api.ozdreamtools.de/api/holidays` (paid above the cap after an emailed human approval) | x402 v2, `exact`, EIP-3009, approval_id | 0.02 USDC | Base | [0xd007b2e41fc08d5a087fa62a52c8cf8028859078b5370e6bffe14a7a2e3af544](https://basescan.org/tx/0xd007b2e41fc08d5a087fa62a52c8cf8028859078b5370e6bffe14a7a2e3af544) |

Notes from the runs:

- The payer wallet held 0 ETH. The facilitator paid the gas, which is the point of the `exact` scheme.
- Coinbase's public facilitator (`https://x402.org/facilitator`) returns `isValid: true` for AgentWallet's v1 and v2 payloads on Base Sepolia (`node test/facilitator-verify.mjs`).
- `node test/x402-live.mjs <url> [method] [body] [max_payment]` drives a real payment through the stdio MCP server in local self-custody mode.

## x402 Payer Report, 2026-09-23

Every endpoint in the x402 Bazaar discovery index priced at 0.01 USDC or less on Base, paid once each from a hosted AgentWallet with a 0.01 cap, x402 v2, exact scheme, EIP-3009 authorization. The payer wallet held 0 ETH throughout; facilitators paid the gas.

**42 settled, 7 answered without asking for payment, 6 could not be paid** (rejected our request or asked again after payment; listed so operators can check their side), 17 not attempted yet (the payer's own API rate limit, will be retried).

| Endpoint | Amount | Settlement |
| --- | --- | --- |
| `GET https://api-dev-v2.ixs.finance/x402/vaults` | 0.001 USDC | [0x4827127d...](https://basescan.org/tx/0x4827127df21a55c48680e67a96b350ef0fc3a429dad407d3dc0802d06fdd031f) |
| `GET https://api.402rates.com/v1/ping` | 0.001 USDC | [0x1eb80844...](https://basescan.org/tx/0x1eb8084427da356cedf16c403038f012b673039e5c3bd521baa54e7d1f68dfb1) |
| `GET https://api.aidress.ai/pay/agent_ottoai_crypto_news` | 0.001 USDC | [0x9d4fd72b...](https://basescan.org/tx/0x9d4fd72b689449b650c3b6dbdd0833214f53fa49b07d27720b23da1d1b10d3b9) |
| `GET https://api.bitrefill.com/x402/gift-cards/search` | 0.002 USDC | [0xc9acc2a2...](https://basescan.org/tx/0xc9acc2a2a2dc1eb6a6a9df6c1907e734669114bf9447ed3676720ff657b46955) |
| `GET https://api.hyperextend.xyz/v1/candles/BTC/1m/latest` | 0.002 USDC | [0xab72f41c...](https://basescan.org/tx/0xab72f41cdb5abef36bd8001fe2e596b3dd4e77ae66e8e4faac85e9b85d459e51) |
| `GET https://api.oblique.markets/api/v1/paid/bazaar-pulse` | 0.002 USDC | [0xd7553548...](https://basescan.org/tx/0xd7553548dd56a56e57c2f8f3bfb2ad3a0dc78fe2c31d39ad9f9d7a95e23bb99a) |
| `GET https://api.onesource.io/api/chain/block-number` | 0.001 USDC | [0xecfdb4b6...](https://basescan.org/tx/0xecfdb4b64587d80cadfa96ad68641496e182ef30dffbfbfcab5c464d277aeadb) |
| `GET https://api.onesource.io/api/chain/chain-id` | 0.001 USDC | [0x9c00f6d8...](https://basescan.org/tx/0x9c00f6d89002c5f244fe13182b05277382e8e7789c66b21c81ea4950d8fd7bc0) |
| `GET https://api.onesource.io/api/chain/erc20-transfers` | 0.005 USDC | [0xda8de2a5...](https://basescan.org/tx/0xda8de2a5e16655a07213989230a644706d426c946ceb96a065cb3b354b283231) |
| `GET https://api.onesource.io/api/chain/events` | 0.005 USDC | [0x07afd5f1...](https://basescan.org/tx/0x07afd5f128d9c214741730a8e640737a114c3f3543b8e610e738bcabed93231c) |
| `GET https://api.onesource.io/api/chain/network-info` | 0.001 USDC | [0x789963c9...](https://basescan.org/tx/0x789963c98c1f464526185dc26d29284d0bf5f053fcf4f03603acbf19b7ddacf1) |
| `GET https://cars2026.vercel.app/api/cars` | 0.0011 USDC | [0x741e4aa0...](https://basescan.org/tx/0x741e4aa014728c0845d4e4ecaa172401c639e6f1ea87db051a7cbfddd71c406e) |
| `GET https://coinflip402.vercel.app/api/coinflip` | 0.001 USDC | [0xce7476d9...](https://basescan.org/tx/0xce7476d98c3abb3b051e5d154d617d7cf313e4440ac989065bcab74f749dd02f) |
| `GET https://crypto.apitoll.cloud/v1/crypto/price` | 0.001 USDC | [0x86b9c07f...](https://basescan.org/tx/0x86b9c07fce9ba00e4ca51358c18299a6bfb65c9c73239d5f061868aa368a1aaa) |
| `GET https://dicex402.vercel.app/api/dice` | 0.001 USDC | [0xb05a87cd...](https://basescan.org/tx/0xb05a87cd44f291e987eb4307c0b5e73b5b66bf95192f226378fd0bc7a3a1a7b1) |
| `GET https://edgar.apitoll.cloud/v1/edgar/filings` | 0.003 USDC | [0x3fedd864...](https://basescan.org/tx/0x3fedd8646b129011fd0c123d44c51f996878320f2f50bfe3088462aafda545bf) |
| `GET https://gas.apitoll.cloud/v1/base/gas` | 0.001 USDC | [0xe309a588...](https://basescan.org/tx/0xe309a5882cbc59571a5bfad0cadadabfbb9251507308d20d2ad06442a402075e) |
| `GET https://horrorstoryapi.vercel.app/api/horror-story` | 0.0013 USDC | [0x9ad37d99...](https://basescan.org/tx/0x9ad37d99b2751e2ba398dc55eb801e32d1d181c4693c7c48be23b7fc6ed768cf) |
| `GET https://hyperliquid-predict.use.x402atlas.com/outcomes` | 0.005 USDC | [0x7aa27804...](https://basescan.org/tx/0x7aa27804d45492666ed515fedaa960f290c05b886636f118a539d8aba251e429) |
| `GET https://jokes-endpoint.vercel.app/api/jokes` | 0.002 USDC | [0xaf5ba561...](https://basescan.org/tx/0xaf5ba5615ead98b16075b86b5efa4d25a0062a476e8a6edaee12b9edf32de17d) |
| `GET https://ladyfortunalx402.vercel.app/api/fortune` | 0.001 USDC | [0xee4330af...](https://basescan.org/tx/0xee4330af86855ec5390ca685a140a2ef24929a890f5b60e779da44db96b8fdcc) |
| `GET https://laso.finance/auth` | 0.001 USDC | [0xbd2c6ecf...](https://basescan.org/tx/0xbd2c6ecf125101f72d0ec75c62bc5161c23a2ed6ac3eda50076ebf9ae4e13450) |
| `GET https://lionx402.com/api/x402/wallet-screen-json` | 0.001 USDC | [0x7f200ae1...](https://basescan.org/tx/0x7f200ae11d773da411898a7cc497524f25700ef043a30f0505c33493f1c02575) |
| `GET https://memegeneratorx402.vercel.app/api/generate-meme` | 0.001 USDC | [0xc19adc3d...](https://basescan.org/tx/0xc19adc3d86fdd4f871b926c99b8b113e924c31f21e1ef3e95f4e1fd5dbd143a9) |
| `GET https://quartermaster.surewhynot.app/v1/gas` | 0.001 USDC | [0x748c77de...](https://basescan.org/tx/0x748c77def10e59f4330aca9f88c2fb55d97c3be45dbd102edcdf9ab556f2db3f) |
| `GET https://randomfactsx402.vercel.app/api/random-fact` | 0.001 USDC | [0x4960d6c3...](https://basescan.org/tx/0x4960d6c32301f0ee62fe0d56e7f0638813960f8e383a6e4364458d3f6ebd67c7) |
| `GET https://riddlex402.vercel.app/api/riddle` | 0.002 USDC | [0x55b6d627...](https://basescan.org/tx/0x55b6d6277c1babc472cd3fd2813c315a75e66f8a6302358e187f97e169926f8a) |
| `GET https://roastx402endpoint.vercel.app/api/roast` | 0.0017 USDC | [0xd83ee3bd...](https://basescan.org/tx/0xd83ee3bdf02c5309fab7e83a194124ee76758bc9197c9de616cab57dbdb1414e) |
| `GET https://rubric-protocol.com/v1/x402/hedera-facts/exchange-rate` | 0.001 USDC | [0x276977e0...](https://basescan.org/tx/0x276977e0e3265c4b6ca0f5fbf4d4e73586c6fc1773971677850d07d971bb30d7) |
| `GET https://rubric-protocol.com/v1/x402/hedera-facts/supply` | 0.001 USDC | [0xc84663c4...](https://basescan.org/tx/0xc84663c494c774f02fdb0419eff6740092dd1e778cb74250e707a9ad6a46d980) |
| `GET https://vibesprings.net/api/price/base-gas` | 0.001 USDC | [0xf048d2d2...](https://basescan.org/tx/0xf048d2d24fb33500aa83b0a9c95c54e5b091850a0e1020d6000abbc51eaf4393) |
| `GET https://vibesprings.net/api/price/btc-usd` | 0.002 USDC | [0x3bbb675e...](https://basescan.org/tx/0x3bbb675ef298261d3230030318339f6370ae38cee4fba50090fe0616b55ae9f3) |
| `GET https://weight402endpoint.vercel.app/api/convert-weight` | 0.0025 USDC | [0x699bf3fd...](https://basescan.org/tx/0x699bf3fd86d12c708a91ec20c7224f71285a6b4deb258b4fd14b562e60faed49) |
| `GET https://x402.ottoai.services/crypto-news` | 0.001 USDC | [0x58032e53...](https://basescan.org/tx/0x58032e5376c87ec680211d6b43d467212d26920a6c1223b98d79b1399c3e35bf) |
| `GET https://x402.ottoai.services/funding-rates` | 0.001 USDC | [0x1fd2912c...](https://basescan.org/tx/0x1fd2912cd1dfd93ecf417d423153671ce14269eb9848a7b32dacf10b62559377) |
| `GET https://x402.ottoai.services/hyperliquid-market` | 0.001 USDC | [0xed53a188...](https://basescan.org/tx/0xed53a188075353a37ff974c2c111503ce23a84ec2915e75e47b815c4c83d182b) |
| `GET https://x402.ottoai.services/tradfi-data` | 0.003 USDC | [0x3cd65f2b...](https://basescan.org/tx/0x3cd65f2b0db3583ef8cbbfe804a7d03cdfbfb9bf2c4c3f169bddab63e3a60b08) |
| `GET https://x402.ottoai.services/twitter-summary` | 0.001 USDC | [0x2bc794d5...](https://basescan.org/tx/0x2bc794d5e9e593e7d6e352716cb4ee81052ecbb3b5a5686a99a06ed65a036022) |
| `GET https://x402.ottoai.services/yield-markets` | 0.001 USDC | [0x1237040b...](https://basescan.org/tx/0x1237040b5b2dc0d35333054878b5b0ff5290b0269d4b2e58c5bca2d8bd887d82) |
| `GET https://x402lifeadvice.vercel.app/api/life-advice` | 0.001 USDC | [0xe9b09efc...](https://basescan.org/tx/0xe9b09efc4f22457e63b3564925f2b3ce80690003df73e1c2f26496800b921b4e) |
| `GET https://x402uselessfacts.vercel.app/api/useless-fact` | 0.001 USDC | [0x20a9beb2...](https://basescan.org/tx/0x20a9beb2111a5b5799a84f918297c0da3741b9134b41969cc28a8bc40464dd65) |
| `GET https://x402wordoftheday.vercel.app/api/word-of-the-day` | 0.0015 USDC | [0x078ecf6e...](https://basescan.org/tx/0x078ecf6efe58aa6cd26b24529ff6ed50d4e230e70a4eb47a25ba645dc6bd780a) |

<details><summary>Not payable on 2026-09-23 (6)</summary>

| Endpoint | Result |
| --- | --- |
| `https://402timezones.vercel.app/api/convert-timezone` | HTTP 400 |
| `https://api.loyalspark.online/x402-gateway/recipient-api/offers` | HTTP 401 |
| `https://api.loyalspark.online/x402-gateway/recipient-api/workflow/reward-status` | HTTP 401 |
| `https://chat.gedx402.com/v1/chat/completions` | HTTP 404 |
| `https://hypernatt.com/api/m2m/liq-radar` | HTTP 200 |
| `https://x402.ottoai.services/token-details` | HTTP 400 |

</details>

Answered without a 402 (no payment needed): api.exa.ai, stableenrich.dev, stableupload.dev, stableupload.dev, api.exa.ai, stableenrich.dev, stablestudio.dev.
