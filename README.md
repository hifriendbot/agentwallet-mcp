# AgentWallet MCP Server

Permissionless EVM wallet infrastructure for AI agents. Create wallets, sign transactions, and broadcast on-chain — on any EVM chain.

**No KYC. No KYT. No transaction monitoring. No one can block your wallet.**

## Features

- **20 MCP tools** — create wallets, send transactions, approve tokens, wrap ETH, check balances, and more
- **9 EVM chains** — Ethereum, Base, Polygon, BSC, Arbitrum, Optimism, Avalanche, Zora, PulseChain
- **Secure** — Private keys encrypted at rest (Sodium XSalsa20-Poly1305), decrypted only during signing, zeroed from memory immediately after
- **Permissionless** — No identity verification, no compliance gatekeeping. Create a wallet and transact immediately.

## Pricing

- **$0.0069 per transaction** (31% less expensive than Coinbase CDP)
- **6,000 free transactions/month**
- No monthly fee, no tiers — just pay as you go

## Quick Start

Get your free API key at [hifriendbot.com/wallet](https://hifriendbot.com/wallet) (no credit card required).

### Claude Desktop / OpenClaw

Add to your config:

```json
{
  "mcpServers": {
    "agentwallet": {
      "command": "npx",
      "args": ["-y", "agentwallet-mcp"],
      "env": {
        "AGENTWALLET_USER": "your_username",
        "AGENTWALLET_PASS": "your_api_key"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add agentwallet \
  -e AGENTWALLET_USER=your_username \
  -e AGENTWALLET_PASS=your_api_key \
  -- npx -y agentwallet-mcp
```

### VS Code

Add to your settings:

```json
{
  "mcp": {
    "servers": {
      "agentwallet": {
        "command": "npx",
        "args": ["-y", "agentwallet-mcp"],
        "env": {
          "AGENTWALLET_USER": "your_username",
          "AGENTWALLET_PASS": "your_api_key"
        }
      }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `create_wallet` | Create a new wallet on any EVM chain |
| `list_wallets` | List all your wallets |
| `get_wallet` | Get wallet details by ID |
| `get_balance` | Check native token balance on any chain |
| `send_transaction` | Sign and broadcast a transaction |
| `sign_transaction` | Sign a transaction (returns raw hex) |
| `approve_token` | Approve ERC-20 token spending |
| `get_allowance` | Check ERC-20 token allowance |
| `wrap_eth` | Wrap native ETH to WETH |
| `unwrap_eth` | Unwrap WETH to native ETH |
| `get_token_info` | Get ERC-20 token name, symbol, decimals, balance |
| `get_usage` | Check your monthly usage and billing |
| `get_chains` | List all supported chains |
| `pause_wallet` | Emergency pause a wallet |
| `unpause_wallet` | Resume a paused wallet |
| `delete_wallet` | Delete a wallet |

## Supported Chains

| Chain | ID | Native Token | Stablecoin |
|-------|-----|-------------|------------|
| Ethereum | 1 | ETH | USDC |
| Base | 8453 | ETH | USDC |
| Polygon | 137 | POL | USDC |
| BSC | 56 | BNB | USDT |
| Arbitrum | 42161 | ETH | USDC |
| Optimism | 10 | ETH | USDC |
| Avalanche | 43114 | AVAX | USDC |
| Zora | 7777777 | ETH | USDC |
| PulseChain | 369 | PLS | USDC |

## Use Case: GuessMarket

Pair with [guessmarket-mcp](https://www.npmjs.com/package/guessmarket-mcp) to let your AI agent trade prediction markets:

1. Create a wallet on Base
2. Approve USDC spending
3. Buy YES/NO shares on prediction markets
4. Provide liquidity and earn trading fees
5. Claim winnings

All on-chain. All through MCP. No frontend needed.

## Security

- Private keys are generated server-side and encrypted at rest with Sodium (XSalsa20-Poly1305)
- Keys are decrypted only during transaction signing and zeroed from memory immediately after
- EIP-1559 transactions only with gas safety caps
- Emergency pause: freeze any wallet or all wallets instantly
- Bug bounty program: $50–$500 for responsible disclosure ([details](https://hifriendbot.com/wallet))

## Links

- **Website:** [hifriendbot.com/wallet](https://hifriendbot.com/wallet)
- **npm:** [agentwallet-mcp](https://www.npmjs.com/package/agentwallet-mcp)
- **Security:** [security@hifriendbot.com](mailto:security@hifriendbot.com)

## License

MIT
