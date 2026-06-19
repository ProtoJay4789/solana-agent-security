# Token Safety Analysis

Check any Solana token for scam indicators before trading or integrating.

## Quick Check

```bash
# Check a token mint address
node src/cli.js check-token <MINT_ADDRESS>
```

## What We Check

### 1. Honeypot Detection
- **Sell blocking** — Can you actually sell? Some tokens allow buys but block sells
- **Transfer hooks** — Malicious transfer hooks that freeze or steal tokens
- **Authority flags** — Freeze authority, mint authority, close authority active
- **Tax analysis** — Buy/sell taxes above 10% are red flags

### 2. Liquidity Analysis
- **LP lock status** — Is liquidity actually locked? Where? For how long?
- **LP age** — Newly added liquidity (< 24h) is higher risk
- **LP concentration** — Single-wallet LP = rug risk
- **Rug history** — Has this deployer rugged before?

### 3. Token Authority Checks
```rust
// Check these fields in Token-2022 or SPL Token account:
mintAuthority     // Should be None for fixed supply
freezeAuthority   // Should be None for safe tokens
closeAuthority    // Should be None
transferHook      // Should be None or known program
```

### 4. Deployer Analysis
- **Deployer wallet age** — New wallets deploying tokens = suspicious
- **Deployer history** — Previous rugged tokens?
- **Bundle analysis** — Was this launched via bundle (MEV)?

### 5. Social Signals
- **Website** — Does it exist? Is it a copy-paste?
- **Twitter** — Real followers or bots?
- **Telegram** — Active community or dead?
- **GitHub** — Any actual code?

## Risk Scoring

| Factor | Weight | Critical Threshold |
|--------|--------|-------------------|
| Honeypot indicators | 30% | Any sell blocking |
| Authority flags | 25% | Freeze/mint authority active |
| Liquidity risk | 20% | Unlocked LP |
| Deployer reputation | 15% | Previous rugs |
| Social presence | 10% | No website/socials |

## Red Flags Summary

- [ ] Freeze authority active
- [ ] Mint authority active (fixed supply expected)
- [ ] Transfer hook enabled
- [ ] LP not locked or locked < 30 days
- [ ] Deployer has rugged before
- [ ] No website or socials
- [ ] Buy tax > 10% or sell tax > 10%
- [ ] Contract is upgradeable proxy
- [ ] Blacklist/pause functions present

## Integration with Agent Rug 2.0

This skill extends the Agent Rug 2.0 Transaction Firewall with Solana-specific patterns:
- SPL Token authority analysis
- Token-2022 extension detection
- PumpFun launch analysis
- Raydium/Orca LP verification
