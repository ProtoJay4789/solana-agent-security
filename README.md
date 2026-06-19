# Solana Agent Security Skill

**Protects agents and users from malicious transactions, drain patterns, and scam tokens on Solana.**

Built for the [Solana AI Kit](https://github.com/solanabr/solana-ai-kit) by Superteam Brasil.

## What It Does

| Feature | Description |
|---------|-------------|
| **Token Safety** | Detect honeypots, freeze authority, dangerous extensions, rug risk |
| **Transaction Analysis** | Identify drain patterns, hidden instructions, MEV bundles |
| **Approval Monitoring** | Track and revoke dangerous token approvals |
| **Program Verification** | Check programs for known vulnerabilities |
| **Agent Auditing** | Audit AI agent behavior and permissions |
| **Security Checklist** | Pre-integration security checklist for any Solana project |

## Installation

```bash
# As part of Solana AI Kit (recommended)
curl -fsSL https://aikit.superteam.codes | bash

# Or install this skill directly
git clone https://github.com/ProtoJay4789/solana-agent-security.git
cd solana-agent-security
npm install
```

## Quick Start

```bash
# Check a token
node src/cli.js check-token So11111111111111111111111111111111111111112

# Analyze a transaction
node src/cli.js check-tx 5KJt1b1n8Qz...

# Full wallet scan
node src/cli.js scan --wallet ABC123...
```

## Skill Structure

```
solana-security-skill/
├── skill/
│   ├── SKILL.md                    # Main skill hub — routes to references
│   └── references/
│       ├── token-safety.md         # Token scam detection
│       ├── transaction-analysis.md # Transaction drain patterns
│       ├── approval-monitoring.md  # Approval management
│       ├── program-verification.md # Program security checks
│       ├── agent-audit.md          # Agent behavior audit
│       └── security-checklist.md   # Pre-integration checklist
├── src/
│   ├── cli.js                      # CLI interface
│   └── engine.js                   # Security analysis engine
├── tests/
│   └── security.test.js            # Test suite
├── README.md
├── LICENSE                         # MIT
└── package.json
```

## Demo

### Quick Token Check
```bash
# Check if a token is safe
$ node src/cli.js check-token So11111111111111111111111111111111111111112

═══ Security Analysis ═══
Risk: SAFE (Score: 0/100)
No issues found.
```

### Unknown Token Detection
```bash
$ node src/cli.js check-token UnknownTokenMint111111111111111111111111111

═══ Security Analysis ═══
Risk: SAFE (Score: 10/100)

Findings (1):
  [MEDIUM] Unknown Token
    Token not in known registry — exercise caution

Recommendations:
  → Verify token on Solscan before trading
  → Check LP lock status on RugCheck or similar
```

### Program Verification
```bash
$ node src/cli.js verify-program whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc

═══ Security Analysis ═══
Risk: SAFE (Score: 0/100)

Findings (1):
  [INFO] Known Program
    Orca Whirlpool
```

### Full Wallet Scan
```bash
$ node src/cli.js scan --wallet ABC123...

═══ Security Analysis ═══
Risk: LOW (Score: 15/100)

Findings (2):
  [INFO] Approval Scan
    Scanning approvals for wallet ABC123... (7 days)
  [INFO] Agent Audit
    Auditing agent ABC123... for last 30 days

Recommendations:
  → Revoke unused approvals regularly
  → Set spending limits
  → Enable kill switch
  → Monitor regularly
```

### Test Suite
```bash
$ npm test

Tests: 16 passed, 16 total

SecurityEngine
  ✓ returns safe for known SPL Token program
  ✓ returns safe for Token-2022
  ✓ flags unknown token
  ✓ findings have required fields
  ✓ handles missing transaction gracefully
  ✓ returns safe for known Orca program
  ✓ flags unknown program
  ✓ returns safe for Jupiter
  ✓ returns analysis for any wallet
  ✓ combines approvals and agent audit
  ✓ contains SPL Token
  ✓ contains Jupiter
  ✓ contains Raydium
  ✓ all entries have name and status
  ✓ custom pattern is executed
  ✓ custom pattern failure does not break engine
```

## Why This Skill?

### The Problem
Solana has no unified security layer for AI agents. Every agent independently checks tokens, approvals, and transactions — or worse, doesn't check at all. This leads to:
- Agents executing drain transactions
- Users losing funds to honeypots
- No standard for agent behavior auditing

### The Solution
A single, production-grade security skill that:
- **Catches known attack patterns** automatically
- **Works out of the box** — no API keys for basic checks
- **Extends Agent Rug 2.0** patterns to Solana
- **Integrates with the Solana AI Kit** seamlessly

### What Makes It Different
1. **Solana-native** — Understands SPL Token, Token-2022, Anchor patterns
2. **Agent-focused** — Built specifically for AI agent security
3. **Pattern-based** — Catches known attacks, not just heuristics
4. **Production-ready** — Not a demo, not a toy

## Security Patterns Detected

| Pattern | Severity | Detection |
|---------|----------|-----------|
| Unlimited approval | Critical | Check approve instruction amounts |
| Freeze authority | Critical | Check mint account freeze authority |
| Permanent delegate | Critical | Token-2022 extension detection |
| Unknown program call | High | Cross-reference with known registry |
| Large instruction data | Medium | Check instruction byte length |
| Multiple signers | Medium | Analyze transaction signers |
| Honeypot token | Critical | Check sell ability and tax rates |
| MEV sandwich | High | Analyze slot-level transaction ordering |

## Testing

```bash
npm test
```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add tests for new patterns
4. Submit a PR

## License

MIT — Ready to be merged/submoduled into the Solana AI Kit.

## Acknowledgments

- [Agent Rug 2.0](https://github.com/ProtoJay4789/genTech-agent-kit) — Original drain pattern research
- [Solana AI Kit](https://github.com/solanabr/solana-ai-kit) — Skill framework
- [Superteam Brasil](https://superteam.fun) — Bounty sponsor
- [Trail of Bits](https://trailofbits.com) — Security research
- [Neodyme](https://neodyme.io) — Solana audit patterns
