# Agent Behavior Audit

Audit AI agent behavior for security, compliance, and trustworthiness.

## Quick Check

```bash
# Audit an agent's recent transactions
node src/cli.js audit-agent --wallet <AGENT_WALLET> --days 7

# Check agent reputation score
node src/cli.js agent-reputation <AGENT_WALLET>
```

## What We Audit

### 1. Transaction Pattern Analysis
- **Frequency** — Is the agent transacting at human rates or bot rates?
- **Amounts** — Are amounts consistent or erratic?
- **Recipients** — Is the agent sending to known contracts or unknown wallets?
- **Timing** — Does the agent transact during unusual hours?

### 2. Permission Analysis
```
Agent Permissions Checklist:
├── Token spending limits
│   ├── Per-transaction limit
│   ├── Daily limit
│   └── Total exposure limit
├── Approved programs
│   ├── Only known protocols?
│   └── No unknown programs?
├── Wallet access
│   ├── Read-only vs write access
│   └── Which keys does the agent hold?
└── Emergency controls
    ├── Kill switch available?
    ├── Can user revoke access?
    └── Timeout on agent actions?
```

### 3. Behavior Consistency
- **Claimed strategy vs actual** — Does the agent follow its stated strategy?
- **Risk parameters** — Does it stay within declared risk limits?
- **Loss handling** — How does it behave after losses? (Chase? Stop? Adjust?)

### 4. External Call Analysis
- **API calls** — What external services does the agent call?
- **Data sources** — Are price feeds reliable? (Pyth, Switchboard, Jupiter)
- **Communication** — Does the agent talk to other agents? (Trust chain?)

## Agent Trust Score

| Factor | Weight | What We Check |
|--------|--------|---------------|
| Transaction consistency | 25% | Follows stated strategy |
| Permission scope | 25% | Minimal necessary permissions |
| Loss behavior | 20% | Doesn't chase losses |
| External calls | 15% | Uses reliable oracles |
| Emergency controls | 15% | Kill switch, revocation |

## Red Flags

- [ ] Agent transacts to unknown wallets
- [ ] Agent approves unknown programs
- [ ] Agent exceeds declared risk limits
- [ ] Agent has no kill switch
- [ ] Agent uses unreliable price feeds
- [ ] Agent transacts at inhuman frequency
- [ ] Agent behavior diverges from stated strategy
- [ ] Agent communicates with unverified external agents

## AAE Integration

This audit integrates with the AAE (Agent Agency Economy) standard:
- **Identity verification** — Agent has ERC-8004 identity
- **Reputation tracking** — On-chain reputation score
- **Enforcement** — Automated rule enforcement
- **Audit trail** — Complete transaction history
