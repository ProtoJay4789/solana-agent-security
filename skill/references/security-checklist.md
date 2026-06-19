# Security Checklist

Comprehensive security checklist for Solana projects, agents, and integrations.

## Pre-Integration Checklist

Before integrating ANY new protocol, token, or agent:

### Token Safety
- [ ] Token mint has no freeze authority
- [ ] Token mint has no mint authority (fixed supply)
- [ ] No transfer hooks enabled (or hooks are from known program)
- [ ] LP is locked (and lock duration > 30 days)
- [ ] Token has been live > 24 hours
- [ ] Deployer wallet is not brand new
- [ ] Social presence exists (website, Twitter, Telegram)
- [ ] No honeypot indicators (can sell freely)

### Program Safety
- [ ] Program source code is publicly available
- [ ] Program has been audited (or is from known team)
- [ ] Program is not upgradeable (or upgrade authority is multisig/timelock)
- [ ] No known vulnerabilities in program
- [ ] Program ID matches source code build
- [ ] IDL is available and matches deployed program

### Agent Safety
- [ ] Agent has kill switch
- [ ] Agent has spending limits (per-transaction and daily)
- [ ] Agent only approves known programs
- [ ] Agent uses reliable price feeds (Pyth, Switchboard, Jupiter)
- [ ] Agent behavior matches stated strategy
- [ ] User can revoke agent access at any time
- [ ] Agent has timeout on actions
- [ ] Agent does not communicate with unverified external agents

### Transaction Safety
- [ ] Transaction simulates successfully before execution
- [ ] No unknown instruction data
- [ ] All signers are expected
- [ ] CPI calls are to known programs
- [ ] No reentrancy patterns
- [ ] Amounts are within expected ranges

## Emergency Response

If you detect a security issue:

### Immediate Actions
1. **Stop** — Do not execute any more transactions
2. **Revoke** — Revoke all approvals for the affected program/token
3. **Transfer** — Move assets to a fresh wallet if compromised
4. **Report** — Report the issue to the community

### Recovery Steps
1. Generate new wallet
2. Transfer any remaining assets
3. Revoke all old approvals
4. Document the incident
5. Share findings with security community

## Quick Reference Commands

```bash
# Full security scan
solana-security scan --wallet <WALLET>

# Token check
solana-security check-token <MINT>

# Transaction analysis
solana-security check-tx <TX_SIG>

# Approval audit
solana-security check-approvals <WALLET>

# Agent reputation
solana-security agent-reputation <AGENT_WALLET>
```
