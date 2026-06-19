---
name: solana-agent-security
description: Protect agents and users from malicious transactions, drain patterns, and scam tokens on Solana. Use when the user says "check token safety", "is this token a scam", "analyze this transaction", "check approvals", "verify program", "audit agent", "drain detection", "honeypot check", "security check", or asks about transaction safety, approval risks, or agent behavior auditing.
user-invocable: true
---

# Solana Agent Security Skill

Protects agents and users from malicious transactions, drain patterns, and scam tokens on Solana.

**Read the relevant section for your task:**

## Quick Reference

| Task | File |
|------|------|
| Check a token for scams/honeypots | [references/token-safety.md](references/token-safety.md) |
| Analyze a transaction for drain patterns | [references/transaction-analysis.md](references/transaction-analysis.md) |
| Monitor wallet approvals | [references/approval-monitoring.md](references/approval-monitoring.md) |
| Verify a program/contract | [references/program-verification.md](references/program-verification.md) |
| Audit an AI agent's behavior | [references/agent-audit.md](references/agent-audit.md) |
| Full security checklist | [references/security-checklist.md](references/security-checklist.md) |

## Core Principles

1. **Never trust, always verify** — every transaction gets scanned before execution
2. **Fail safe** — if uncertain, block and warn (never silently allow)
3. **Pattern-based detection** — known attack patterns caught automatically
4. **Community intelligence** — threat database grows with usage

## When to Use This Skill

- Before executing any agent-initiated transaction
- When a user asks "is this token safe?"
- When integrating a new protocol or SDK
- When auditing agent behavior or permissions
- After detecting suspicious activity in a wallet

## Severity Levels

| Level | Score | Action |
|-------|-------|--------|
| **Critical** | 90-100 | BLOCK — never execute |
| **High** | 70-89 | WARN — require user confirmation |
| **Medium** | 40-69 | CAUTION — log and monitor |
| **Low** | 20-39 | INFO — note for awareness |
| **Safe** | 0-19 | ALLOW — no action needed |
