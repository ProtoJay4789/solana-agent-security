# Program Verification

Verify Solana programs for security before integration.

## Quick Check

```bash
# Verify a program by address
node src/cli.js verify-program <PROGRAM_ADDRESS>

# Deep audit with source code analysis
node src/cli.js audit-program <PROGRAM_ADDRESS> --deep
```

## What We Check

### 1. Source Code Verification
- **Open source?** Is the program source publicly available?
- **Build reproducibility** — Can you rebuild from source and get the same binary?
- **IDL match** — Does the IDL match the deployed program?

### 2. Authority Analysis
```rust
// Check these authority patterns:
admin: Pubkey          // Who can upgrade?
upgrade_authority: Pubkey  // Can the program be changed post-deploy?
close_authority: Option<Pubkey>  // Can the program be closed?
```

**Red flags:**
- Single admin key (centralization risk)
- Admin is a PDA with weak seeds
- No timelock on admin operations

### 3. Vulnerability Patterns

| Pattern | Severity | Description |
|---------|----------|-------------|
| Reentrancy | Critical | CPI back to caller before state update |
| Integer overflow | Critical | Unchecked math on amounts |
| Missing signer check | Critical | Operations without required signatures |
| Privilege escalation | High | User can access admin functions |
| Oracle manipulation | High | Price feed can be manipulated |
| Flash loan attack | High | Atomic arbitrage possible |
| PDA seed collision | Medium | Two users derive same PDA |
| Close account drain | Medium | Rent sent to wrong destination |
| Unchecked CPI | Medium | CPI results not validated |

### 4. Known Vulnerability Scan
Cross-reference program against:
- **Trail of Bits findings** — Known Solana vulnerability patterns
- **Neodyme audit reports** — Common DeFi vulnerabilities
- **Ackee blockchain audits** — Anchor-specific issues
- **Sec3 findings** — Solana-specific attack vectors

### 5. Upgrade Safety
```
Is program upgradeable?
    ├── YES → Check upgrade authority
    │   ├── Multisig → SAFER
    │   ├── Timelock → SAFEST
    │   └── Single key → RISK
    └── NO → Immutable (safest)
```

## Scoring

| Factor | Weight |
|--------|--------|
| Source available | 20% |
| Authority decentralized | 20% |
| No known vulnerabilities | 25% |
| Upgrade safety | 15% |
| Audit history | 10% |
| Community trust | 10% |

## Integration with Security Checklist

Use the [security checklist](security-checklist.md) for comprehensive program evaluation.
