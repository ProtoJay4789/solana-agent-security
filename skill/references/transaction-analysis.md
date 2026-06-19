# Transaction Analysis

Analyze Solana transactions for drain patterns before execution.

## Quick Check

```bash
# Analyze a transaction signature
node src/cli.js check-tx <TX_SIGNATURE>

# Analyze a simulated transaction
node src/cli.js simulate --to <RECIPIENT> --amount <LAMPORTS> --data <BASE64>
```

## Drain Patterns We Detect

### 1. Approval Abuse (Critical)
**Pattern:** Transaction requests unlimited token approval to unknown program
```
TokenInstruction::Approve {
    amount: u64::MAX,  // Unlimited approval
    to: unknown_program
}
```
**Detection:** Check for `approve` instructions with max uint64 to non-whitelisted programs
**Action:** BLOCK immediately

### 2. Hidden Instruction Data (Critical)
**Pattern:** Transaction contains opaque instruction data to unknown program
```
TransactionInstruction {
    program_id: suspicious_program,
    data: [0x41, 0x42, ...]  // Encoded malicious payload
}
```
**Detection:** Flag instructions to programs not in known registry with non-standard selectors
**Action:** WARN — require manual review

### 3. PDA Drain (High)
**Pattern:** Transaction derives PDA that controls user assets
```
PDA::find_program_address(
    &[b"authority", user_wallet.key()],
    suspicious_program
)
// PDA then signs for transfer
```
**Detection:** Look for create_account with PDA seeds that match user wallet
**Action:** WARN — verify program is known

### 4. Bundle Sandwich (High)
**Pattern:** Transaction is part of a MEV bundle
- Front-run: Large buy before user's swap
- User's swap at worse price
- Back-run: Large sell after
**Detection:** Check for matching transactions in same slot with opposing directions
**Action:** INFO — alert user to potential MEV

### 5. Token Freeze (Critical)
**Pattern:** Transaction interacts with token that has active freeze authority
```
// After user buys, deployer freezes their account
TokenInstruction::FreezeAccount {
    account: user_wallet,
    mint: suspicious_token
}
```
**Detection:** Check freeze authority before execution
**Action:** BLOCK if freeze authority is active

### 6. Close Account Drain (High)
**Pattern:** Transaction closes token account, sending rent to attacker
```
TokenInstruction::CloseAccount {
    destination: attacker_wallet  // Steals rent-exempt lamports
}
```
**Detection:** Check close account destination is user's own wallet
**Action:** WARN if destination is unknown

### 7. CPI Reentrancy (High)
**Pattern:** Cross-program invocation creates reentrancy vulnerability
```
Program A calls Program B
Program B calls Program A (reentrancy)
Before A finishes, B drains funds
```
**Detection:** Analyze CPI depth and circular calls
**Action:** WARN — flag for manual audit

### 8. Memo Spam (Medium)
**Pattern:** Transaction includes large memo data (potential attack vector)
```
MemoInstruction {
    data: [very long data]  // Could contain malicious payloads
}
```
**Detection:** Flag transactions with memo data > 1KB
**Action:** INFO — note for awareness

## Simulation Flow

```
Transaction
    ↓
Decode Instructions
    ↓
Map to Known Programs (Jupiter, Raydium, Orca, etc.)
    ↓
For each instruction:
    ├── Known + Safe → ALLOW
    ├── Known + Suspicious → WARN
    └── Unknown → FLAG for review
    ↓
Check Signers
    ├── Only user → OK
    └── Multiple signers → VERIFY all are expected
    ↓
Risk Score → Decision
```

## Known Program Registry

| Program | Status | Notes |
|---------|--------|-------|
| TokenkegQEQ... | Safe | SPL Token Program |
| TokenzQd... | Safe | Token-2022 |
| 675kPX... | Safe | Raydium AMM |
| whirLbMiic... | Safe | Orca Whirlpools |
| JUP6LkbZp... | Safe | Jupiter v6 |
| PumpFun... | Caution | High-risk launches |
| Unknown | FLAG | Require manual review |
