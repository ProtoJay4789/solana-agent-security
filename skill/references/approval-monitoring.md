# Approval Monitoring

Monitor and manage token approvals to prevent drain attacks.

## Quick Check

```bash
# Check all approvals for a wallet
node src/cli.js check-approvals <WALLET_ADDRESS>

# Revoke a specific approval
node src/cli.js revoke-approval --mint <MINT> --wallet <WALLET>
```

## How Approvals Work on Solana

### SPL Token Approvals
```
User → Approves Program X to spend Token Y → Program X can transfer Token Y
```

### Token-2022 Delegated Transfers
Token-2022 introduces transfer hooks and CPI guards that can be exploited:
- **Transfer Hook:** Executes arbitrary code on every transfer
- **CPI Guard:** Forces certain operations through specific programs
- **Permanent Delegate:** Allows a delegate to transfer tokens without approval

## Dangerous Approval Patterns

### 1. Unlimited Approval
```
Approve {
    amount: u64::MAX,  // ⚠️ NEVER do this to unknown programs
    delegate: unknown_program
}
```
**Risk:** Program can drain all tokens at any time
**Fix:** Revoke immediately: `RevokeAuthority { mint, authority }`

### 2. Approval to Unknown Program
```
Approve {
    amount: specific_amount,
    delegate: program_not_in_known_registry
}
```
**Risk:** Unknown program could be malicious
**Fix:** Verify program source code before approving

### 3. Approval Chaining
```
User → Approve A → A approves B → B approves C → C drains
```
**Risk:** Indirect approval chain hides the real drain vector
**Fix:** Check all downstream approvals from approved programs

### 4. Token-2022 Permanent Delegate
```
InitializePermanentDelegate {
    delegate: deployer_wallet  // ⚠️ Can transfer tokens without approval
}
```
**Risk:** Deployer can steal tokens at any time
**Fix:** Avoid tokens with permanent delegate extension

## Monitoring Commands

```bash
# List all active approvals
solana-security approvals --wallet <ADDRESS> --format table

# Check for high-risk approvals
solana-security approvals --wallet <ADDRESS> --risk high

# Auto-revoke approvals older than 30 days
solana-security revoke-old --wallet <ADDRESS> --days 30
```

## Best Practices

1. **Revoke after use** — Don't leave approvals active
2. **Set specific amounts** — Never approve u64::MAX
3. **Whitelist programs** — Only approve known, verified programs
4. **Regular audits** — Check approvals weekly
5. **Revoke before selling** — If selling a token, revoke approvals first
