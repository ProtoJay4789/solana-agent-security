#!/usr/bin/env node
/**
 * Solana Agent Security — CLI
 * 
 * Quick security checks for Solana tokens, transactions, and agents.
 * 
 * Usage:
 *   node cli.js check-token <MINT_ADDRESS>
 *   node cli.js check-tx <TX_SIGNATURE>
 *   node cli.js check-approvals <WALLET_ADDRESS>
 *   node cli.js verify-program <PROGRAM_ADDRESS>
 *   node cli.js audit-agent --wallet <AGENT_WALLET> --days 7
 *   node cli.js scan --wallet <WALLET>
 */

const { SecurityEngine } = require('./engine');

const args = process.argv.slice(2);
const command = args[0];

function printResult(result) {
  const colors = {
    critical: '\x1b[31m',  // red
    high: '\x1b[33m',      // yellow
    medium: '\x1b[36m',    // cyan
    low: '\x1b[37m',       // white
    safe: '\x1b[32m',      // green
    reset: '\x1b[0m'
  };

  const color = colors[result.risk] || colors.safe;
  
  console.log(`\n${color}═══ Security Analysis ═══${colors.reset}`);
  console.log(`Risk: ${color}${result.risk.toUpperCase()}${colors.reset} (Score: ${result.score}/100)`);
  
  if (result.findings && result.findings.length > 0) {
    console.log(`\nFindings (${result.findings.length}):`);
    for (const f of result.findings) {
      const sev = colors[f.severity] || colors.safe;
      console.log(`  ${sev}[${f.severity.toUpperCase()}]${colors.reset} ${f.name}`);
      console.log(`    ${f.detail}`);
    }
  } else {
    console.log('\nNo issues found.');
  }
  
  if (result.recommendations) {
    console.log('\nRecommendations:');
    for (const r of result.recommendations) {
      console.log(`  → ${r}`);
    }
  }
  
  console.log('');
}

async function main() {
  const engine = new SecurityEngine();

  switch (command) {
    case 'check-token': {
      const mint = args[1];
      if (!mint) { console.error('Usage: check-token <MINT_ADDRESS>'); process.exit(1); }
      console.log(`Checking token: ${mint}...`);
      const result = await engine.checkToken(mint);
      printResult(result);
      break;
    }

    case 'check-tx': {
      const sig = args[1];
      if (!sig) { console.error('Usage: check-tx <TX_SIGNATURE>'); process.exit(1); }
      console.log(`Analyzing transaction: ${sig}...`);
      const result = await engine.checkTransaction(sig);
      printResult(result);
      break;
    }

    case 'check-approvals': {
      const wallet = args[1];
      if (!wallet) { console.error('Usage: check-approvals <WALLET_ADDRESS>'); process.exit(1); }
      console.log(`Checking approvals for: ${wallet}...`);
      const result = await engine.checkApprovals(wallet);
      printResult(result);
      break;
    }

    case 'verify-program': {
      const program = args[1];
      if (!program) { console.error('Usage: verify-program <PROGRAM_ADDRESS>'); process.exit(1); }
      console.log(`Verifying program: ${program}...`);
      const result = await engine.verifyProgram(program);
      printResult(result);
      break;
    }

    case 'audit-agent': {
      const walletIdx = args.indexOf('--wallet');
      const daysIdx = args.indexOf('--days');
      const wallet = walletIdx >= 0 ? args[walletIdx + 1] : null;
      const days = daysIdx >= 0 ? parseInt(args[daysIdx + 1]) : 7;
      if (!wallet) { console.error('Usage: audit-agent --wallet <WALLET> [--days 7]'); process.exit(1); }
      console.log(`Auditing agent: ${wallet} (last ${days} days)...`);
      const result = await engine.auditAgent(wallet, days);
      printResult(result);
      break;
    }

    case 'scan': {
      const walletIdx = args.indexOf('--wallet');
      const wallet = walletIdx >= 0 ? args[walletIdx + 1] : null;
      if (!wallet) { console.error('Usage: scan --wallet <WALLET>'); process.exit(1); }
      console.log(`Full security scan for: ${wallet}...`);
      const result = await engine.fullScan(wallet);
      printResult(result);
      break;
    }

    default:
      console.log(`
Solana Agent Security — CLI

Commands:
  check-token <MINT>         Check token for scam indicators
  check-tx <SIGNATURE>       Analyze transaction for drain patterns
  check-approvals <WALLET>   Check wallet approvals
  verify-program <PROGRAM>   Verify program security
  audit-agent --wallet <W>   Audit agent behavior
  scan --wallet <WALLET>     Full security scan

Examples:
  node cli.js check-token So11111111111111111111111111111111111111112
  node cli.js check-tx 5KJt1b1n8Qz...
  node cli.js scan --wallet ABC123...
      `);
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
