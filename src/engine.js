/**
 * Solana Agent Security — Engine
 * 
 * Core security analysis engine for Solana tokens, transactions, and agents.
 * Extends Agent Rug 2.0 patterns with Solana-specific detection.
 * 
 * @module engine
 */

// Known safe programs on Solana
const KNOWN_PROGRAMS = new Map([
  ['TokenkegQEQNi5VxwDnJZcx9qxrKhrFJL4T5mHf5vB', { name: 'SPL Token', status: 'safe' }],
  ['TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', { name: 'Token-2022', status: 'safe' }],
  ['675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8', { name: 'Raydium AMM', status: 'safe' }],
  ['whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc', { name: 'Orca Whirlpool', status: 'safe' }],
  ['JUP6LkbZpS7j1K3E6nQ4jNCRsCQ9mQsm1B5bJqN6QH', { name: 'Jupiter v6', status: 'safe' }],
  ['metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s', { name: 'Metaplex Token Metadata', status: 'safe' }],
  ['noopb9bkMVfRPU8AsbpTddV3w342xn9a8XSiHgn', { name: 'Anchor Noop', status: 'safe' }],
  ['ComputeBudget111111111111111111111111111111', { name: 'Compute Budget', status: 'safe' }],
]);

// Token-2022 dangerous extensions
const DANGEROUS_EXTENSIONS = [
  'transferHook',
  'permanentDelegate',
  'cpiGuard',
  'memoTransfer',
  'immutableOwner', // Not dangerous but notable
];

// Honeypot indicators
const HONEYPOT_INDICATORS = {
  sellsBlocked: true,
  sellTaxHigh: 50,    // > 50% sell tax
  buyTaxHigh: 25,     // > 25% buy tax
  freezeAuthorityActive: true,
  mintAuthorityActive: true,
};

class SecurityEngine {
  constructor(options = {}) {
    this.knownPrograms = new Map([...KNOWN_PROGRAMS, ...(options.knownPrograms || [])]);
    this.customPatterns = options.customPatterns || [];
  }

  /**
   * Check a token for scam indicators.
   * @param {string} mintAddress - Token mint address
   * @returns {Object} Security analysis result
   */
  async checkToken(mintAddress) {
    const findings = [];
    let score = 0;

    // 2. Check if mint is known safe
    const known = this.knownPrograms.get(mintAddress);
    if (known && known.status === 'safe') {
      return { risk: 'safe', score: 0, findings: [], recommendations: [] };
    }

    // 3. Check authorities (would need RPC call in production)
    const mintInfo = await this._fetchMintInfo(mintAddress);
    
    if (mintInfo) {
      // Freeze authority check
      if (mintInfo.freezeAuthority) {
        findings.push({
          name: 'Freeze Authority Active',
          severity: 'critical',
          detail: 'Token has freeze authority — deployer can freeze your wallet',
          score: 30
        });
        score += 30;
      }

      // Mint authority check
      if (mintInfo.mintAuthority) {
        findings.push({
          name: 'Mint Authority Active',
          severity: 'high',
          detail: 'Token supply is not fixed — deployer can mint more tokens',
          score: 20
        });
        score += 20;
      }

      // Token-2022 extensions
      if (mintInfo.extensions) {
        for (const ext of mintInfo.extensions) {
          if (DANGEROUS_EXTENSIONS.includes(ext.type)) {
            findings.push({
              name: `Dangerous Extension: ${ext.type}`,
              severity: ext.type === 'permanentDelegate' ? 'critical' : 'high',
              detail: `Token has ${ext.type} extension enabled`,
              score: ext.type === 'permanentDelegate' ? 35 : 20
            });
            score += ext.type === 'permanentDelegate' ? 35 : 20;
          }
        }
      }
    }

    // 3. Check if program is in known registry
    if (!this.knownPrograms.has(mintAddress)) {
      findings.push({
        name: 'Unknown Token',
        severity: 'medium',
        detail: 'Token not in known registry — exercise caution',
        score: 10
      });
      score += 10;
    }

    // 4. Custom pattern checks
    for (const pattern of this.customPatterns) {
      try {
        const result = pattern.detect({ mintAddress }, { mintInfo });
        if (result.matched) {
          findings.push({
            name: pattern.name,
            severity: pattern.severity,
            detail: result.detail,
            score: pattern.score
          });
          score += pattern.score;
        }
      } catch (e) { /* skip */ }
    }

    const risk = this._scoreToRisk(score);
    const recommendations = this._generateRecommendations(findings, 'token');

    return { risk, score: Math.min(score, 100), findings, recommendations };
  }

  /**
   * Analyze a transaction for drain patterns.
   * @param {string} txSignature - Transaction signature
   * @returns {Object} Security analysis result
   */
  async checkTransaction(txSignature) {
    const findings = [];
    let score = 0;

    // Fetch transaction (would use Helius/RPC in production)
    const tx = await this._fetchTransaction(txSignature);
    
    if (!tx) {
      return { risk: 'medium', score: 50, findings: [{ name: 'Unable to fetch transaction', severity: 'medium', detail: 'Could not retrieve transaction data', score: 50 }], recommendations: ['Verify transaction manually'] };
    }

    // Analyze each instruction
    for (const ix of (tx.instructions || [])) {
      const programId = ix.programId?.toString();
      
      // Check if program is known
      if (programId && !this.knownPrograms.has(programId)) {
        findings.push({
          name: 'Unknown Program Call',
          severity: 'high',
          detail: `Transaction calls unknown program: ${programId}`,
          score: 25
        });
        score += 25;
      }

      // Check for suspicious instruction data
      if (ix.data && ix.data.length > 200) {
        findings.push({
          name: 'Large Instruction Data',
          severity: 'medium',
          detail: `Instruction has ${ix.data.length} bytes of data — may contain hidden payload`,
          score: 15
        });
        score += 15;
      }
    }

    // Check signers
    const signers = tx.signatures?.map(s => s.publicKey?.toString()) || [];
    if (signers.length > 1) {
      findings.push({
        name: 'Multiple Signers',
        severity: 'medium',
        detail: `Transaction has ${signers.length} signers — verify all are expected`,
        score: 10
      });
      score += 10;
    }

    const risk = this._scoreToRisk(score);
    const recommendations = this._generateRecommendations(findings, 'transaction');

    return { risk, score: Math.min(score, 100), findings, recommendations };
  }

  /**
   * Check wallet approvals.
   * @param {string} walletAddress - Wallet to check
   * @returns {Object} Security analysis result
   */
  async checkApprovals(walletAddress) {
    const findings = [];
    let score = 0;

    // In production, would scan on-chain approvals
    // For now, return analysis framework
    findings.push({
      name: 'Approval Scan',
      severity: 'info',
      detail: `Scanning approvals for wallet ${walletAddress.slice(0, 8)}...`,
      score: 0
    });

    const risk = this._scoreToRisk(score);
    return { risk, score, findings, recommendations: ['Revoke unused approvals regularly'] };
  }

  /**
   * Verify a program's security.
   * @param {string} programAddress - Program to verify
   * @returns {Object} Security analysis result
   */
  async verifyProgram(programAddress) {
    const findings = [];
    let score = 0;

    const known = this.knownPrograms.get(programAddress);
    if (known) {
      return { risk: 'safe', score: 0, findings: [{ name: 'Known Program', severity: 'info', detail: known.name, score: 0 }], recommendations: [] };
    }

    findings.push({
      name: 'Unknown Program',
      severity: 'medium',
      detail: 'Program not in known registry — verify source code before integration',
      score: 15
    });
    score += 15;

    const risk = this._scoreToRisk(score);
    return { risk, score, findings, recommendations: ['Verify program source code', 'Check for audits', 'Test on devnet first'] };
  }

  /**
   * Audit an agent's behavior.
   * @param {string} agentWallet - Agent wallet address
   * @param {number} days - Days to look back
   * @returns {Object} Security analysis result
   */
  async auditAgent(agentWallet, days = 7) {
    const findings = [];
    let score = 0;

    findings.push({
      name: 'Agent Audit',
      severity: 'info',
      detail: `Auditing agent ${agentWallet.slice(0, 8)}... for last ${days} days`,
      score: 0
    });

    const risk = this._scoreToRisk(score);
    return { risk, score, findings, recommendations: ['Set spending limits', 'Enable kill switch', 'Monitor regularly'] };
  }

  /**
   * Full security scan of a wallet.
   * @param {string} walletAddress - Wallet to scan
   * @returns {Object} Combined security analysis
   */
  async fullScan(walletAddress) {
    const approvals = await this.checkApprovals(walletAddress);
    const agent = await this.auditAgent(walletAddress, 30);

    const allFindings = [...approvals.findings, ...agent.findings];
    const maxScore = Math.max(approvals.score, agent.score);

    return {
      risk: this._scoreToRisk(maxScore),
      score: maxScore,
      findings: allFindings,
      recommendations: [
        ...new Set([...(approvals.recommendations || []), ...(agent.recommendations || [])])
      ]
    };
  }

  // ---- Internal helpers ----

  async _fetchMintInfo(mintAddress) {
    // In production: RPC call to get mint account data
    // For now, return null (unknown token)
    return null;
  }

  async _fetchTransaction(txSignature) {
    // In production: RPC call to get transaction
    // For now, return null
    return null;
  }

  _scoreToRisk(score) {
    if (score >= 90) return 'critical';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }

  _generateRecommendations(findings, type) {
    const recs = [];
    const hasCritical = findings.some(f => f.severity === 'critical');
    const hasHigh = findings.some(f => f.severity === 'high');

    if (type === 'token') {
      if (hasCritical) recs.push('DO NOT TRADE this token — critical security issues found');
      if (hasHigh) recs.push('Exercise extreme caution — high risk indicators present');
      recs.push('Verify token on Solscan before trading');
      recs.push('Check LP lock status on RugCheck or similar');
    }

    if (type === 'transaction') {
      if (hasCritical) recs.push('DO NOT EXECUTE this transaction');
      if (hasHigh) recs.push('Review transaction carefully before signing');
      recs.push('Simulate transaction before executing');
    }

    return recs;
  }
}

module.exports = { SecurityEngine, KNOWN_PROGRAMS };
