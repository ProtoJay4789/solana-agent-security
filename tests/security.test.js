/**
 * Solana Agent Security — Tests
 * 
 * Tests token safety, transaction analysis, approval monitoring, and engine.
 */

const { SecurityEngine, KNOWN_PROGRAMS } = require('../src/engine');

describe('SecurityEngine', () => {
  let engine;

  beforeEach(() => {
    engine = new SecurityEngine();
  });

  describe('checkToken', () => {
    test('returns safe for known SPL Token program', async () => {
      const result = await engine.checkToken('TokenkegQEQNi5VxwDnJZcx9qxrKhrFJL4T5mHf5vB');
      expect(result.risk).toBe('safe');
      expect(result.score).toBe(0);
    });

    test('returns safe for Token-2022', async () => {
      const result = await engine.checkToken('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
      expect(result.risk).toBe('safe');
    });

    test('flags unknown token', async () => {
      const result = await engine.checkToken('UnknownTokenMint111111111111111111111111111');
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some(f => f.name === 'Unknown Token')).toBe(true);
      expect(result.score).toBeGreaterThan(0);
    });

    test('findings have required fields', async () => {
      const result = await engine.checkToken('UnknownTokenMint111111111111111111111111111');
      for (const f of result.findings) {
        expect(f.name).toBeDefined();
        expect(f.severity).toBeDefined();
        expect(f.detail).toBeDefined();
      }
    });
  });

  describe('checkTransaction', () => {
    test('handles missing transaction gracefully', async () => {
      const result = await engine.checkTransaction('invalid_signature');
      expect(result.risk).toBeDefined();
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });

  describe('verifyProgram', () => {
    test('returns safe for known Orca program', async () => {
      const result = await engine.verifyProgram('whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc');
      expect(result.risk).toBe('safe');
      expect(result.findings[0].detail).toBe('Orca Whirlpool');
    });

    test('flags unknown program', async () => {
      const result = await engine.verifyProgram('UnknownProgram1111111111111111111111111111');
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some(f => f.name === 'Unknown Program')).toBe(true);
      expect(result.score).toBeGreaterThan(0);
    });

    test('returns safe for Jupiter', async () => {
      const result = await engine.verifyProgram('JUP6LkbZpS7j1K3E6nQ4jNCRsCQ9mQsm1B5bJqN6QH');
      expect(result.risk).toBe('safe');
    });
  });

  describe('auditAgent', () => {
    test('returns analysis for any wallet', async () => {
      const result = await engine.auditAgent('SomeWallet11111111111111111111111111111111', 7);
      expect(result.risk).toBeDefined();
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });

  describe('fullScan', () => {
    test('combines approvals and agent audit', async () => {
      const result = await engine.fullScan('SomeWallet11111111111111111111111111111111');
      expect(result.risk).toBeDefined();
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.recommendations.length).toBeGreaterThan(0);
    });
  });

  describe('KNOWN_PROGRAMS', () => {
    test('contains SPL Token', () => {
      expect(KNOWN_PROGRAMS.has('TokenkegQEQNi5VxwDnJZcx9qxrKhrFJL4T5mHf5vB')).toBe(true);
    });

    test('contains Jupiter', () => {
      expect(KNOWN_PROGRAMS.has('JUP6LkbZpS7j1K3E6nQ4jNCRsCQ9mQsm1B5bJqN6QH')).toBe(true);
    });

    test('contains Raydium', () => {
      expect(KNOWN_PROGRAMS.has('675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8')).toBe(true);
    });

    test('all entries have name and status', () => {
      for (const [addr, info] of KNOWN_PROGRAMS) {
        expect(info.name).toBeDefined();
        expect(info.status).toBeDefined();
      }
    });
  });

  describe('Custom Patterns', () => {
    test('custom pattern is executed', async () => {
      let patternRan = false;
      const engine = new SecurityEngine({
        customPatterns: [{
          name: 'Custom Check',
          severity: 'medium',
          score: 10,
          detect: () => { patternRan = true; return { matched: true, detail: 'test' }; }
        }]
      });
      await engine.checkToken('unknown');
      expect(patternRan).toBe(true);
    });

    test('custom pattern failure does not break engine', async () => {
      const engine = new SecurityEngine({
        customPatterns: [{
          name: 'Broken Pattern',
          severity: 'high',
          score: 50,
          detect: () => { throw new Error('broken'); }
        }]
      });
      const result = await engine.checkToken('unknown');
      expect(result.risk).toBeDefined(); // Should not throw
    });
  });
});

console.log('All Solana Agent Security tests defined.');
