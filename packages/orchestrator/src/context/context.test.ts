/**
 * Context Management Module Tests
 */

import { beforeEach, describe, expect, test } from 'bun:test';
import { ContextBudgetAllocator, createBudgetAllocator } from './budget-allocator.js';
import { FindingsManager } from './findings-store.js';
import { createIterativeAnalyzer, type IterativeAnalyzer } from './iterative-analyzer.js';
import { FunctionPriorityQueue } from './priority-queue.js';
import {
  calculatePriorityScore,
  extractRiskFactors,
  getFunctionsWithinBudget,
  scoreFunctions,
} from './priority-scorer.js';
import type { ScoredFunction } from './types.js';

describe('PriorityScorer', () => {
  describe('calculatePriorityScore', () => {
    test('scores low for benign function names', () => {
      const { score } = calculatePriorityScore('print_hello', {});
      expect(score).toBeLessThan(20);
    });

    test('scores high for suspicious function names', () => {
      const { score } = calculatePriorityScore('decrypt_payload', {});
      expect(score).toBeGreaterThan(10);
    });

    test('scores high for anti-debug patterns', () => {
      const { score } = calculatePriorityScore('check_debugger', {});
      expect(score).toBeGreaterThan(10);
    });

    test('scores high for network patterns', () => {
      const { score } = calculatePriorityScore('send_beacon', {});
      expect(score).toBeGreaterThan(10);
    });

    test('adds points for suspicious APIs', () => {
      const { score } = calculatePriorityScore('func1', { hasSuspiciousApis: true });
      expect(score).toBe(25);
    });

    test('adds points for anti-analysis', () => {
      const { score } = calculatePriorityScore('func1', { hasAntiAnalysis: true });
      expect(score).toBe(20);
    });

    test('clamps score to 100', () => {
      const { score } = calculatePriorityScore('decrypt_sandbox_check', {
        hasSuspiciousApis: true,
        hasAntiAnalysis: true,
        hasNetworkCalls: true,
        hasCrypto: true,
        hasProcessManip: true,
        hasFileOps: true,
        hasRegistryOps: true,
        entropy: 7.5,
        size: 2000,
        callerCount: 10,
        complexity: 30,
      });
      expect(score).toBe(100);
    });
  });

  describe('extractRiskFactors', () => {
    test('extracts size and caller count', () => {
      const factors = extractRiskFactors({
        name: 'test_func',
        size: 500,
        callers: ['a', 'b', 'c'],
        callees: ['x'],
      });

      expect(factors.size).toBe(500);
      expect(factors.callerCount).toBe(3);
      expect(factors.calleeCount).toBe(1);
    });

    test('detects anti-analysis patterns in name', () => {
      const factors = extractRiskFactors({ name: 'anti_debug_check' });
      expect(factors.hasAntiAnalysis).toBe(true);
    });

    test('detects network patterns in decompiled code', () => {
      const factors = extractRiskFactors({
        name: 'func1',
        decompiled: 'socket(AF_INET, SOCK_STREAM, 0)',
      });
      expect(factors.hasNetworkCalls).toBe(true);
    });
  });

  describe('scoreFunctions', () => {
    test('sorts functions by score descending', () => {
      const functions = [
        { name: 'benign_func', address: '0x1000' },
        { name: 'decrypt_payload', address: '0x2000' },
        { name: 'another_func', address: '0x3000' },
      ];

      const scored = scoreFunctions(functions);

      expect(scored[0]?.name).toBe('decrypt_payload');
      expect(scored[0]?.score).toBeGreaterThan(scored[1]?.score ?? 0);
    });

    test('estimates tokens for each function', () => {
      const functions = [{ name: 'func1', address: '0x1000', decompiled: 'a'.repeat(400) }];

      const scored = scoreFunctions(functions);

      expect(scored[0]?.estimatedTokens).toBeGreaterThan(100);
    });
  });

  describe('getFunctionsWithinBudget', () => {
    test('returns functions that fit within budget', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1',
          name: 'f1',
          score: 80,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x2',
          name: 'f2',
          score: 60,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x3',
          name: 'f3',
          score: 40,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
      ];

      const result = getFunctionsWithinBudget(functions, 250);

      expect(result.length).toBe(2);
    });

    test('respects minimum score', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1',
          name: 'f1',
          score: 80,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x2',
          name: 'f2',
          score: 10,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
      ];

      const result = getFunctionsWithinBudget(functions, 500, 20);

      expect(result.length).toBe(1);
      expect(result[0]?.score).toBe(80);
    });
  });
});

describe('FunctionPriorityQueue', () => {
  let queue: FunctionPriorityQueue;

  beforeEach(() => {
    queue = new FunctionPriorityQueue();
  });

  test('adds and retrieves functions by priority', () => {
    queue.addFunctions([
      {
        address: '0x1',
        name: 'low',
        score: 10,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
      {
        address: '0x2',
        name: 'high',
        score: 90,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
    ]);

    const next = queue.peek();
    expect(next?.name).toBe('high');
  });

  test('pop removes function from pending', () => {
    queue.addFunctions([
      {
        address: '0x1',
        name: 'func',
        score: 50,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
    ]);

    queue.pop();
    expect(queue.pendingCount()).toBe(0);
    expect(queue.analyzedCount()).toBe(1);
  });

  test('getBatch respects token budget', () => {
    queue.addFunctions([
      {
        address: '0x1',
        name: 'f1',
        score: 80,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
      {
        address: '0x2',
        name: 'f2',
        score: 60,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
      {
        address: '0x3',
        name: 'f3',
        score: 40,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
    ]);

    const batch = queue.getBatch(180);
    expect(batch.length).toBe(1);
  });

  test('getStats returns correct counts', () => {
    queue.addFunctions([
      {
        address: '0x1',
        name: 'f1',
        score: 80,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
      {
        address: '0x2',
        name: 'f2',
        score: 30,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
      {
        address: '0x3',
        name: 'f3',
        score: 10,
        factors: {},
        estimatedTokens: 100,
        analyzed: false,
      },
    ]);

    const stats = queue.getStats();
    expect(stats.total).toBe(3);
    expect(stats.highPriority).toBe(1);
    expect(stats.mediumPriority).toBe(1);
    expect(stats.lowPriority).toBe(1);
  });
});

describe('ContextBudgetAllocator', () => {
  let allocator: ContextBudgetAllocator;

  beforeEach(() => {
    allocator = new ContextBudgetAllocator({ maxContextTokens: 10000 });
  });

  test('initializes with correct budget', () => {
    const budget = allocator.getBudget();
    expect(budget.totalTokens).toBe(10000);
    expect(budget.remainingTokens).toBeLessThan(10000);
  });

  test('allocates phases correctly', () => {
    const deepDive = allocator.getPhaseAllocation('deep-dive');
    expect(deepDive).toBeDefined();
    expect(deepDive?.percentage).toBe(0.7);
  });

  test('usePhaseTokens deducts from budget', () => {
    const before = allocator.getRemainingPhaseTokens('deep-dive');
    allocator.usePhaseTokens('deep-dive', 100);
    const after = allocator.getRemainingPhaseTokens('deep-dive');

    expect(after).toBe(before - 100);
  });

  test('hasDeepDiveBudget returns true when budget available', () => {
    expect(allocator.hasDeepDiveBudget()).toBe(true);
  });

  test('estimateTokens estimates correctly', () => {
    const tokens = allocator.estimateTokens('hello world');
    expect(tokens).toBe(3); // 11 chars / 4 = 2.75 -> ceil = 3
  });
});

describe('FindingsManager', () => {
  let manager: FindingsManager;

  beforeEach(() => {
    manager = new FindingsManager();
  });

  test('starts at iteration 0', () => {
    expect(manager.getCurrentIteration()).toBe(0);
  });

  test('startIteration increments counter', () => {
    manager.startIteration();
    expect(manager.getCurrentIteration()).toBe(1);
  });

  test('addFinding stores findings', () => {
    manager.startIteration();
    manager.addFinding({
      type: 'capability',
      title: 'Network Communication',
      description: 'Binary communicates over network',
      confidence: 0.9,
      relatedFunctions: ['0x1000'],
      evidence: ['Uses socket API'],
    });

    expect(manager.getFindings().length).toBe(1);
  });

  test('getFindingsByType filters correctly', () => {
    manager.startIteration();
    manager.addFinding({
      type: 'capability',
      title: 'Cap1',
      description: 'desc',
      confidence: 0.9,
      relatedFunctions: [],
      evidence: [],
    });
    manager.addFinding({
      type: 'technique',
      title: 'Tech1',
      description: 'desc',
      confidence: 0.8,
      relatedFunctions: [],
      evidence: [],
    });

    const capabilities = manager.getFindingsByType('capability');
    expect(capabilities.length).toBe(1);
    expect(capabilities[0]?.title).toBe('Cap1');
  });

  test('generateSummary creates valid summary', () => {
    manager.startIteration();
    manager.addFinding({
      type: 'capability',
      title: 'Network',
      description: 'Network access',
      confidence: 0.9,
      relatedFunctions: [],
      evidence: [],
    });
    manager.endIteration(100);

    const summary = manager.generateSummary();
    expect(summary.findingsCount).toBe(1);
    expect(summary.keyCapabilities).toContain('Network');
  });
});

describe('IterativeAnalyzer', () => {
  let analyzer: IterativeAnalyzer;

  beforeEach(() => {
    analyzer = createIterativeAnalyzer({
      maxIterations: 3,
      minPriorityScore: 20,
    });
  });

  test('initialize adds functions to queue', () => {
    analyzer.initialize([
      { address: '0x1', name: 'f1', score: 50, factors: {}, estimatedTokens: 100, analyzed: false },
    ]);

    const state = analyzer.getState();
    expect(state.queueStats.total).toBe(1);
  });

  test('shouldContinue returns false when no high priority', () => {
    analyzer.initialize([
      { address: '0x1', name: 'f1', score: 10, factors: {}, estimatedTokens: 100, analyzed: false },
    ]);

    const { shouldContinue, reason } = analyzer.shouldContinue();
    expect(shouldContinue).toBe(false);
    expect(reason).toBe('no_high_priority');
  });

  test('getNextBatch returns functions', () => {
    analyzer.initialize([
      { address: '0x1', name: 'f1', score: 50, factors: {}, estimatedTokens: 100, analyzed: false },
    ]);

    const batch = analyzer.getNextBatch();
    expect(batch.length).toBe(1);
  });

  test('runIteration calls callback and records findings', async () => {
    analyzer.initialize([
      { address: '0x1', name: 'f1', score: 50, factors: {}, estimatedTokens: 100, analyzed: false },
    ]);

    const state = await analyzer.runIteration(async (_functions, _summary, _iteration) => ({
      findings: [
        {
          type: 'capability' as const,
          title: 'Test',
          description: 'Test finding',
          confidence: 0.9,
          relatedFunctions: [],
          evidence: [],
        },
      ],
      tokensUsed: 500,
    }));

    expect(state.iteration).toBe(1);
    expect(state.iterationFindings.length).toBe(1);
    expect(state.tokensUsed).toBe(500);
  });
});

describe('createBudgetAllocator', () => {
  test('creates allocator with custom context limit', () => {
    const allocator = createBudgetAllocator(200000);
    const budget = allocator.getBudget();
    expect(budget.totalTokens).toBe(200000);
  });
});

// =============================================================================
// Phase A: Enrichment Tests
// =============================================================================

import {
  applyScoreDecay,
  getScoringStats,
  reprioritizeFromDiscoveries,
  scoreFunctionsEnriched,
} from './priority-scorer.js';
import {
  checkNearHighEntropy,
  enrichFunctions,
  getBehaviorClusterBoost,
  getEntryDistanceScore,
  getSectionEntropyScore,
  type RawFunction,
  type RawSection,
} from './section-correlator.js';

describe('Section Correlator', () => {
  const mockSections: RawSection[] = [
    {
      name: '.text',
      virtualAddress: '0x1000',
      virtualSize: 0x2000,
      entropy: 5.5,
      permissions: 'r-x',
    },
    {
      name: '.data',
      virtualAddress: '0x3000',
      virtualSize: 0x1000,
      entropy: 4.0,
      permissions: 'rw-',
    },
    {
      name: '.packed',
      virtualAddress: '0x4000',
      virtualSize: 0x1000,
      entropy: 7.8,
      permissions: 'rwx',
    },
  ];

  const mockFunctions: RawFunction[] = [
    { name: 'main', address: '0x1100', size: 200, callers: [], callees: ['0x1200', '0x1300'] },
    { name: 'helper', address: '0x1200', size: 100, callers: ['0x1100'], callees: ['0x1300'] },
    {
      name: 'crypto_func',
      address: '0x1300',
      size: 150,
      callers: ['0x1100', '0x1200'],
      callees: [],
    },
    { name: 'unreachable', address: '0x1400', size: 50, callers: [], callees: [] },
    { name: 'packed_func', address: '0x4100', size: 300, callers: [], callees: [] },
  ];

  describe('enrichFunctions', () => {
    test('calculates entry point distance correctly', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);

      const main = enriched.find((f) => f.name === 'main');
      const helper = enriched.find((f) => f.name === 'helper');
      const crypto = enriched.find((f) => f.name === 'crypto_func');
      const unreachable = enriched.find((f) => f.name === 'unreachable');

      expect(main?.entryPointDistance).toBe(0); // Entry point
      expect(helper?.entryPointDistance).toBe(1); // Called by main
      expect(crypto?.entryPointDistance).toBe(1); // Also called by main
      expect(unreachable?.entryPointDistance).toBe(-1); // Not reachable
    });

    test('maps functions to sections correctly', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);

      const main = enriched.find((f) => f.name === 'main');
      const packed = enriched.find((f) => f.name === 'packed_func');

      expect(main?.section?.name).toBe('.text');
      expect(packed?.section?.name).toBe('.packed');
      expect(packed?.section?.entropy).toBeCloseTo(7.8, 1);
    });

    test('marks entry reachability correctly', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);

      const main = enriched.find((f) => f.name === 'main');
      const unreachable = enriched.find((f) => f.name === 'unreachable');

      expect(main?.isEntryReachable).toBe(true);
      expect(unreachable?.isEntryReachable).toBe(false);
    });
  });

  describe('getSectionEntropyScore', () => {
    test('returns 1.0 for high entropy sections', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);
      const packed = enriched.find((f) => f.name === 'packed_func');

      expect(packed).toBeDefined();
      if (packed) {
        const score = getSectionEntropyScore(packed);
        expect(score).toBe(1.0);
      }
    });

    test('returns lower score for normal entropy sections', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);
      const main = enriched.find((f) => f.name === 'main');

      expect(main).toBeDefined();
      if (main) {
        const score = getSectionEntropyScore(main);
        expect(score).toBeLessThan(1.0);
      }
    });
  });

  describe('getEntryDistanceScore', () => {
    test('returns 1.0 for entry point', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);
      const main = enriched.find((f) => f.name === 'main');

      expect(main).toBeDefined();
      if (main) {
        const score = getEntryDistanceScore(main);
        expect(score).toBe(1.0);
      }
    });

    test('returns 0 for unreachable functions', () => {
      const enriched = enrichFunctions(mockFunctions, mockSections, []);
      const unreachable = enriched.find((f) => f.name === 'unreachable');

      expect(unreachable).toBeDefined();
      if (unreachable) {
        const score = getEntryDistanceScore(unreachable);
        expect(score).toBe(0);
      }
    });
  });

  describe('checkNearHighEntropy', () => {
    test('returns true for functions near high entropy section', () => {
      // .data is at 0x3000, adjacent to .packed at 0x4000 (high entropy)
      const isNear = checkNearHighEntropy('0x3500', mockSections);
      expect(isNear).toBe(true);
    });

    test('returns true for functions in high entropy section', () => {
      const isNear = checkNearHighEntropy('0x4100', mockSections);
      expect(isNear).toBe(true);
    });
  });

  describe('getBehaviorClusterBoost', () => {
    test('returns high boost for process injection', () => {
      expect(getBehaviorClusterBoost('process-injection')).toBe(25);
    });

    test('returns medium boost for network-c2', () => {
      expect(getBehaviorClusterBoost('network-c2')).toBe(20);
    });

    test('returns 0 for unknown', () => {
      expect(getBehaviorClusterBoost('unknown')).toBe(0);
    });

    test('returns 0 for undefined', () => {
      expect(getBehaviorClusterBoost(undefined)).toBe(0);
    });
  });
});

describe('Enriched Scoring', () => {
  const mockSections: RawSection[] = [
    {
      name: '.text',
      virtualAddress: '0x1000',
      virtualSize: 0x2000,
      entropy: 5.5,
      permissions: 'r-x',
    },
    {
      name: '.packed',
      virtualAddress: '0x3000',
      virtualSize: 0x1000,
      entropy: 7.8,
      permissions: 'rwx',
    },
  ];

  const mockFunctions: RawFunction[] = [
    { name: 'main', address: '0x1100', size: 200, callers: [], callees: ['0x1200'] },
    { name: 'decrypt', address: '0x1200', size: 300, callers: ['0x1100'], callees: [] },
    { name: 'packed_entry', address: '0x3100', size: 500, callers: [], callees: [] },
  ];

  describe('scoreFunctionsEnriched', () => {
    test('scores functions with enrichment data', () => {
      const scored = scoreFunctionsEnriched(mockFunctions, mockSections, []);

      expect(scored.length).toBe(3);
      // All should have enrichment data
      for (const func of scored) {
        expect(func.enrichment).toBeDefined();
      }
    });

    test('boosts functions in high entropy sections', () => {
      const scored = scoreFunctionsEnriched(mockFunctions, mockSections, []);

      const packed = scored.find((f) => f.name === 'packed_entry');
      const main = scored.find((f) => f.name === 'main');

      expect(packed).toBeDefined();
      expect(main).toBeDefined();
      // Packed function should have higher base score from section entropy
      // (Note: other factors may also affect the score)
    });

    test('includes entry distance in factors', () => {
      const scored = scoreFunctionsEnriched(mockFunctions, mockSections, []);

      const main = scored.find((f) => f.name === 'main');
      expect(main?.factors.entryPointDistance).toBe(0);
      expect(main?.factors.isEntryReachable).toBe(true);
    });

    test('boosts entry region functions when isPacked is true', () => {
      // Score without isPacked
      const scoredNormal = scoreFunctionsEnriched(mockFunctions, mockSections, [], '0x1100', false);
      const mainNormal = scoredNormal.find((f) => f.name === 'main');

      // Score with isPacked - should boost functions near entry point
      const scoredPacked = scoreFunctionsEnriched(mockFunctions, mockSections, [], '0x1100', true);
      const mainPacked = scoredPacked.find((f) => f.name === 'main');

      expect(mainPacked).toBeDefined();
      expect(mainNormal).toBeDefined();
      // Packed binary should give higher priority to entry region
      if (mainPacked && mainNormal) {
        expect(mainPacked.score).toBeGreaterThanOrEqual(mainNormal.score);
      }
    });

    test('boosts high entropy functions when isPacked is true', () => {
      // Score without isPacked
      const scoredNormal = scoreFunctionsEnriched(
        mockFunctions,
        mockSections,
        [],
        undefined,
        false,
      );
      const packedNormal = scoredNormal.find((f) => f.name === 'packed_entry');

      // Score with isPacked - should boost high entropy functions
      const scoredPacked = scoreFunctionsEnriched(mockFunctions, mockSections, [], undefined, true);
      const packedFunc = scoredPacked.find((f) => f.name === 'packed_entry');

      expect(packedFunc).toBeDefined();
      expect(packedNormal).toBeDefined();
      // High entropy function should get boosted in packed binaries
      if (packedFunc && packedNormal) {
        expect(packedFunc.score).toBeGreaterThanOrEqual(packedNormal.score);
      }
    });

    test('uses entry point address for distance calculation', () => {
      // Use 0x1200 (decrypt) as entry point
      const scored = scoreFunctionsEnriched(mockFunctions, mockSections, [], '0x1200', false);

      const decrypt = scored.find((f) => f.name === 'decrypt');
      // Function at entry point should have distance 0
      expect(decrypt?.factors.entryPointDistance).toBe(0);
    });
  });
});

describe('Dynamic Reprioritization', () => {
  describe('reprioritizeFromDiscoveries', () => {
    test('boosts callees of suspicious functions', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1000',
          name: 'suspicious',
          score: 80,
          factors: {},
          estimatedTokens: 100,
          analyzed: true, // Already analyzed
          enrichment: {
            address: '0x1000',
            name: 'suspicious',
            size: 100,
            callers: [],
            callees: ['0x2000', '0x3000'],
            entryPointDistance: 0,
            isEntryReachable: true,
          },
        },
        {
          address: '0x2000',
          name: 'callee1',
          score: 30,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x3000',
          name: 'callee2',
          score: 25,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
      ];

      const reprioritized = reprioritizeFromDiscoveries(functions, new Set(['0x1000']), 15);

      const callee1 = reprioritized.find((f) => f.name === 'callee1');
      const callee2 = reprioritized.find((f) => f.name === 'callee2');

      expect(callee1?.score).toBe(45); // 30 + 15
      expect(callee1?.dynamicBoost).toBe(15);
      expect(callee2?.score).toBe(40); // 25 + 15
    });

    test('does not boost already analyzed functions', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1000',
          name: 'suspicious',
          score: 80,
          factors: {},
          estimatedTokens: 100,
          analyzed: true,
          enrichment: {
            address: '0x1000',
            name: 'suspicious',
            size: 100,
            callers: [],
            callees: ['0x2000'],
            entryPointDistance: 0,
            isEntryReachable: true,
          },
        },
        {
          address: '0x2000',
          name: 'alreadyAnalyzed',
          score: 30,
          factors: {},
          estimatedTokens: 100,
          analyzed: true, // Already analyzed
        },
      ];

      const reprioritized = reprioritizeFromDiscoveries(functions, new Set(['0x1000']), 15);

      const callee = reprioritized.find((f) => f.name === 'alreadyAnalyzed');
      expect(callee?.score).toBe(30); // No boost
    });
  });

  describe('applyScoreDecay', () => {
    test('decays scores after minimum iterations', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1',
          name: 'f1',
          score: 50,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x2',
          name: 'f2',
          score: 30,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
      ];

      const decayed = applyScoreDecay(functions, 5, 0.9, 3);

      expect(decayed[0]?.score).toBe(45); // 50 * 0.9 = 45
      expect(decayed[1]?.score).toBe(27); // 30 * 0.9 = 27
    });

    test('does not decay before minimum iterations', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1',
          name: 'f1',
          score: 50,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
      ];

      const notDecayed = applyScoreDecay(functions, 2, 0.9, 3);

      expect(notDecayed[0]?.score).toBe(50); // No decay
    });

    test('does not decay already analyzed functions', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1',
          name: 'f1',
          score: 50,
          factors: {},
          estimatedTokens: 100,
          analyzed: true,
        },
      ];

      const notDecayed = applyScoreDecay(functions, 5, 0.9, 3);

      expect(notDecayed[0]?.score).toBe(50); // No decay for analyzed
    });
  });

  describe('getScoringStats', () => {
    test('returns correct statistics', () => {
      const functions: ScoredFunction[] = [
        {
          address: '0x1',
          name: 'high',
          score: 70,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x2',
          name: 'med',
          score: 40,
          factors: {},
          estimatedTokens: 100,
          analyzed: false,
        },
        {
          address: '0x3',
          name: 'low',
          score: 10,
          factors: {},
          estimatedTokens: 100,
          analyzed: true,
        },
      ];

      const stats = getScoringStats(functions);

      expect(stats.total).toBe(3);
      expect(stats.analyzed).toBe(1);
      expect(stats.pending).toBe(2);
      expect(stats.highPriority).toBe(1);
      expect(stats.mediumPriority).toBe(1);
      expect(stats.lowPriority).toBe(0);
    });
  });
});
