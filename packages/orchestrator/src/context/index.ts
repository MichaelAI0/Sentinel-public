/**
 * Context Management Module
 * Handles large binary analysis with context budgeting and prioritization
 */

// Budget allocation
export { ContextBudgetAllocator, createBudgetAllocator } from './budget-allocator.js';

// Findings persistence
export { FindingsManager } from './findings-store.js';

// Iterative analysis
export {
  type AnalyzeBatchCallback,
  createIterativeAnalyzer,
  IterativeAnalyzer,
} from './iterative-analyzer.js';

// Priority queue
export { FunctionPriorityQueue } from './priority-queue.js';

// Priority scoring
export {
  applyScoreDecay,
  calculatePriorityScore,
  extractRiskFactors,
  getFunctionsWithinBudget,
  getScoringStats,
  getTopPriorityFunctions,
  hasSuspiciousApiCalls,
  reprioritizeFromDiscoveries,
  scoreFunctions,
  scoreFunctionsEnriched,
} from './priority-scorer.js';

// Section correlation
export {
  checkNearHighEntropy,
  ENTROPY_THRESHOLDS,
  enrichFunctions,
  getBehaviorClusterBoost,
  getEntryDistanceScore,
  getSectionEntropyScore,
  type ImportInfo,
  type RawFunction,
  type RawSection,
} from './section-correlator.js';

// Types
export type {
  AnalysisFinding,
  BehaviorCluster,
  ContextBudget,
  ContextManagerConfig,
  EnrichedFunction,
  FindingsStore,
  FindingsSummary,
  IterationState,
  PhaseAllocation,
  RiskFactors,
  ScoredFunction,
  SectionInfo,
} from './types.js';

export { DEFAULT_CONTEXT_CONFIG } from './types.js';
