/**
 * Context Budget Allocator
 * Manages token budget allocation across analysis phases
 */

import type { ContextBudget, ContextManagerConfig, PhaseAllocation } from './types.js';

/**
 * Default phase allocation percentages
 */
const DEFAULT_PHASE_ALLOCATION = {
  overview: 0.1, // 10% for initial overview
  prioritization: 0.05, // 5% for scoring and prioritization
  'deep-dive': 0.7, // 70% for iterative function analysis
  synthesis: 0.15, // 15% for final report synthesis
};

/**
 * Context Budget Allocator
 * Tracks and allocates tokens across analysis phases
 */
export class ContextBudgetAllocator {
  private config: ContextManagerConfig;
  private budget: ContextBudget;
  private phases: Map<PhaseAllocation['phase'], PhaseAllocation>;

  constructor(config?: Partial<ContextManagerConfig>) {
    this.config = {
      maxContextTokens: config?.maxContextTokens ?? 128000,
      maxIterations: config?.maxIterations ?? 10,
      minPriorityScore: config?.minPriorityScore ?? 20,
      batchSize: config?.batchSize ?? 10,
      systemPromptReserve: config?.systemPromptReserve ?? 2000,
      outputReserve: config?.outputReserve ?? 4000,
    };

    // Calculate available tokens
    const availableTokens =
      this.config.maxContextTokens - this.config.systemPromptReserve - this.config.outputReserve;

    this.budget = {
      totalTokens: this.config.maxContextTokens,
      systemPromptTokens: this.config.systemPromptReserve,
      findingsSummaryTokens: 0,
      functionAnalysisTokens: availableTokens,
      usedTokens: this.config.systemPromptReserve,
      remainingTokens: availableTokens,
    };

    // Initialize phase allocations
    this.phases = new Map();
    for (const [phase, percentage] of Object.entries(DEFAULT_PHASE_ALLOCATION)) {
      this.phases.set(phase as PhaseAllocation['phase'], {
        phase: phase as PhaseAllocation['phase'],
        percentage,
        allocatedTokens: Math.floor(availableTokens * percentage),
        usedTokens: 0,
      });
    }
  }

  /**
   * Get current budget state
   */
  getBudget(): ContextBudget {
    return { ...this.budget };
  }

  /**
   * Get phase allocation
   */
  getPhaseAllocation(phase: PhaseAllocation['phase']): PhaseAllocation | undefined {
    return this.phases.get(phase);
  }

  /**
   * Get all phase allocations
   */
  getAllPhaseAllocations(): PhaseAllocation[] {
    return [...this.phases.values()];
  }

  /**
   * Get remaining tokens for a specific phase
   */
  getRemainingPhaseTokens(phase: PhaseAllocation['phase']): number {
    const allocation = this.phases.get(phase);
    if (!allocation) return 0;
    return allocation.allocatedTokens - allocation.usedTokens;
  }

  /**
   * Use tokens from a phase
   */
  usePhaseTokens(phase: PhaseAllocation['phase'], tokens: number): boolean {
    const allocation = this.phases.get(phase);
    if (!allocation) return false;

    const remaining = allocation.allocatedTokens - allocation.usedTokens;
    if (tokens > remaining) return false;

    allocation.usedTokens += tokens;
    this.budget.usedTokens += tokens;
    this.budget.remainingTokens -= tokens;

    return true;
  }

  /**
   * Check if there's budget remaining for deep-dive
   */
  hasDeepDiveBudget(): boolean {
    return this.getRemainingPhaseTokens('deep-dive') > 1000;
  }

  /**
   * Get tokens available for next iteration
   */
  getIterationBudget(iterationNumber: number): number {
    const deepDive = this.phases.get('deep-dive');
    if (!deepDive) return 0;

    const remaining = deepDive.allocatedTokens - deepDive.usedTokens;
    const remainingIterations = this.config.maxIterations - iterationNumber + 1;

    // Distribute remaining budget across remaining iterations
    return Math.floor(remaining / remainingIterations);
  }

  /**
   * Reserve tokens for findings summary
   */
  reserveFindingsSummaryTokens(tokens: number): void {
    this.budget.findingsSummaryTokens = tokens;
  }

  /**
   * Estimate tokens for a text string
   */
  estimateTokens(text: string): number {
    // Rough estimate: ~4 characters per token
    return Math.ceil(text.length / 4);
  }

  /**
   * Check if text fits within remaining budget
   */
  fitsInBudget(text: string, phase: PhaseAllocation['phase']): boolean {
    const tokens = this.estimateTokens(text);
    return tokens <= this.getRemainingPhaseTokens(phase);
  }

  /**
   * Get configuration
   */
  getConfig(): ContextManagerConfig {
    return { ...this.config };
  }

  /**
   * Reset budget (for testing or new analysis)
   */
  reset(): void {
    const availableTokens =
      this.config.maxContextTokens - this.config.systemPromptReserve - this.config.outputReserve;

    this.budget = {
      totalTokens: this.config.maxContextTokens,
      systemPromptTokens: this.config.systemPromptReserve,
      findingsSummaryTokens: 0,
      functionAnalysisTokens: availableTokens,
      usedTokens: this.config.systemPromptReserve,
      remainingTokens: availableTokens,
    };

    for (const [phase, percentage] of Object.entries(DEFAULT_PHASE_ALLOCATION)) {
      this.phases.set(phase as PhaseAllocation['phase'], {
        phase: phase as PhaseAllocation['phase'],
        percentage,
        allocatedTokens: Math.floor(availableTokens * percentage),
        usedTokens: 0,
      });
    }
  }
}

/**
 * Create a budget allocator for a specific provider's context limit
 */
export function createBudgetAllocator(
  maxContextTokens: number,
  config?: Partial<ContextManagerConfig>,
): ContextBudgetAllocator {
  return new ContextBudgetAllocator({
    ...config,
    maxContextTokens,
  });
}
