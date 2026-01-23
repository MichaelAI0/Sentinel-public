/**
 * Iterative Analyzer
 * Multi-turn analysis loop with budget management
 */

import { ContextBudgetAllocator } from './budget-allocator.js';
import { FindingsManager } from './findings-store.js';
import { FunctionPriorityQueue } from './priority-queue.js';
import type {
  AnalysisFinding,
  ContextManagerConfig,
  IterationState,
  ScoredFunction,
} from './types.js';

/**
 * Callback for analyzing a batch of functions
 * Returns findings from the analysis
 */
export type AnalyzeBatchCallback = (
  functions: ScoredFunction[],
  previousFindings: string,
  iteration: number,
) => Promise<{
  findings: Omit<AnalysisFinding, 'id' | 'timestamp' | 'iteration'>[];
  tokensUsed: number;
}>;

/**
 * Iterative Analyzer
 * Coordinates multi-turn analysis with budget management
 */
export class IterativeAnalyzer {
  private budgetAllocator: ContextBudgetAllocator;
  private findingsManager: FindingsManager;
  private priorityQueue: FunctionPriorityQueue;
  private config: ContextManagerConfig;

  constructor(config?: Partial<ContextManagerConfig>) {
    this.config = {
      maxContextTokens: config?.maxContextTokens ?? 128000,
      maxIterations: config?.maxIterations ?? 10,
      minPriorityScore: config?.minPriorityScore ?? 20,
      batchSize: config?.batchSize ?? 10,
      systemPromptReserve: config?.systemPromptReserve ?? 2000,
      outputReserve: config?.outputReserve ?? 4000,
    };

    this.budgetAllocator = new ContextBudgetAllocator(this.config);
    this.findingsManager = new FindingsManager();
    this.priorityQueue = new FunctionPriorityQueue();
  }

  /**
   * Initialize with scored functions
   */
  initialize(functions: ScoredFunction[]): void {
    this.priorityQueue.addFunctions(functions);
  }

  /**
   * Check if analysis should continue
   */
  shouldContinue(): { shouldContinue: boolean; reason?: IterationState['stopReason'] } {
    const iteration = this.findingsManager.getCurrentIteration();

    // Check max iterations
    if (iteration >= this.config.maxIterations) {
      return { shouldContinue: false, reason: 'max_iterations' };
    }

    // Check budget
    if (!this.budgetAllocator.hasDeepDiveBudget()) {
      return { shouldContinue: false, reason: 'budget_exhausted' };
    }

    // Check if there are high-priority functions left
    if (!this.priorityQueue.hasHighPriority(this.config.minPriorityScore)) {
      return { shouldContinue: false, reason: 'no_high_priority' };
    }

    // Check if all functions analyzed
    if (this.priorityQueue.pendingCount() === 0) {
      return { shouldContinue: false, reason: 'all_analyzed' };
    }

    return { shouldContinue: true };
  }

  /**
   * Get the next batch of functions to analyze
   */
  getNextBatch(): ScoredFunction[] {
    const iteration = this.findingsManager.getCurrentIteration() + 1;
    const tokenBudget = this.budgetAllocator.getIterationBudget(iteration);

    return this.priorityQueue.getBatch(tokenBudget, this.config.minPriorityScore);
  }

  /**
   * Run a single iteration
   */
  async runIteration(analyzeBatch: AnalyzeBatchCallback): Promise<IterationState> {
    const { shouldContinue, reason } = this.shouldContinue();

    if (!shouldContinue) {
      return {
        iteration: this.findingsManager.getCurrentIteration(),
        maxIterations: this.config.maxIterations,
        functionsToAnalyze: [],
        iterationFindings: [],
        tokensUsed: 0,
        shouldContinue: false,
        stopReason: reason,
      };
    }

    // Start new iteration
    const iteration = this.findingsManager.startIteration();

    // Get batch of functions to analyze
    const batch = this.getNextBatch();

    if (batch.length === 0) {
      return {
        iteration,
        maxIterations: this.config.maxIterations,
        functionsToAnalyze: [],
        iterationFindings: [],
        tokensUsed: 0,
        shouldContinue: false,
        stopReason: 'no_high_priority',
      };
    }

    // Get previous findings summary for context
    const previousSummary = this.findingsManager.generateSummary(1000);

    // Run analysis
    const { findings, tokensUsed } = await analyzeBatch(
      batch,
      previousSummary.summaryText,
      iteration,
    );

    // Record findings
    this.findingsManager.addFindings(findings);
    this.findingsManager.markFunctionsAnalyzed(batch.map((f) => f.address));
    this.findingsManager.endIteration(tokensUsed);

    // Update budget
    this.budgetAllocator.usePhaseTokens('deep-dive', tokensUsed);

    // Mark functions as analyzed in queue
    this.priorityQueue.markBatchAnalyzed(batch.map((f) => f.address));

    // Check if we should continue
    const continueCheck = this.shouldContinue();

    return {
      iteration,
      maxIterations: this.config.maxIterations,
      functionsToAnalyze: batch,
      iterationFindings: findings.map((f, i) => ({
        ...f,
        id: `finding-${iteration}-${i}`,
        timestamp: new Date(),
        iteration,
      })),
      tokensUsed,
      shouldContinue: continueCheck.shouldContinue,
      stopReason: continueCheck.reason,
    };
  }

  /**
   * Run all iterations until complete
   */
  async runAllIterations(
    analyzeBatch: AnalyzeBatchCallback,
    onIteration?: (state: IterationState) => void,
  ): Promise<{
    iterations: IterationState[];
    summary: ReturnType<FindingsManager['generateSummary']>;
    stats: ReturnType<FindingsManager['getStats']>;
  }> {
    const iterations: IterationState[] = [];

    let continueAnalysis = true;
    while (continueAnalysis) {
      const state = await this.runIteration(analyzeBatch);
      iterations.push(state);

      if (onIteration) {
        onIteration(state);
      }

      continueAnalysis = state.shouldContinue;
    }

    return {
      iterations,
      summary: this.findingsManager.generateSummary(),
      stats: this.findingsManager.getStats(),
    };
  }

  /**
   * Get current state
   */
  getState(): {
    queueStats: ReturnType<FunctionPriorityQueue['getStats']>;
    budget: ReturnType<ContextBudgetAllocator['getBudget']>;
    findingsStats: ReturnType<FindingsManager['getStats']>;
  } {
    return {
      queueStats: this.priorityQueue.getStats(),
      budget: this.budgetAllocator.getBudget(),
      findingsStats: this.findingsManager.getStats(),
    };
  }

  /**
   * Get findings manager for export
   */
  getFindingsManager(): FindingsManager {
    return this.findingsManager;
  }

  /**
   * Reset for new analysis
   */
  reset(): void {
    this.budgetAllocator.reset();
    this.findingsManager.reset();
    this.priorityQueue.clear();
  }
}

/**
 * Create an iterative analyzer with custom configuration
 */
export function createIterativeAnalyzer(config?: Partial<ContextManagerConfig>): IterativeAnalyzer {
  return new IterativeAnalyzer(config);
}
