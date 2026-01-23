/**
 * Priority Queue
 * Manages prioritized queue of functions for analysis
 */

import type { ScoredFunction } from './types.js';

/**
 * Priority Queue for function analysis
 * Functions are ordered by priority score (highest first)
 */
export class FunctionPriorityQueue {
  private queue: ScoredFunction[] = [];
  private analyzedSet: Set<string> = new Set();

  constructor(functions?: ScoredFunction[]) {
    if (functions) {
      this.queue = [...functions].sort((a, b) => b.score - a.score);
    }
  }

  /**
   * Add functions to the queue
   */
  addFunctions(functions: ScoredFunction[]): void {
    for (const func of functions) {
      if (!this.analyzedSet.has(func.address)) {
        this.queue.push(func);
      }
    }
    // Re-sort after adding
    this.queue.sort((a, b) => b.score - a.score);
  }

  /**
   * Get next function to analyze (highest priority)
   */
  peek(): ScoredFunction | undefined {
    return this.queue.find((f) => !this.analyzedSet.has(f.address));
  }

  /**
   * Get and remove next function
   */
  pop(): ScoredFunction | undefined {
    const next = this.peek();
    if (next) {
      this.markAnalyzed(next.address);
    }
    return next;
  }

  /**
   * Get batch of functions within token budget
   */
  getBatch(tokenBudget: number, minScore = 0): ScoredFunction[] {
    const batch: ScoredFunction[] = [];
    let tokensUsed = 0;

    for (const func of this.queue) {
      if (this.analyzedSet.has(func.address)) continue;
      if (func.score < minScore) continue;
      if (tokensUsed + func.estimatedTokens > tokenBudget) continue;

      batch.push(func);
      tokensUsed += func.estimatedTokens;
    }

    return batch;
  }

  /**
   * Mark function as analyzed
   */
  markAnalyzed(address: string): void {
    this.analyzedSet.add(address);
    const func = this.queue.find((f) => f.address === address);
    if (func) {
      func.analyzed = true;
    }
  }

  /**
   * Mark batch as analyzed
   */
  markBatchAnalyzed(addresses: string[]): void {
    for (const address of addresses) {
      this.markAnalyzed(address);
    }
  }

  /**
   * Get count of unanalyzed functions
   */
  pendingCount(): number {
    return this.queue.filter((f) => !this.analyzedSet.has(f.address)).length;
  }

  /**
   * Get count of analyzed functions
   */
  analyzedCount(): number {
    return this.analyzedSet.size;
  }

  /**
   * Get total function count
   */
  totalCount(): number {
    return this.queue.length;
  }

  /**
   * Check if there are high-priority functions remaining
   */
  hasHighPriority(minScore: number): boolean {
    return this.queue.some((f) => !this.analyzedSet.has(f.address) && f.score >= minScore);
  }

  /**
   * Get all pending functions
   */
  getPending(): ScoredFunction[] {
    return this.queue.filter((f) => !this.analyzedSet.has(f.address));
  }

  /**
   * Get all analyzed functions
   */
  getAnalyzed(): ScoredFunction[] {
    return this.queue.filter((f) => this.analyzedSet.has(f.address));
  }

  /**
   * Get statistics about the queue
   */
  getStats(): {
    total: number;
    pending: number;
    analyzed: number;
    highPriority: number;
    mediumPriority: number;
    lowPriority: number;
  } {
    const pending = this.getPending();
    return {
      total: this.queue.length,
      pending: pending.length,
      analyzed: this.analyzedSet.size,
      highPriority: pending.filter((f) => f.score >= 50).length,
      mediumPriority: pending.filter((f) => f.score >= 20 && f.score < 50).length,
      lowPriority: pending.filter((f) => f.score < 20).length,
    };
  }

  /**
   * Reset the queue (clear analyzed set)
   */
  reset(): void {
    this.analyzedSet.clear();
    for (const func of this.queue) {
      func.analyzed = false;
    }
  }

  /**
   * Clear the queue entirely
   */
  clear(): void {
    this.queue = [];
    this.analyzedSet.clear();
  }
}
