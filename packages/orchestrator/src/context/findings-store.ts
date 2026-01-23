/**
 * Findings Store
 * Persists analysis findings across iterations
 */

import type { AnalysisFinding, FindingsStore, FindingsSummary } from './types.js';

/**
 * In-memory store for analysis findings
 */
export class FindingsManager {
  private store: FindingsStore;

  constructor() {
    this.store = {
      findings: [],
      analyzedFunctions: new Set(),
      currentIteration: 0,
      totalIterations: 0,
      tokenUsageByIteration: [],
    };
  }

  /**
   * Start a new iteration
   */
  startIteration(): number {
    this.store.currentIteration++;
    return this.store.currentIteration;
  }

  /**
   * End current iteration
   */
  endIteration(tokensUsed: number): void {
    this.store.totalIterations = this.store.currentIteration;
    this.store.tokenUsageByIteration.push(tokensUsed);
  }

  /**
   * Add a finding
   */
  addFinding(finding: Omit<AnalysisFinding, 'id' | 'timestamp' | 'iteration'>): void {
    const id = `finding-${this.store.findings.length + 1}`;
    this.store.findings.push({
      ...finding,
      id,
      timestamp: new Date(),
      iteration: this.store.currentIteration,
    });
  }

  /**
   * Add multiple findings
   */
  addFindings(findings: Omit<AnalysisFinding, 'id' | 'timestamp' | 'iteration'>[]): void {
    for (const finding of findings) {
      this.addFinding(finding);
    }
  }

  /**
   * Mark functions as analyzed
   */
  markFunctionsAnalyzed(addresses: string[]): void {
    for (const address of addresses) {
      this.store.analyzedFunctions.add(address);
    }
  }

  /**
   * Check if a function has been analyzed
   */
  isFunctionAnalyzed(address: string): boolean {
    return this.store.analyzedFunctions.has(address);
  }

  /**
   * Get all findings
   */
  getFindings(): AnalysisFinding[] {
    return [...this.store.findings];
  }

  /**
   * Get findings by type
   */
  getFindingsByType(type: AnalysisFinding['type']): AnalysisFinding[] {
    return this.store.findings.filter((f) => f.type === type);
  }

  /**
   * Get high-confidence findings
   */
  getHighConfidenceFindings(threshold = 0.7): AnalysisFinding[] {
    return this.store.findings.filter((f) => f.confidence >= threshold);
  }

  /**
   * Get findings from a specific iteration
   */
  getFindingsByIteration(iteration: number): AnalysisFinding[] {
    return this.store.findings.filter((f) => f.iteration === iteration);
  }

  /**
   * Get current iteration number
   */
  getCurrentIteration(): number {
    return this.store.currentIteration;
  }

  /**
   * Get store statistics
   */
  getStats(): {
    totalFindings: number;
    findingsByType: Record<string, number>;
    analyzedFunctions: number;
    iterations: number;
    totalTokensUsed: number;
    averageTokensPerIteration: number;
  } {
    const findingsByType: Record<string, number> = {};
    for (const finding of this.store.findings) {
      findingsByType[finding.type] = (findingsByType[finding.type] ?? 0) + 1;
    }

    const totalTokensUsed = this.store.tokenUsageByIteration.reduce((a, b) => a + b, 0);

    return {
      totalFindings: this.store.findings.length,
      findingsByType,
      analyzedFunctions: this.store.analyzedFunctions.size,
      iterations: this.store.totalIterations,
      totalTokensUsed,
      averageTokensPerIteration:
        this.store.totalIterations > 0 ? totalTokensUsed / this.store.totalIterations : 0,
    };
  }

  /**
   * Generate a compressed summary of findings
   */
  generateSummary(maxTokens = 2000): FindingsSummary {
    const capabilities = new Set<string>();
    const techniques = new Set<string>();
    const iocs = new Set<string>();

    // Extract key information from findings
    for (const finding of this.store.findings) {
      if (finding.type === 'capability') {
        capabilities.add(finding.title);
      }
      if (finding.type === 'technique' && finding.mitreTechnique) {
        techniques.add(finding.mitreTechnique);
      }
      if (finding.type === 'ioc') {
        iocs.add(finding.title);
      }
    }

    // Build summary text
    const lines: string[] = [];
    lines.push(
      `Analysis Summary (${this.store.findings.length} findings from ${this.store.totalIterations} iterations)`,
    );
    lines.push('');

    if (capabilities.size > 0) {
      lines.push(`Capabilities: ${[...capabilities].slice(0, 10).join(', ')}`);
    }
    if (techniques.size > 0) {
      lines.push(`MITRE Techniques: ${[...techniques].slice(0, 10).join(', ')}`);
    }
    if (iocs.size > 0) {
      lines.push(`IOCs: ${[...iocs].slice(0, 5).join(', ')}`);
    }

    // Add high-confidence findings
    const highConf = this.getHighConfidenceFindings(0.8);
    if (highConf.length > 0) {
      lines.push('');
      lines.push('Key Findings:');
      for (const finding of highConf.slice(0, 5)) {
        lines.push(`- ${finding.title}: ${finding.description.slice(0, 100)}`);
      }
    }

    const summaryText = lines.join('\n');

    // Estimate tokens (4 chars per token)
    const tokenCount = Math.ceil(summaryText.length / 4);

    // Truncate if over budget
    const finalText =
      tokenCount > maxTokens ? `${summaryText.slice(0, maxTokens * 4)}...` : summaryText;

    return {
      summaryText: finalText,
      findingsCount: this.store.findings.length,
      tokenCount: Math.ceil(finalText.length / 4),
      keyCapabilities: [...capabilities].slice(0, 10),
      keyTechniques: [...techniques].slice(0, 10),
      keyIocs: [...iocs].slice(0, 10),
    };
  }

  /**
   * Export findings for report generation
   */
  exportForReport(): {
    findings: AnalysisFinding[];
    summary: FindingsSummary;
    stats: ReturnType<FindingsManager['getStats']>;
  } {
    return {
      findings: this.getFindings(),
      summary: this.generateSummary(),
      stats: this.getStats(),
    };
  }

  /**
   * Reset the store
   */
  reset(): void {
    this.store = {
      findings: [],
      analyzedFunctions: new Set(),
      currentIteration: 0,
      totalIterations: 0,
      tokenUsageByIteration: [],
    };
  }
}
