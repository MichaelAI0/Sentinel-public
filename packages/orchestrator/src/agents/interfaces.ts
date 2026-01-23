/**
 * Premium Agent Interfaces
 *
 * These interfaces define the contract for premium agents.
 * The actual implementations are loaded dynamically from @sentinel/premium
 * when a valid Professional/Enterprise license is present.
 *
 * @module agents/interfaces
 */

import type {
  AnalysisResults,
  AnalysisState,
  ReportPaths,
  TriageResults,
} from '../types.js';

/**
 * Interface for the Triage Agent
 * Performs fast initial assessment and risk scoring
 */
export interface ITriageAgent {
  /**
   * Run triage analysis on a binary
   * @param state - Current analysis state with binaryPath set
   * @returns Updated state with triageResults populated
   */
  run(state: AnalysisState): Promise<AnalysisState>;
}

/**
 * Interface for the Analyzer Agent
 * Performs deep static analysis using Ghidra + AI
 */
export interface IAnalyzerAgent {
  /**
   * Run deep analysis on a binary
   * @param state - Current analysis state with triageResults set
   * @returns Updated state with analysisResults populated
   */
  run(state: AnalysisState): Promise<AnalysisState>;
}

/**
 * Interface for the Report Agent
 * Generates professional reports in multiple formats
 */
export interface IReportAgent {
  /**
   * Generate reports from analysis results
   * @param state - Complete analysis state
   * @returns Paths to generated report files
   */
  run(state: AnalysisState): Promise<ReportPaths>;
}

/**
 * Premium module interface - what @sentinel/premium exports
 */
export interface IPremiumModule {
  TriageAgent: {
    run: ITriageAgent['run'];
  };
  AnalyzerAgent: {
    run: IAnalyzerAgent['run'];
  };
  ReportAgent: {
    run: IReportAgent['run'];
  };
  /** Version of the premium module */
  version: string;
}

/**
 * Result of attempting to load premium module
 */
export type PremiumLoadResult =
  | { loaded: true; module: IPremiumModule }
  | { loaded: false; reason: string };
