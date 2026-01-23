/**
 * Type declarations for @sentinel/premium package
 * 
 * This file provides TypeScript type information for the optional
 * @sentinel/premium package which is dynamically loaded at runtime.
 * 
 * The actual package is distributed separately to licensed users.
 */

declare module '@sentinel/premium' {
  import type { AnalysisState, ReportPaths } from '../types';
  import type { ITriageAgent, IAnalyzerAgent, IReportAgent, IPremiumModule } from '../agents/interfaces';

  // Re-export interfaces
  export type { ITriageAgent, IAnalyzerAgent, IReportAgent };

  // Agent classes with run methods
  export const TriageAgent: {
    run: ITriageAgent['run'];
  };

  export const AnalyzerAgent: {
    run: IAnalyzerAgent['run'];
  };

  export const ReportAgent: {
    run: IReportAgent['run'];
  };

  // Prompts
  export const prompts: {
    ANALYZER_SYSTEM_PROMPT: string;
    TRIAGE_SYSTEM_PROMPT: string;
    REPORT_SYSTEM_PROMPT: string;
  };

  // Version
  export const version: string;

  // LLM Providers
  export class OpenAIProvider {
    constructor(apiKey: string);
    complete(request: unknown): Promise<unknown>;
    isAvailable(): Promise<boolean>;
  }

  export class AnthropicProvider {
    constructor(apiKey: string);
    complete(request: unknown): Promise<unknown>;
    isAvailable(): Promise<boolean>;
  }

  // Multi-model orchestrator
  export class MultiModelOrchestrator {
    constructor(config: unknown);
    route(request: unknown): Promise<unknown>;
  }

  // Full module export for dynamic import
  const _default: IPremiumModule;
  export default _default;
}
