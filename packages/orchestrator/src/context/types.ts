/**
 * Context Management Types
 * Types for managing analysis context and prioritization
 */

/**
 * Section information from binary analysis
 */
export type SectionInfo = {
  /** Section name (.text, .data, .rdata, etc.) */
  name: string;
  /** Virtual address (hex string) */
  virtualAddress: string;
  /** Virtual size in bytes */
  virtualSize: number;
  /** Entropy score (0-8) */
  entropy: number;
  /** Section permissions (rwx) */
  permissions: string;
};

/**
 * Enriched function data with section correlation
 */
export type EnrichedFunction = {
  /** Function address */
  address: string;
  /** Function name */
  name: string;
  /** Function size in bytes */
  size: number;
  /** Caller addresses */
  callers: string[];
  /** Callee addresses */
  callees: string[];
  /** Section this function resides in */
  section?: SectionInfo;
  /** Distance from entry point (call depth, -1 if unreachable) */
  entryPointDistance: number;
  /** Is this function reachable from entry point? */
  isEntryReachable: boolean;
  /** Behavior cluster based on import patterns */
  behaviorCluster?: BehaviorCluster;
};

/**
 * Behavior clusters for import-based grouping
 */
export type BehaviorCluster =
  | 'process-injection'
  | 'network-c2'
  | 'file-crypto'
  | 'persistence'
  | 'anti-analysis'
  | 'credential-access'
  | 'discovery'
  | 'execution'
  | 'defense-evasion'
  | 'unknown';

/**
 * Risk factors used for priority scoring
 */
export type RiskFactors = {
  /** Entropy score (0-8, higher = more random/encrypted) */
  entropy: number;
  /** Has suspicious API calls (VirtualAlloc, CreateRemoteThread, etc.) */
  hasSuspiciousApis: boolean;
  /** Has anti-debug/anti-analysis patterns */
  hasAntiAnalysis: boolean;
  /** Has network-related calls */
  hasNetworkCalls: boolean;
  /** Has crypto-related patterns */
  hasCrypto: boolean;
  /** Has file system operations */
  hasFileOps: boolean;
  /** Has registry operations (Windows) */
  hasRegistryOps: boolean;
  /** Has process manipulation */
  hasProcessManip: boolean;
  /** Function size in bytes */
  size: number;
  /** Number of callers (higher = more important) */
  callerCount: number;
  /** Number of callees */
  calleeCount: number;
  /** Cyclomatic complexity estimate */
  complexity: number;
  /** Section entropy score (inherited from containing section) */
  sectionEntropy?: number;
  /** Distance from entry point (-1 if unreachable) */
  entryPointDistance?: number;
  /** Is reachable from entry point */
  isEntryReachable?: boolean;
  /** Behavior cluster assignment */
  behaviorCluster?: BehaviorCluster;
  /** Near high-entropy section (within 1 section boundary) */
  nearHighEntropy?: boolean;
};

/**
 * Scored function ready for priority queue
 */
export type ScoredFunction = {
  /** Function address */
  address: string;
  /** Function name */
  name: string;
  /** Computed priority score (0-100) */
  score: number;
  /** Individual risk factors */
  factors: Partial<RiskFactors>;
  /** Estimated tokens for decompiled code */
  estimatedTokens: number;
  /** Has been analyzed in current session */
  analyzed: boolean;
  /** Raw enrichment data */
  enrichment?: EnrichedFunction;
  /** Score boost from dynamic reprioritization */
  dynamicBoost?: number;
};

/**
 * Context budget configuration
 */
export type ContextBudget = {
  /** Total tokens available for analysis */
  totalTokens: number;
  /** Tokens reserved for system prompt */
  systemPromptTokens: number;
  /** Tokens reserved for findings summary */
  findingsSummaryTokens: number;
  /** Tokens available for function analysis */
  functionAnalysisTokens: number;
  /** Tokens used so far */
  usedTokens: number;
  /** Remaining tokens */
  remainingTokens: number;
};

/**
 * Phase allocation for context budget
 */
export type PhaseAllocation = {
  /** Phase name */
  phase: 'overview' | 'prioritization' | 'deep-dive' | 'synthesis';
  /** Percentage of budget */
  percentage: number;
  /** Allocated tokens */
  allocatedTokens: number;
  /** Used tokens */
  usedTokens: number;
};

/**
 * Analysis finding from a single iteration
 */
export type AnalysisFinding = {
  /** Unique ID */
  id: string;
  /** Finding type */
  type:
    | 'capability'
    | 'technique'
    | 'ioc'
    | 'anti-analysis'
    | 'crypto'
    | 'network'
    | 'persistence'
    | 'other';
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  /** Confidence score (0-1) */
  confidence: number;
  /** Related function addresses */
  relatedFunctions: string[];
  /** Evidence supporting the finding */
  evidence: string[];
  /** MITRE ATT&CK technique ID if applicable */
  mitreTechnique?: string;
  /** Timestamp when found */
  timestamp: Date;
  /** Iteration number when found */
  iteration: number;
};

/**
 * Accumulated findings across all iterations
 */
export type FindingsStore = {
  /** All findings */
  findings: AnalysisFinding[];
  /** Functions that have been analyzed */
  analyzedFunctions: Set<string>;
  /** Current iteration number */
  currentIteration: number;
  /** Total iterations completed */
  totalIterations: number;
  /** Token usage per iteration */
  tokenUsageByIteration: number[];
};

/**
 * Iteration state for multi-turn analysis
 */
export type IterationState = {
  /** Current iteration number (1-based) */
  iteration: number;
  /** Maximum iterations allowed */
  maxIterations: number;
  /** Functions to analyze this iteration */
  functionsToAnalyze: ScoredFunction[];
  /** Findings from this iteration */
  iterationFindings: AnalysisFinding[];
  /** Tokens used this iteration */
  tokensUsed: number;
  /** Should continue to next iteration */
  shouldContinue: boolean;
  /** Reason for stopping if shouldContinue is false */
  stopReason?: 'budget_exhausted' | 'all_analyzed' | 'max_iterations' | 'no_high_priority';
};

/**
 * Summary of findings for context compression
 */
export type FindingsSummary = {
  /** Compressed summary text */
  summaryText: string;
  /** Number of findings summarized */
  findingsCount: number;
  /** Token count of summary */
  tokenCount: number;
  /** Key capabilities identified */
  keyCapabilities: string[];
  /** Key techniques identified */
  keyTechniques: string[];
  /** High-confidence IOCs */
  keyIocs: string[];
};

/**
 * Context manager configuration
 */
export type ContextManagerConfig = {
  /** Maximum context window size in tokens */
  maxContextTokens: number;
  /** Maximum iterations for analysis */
  maxIterations: number;
  /** Minimum priority score to analyze (0-100) */
  minPriorityScore: number;
  /** Batch size for function analysis */
  batchSize: number;
  /** Reserved tokens for system prompt */
  systemPromptReserve: number;
  /** Reserved tokens for output */
  outputReserve: number;
};

/**
 * Default configuration values
 */
export const DEFAULT_CONTEXT_CONFIG: ContextManagerConfig = {
  maxContextTokens: 128000, // Conservative default, adjust per provider
  maxIterations: 10,
  minPriorityScore: 20,
  batchSize: 10,
  systemPromptReserve: 2000,
  outputReserve: 4000,
};
