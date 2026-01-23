// Re-export all types from schemas

// ============================================
// NEW ERROR & RESULT TYPES (Phase 1)
// ============================================

// Re-export type aliases from constants
export type {
  AgentName,
  Architecture,
  ConfidenceLevel,
  Endianness,
  FileFormat,
  HashAlgorithm,
  MitreTactic,
  OperatingSystem,
  PriorityLevel,
  Recommendation,
  RiskLevel,
  Severity,
  SophisticationLevel,
  TlpMarking,
  ToolName,
} from '../constants.js';
export type {
  AgentConfig,
  AnalyzerAgentOutput,
  ReportAgentOutput,
  TriageAgentOutput,
} from '../schemas/agents.js';
export type {
  AnalysisResults,
  AnalysisState,
  Export,
  ExtractedString,
  FileInfo,
  Function,
  Hashes,
  Import,
  IOCs,
  MitreTechnique,
  Section,
  SuspiciousPattern,
  TriageResults,
} from '../schemas/analysis.js';
export type {
  AnalyzeBinaryInput,
  AnalyzeFunctionsInput,
  AnalyzeFunctionsOutput,
  CalculateHashesInput,
  CalculateHashesOutput,
  DetectFileTypeInput,
  DetectFileTypeOutput,
  DetectPackingInput,
  DetectPackingOutput,
  ExtractELFHeadersInput,
  ExtractELFHeadersOutput,
  ExtractPEHeadersInput,
  ExtractPEHeadersOutput,
  ExtractStringsInput,
  ExtractStringsOutput,
  GenerateJsonReportInput,
  GenerateJsonReportOutput,
  GenerateMarkdownReportInput,
  GenerateMarkdownReportOutput,
  GenerateStixReportInput,
  GenerateStixReportOutput,
  MapToMitreAttackInput,
  MapToMitreAttackOutput,
} from '../schemas/tools.js';
export * from './branded.js';
export * from './errors.js';
export * from './result.js';

// ============================================
// ERROR RESPONSE TYPES (for API responses)
// ============================================

export type ErrorResponsePayload = {
  code: string;
  message: string;
  details?: unknown;
  timestamp: string;
};

// ============================================
// MCP TOOL DEFINITION
// ============================================

export type MCPToolDefinition = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: unknown) => Promise<unknown>;
};

// ============================================
// LOGGING TYPES
// ============================================

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export type LogEntry = {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, unknown>;
};

// ============================================
// CACHE TYPES
// ============================================

export type CacheEntry<T> = {
  data: T;
  timestamp: string;
  expiresAt: string;
  hash: string;
};

export type CacheOptions = {
  maxSize: number;
  ttlSeconds: number;
};
