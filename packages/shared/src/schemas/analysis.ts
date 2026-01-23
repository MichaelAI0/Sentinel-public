import { z } from 'zod';
import {
  ARCHITECTURES,
  FILE_FORMATS,
  PRIORITY_LEVELS,
  RECOMMENDATIONS,
  RISK_LEVELS,
  SEVERITIES,
  SOPHISTICATION_LEVELS,
  STRING_TYPES,
} from '../constants.js';

// ============================================
// HASH SCHEMAS
// ============================================

export const HashesSchema = z.object({
  md5: z.string().optional(),
  sha1: z.string().optional(),
  sha256: z.string(),
  ssdeep: z.string().optional(),
});

// ============================================
// FILE INFO SCHEMAS
// ============================================

export const FileInfoSchema = z.object({
  type: z.enum(FILE_FORMATS),
  architecture: z.enum(ARCHITECTURES),
  size: z.number().int().positive(),
  entropy: z.number().min(0).max(8),
  mimeType: z.string().optional(),
});

// ============================================
// FUNCTION SCHEMAS
// ============================================

export const FunctionSchema = z.object({
  name: z.string(),
  address: z.string(),
  description: z.string().optional(),
  techniques: z.array(z.string()).optional(),
  isSuspicious: z.boolean(),
});

// ============================================
// IMPORT/EXPORT SCHEMAS
// ============================================

export const ImportSchema = z.object({
  library: z.string(),
  function: z.string(),
  address: z.string().optional(),
  isSuspicious: z.boolean(),
});

export const ExportSchema = z.string();

// ============================================
// STRING SCHEMAS
// ============================================

export const ExtractedStringSchema = z.object({
  value: z.string(),
  address: z.string().optional(),
  offset: z.number().int().optional(),
  type: z.enum(STRING_TYPES),
});

// ============================================
// SECTION SCHEMAS
// ============================================

export const SectionSchema = z.object({
  name: z.string(),
  virtualAddress: z.string(),
  virtualSize: z.number().int().nonnegative(),
  rawSize: z.number().int().nonnegative(),
  entropy: z.number().min(0).max(8),
  permissions: z.string(),
});

// ============================================
// SUSPICIOUS PATTERN SCHEMAS
// ============================================

export const SuspiciousPatternSchema = z.object({
  pattern: z.string(),
  description: z.string(),
  severity: z.enum(SEVERITIES),
});

// ============================================
// TRIAGE RESULTS
// ============================================

export const TriageResultsSchema = z.object({
  fileType: z.string(),
  architecture: z.string(),
  entropy: z.number().min(0).max(8),
  riskLevel: z.enum(RISK_LEVELS),
  confidence: z.number().min(0).max(1),
  suspiciousStrings: z.array(z.string()),
  suspiciousImports: z.array(z.string()),
  recommendation: z.enum(RECOMMENDATIONS),
  reasoning: z.string(),
  estimatedAnalysisTime: z.string().optional(),
  priority: z.enum(PRIORITY_LEVELS).optional(),
});

// ============================================
// IOC SCHEMAS
// ============================================

export const IOCsSchema = z.object({
  ipAddresses: z.array(z.string()),
  domains: z.array(z.string()),
  urls: z.array(z.string()),
  filePaths: z.array(z.string()),
  registryKeys: z.array(z.string()),
  mutexes: z.array(z.string()),
  encryptionKeys: z.array(z.string()).optional(),
});

// ============================================
// MITRE ATT&CK SCHEMAS
// ============================================

export const MitreTechniqueSchema = z.object({
  id: z.string(), // e.g., "T1055.002"
  name: z.string(), // e.g., "Process Injection: Portable Executable Injection"
  tactic: z.string(), // e.g., "Defense Evasion"
  confidence: z.number().min(0).max(1),
  evidence: z.array(z.string()),
});

// ============================================
// PHASE 2 & 3 SCHEMAS
// ============================================

export const YaraMatchSchema = z.object({
  ruleName: z.string(),
  tags: z.array(z.string()),
  matches: z.array(
    z.object({
      identifier: z.string(),
      offset: z.number().int(),
      data: z.string().optional(),
    }),
  ),
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
});

export const CryptoFindingSchema = z.object({
  algorithm: z.string(),
  type: z.enum(['constants', 'operations', 'xor', 'custom']),
  confidence: z.number().min(0).max(1),
  offset: z.number().int().optional(),
  evidence: z.string(),
});

export const AssemblyPatternSchema = z.object({
  category: z.enum(['syscall', 'anti-debug', 'crypto', 'packing', 'shellcode']),
  name: z.string(),
  instructions: z.array(z.string()),
  address: z.string().optional(),
  technique: z.string().optional(),
});

export const EnhancedStringSchema = z.object({
  value: z.string(),
  encoding: z.string(),
  category: z.string(),
  entropy: z.number().min(0).max(8),
  isSuspicious: z.boolean(),
  suspicionReason: z.string().optional(),
});

const CfgBasicBlockSchema = z.object({
  id: z.string(),
  startAddress: z.string(),
  instructionCount: z.number().int().nonnegative(),
  isEntryBlock: z.boolean(),
  isExitBlock: z.boolean(),
});

const CfgEdgeSchema = z.object({
  fromBlock: z.string(),
  toBlock: z.string(),
  edgeType: z.string(),
});

const FunctionCfgSchema = z.object({
  functionName: z.string(),
  functionAddress: z.string(),
  basicBlocks: z.array(CfgBasicBlockSchema),
  edges: z.array(CfgEdgeSchema),
  mermaidDiagram: z.string().optional(),
});

export const CfgDataSchema = z.object({
  functionCFGs: z.array(FunctionCfgSchema),
  totalBlocks: z.number().int().nonnegative(),
  totalEdges: z.number().int().nonnegative(),
});

export const GhidraCryptoSchema = z.object({
  algorithm: z.string(),
  type: z.string(),
  address: z.string(),
  confidence: z.number().min(0).max(1),
  nearbyFunctions: z.array(z.string()),
});

export const ApiCallMappingSchema = z.object({
  imports: z.array(
    z.object({
      library: z.string(),
      functionName: z.string(),
      calledBy: z.array(z.string()),
    }),
  ),
  libraryGroups: z
    .array(
      z.object({
        libraryName: z.string(),
        functionCount: z.number().int().nonnegative(),
        functions: z.array(z.string()),
      }),
    )
    .optional(),
});

// ============================================
// FULL ANALYSIS RESULTS
// ============================================

export const AnalysisResultsSchema = z.object({
  functions: z.array(FunctionSchema),
  imports: z.array(ImportSchema),
  exports: z.array(ExportSchema),
  iocs: IOCsSchema,
  mitreTechniques: z.array(MitreTechniqueSchema),
  malwareFamily: z.string().nullable().optional(),
  familyConfidence: z.number().min(0).max(1).optional(),
  capabilities: z.array(z.string()),
  antiAnalysis: z.array(z.string()),
  sophistication: z.enum(SOPHISTICATION_LEVELS),
  keyFindings: z.array(z.string()),
  technicalNotes: z.string(),
  yaraMatches: z.array(YaraMatchSchema).optional(),
  cryptoFindings: z.array(CryptoFindingSchema).optional(),
  assemblyPatterns: z.array(AssemblyPatternSchema).optional(),
  enhancedStrings: z.array(EnhancedStringSchema).optional(),
  wasUnpacked: z.boolean().optional(),
  originalPacker: z.string().optional(),
  cfgData: CfgDataSchema.optional(),
  ghidraCrypto: z.array(GhidraCryptoSchema).optional(),
  apiCallMapping: ApiCallMappingSchema.optional(),
  specialistFindings: z.array(z.string()).optional(),
  overallAssessment: z.string().optional(),
  malwareLikelihood: z.number().min(0).max(1).optional(),
});

// ============================================
// ANALYSIS STATE (LangGraph)
// ============================================

export const AnalysisStateSchema = z.object({
  // Input
  binaryPath: z.string(),
  binaryHash: z.string().nullable(),

  // Triage Results
  triageResults: TriageResultsSchema.nullable(),

  // Analysis Results
  analysisResults: AnalysisResultsSchema.nullable(),

  // Report Outputs
  reportPaths: z
    .object({
      markdown: z.string(),
      json: z.string(),
      stix: z.string(),
    })
    .nullable(),

  // Metadata
  startTime: z.string(), // ISO 8601
  endTime: z.string().nullable(),
  cacheHit: z.boolean(),
  errors: z.array(z.string()),
});

// ============================================
// TYPE EXPORTS
// ============================================

export type Hashes = z.infer<typeof HashesSchema>;
export type FileInfo = z.infer<typeof FileInfoSchema>;
export type Function = z.infer<typeof FunctionSchema>;
export type Import = z.infer<typeof ImportSchema>;
export type Export = z.infer<typeof ExportSchema>;
export type ExtractedString = z.infer<typeof ExtractedStringSchema>;
export type Section = z.infer<typeof SectionSchema>;
export type SuspiciousPattern = z.infer<typeof SuspiciousPatternSchema>;
export type TriageResults = z.infer<typeof TriageResultsSchema>;
export type IOCs = z.infer<typeof IOCsSchema>;
export type MitreTechnique = z.infer<typeof MitreTechniqueSchema>;
export type YaraMatch = z.infer<typeof YaraMatchSchema>;
export type CryptoFinding = z.infer<typeof CryptoFindingSchema>;
export type AssemblyPattern = z.infer<typeof AssemblyPatternSchema>;
export type EnhancedString = z.infer<typeof EnhancedStringSchema>;
export type CfgData = z.infer<typeof CfgDataSchema>;
export type GhidraCrypto = z.infer<typeof GhidraCryptoSchema>;
export type ApiCallMapping = z.infer<typeof ApiCallMappingSchema>;
export type AnalysisResults = z.infer<typeof AnalysisResultsSchema>;
export type AnalysisState = z.infer<typeof AnalysisStateSchema>;
