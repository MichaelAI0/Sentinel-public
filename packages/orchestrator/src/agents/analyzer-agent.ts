/**
 * Analyzer Agent
 * Deep static analysis using Ghidra + Phase 2 enhanced analysis + Phase 3 advanced analysis
 *
 * @module agents/analyzer-agent
 *
 * @todo Phase 4: Add distributed analysis across multiple Ghidra instances
 * @todo Phase 4: Add ML-based triage to skip analysis of known-benign
 */

import {
  API_TECHNIQUE_MAP,
  containsSuspiciousAPI,
  type TechniqueDef,
  type YARAMatch,
  type YARAStringInstance,
  type YARAStringMatch,
} from '@sentinel/shared';
import { requireFeature } from '../config/features.js';
import {
  type AnalyzeBatchCallback,
  createIterativeAnalyzer,
  getFunctionsWithinBudget,
  type RawFunction,
  type RawSection,
  reprioritizeFromDiscoveries,
  type ScoredFunction,
  scoreFunctions,
  scoreFunctionsEnriched,
} from '../context/index.js';
// LLM provider
import { getLLMClient } from '../llm/llm-client.js';
// Prompts
import { ANALYZER_SYSTEM_PROMPT } from '../prompts/index.js';
import type {
  AnalysisResults,
  AnalysisState,
  AssemblyPattern,
  CryptoFinding,
  EnhancedString,
  FunctionInfo,
  ImportEntry,
  IOCs,
  MitreTechnique,
  YaraMatch,
} from '../types.js';
// Phase 2 utilities
import { AssemblyExtractor } from '../utils/assembly-extractor.js';
import { BehaviorPredictor } from '../utils/behavior-predictor.js';
import { CryptoDetector } from '../utils/crypto-detector.js';
import { analyzerLogger as logger } from '../utils/logger.js';
import { getMcpBridge } from '../utils/mcp-bridge.js';
import { MitreMapper } from '../utils/mitre-mapper.js';
// Phase 3 utilities
import { MultiModelOrchestrator } from '../utils/multi-model-orchestrator.js';
import { StringAnalyzer } from '../utils/string-analyzer.js';
import { BinaryUnpacker } from '../utils/unpacker.js';
import { YARAManager } from '../utils/yara-manager.js';

// Note: ANALYZER_SYSTEM_PROMPT imported from ../prompts/index.js
// See: packages/orchestrator/src/prompts/index.ts

// Note: MITRE technique mappings now imported from @sentinel/shared
// See: packages/shared/src/data/mitre-mappings.ts

/** Ghidra analysis data structure */
interface GhidraAnalysisData {
  functions: Array<{
    name: string;
    address: string;
    size?: number;
    callers?: string[];
    callees?: string[];
  }>;
  sections: Array<{
    name: string;
    virtualAddress: string;
    virtualSize: number;
    rawSize: number;
    entropy?: number;
    permissions?: string;
  }>;
  imports: Array<{
    library: string;
    function: string;
    address?: string;
  }>;
  exports: Array<{ name: string; address?: string }>;
  strings: Array<{ value: string; address?: string }>;
  fileInfo?: { format?: string };
}

/**
 * Identify suspicious functions from Ghidra output
 */
function analyzeFunctions(
  functions: Array<{
    name: string;
    address: string;
    size?: number;
    callers?: string[];
    callees?: string[];
  }>,
): {
  functions: FunctionInfo[];
  techniques: MitreTechnique[];
} {
  const analyzedFunctions: FunctionInfo[] = [];
  const techniques: MitreTechnique[] = [];
  const seenTechniques = new Set<string>();

  for (const func of functions) {
    const matchedTechnique = containsSuspiciousAPI(func.name);
    const isSuspicious = matchedTechnique !== undefined;

    const funcInfo: FunctionInfo = {
      name: func.name,
      address: func.address,
      isSuspicious,
      techniques: [],
    };

    // Check for technique mappings using shared API_TECHNIQUE_MAP
    for (const [api, technique] of Object.entries(API_TECHNIQUE_MAP) as [string, TechniqueDef][]) {
      if (func.name.toLowerCase().includes(api.toLowerCase())) {
        funcInfo.techniques?.push(technique.id);

        if (!seenTechniques.has(technique.id)) {
          seenTechniques.add(technique.id);
          techniques.push({
            id: technique.id,
            name: technique.name,
            tactic: technique.tactic,
            evidence: [`Function ${func.name} at ${func.address}`],
            confidence: 0.7,
          });
        }
      }
    }

    analyzedFunctions.push(funcInfo);
  }

  return { functions: analyzedFunctions, techniques };
}

type MitreTechniqueInput = Omit<MitreTechnique, 'evidence'> & {
  evidence?: string | string[];
};

function normalizeTechnique(technique: MitreTechniqueInput): MitreTechnique {
  const evidence = technique.evidence
    ? Array.isArray(technique.evidence)
      ? technique.evidence
      : [technique.evidence]
    : [];

  return {
    ...technique,
    evidence,
  };
}

/**
 * Analyze imports for suspicious patterns
 * Accepts either string[] (legacy) or array of import objects from Ghidra
 */
function analyzeImports(
  imports: Array<string | { library: string; function: string; address?: string; name?: string }>,
): ImportEntry[] {
  return imports.map((imp) => {
    // Handle object format from Ghidra
    if (typeof imp === 'object' && imp !== null) {
      const library = imp.library ?? 'unknown';
      const func = imp.function ?? imp.name ?? 'unknown';
      const isSuspicious = containsSuspiciousAPI(func) !== undefined;
      return { library, function: func, isSuspicious };
    }

    // Handle legacy string format "library:function"
    const parts = imp.includes(':') ? imp.split(':') : ['unknown', imp];
    const library = parts[0] ?? 'unknown';
    const func = parts[1] ?? imp;
    const isSuspicious = containsSuspiciousAPI(func) !== undefined;

    return { library, function: func, isSuspicious };
  });
}

/**
 * Extract IOCs from strings
 * Handles both string[] and array of string objects from Ghidra
 */
function extractIocs(
  rawStrings: Array<string | { value: string; address?: string; type?: string }>,
): IOCs {
  // Normalize strings to string[]
  const strings = rawStrings.map((s) => (typeof s === 'string' ? s : s.value));

  const iocs: IOCs = {
    ipAddresses: [],
    domains: [],
    urls: [],
    filePaths: [],
    registryKeys: [],
    mutexes: [],
  };

  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
  const domainRegex = /\b[a-z0-9][-a-z0-9]*\.(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|pw)\b/gi;
  const pathRegex = /[A-Z]:\\[\w\\]+\.\w+/gi;
  const registryRegex = /(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s"']+/gi;

  for (const str of strings) {
    // IPs
    const ips = str.match(ipRegex);
    if (ips) {
      for (const ip of ips) {
        // Filter out common false positives
        if (!ip.startsWith('0.') && !ip.startsWith('127.') && !ip.startsWith('255.')) {
          iocs.ipAddresses.push(ip);
        }
      }
    }

    // URLs
    const urls = str.match(urlRegex);
    if (urls) iocs.urls.push(...urls);

    // Domains
    const domains = str.match(domainRegex);
    if (domains) iocs.domains.push(...domains);

    // File paths
    const paths = str.match(pathRegex);
    if (paths) iocs.filePaths.push(...paths);

    // Registry keys
    const regKeys = str.match(registryRegex);
    if (regKeys) iocs.registryKeys.push(...regKeys);
  }

  // Dedupe all arrays
  iocs.ipAddresses = [...new Set(iocs.ipAddresses)];
  iocs.domains = [...new Set(iocs.domains)];
  iocs.urls = [...new Set(iocs.urls)];
  iocs.filePaths = [...new Set(iocs.filePaths)];
  iocs.registryKeys = [...new Set(iocs.registryKeys)];

  return iocs;
}

// ============================================================================
// Phase 2: Enhanced Analysis Functions
// ============================================================================

/**
 * Run YARA signature scanning on a binary
 */
async function runYaraScan(binaryPath: string): Promise<YaraMatch[]> {
  try {
    const yara = new YARAManager();

    // Check if YARA-X is available
    if (!(await yara.isAvailable())) {
      logger.warn`YARA-X not available, skipping signature scan`;
      return [];
    }

    const scanResult = await yara.scan(binaryPath);
    if (!scanResult.ok) {
      logger.warn`YARA scan failed: ${scanResult.error.message}`;
      return [];
    }

    return scanResult.value.matches.map((match: YARAMatch) => ({
      ruleName: match.rule,
      tags: match.tags ?? [],
      matches:
        match.strings?.flatMap((s: YARAStringMatch) =>
          s.instances.map((inst: YARAStringInstance) => ({
            identifier: s.identifier,
            offset: inst.offset,
            data: inst.matchedBytes,
          })),
        ) ?? [],
      metadata: match.metas as Record<string, string | number | boolean> | undefined,
    }));
  } catch (error) {
    logger.error`YARA scan failed: ${error}`;
    return [];
  }
}

/**
 * Detect cryptographic operations in binary
 */
async function runCryptoDetection(binaryPath: string): Promise<CryptoFinding[]> {
  try {
    const detector = new CryptoDetector();
    const fileData = await Bun.file(binaryPath).arrayBuffer();
    const result = detector.analyze(new Uint8Array(fileData));

    // Type-safe mapping from detection method/algorithm to CryptoFinding type
    const getCryptoFindingType = (detection: {
      method?: string;
      algorithm: string;
    }): CryptoFinding['type'] => {
      if (detection.method === 'constant') return 'constants';
      if (detection.algorithm === 'xor') return 'xor';
      return 'operations';
    };

    // Convert detections to CryptoFinding format
    return result.detections.map((detection) => ({
      algorithm: detection.algorithm,
      type: getCryptoFindingType(detection),
      confidence: detection.confidence,
      offset: detection.offset,
      evidence: detection.details,
    }));
  } catch (error) {
    logger.error`Crypto detection failed: ${error}`;
    return [];
  }
}

/**
 * Analyze assembly for suspicious patterns
 */
function runAssemblyAnalysis(assemblyText: string): AssemblyPattern[] {
  try {
    const extractor = new AssemblyExtractor();
    const instructions = extractor.parseAssemblyText(assemblyText);
    const detectedPatterns = extractor.analyzeInstructions(instructions);

    const patterns: AssemblyPattern[] = [];

    // Type-safe mapping from pattern type to AssemblyPattern category
    const PATTERN_CATEGORY_MAP = {
      syscall: 'syscall',
      antiDebug: 'anti-debug',
      crypto: 'crypto',
      memory: 'packing',
    } as const satisfies Record<string, AssemblyPattern['category']>;

    // Convert detected patterns from assembly-extractor format to types.ts format
    for (const pattern of detectedPatterns) {
      const category: AssemblyPattern['category'] =
        pattern.type in PATTERN_CATEGORY_MAP
          ? PATTERN_CATEGORY_MAP[pattern.type as keyof typeof PATTERN_CATEGORY_MAP]
          : 'shellcode';

      patterns.push({
        category,
        name: pattern.description,
        instructions: pattern.instructions.map(
          (inst) => `${inst.address}: ${inst.mnemonic} ${inst.operands}`,
        ),
        address: pattern.instructions[0]?.address,
      });
    }

    return patterns;
  } catch (error) {
    logger.error`Assembly analysis failed: ${error}`;
    return [];
  }
}

/**
 * Enhance string analysis with entropy and categorization
 */
function runEnhancedStringAnalysis(
  rawStrings: Array<string | { value: string; address?: string; type?: string }>,
): EnhancedString[] {
  try {
    const analyzer = new StringAnalyzer();

    // Normalize strings
    const strings = rawStrings.map((s) => (typeof s === 'string' ? s : s.value));

    // Analyze all strings
    const result = analyzer.analyze(strings);

    return result.strings.map((s) => ({
      value: s.value,
      encoding: s.encoding,
      category: s.category,
      entropy: s.entropy,
      isSuspicious: s.suspicious,
      suspicionReason: s.suspicionReasons?.join(', '),
    }));
  } catch (error) {
    logger.error`Enhanced string analysis failed: ${error}`;
    return [];
  }
}

/**
 * Attempt to unpack binary if packed
 */
async function attemptUnpack(
  binaryPath: string,
  isPacked: boolean,
): Promise<{ unpacked: boolean; path: string; packer?: string }> {
  if (!isPacked) {
    return { unpacked: false, path: binaryPath };
  }

  try {
    const unpacker = new BinaryUnpacker();
    const detectionResult = await unpacker.detect(binaryPath);

    if (!detectionResult.ok || !detectionResult.value.isPacked) {
      return { unpacked: false, path: binaryPath };
    }

    const detection = detectionResult.value;
    logger.info`Detected packer: ${detection.packerType}, attempting unpack...`;

    const result = await unpacker.unpack(binaryPath);

    if (result.ok && result.value.success && result.value.unpackedPath) {
      logger.info`Successfully unpacked to: ${result.value.unpackedPath}`;
      return {
        unpacked: true,
        path: result.value.unpackedPath,
        packer: detection.packerType,
      };
    }

    const errorMessage = result.ok ? result.value.error : result.error.message;
    logger.warn`Unpack failed: ${errorMessage}`;
    return { unpacked: false, path: binaryPath, packer: detection.packerType };
  } catch (error) {
    logger.error`Unpack attempt failed: ${error}`;
    return { unpacked: false, path: binaryPath };
  }
}

// ============================================================================
// Phase 3: Advanced Ghidra Analysis Functions
// ============================================================================

/**
 * Phase 3 advanced analysis results from Ghidra scripts
 */
type Phase3Results = {
  cfgData?: {
    functionCFGs: Array<{
      functionName: string;
      functionAddress: string;
      basicBlocks: Array<{
        id: string;
        startAddress: string;
        instructionCount: number;
        isEntryBlock: boolean;
        isExitBlock: boolean;
      }>;
      edges: Array<{
        fromBlock: string;
        toBlock: string;
        edgeType: string;
      }>;
      mermaidDiagram?: string;
    }>;
    totalBlocks: number;
    totalEdges: number;
  };
  ghidraCrypto?: Array<{
    algorithm: string;
    type: string;
    address: string;
    confidence: number;
    nearbyFunctions: string[];
  }>;
  apiCalls?: {
    imports: Array<{
      library: string;
      functionName: string;
      calledBy: string[];
    }>;
    libraryGroups?: Array<{
      libraryName: string;
      functionCount: number;
      functions: string[];
    }>;
  };
};

/**
 * Run Phase 3 advanced Ghidra analysis (CFG, crypto, API calls)
 */
async function runPhase3Analysis(binaryPath: string): Promise<Phase3Results> {
  const mcp = getMcpBridge();
  const results: Phase3Results = {};

  // Run all Phase 3 scripts in parallel
  const [cfgResult, cryptoResult, apiResult] = await Promise.all([
    mcp.extractCFG(binaryPath, { maxFunctions: 20 }).catch((err) => {
      logger.warn`CFG extraction failed: ${err}`;
      return null;
    }),
    mcp.detectCrypto(binaryPath, { minConfidence: 0.7 }).catch((err) => {
      logger.warn`Ghidra crypto detection failed: ${err}`;
      return null;
    }),
    mcp.extractAPICalls(binaryPath, { groupByLib: true }).catch((err) => {
      logger.warn`API call extraction failed: ${err}`;
      return null;
    }),
  ]);

  // Process CFG results
  if (cfgResult?.success && cfgResult.data?.data) {
    const cfgData = cfgResult.data.data;
    results.cfgData = {
      functionCFGs: cfgData.functionCFGs,
      totalBlocks: cfgData.metadata.totalBlocks,
      totalEdges: cfgData.metadata.totalEdges,
    };
    logger.info`CFG extraction: ${cfgData.functionCFGs.length} functions, ${cfgData.metadata.totalBlocks} blocks`;
  }

  // Process Ghidra crypto results
  if (cryptoResult?.success && cryptoResult.data?.data) {
    const cryptoData = cryptoResult.data.data;
    results.ghidraCrypto = cryptoData.findings;
    logger.info`Ghidra crypto: ${cryptoData.findings.length} findings`;
  }

  // Process API call results
  if (apiResult?.success && apiResult.data?.data) {
    const apiData = apiResult.data.data;
    results.apiCalls = {
      imports: apiData.imports,
      libraryGroups: apiData.libraryGroups,
    };
    logger.info`API calls: ${apiData.imports.length} imports, ${apiData.metadata.libraryCount} libraries`;
  }

  return results;
}

/**
 * Run multi-model specialist analysis (Phase 3)
 */
async function runMultiModelAnalysis(
  analysisResults: AnalysisResults,
  binaryName: string,
): Promise<{
  specialistFindings?: string[];
  overallAssessment?: string;
  malwareLikelihood?: number;
}> {
  try {
    const llm = getLLMClient();
    const orchestrator = new MultiModelOrchestrator(llm);

    const input = MultiModelOrchestrator.fromAnalysisResults(analysisResults, binaryName);
    const specialistResults = await orchestrator.analyzeWithSpecialists(input);

    const findings: string[] = [];

    // Collect string analysis findings
    if (specialistResults.strings?.summary) {
      findings.push(`String Analysis: ${specialistResults.strings.summary}`);
    }

    // Collect function summaries
    if (specialistResults.functions?.summaries.length) {
      const highRisk = specialistResults.functions.summaries.filter((f) => f.riskLevel === 'high');
      if (highRisk.length > 0) {
        findings.push(`High-Risk Functions: ${highRisk.map((f) => f.name).join(', ')}`);
      }
    }

    // Collect assembly patterns
    if (specialistResults.assembly?.systemCalls.length) {
      findings.push(`System Calls: ${specialistResults.assembly.systemCalls.join(', ')}`);
    }

    return {
      specialistFindings: findings.length > 0 ? findings : undefined,
      overallAssessment: specialistResults.synthesis?.overallAssessment,
      malwareLikelihood: specialistResults.synthesis?.malwareLikelihood,
    };
  } catch (error) {
    logger.warn`Multi-model analysis failed: ${error}`;
    return {};
  }
}

/**
 * Extract entry point address from PE or ELF binary
 */
async function extractEntryPoint(
  analysisPath: string,
  fileFormat: string,
  mcp: ReturnType<typeof getMcpBridge>,
): Promise<string | undefined> {
  if (fileFormat.includes('pe')) {
    const peResult = await mcp.extractPeHeaders(analysisPath);
    if (peResult.success && peResult.data?.optionalHeader?.entryPoint) {
      logger.debug`Extracted PE entry point: ${peResult.data.optionalHeader.entryPoint}`;
      return peResult.data.optionalHeader.entryPoint;
    }
  } else if (fileFormat.includes('elf')) {
    const elfResult = await mcp.extractElfHeaders(analysisPath);
    if (elfResult.success && elfResult.data?.header?.entryPoint) {
      logger.debug`Extracted ELF entry point: ${elfResult.data.header.entryPoint}`;
      return elfResult.data.header.entryPoint;
    }
  }
  return undefined;
}

/**
 * Score and prioritize functions for analysis based on binary size
 */
function scoreFunctionsForAnalysis(
  ghidraData: GhidraAnalysisData,
  entryPointAddress: string | undefined,
  isPacked: boolean,
  isLargeBinary: boolean,
): ScoredFunction[] {
  if (isLargeBinary) {
    // Convert Ghidra data to enrichment format
    const rawFunctions: RawFunction[] = ghidraData.functions.map((f) => ({
      name: f.name,
      address: f.address,
      size: f.size ?? 0,
      callers: f.callers ?? [],
      callees: f.callees ?? [],
    }));

    const rawSections: RawSection[] = ghidraData.sections.map((s) => ({
      name: s.name,
      virtualAddress: s.virtualAddress,
      virtualSize: s.virtualSize,
      rawSize: s.rawSize,
      entropy: s.entropy ?? 0,
      permissions: s.permissions ?? '',
    }));

    const importInfos = ghidraData.imports.map((i) => ({
      library: i.library,
      function: i.function,
      address: i.address,
    }));

    logger.info`Using enriched scoring for large binary (${ghidraData.functions.length} functions, isPacked=${isPacked})`;
    return scoreFunctionsEnriched(
      rawFunctions,
      rawSections,
      importInfos,
      entryPointAddress,
      isPacked,
    );
  }

  // Basic scoring for smaller binaries
  return scoreFunctions(
    ghidraData.functions.map((f) => ({
      name: f.name,
      address: f.address,
      size: f.size ?? 0,
      callers: f.callers ?? [],
      callees: f.callees ?? [],
    })),
  );
}

/** Phase 2/3 context data for LLM analysis */
interface AnalysisContextData {
  filename: string;
  riskLevel: string;
  unpackInfo: { unpacked: boolean; packer?: string };
  functions: FunctionInfo[];
  prioritizedFunctions: ScoredFunction[];
  imports: ImportEntry[];
  exports: string[];
  iocs: IOCs;
  techniques: MitreTechnique[];
  yaraMatches: YaraMatch[];
  cryptoFindings: CryptoFinding[];
  assemblyPatterns: AssemblyPattern[];
  enhancedStrings: EnhancedString[];
  phase3Results: Phase3Results;
  ghidraStrings: Array<{ value: string }>;
  totalFunctions: number;
  isLargeBinary: boolean;
}

/**
 * Build the analysis context string for LLM assessment
 */
function buildAnalysisContext(data: AnalysisContextData): string {
  const {
    filename,
    riskLevel,
    unpackInfo,
    functions,
    prioritizedFunctions,
    imports,
    exports,
    iocs,
    techniques,
    yaraMatches,
    cryptoFindings,
    assemblyPatterns,
    enhancedStrings,
    phase3Results,
    ghidraStrings,
    totalFunctions,
    isLargeBinary,
  } = data;

  return `
File: ${filename}
Risk Level from Triage: ${riskLevel}
${unpackInfo.unpacked ? `Binary was unpacked from: ${unpackInfo.packer}` : ''}

Functions Analyzed: ${functions.length}
Suspicious Functions: ${functions.filter((f) => f.isSuspicious).length}
Binary Scale: ${totalFunctions} functions${isLargeBinary ? ' (large, prioritization applied)' : ''}
Top Priority Functions (${prioritizedFunctions.length}):
${prioritizedFunctions
  .slice(0, 25)
  .map((f) => {
    const size = f.factors.size ?? 0;
    const callers = f.factors.callerCount ?? 0;
    const callees = f.factors.calleeCount ?? 0;
    return `- ${f.name} @ ${f.address} (score ${f.score}, size ${size}, callers ${callers}, callees ${callees})`;
  })
  .join('\n')}

Imports: ${imports.length}
Suspicious Imports: ${imports.filter((i) => i.isSuspicious).length}
${imports
  .filter((i) => i.isSuspicious)
  .slice(0, 20)
  .map((i) => `- ${i.library}:${i.function}`)
  .join('\n')}

Exports: ${exports.length}
${exports.slice(0, 10).join(', ')}

IOCs Found:
- IP Addresses: ${iocs.ipAddresses.length} (${iocs.ipAddresses.slice(0, 5).join(', ')})
- Domains: ${iocs.domains.length} (${iocs.domains.slice(0, 5).join(', ')})
- URLs: ${iocs.urls.length}
- File Paths: ${iocs.filePaths.length}
- Registry Keys: ${iocs.registryKeys.length}

Preliminary MITRE Mappings:
${techniques.map((t) => `- ${t.id}: ${t.name} (${t.tactic})`).join('\n')}

=== PHASE 2 ENHANCED ANALYSIS ===

YARA Signature Matches (${yaraMatches.length}):
${
  yaraMatches
    .slice(0, 10)
    .map((m) => `- ${m.ruleName} [${m.tags.join(', ')}]`)
    .join('\n') || 'None'
}

Cryptographic Operations Detected (${cryptoFindings.length}):
${
  cryptoFindings
    .slice(0, 10)
    .map((c) => `- ${c.algorithm} (${c.type}, confidence: ${(c.confidence * 100).toFixed(0)}%)`)
    .join('\n') || 'None'
}

Assembly Patterns (${assemblyPatterns.length}):
${
  assemblyPatterns
    .slice(0, 10)
    .map((p) => `- [${p.category}] ${p.name}${p.technique ? ` (${p.technique})` : ''}`)
    .join('\n') || 'None'
}

Suspicious Strings (${enhancedStrings.filter((s) => s.isSuspicious).length}):
${
  enhancedStrings
    .filter((s) => s.isSuspicious)
    .slice(0, 20)
    .map(
      (s) =>
        `- [${s.category}] ${s.value.slice(0, 60)}${s.suspicionReason ? ` (${s.suspicionReason})` : ''}`,
    )
    .join('\n') || 'None'
}

=== PHASE 3 ADVANCED ANALYSIS ===

Control Flow Graph Analysis:
${
  phase3Results.cfgData
    ? `- Functions analyzed: ${phase3Results.cfgData.functionCFGs.length}
- Total basic blocks: ${phase3Results.cfgData.totalBlocks}
- Total edges: ${phase3Results.cfgData.totalEdges}
- Complex functions: ${
        phase3Results.cfgData.functionCFGs
          .filter((f) => f.basicBlocks.length > 10)
          .map((f) => f.functionName)
          .join(', ') || 'None'
      }`
    : 'CFG extraction not available'
}

Ghidra Cryptographic Constants (${phase3Results.ghidraCrypto?.length ?? 0}):
${
  phase3Results.ghidraCrypto
    ?.slice(0, 10)
    .map((c) => `- ${c.algorithm} @ ${c.address} (confidence: ${(c.confidence * 100).toFixed(0)}%)`)
    .join('\n') || 'None'
}

API/Import Mapping:
${
  phase3Results.apiCalls
    ? `- Total imports: ${phase3Results.apiCalls.imports.length}
- Libraries: ${phase3Results.apiCalls.libraryGroups?.map((g) => `${g.libraryName}(${g.functionCount})`).join(', ') || 'N/A'}
- Suspicious APIs: ${
        phase3Results.apiCalls.imports
          .filter((i) =>
            [
              'CreateRemoteThread',
              'VirtualAllocEx',
              'WriteProcessMemory',
              'NtUnmapViewOfSection',
              'SetWindowsHookEx',
            ].includes(i.functionName),
          )
          .map((i) => i.functionName)
          .join(', ') || 'None'
      }`
    : 'API extraction not available'
}

Strings (sample):
${ghidraStrings
  .slice(0, 30)
  .map((s) => s.value)
  .join('\n')}
`;
}

/**
 * Merge LLM analysis results into the analysis results
 */
function mergeLlmResults(
  analysisResults: AnalysisResults,
  llmResult: {
    malwareFamily?: string;
    familyConfidence?: number;
    capabilities: string[];
    antiAnalysis: string[];
    sophistication: 'Basic' | 'Intermediate' | 'Advanced' | 'Expert';
    mitreTechniques?: MitreTechniqueInput[];
    iocs?: Partial<IOCs>;
    keyFindings: string[];
    technicalNotes: string;
  },
  existingTechniques: MitreTechnique[],
): AnalysisResults {
  const merged = {
    ...analysisResults,
    malwareFamily: llmResult.malwareFamily,
    familyConfidence: llmResult.familyConfidence,
    capabilities: llmResult.capabilities,
    antiAnalysis: llmResult.antiAnalysis,
    sophistication: llmResult.sophistication,
    keyFindings: llmResult.keyFindings,
    technicalNotes: llmResult.technicalNotes,
  };

  // Merge LLM-identified techniques
  if (llmResult.mitreTechniques) {
    const existingIds = new Set(existingTechniques.map((t) => t.id));
    for (const tech of llmResult.mitreTechniques) {
      const normalized = normalizeTechnique(tech);
      if (!existingIds.has(normalized.id)) {
        merged.mitreTechniques.push(normalized);
      }
    }
  }

  // Merge LLM-identified IOCs
  if (llmResult.iocs) {
    for (const [key, values] of Object.entries(llmResult.iocs)) {
      if (Array.isArray(values)) {
        // Skip ipAddressesEnriched - it's handled separately and has a different structure
        if (key === 'ipAddressesEnriched') {
          continue;
        }
        const iocKey = key as keyof Pick<
          IOCs,
          | 'ipAddresses'
          | 'domains'
          | 'urls'
          | 'filePaths'
          | 'registryKeys'
          | 'mutexes'
          | 'encryptionKeys'
        >;
        const existing = merged.iocs[iocKey] ?? [];
        merged.iocs[iocKey] = [...new Set([...existing, ...(values as string[])])];
      }
    }
  }

  return merged;
}

/**
 * Create fallback findings when LLM analysis fails
 */
function createFallbackFindings(
  functions: FunctionInfo[],
  iocs: IOCs,
  techniques: MitreTechnique[],
  yaraMatches: YaraMatch[],
  cryptoFindings: CryptoFinding[],
  assemblyPatterns: AssemblyPattern[],
): string[] {
  const findings: string[] = [
    'LLM analysis unavailable',
    `Found ${functions.filter((f) => f.isSuspicious).length} suspicious functions`,
    `Extracted ${Object.values(iocs).flat().length} IOCs`,
    `Mapped ${techniques.length} MITRE ATT&CK techniques`,
  ];

  if (yaraMatches.length > 0) {
    findings.push(`${yaraMatches.length} YARA signature matches`);
  }
  if (cryptoFindings.length > 0) {
    findings.push(`${cryptoFindings.length} cryptographic operations detected`);
  }
  if (assemblyPatterns.length > 0) {
    findings.push(`${assemblyPatterns.length} suspicious assembly patterns`);
  }

  return findings;
}

/**
 * Add MITRE techniques from assembly patterns
 */
function addAssemblyPatternTechniques(
  analysisResults: AnalysisResults,
  assemblyPatterns: AssemblyPattern[],
): void {
  const existingTechniqueIds = new Set(analysisResults.mitreTechniques.map((t) => t.id));
  for (const pattern of assemblyPatterns) {
    if (pattern.technique && !existingTechniqueIds.has(pattern.technique)) {
      existingTechniqueIds.add(pattern.technique);
      analysisResults.mitreTechniques.push({
        id: pattern.technique,
        name: pattern.name,
        tactic: pattern.category,
        evidence: [`Assembly pattern: ${pattern.instructions.slice(0, 3).join(', ')}`],
        confidence: 0.8,
      });
    }
  }
}

/**
 * Run iterative deep-dive analysis for large binaries
 */
async function runIterativeDeepDive(
  scoredFunctions: ScoredFunction[],
  analysisResults: AnalysisResults,
  maxContextTokens: number,
  minPriorityScore: number,
  llm: ReturnType<typeof getLLMClient>,
): Promise<void> {
  logger.info`Running iterative deep-dive analysis for large binary...`;

  const iterativeAnalyzer = createIterativeAnalyzer({
    maxContextTokens,
    maxIterations: 5,
    minPriorityScore,
    batchSize: 10,
    systemPromptReserve: 2000,
    outputReserve: 4000,
  });

  iterativeAnalyzer.initialize(scoredFunctions);
  const suspiciousFunctions = new Set<string>();

  const analyzeBatch: AnalyzeBatchCallback = async (batch, previousFindings, iteration) => {
    logger.info`Iteration ${iteration}: Analyzing ${batch.length} functions`;

    const batchContext = batch
      .map((f) => {
        const enrichment = f.enrichment;
        const section = enrichment?.section?.name ?? 'unknown';
        const entryDist = enrichment?.entryPointDistance ?? -1;
        const cluster = enrichment?.behaviorCluster ?? 'unknown';

        return `Function: ${f.name} @ ${f.address}
  Score: ${f.score}, Section: ${section}, Entry Distance: ${entryDist}, Cluster: ${cluster}
  Size: ${f.factors.size ?? 0} bytes, Callers: ${f.factors.callerCount ?? 0}, Callees: ${f.factors.calleeCount ?? 0}`;
      })
      .join('\n\n');

    const iterationPrompt = `You are analyzing a batch of prioritized functions from a binary.
Previous findings summary: ${previousFindings || 'None yet'}

Current batch (iteration ${iteration}):
${batchContext}

For each suspicious function, provide:
1. What capability it likely implements
2. Any MITRE ATT&CK techniques it maps to
3. Whether its callees should be investigated (mark as high priority)

Output JSON:
{
  "findings": [
    {
      "type": "capability" | "technique" | "anti-analysis" | "network" | "crypto",
      "title": "Brief title",
      "description": "What this function does",
      "confidence": 0.0-1.0,
      "relatedFunctions": ["0xADDR1", "0xADDR2"],
      "evidence": ["Evidence 1", "Evidence 2"],
      "mitreTechnique": "T1055" // optional
    }
  ],
  "suspiciousAddresses": ["0xADDR1"] // functions whose callees should be prioritized
}`;

    try {
      const result = await llm.analyzeJson<{
        findings: Array<{
          type: 'capability' | 'technique' | 'anti-analysis' | 'network' | 'crypto' | 'other';
          title: string;
          description: string;
          confidence: number;
          relatedFunctions: string[];
          evidence: string[];
          mitreTechnique?: string;
        }>;
        suspiciousAddresses?: string[];
      }>(ANALYZER_SYSTEM_PROMPT, iterationPrompt, { temperature: 0.1 });

      if (result?.findings) {
        if (result.suspiciousAddresses) {
          for (const addr of result.suspiciousAddresses) {
            suspiciousFunctions.add(addr);
          }
        }
        const tokensUsed = Math.ceil(iterationPrompt.length / 4) + 500;
        return { findings: result.findings, tokensUsed };
      }
    } catch (error) {
      logger.warn`Iterative analysis iteration ${iteration} failed: ${error}`;
    }

    return { findings: [], tokensUsed: 0 };
  };

  const { iterations, stats } = await iterativeAnalyzer.runAllIterations(analyzeBatch, (state) => {
    logger.info`Iteration ${state.iteration} complete: ${state.iterationFindings.length} findings, ${state.tokensUsed} tokens`;

    if (suspiciousFunctions.size > 0) {
      reprioritizeFromDiscoveries(scoredFunctions, suspiciousFunctions);
      logger.info`Boosted priority of ${suspiciousFunctions.size} callee chains`;
    }
  });

  // Merge iterative findings into main results
  const findingsManager = iterativeAnalyzer.getFindingsManager();
  const allFindings = findingsManager.getFindings();

  for (const finding of allFindings) {
    if (finding.type === 'capability' && !analysisResults.capabilities.includes(finding.title)) {
      analysisResults.capabilities.push(finding.title);
    }

    if (finding.mitreTechnique) {
      const existingTechIds = new Set(analysisResults.mitreTechniques.map((t) => t.id));
      if (!existingTechIds.has(finding.mitreTechnique)) {
        analysisResults.mitreTechniques.push({
          id: finding.mitreTechnique,
          name: finding.title,
          tactic: finding.type,
          evidence: finding.evidence,
          confidence: finding.confidence,
        });
      }
    }
  }

  analysisResults.keyFindings.push(
    `Iterative analysis: ${stats.totalFindings} findings across ${iterations.length} iterations`,
  );

  logger.info`Iterative analysis complete: ${stats.totalFindings} findings, ${iterations.length} iterations, ${stats.totalTokensUsed} tokens`;
}

/**
 * Run deep analysis on a binary
 * Coordinates Phase 1 (Ghidra) and Phase 2 (YARA, crypto, assembly, strings) and Phase 3 (CFG, multi-model) analysis
 *
 * Community Edition: Basic static analysis without AI interpretation
 * Professional+: Full AI-powered deep analysis with LLM reasoning
 */
export async function runAnalyzerAgent(state: AnalysisState): Promise<Partial<AnalysisState>> {
  // AI-powered analysis requires Professional or higher
  requireFeature('AI_ANALYZER');

  logger.info`Starting deep analysis for: ${state.binaryPath}`;

  // Skip if triage said LOW risk
  if (state.triageResults?.recommendation === 'IGNORE') {
    logger.info`Skipping deep analysis - triage recommendation was IGNORE`;
    return {
      analysisComplete: true,
      status: 'reporting',
    };
  }

  const mcp = getMcpBridge();
  const llm = getLLMClient();

  // Phase 2: Attempt to unpack if binary is packed
  const isPacked = state.triageResults?.isPacked ?? false;
  const unpackResult = await attemptUnpack(state.binaryPath, isPacked);
  const analysisPath = unpackResult.path;

  // Run Ghidra analysis (on unpacked binary if available)
  logger.info`Running Ghidra analysis on: ${analysisPath}`;
  const ghidraResult = await mcp.analyzeBinary(analysisPath, { timeout: 300000 });

  if (!ghidraResult.success || !ghidraResult.data) {
    logger.error`Ghidra analysis failed: ${ghidraResult.error}`;
    return {
      analysisComplete: true,
      status: 'reporting',
      errors: [...state.errors, `Ghidra analysis failed: ${ghidraResult.error}`],
    };
  }

  const ghidraData = ghidraResult.data;

  // ============================================================================
  // Extract entry point for enriched scoring
  // ============================================================================
  const fileFormat = ghidraData.fileInfo?.format?.toLowerCase() ?? '';
  const entryPointAddress = await extractEntryPoint(analysisPath, fileFormat, mcp);

  // ============================================================================
  // Phase 2: Run enhanced analysis in parallel
  // ============================================================================
  logger.info`Running Phase 2 enhanced analysis...`;

  // Run YARA scan, crypto detection, and Phase 3 Ghidra scripts in parallel
  const [yaraMatches, cryptoFindings, phase3Results] = await Promise.all([
    runYaraScan(analysisPath),
    runCryptoDetection(analysisPath),
    runPhase3Analysis(analysisPath),
  ]);

  // Analyze the Ghidra output
  const { functions, techniques } = analyzeFunctions(ghidraData.functions);
  const imports = analyzeImports(ghidraData.imports);
  const iocs = extractIocs(ghidraData.strings);

  const totalFunctions = ghidraData.functions.length;
  const isLargeBinary = totalFunctions > 3000;
  const llmCaps = llm.getCapabilities();
  const maxContextTokens = llmCaps.maxContextTokens ?? 128000;
  const minPriorityScore = totalFunctions > 5000 ? 40 : 20;
  const functionTokenBudget = Math.min(8000, Math.max(2000, Math.floor(maxContextTokens * 0.05)));

  // Score and prioritize functions based on binary size
  const scoredFunctions = scoreFunctionsForAnalysis(
    ghidraData as GhidraAnalysisData,
    entryPointAddress,
    isPacked,
    isLargeBinary,
  );

  const prioritizedFunctions = getFunctionsWithinBudget(
    scoredFunctions,
    functionTokenBudget,
    minPriorityScore,
  );

  // Run enhanced string analysis on Ghidra strings
  const enhancedStrings = runEnhancedStringAnalysis(ghidraData.strings);

  // Run assembly analysis if Ghidra provided disassembly
  // NOTE: disassembly is not currently provided by the MCP analyze_binary tool
  // This will be populated in Phase 3 when Ghidra scripting is enhanced
  let assemblyPatterns: AssemblyPattern[] = [];
  const ghidraDataWithDisasm = ghidraData as typeof ghidraData & { disassembly?: string };
  if (ghidraDataWithDisasm.disassembly) {
    assemblyPatterns = runAssemblyAnalysis(ghidraDataWithDisasm.disassembly);
  }

  // Log Phase 2 findings
  logger.info`Phase 2 findings: ${yaraMatches.length} YARA matches, ${cryptoFindings.length} crypto, ${assemblyPatterns.length} patterns`;

  // Build context for LLM (including Phase 2 findings)
  const analysisContext = buildAnalysisContext({
    filename: state.filename,
    riskLevel: state.triageResults?.riskLevel ?? 'UNKNOWN',
    unpackInfo: { unpacked: unpackResult.unpacked, packer: unpackResult.packer },
    functions,
    prioritizedFunctions,
    imports,
    exports: ghidraData.exports.map((e) => e.name),
    iocs,
    techniques,
    yaraMatches,
    cryptoFindings,
    assemblyPatterns,
    enhancedStrings,
    phase3Results,
    ghidraStrings: ghidraData.strings,
    totalFunctions,
    isLargeBinary,
  });

  // Get LLM assessment
  let analysisResults: AnalysisResults = {
    functions,
    imports,
    exports: ghidraData.exports.map((e) => e.name),
    iocs,
    mitreTechniques: techniques,
    capabilities: [],
    antiAnalysis: [],
    sophistication: 'Intermediate',
    keyFindings: [],
    technicalNotes: 'Analysis completed with heuristics only',
    // Phase 2 enhanced fields
    yaraMatches,
    cryptoFindings,
    assemblyPatterns,
    enhancedStrings,
    wasUnpacked: unpackResult.unpacked,
    originalPacker: unpackResult.packer,
    // Phase 3 enhanced fields
    cfgData: phase3Results.cfgData,
    ghidraCrypto: phase3Results.ghidraCrypto,
    apiCallMapping: phase3Results.apiCalls,
  };

  try {
    const llmResult = await llm.analyzeJson<{
      malwareFamily?: string;
      familyConfidence?: number;
      capabilities: string[];
      antiAnalysis: string[];
      sophistication: 'Basic' | 'Intermediate' | 'Advanced' | 'Expert';
      mitreTechniques?: MitreTechniqueInput[];
      iocs?: Partial<IOCs>;
      keyFindings: string[];
      technicalNotes: string;
    }>(ANALYZER_SYSTEM_PROMPT, analysisContext, { temperature: 0.1 });

    if (llmResult) {
      analysisResults = mergeLlmResults(analysisResults, llmResult, techniques);
    }
  } catch (error) {
    logger.error`LLM analysis failed: ${error}`;
    analysisResults.keyFindings = createFallbackFindings(
      functions,
      iocs,
      techniques,
      yaraMatches,
      cryptoFindings,
      assemblyPatterns,
    );
  }

  // Add MITRE techniques from assembly patterns
  addAssemblyPatternTechniques(analysisResults, assemblyPatterns);

  const mitreMapper = new MitreMapper();
  const mappedTechniques = mitreMapper.map(analysisResults);
  analysisResults.mitreTechniques = mitreMapper.merge(
    analysisResults.mitreTechniques,
    mappedTechniques,
  );

  // ============================================================================
  // Phase 3.1: Iterative Deep-Dive Analysis (for large binaries)
  // ============================================================================
  if (isLargeBinary && scoredFunctions.length > 100) {
    await runIterativeDeepDive(
      scoredFunctions,
      analysisResults,
      maxContextTokens,
      minPriorityScore,
      llm,
    );
  }

  // ============================================================================
  // Phase 3.5: Behavioral Analysis Hints
  // ============================================================================
  logger.info`Running behavioral analysis...`;
  const behaviorPredictor = new BehaviorPredictor();
  const behaviorHints = behaviorPredictor.predict(analysisResults);
  analysisResults.behaviorHints = behaviorHints;
  analysisResults.mitreTechniques = behaviorPredictor.augmentTechniques(
    analysisResults.mitreTechniques,
    behaviorHints,
  );

  // ============================================================================
  // Phase 3: Multi-Model Specialist Analysis
  // ============================================================================
  logger.info`Running Phase 3 multi-model specialist analysis...`;
  const multiModelResults = await runMultiModelAnalysis(analysisResults, state.filename);

  if (multiModelResults.specialistFindings) {
    analysisResults.specialistFindings = multiModelResults.specialistFindings;
  }
  if (multiModelResults.overallAssessment) {
    analysisResults.overallAssessment = multiModelResults.overallAssessment;
  }
  if (multiModelResults.malwareLikelihood !== undefined) {
    analysisResults.malwareLikelihood = multiModelResults.malwareLikelihood;
  }

  logger.info`Analysis complete: ${analysisResults.mitreTechniques.length} techniques, ${analysisResults.capabilities.length} capabilities, ${yaraMatches.length} YARA, ${cryptoFindings.length} crypto, Phase 3: ${phase3Results.cfgData ? 'CFG' : ''} ${phase3Results.ghidraCrypto ? 'Crypto' : ''} ${phase3Results.apiCalls ? 'API' : ''}`;

  return {
    analysisResults,
    analysisComplete: true,
    status: 'reporting',
  };
}
