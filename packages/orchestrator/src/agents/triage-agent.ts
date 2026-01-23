/**
 * Triage Agent
 * Fast initial assessment and risk scoring
 */

import { SUSPICIOUS_APIS } from '@sentinel/shared';
import { hasFeature } from '../config/features.js';
import { getLLMClient } from '../llm/llm-client.js';
// Prompts
import { TRIAGE_SYSTEM_PROMPT } from '../prompts/index.js';
import type { AnalysisState, RiskLevel, TriageRecommendation, TriageResults } from '../types.js';
import { triageLogger as logger } from '../utils/logger.js';
import { getMcpBridge } from '../utils/mcp-bridge.js';

// Note: TRIAGE_SYSTEM_PROMPT imported from ../prompts/index.js
// See: packages/orchestrator/src/prompts/index.ts

/**
 * Extract suspicious strings from string list
 */
function findSuspiciousStrings(strings: string[]): string[] {
  const suspicious: string[] = [];

  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const urlRegex = /https?:\/\/[^\s"']+/i;
  const domainRegex = /\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b/i;
  const pathRegex = /[A-Z]:\\[\w\\]+\.\w+/i;
  const registryRegex = /HKEY_|HKLM|HKCU/i;

  for (const str of strings) {
    if (ipRegex.test(str)) suspicious.push(str);
    else if (urlRegex.test(str)) suspicious.push(str);
    else if (domainRegex.test(str) && str.includes('.')) suspicious.push(str);
    else if (pathRegex.test(str)) suspicious.push(str);
    else if (registryRegex.test(str)) suspicious.push(str);
  }

  return [...new Set(suspicious)].slice(0, 50); // Dedupe and limit
}

/**
 * Find suspicious imports from PE import table
 */
function findSuspiciousImports(imports: Array<{ dll: string; functions: string[] }>): string[] {
  const found: string[] = [];

  for (const dll of imports) {
    for (const func of dll.functions) {
      if (SUSPICIOUS_APIS.has(func)) {
        found.push(`${dll.dll}:${func}`);
      }
    }
  }

  return found;
}

/**
 * Calculate overall entropy from section entropies
 */
function calculateOverallEntropy(sections: Array<{ entropy: number }>): number {
  if (sections.length === 0) return 0;
  const sum = sections.reduce((acc, s) => acc + s.entropy, 0);
  return sum / sections.length;
}

type McpBridge = ReturnType<typeof getMcpBridge>;

type TriageData = {
  hashResult: Awaited<ReturnType<McpBridge['calculateHashes']>>;
  typeResult: Awaited<ReturnType<McpBridge['detectFileType']>>;
  stringsResult: Awaited<ReturnType<McpBridge['extractStrings']>>;
  packingResult: Awaited<ReturnType<McpBridge['detectPacking']>>;
};

async function collectTriageData(
  mcp: ReturnType<typeof getMcpBridge>,
  binaryPath: string,
): Promise<TriageData> {
  const [hashResult, typeResult, stringsResult, packingResult] = await Promise.all([
    mcp.calculateHashes(binaryPath),
    mcp.detectFileType(binaryPath),
    mcp.extractStrings(binaryPath, { minLength: 6 }),
    mcp.detectPacking(binaryPath),
  ]);
  return { hashResult, typeResult, stringsResult, packingResult };
}

type HeuristicInput = {
  isPacked: boolean;
  entropy: number;
  suspiciousImports: string[];
  suspiciousStrings: string[];
};

function computeFallbackAssessment(input: HeuristicInput): {
  riskLevel: RiskLevel;
  recommendation: TriageRecommendation;
  confidence: number;
  reasoning: string;
} {
  const { isPacked, entropy, suspiciousImports, suspiciousStrings } = input;

  if (isPacked || entropy > 7 || suspiciousImports.length > 5) {
    return {
      riskLevel: 'HIGH',
      recommendation: 'ESCALATE',
      confidence: 0.7,
      reasoning: 'Heuristic: High entropy/packing or many suspicious imports detected',
    };
  }
  if (suspiciousStrings.length > 10 || suspiciousImports.length > 2) {
    return {
      riskLevel: 'MEDIUM',
      recommendation: 'INVESTIGATE',
      confidence: 0.6,
      reasoning: 'Heuristic: Some suspicious indicators found',
    };
  }
  return {
    riskLevel: 'LOW',
    recommendation: 'IGNORE',
    confidence: 0.5,
    reasoning: 'Heuristic: No obvious malicious indicators',
  };
}

/** Extract format-specific headers based on file type */
async function extractFormatHeaders(
  mcp: ReturnType<typeof getMcpBridge>,
  binaryPath: string,
  fileType: string,
): Promise<{
  peHeaders:
    | Awaited<ReturnType<ReturnType<typeof getMcpBridge>['extractPeHeaders']>>['data']
    | null;
  elfHeaders:
    | Awaited<ReturnType<ReturnType<typeof getMcpBridge>['extractElfHeaders']>>['data']
    | null;
}> {
  if (fileType.includes('PE') || fileType.includes('Windows')) {
    const result = await mcp.extractPeHeaders(binaryPath);
    return { peHeaders: result.success ? (result.data ?? null) : null, elfHeaders: null };
  }
  if (fileType.includes('ELF') || fileType.includes('Linux')) {
    const result = await mcp.extractElfHeaders(binaryPath);
    return { peHeaders: null, elfHeaders: result.success ? (result.data ?? null) : null };
  }
  return { peHeaders: null, elfHeaders: null };
}

/** Get entropy level description */
function getEntropyDescription(entropy: number): string {
  if (entropy > 7) return 'HIGH - likely packed';
  if (entropy > 6) return 'MODERATE';
  return 'NORMAL';
}

type AnalysisContext = {
  filename: string;
  fileType: string;
  sha256: string;
  md5: string;
  entropy: number;
  isPacked: boolean;
  packerName?: string;
  suspiciousStrings: string[];
  suspiciousImports: string[];
  peHeaders:
    | Awaited<ReturnType<ReturnType<typeof getMcpBridge>['extractPeHeaders']>>['data']
    | null;
  elfHeaders:
    | Awaited<ReturnType<ReturnType<typeof getMcpBridge>['extractElfHeaders']>>['data']
    | null;
  totalStrings: number;
};

/** Build LLM analysis context string */
function buildAnalysisContextString(ctx: AnalysisContext): string {
  const lines = [
    `File: ${ctx.filename}`,
    `Type: ${ctx.fileType}`,
    `SHA256: ${ctx.sha256}`,
    `MD5: ${ctx.md5}`,
    '',
    `Entropy: ${ctx.entropy.toFixed(2)} (${getEntropyDescription(ctx.entropy)})`,
    `Packing Detected: ${ctx.isPacked ? `YES - ${ctx.packerName ?? 'Unknown packer'}` : 'NO'}`,
    '',
    `Suspicious Strings Found (${ctx.suspiciousStrings.length}):`,
    ctx.suspiciousStrings.slice(0, 20).join('\n'),
    '',
    `Suspicious API Imports (${ctx.suspiciousImports.length}):`,
    ctx.suspiciousImports.slice(0, 20).join('\n'),
    '',
  ];

  if (ctx.peHeaders) {
    const sections = ctx.peHeaders.sections
      .map((s) => `${s.name}(entropy:${s.entropy.toFixed(1)})`)
      .join(', ');
    lines.push(`PE Sections: ${sections}`);
  }
  if (ctx.elfHeaders) {
    lines.push(`ELF Class: ${ctx.elfHeaders.class}, Machine: ${ctx.elfHeaders.machine}`);
  }

  lines.push('');
  lines.push(`Total Strings: ${ctx.totalStrings}`);
  lines.push(
    `Total Imports: ${ctx.peHeaders?.imports.reduce((acc, d) => acc + d.functions.length, 0) ?? 0}`,
  );

  return lines.join('\n');
}

/** Parse strings from raw data (handles both string[] and object[]) */
function parseStrings(rawStrings: Array<string | { value: string }>): string[] {
  return rawStrings.map((s) => (typeof s === 'string' ? s : s.value));
}

/**
 * Run triage analysis on a binary
 *
 * Community Edition: Uses heuristic-only analysis (no LLM)
 * Professional+: Full LLM-powered triage with AI reasoning
 */
export async function runTriageAgent(state: AnalysisState): Promise<Partial<AnalysisState>> {
  logger.info`Starting triage for: ${state.binaryPath}`;

  const mcp = getMcpBridge();
  const useLLM = hasFeature('AI_TRIAGE');

  // Collect data in parallel for speed
  const { hashResult, typeResult, stringsResult, packingResult } = await collectTriageData(
    mcp,
    state.binaryPath,
  );

  // Check for failures
  const errors: string[] = [];
  if (!hashResult.success) errors.push(`Hash calculation failed: ${hashResult.error}`);
  if (!typeResult.success) errors.push(`File type detection failed: ${typeResult.error}`);

  const fileType = typeResult.data?.type ?? 'unknown';
  const { peHeaders, elfHeaders } = await extractFormatHeaders(mcp, state.binaryPath, fileType);

  // Extract analysis data
  const strings = parseStrings(stringsResult.data?.strings ?? []);
  const suspiciousStrings = findSuspiciousStrings(strings);
  const suspiciousImports = peHeaders ? findSuspiciousImports(peHeaders.imports) : [];
  const entropy = peHeaders ? calculateOverallEntropy(peHeaders.sections) : 0;
  const isPacked = packingResult.data?.isPacked ?? false;
  const packerName = packingResult.data?.packerName;

  // Build context for LLM analysis
  const analysisContext = buildAnalysisContextString({
    filename: state.filename,
    fileType,
    sha256: hashResult.data?.sha256 ?? 'unknown',
    md5: hashResult.data?.md5 ?? 'unknown',
    entropy,
    isPacked,
    packerName,
    suspiciousStrings,
    suspiciousImports,
    peHeaders,
    elfHeaders,
    totalStrings: strings.length,
  });

  // Get assessment (LLM for Professional+, heuristics for Community)
  let riskLevel: RiskLevel = 'MEDIUM';
  let confidence = 0.5;
  let reasoning = 'Heuristic analysis (upgrade to Professional for AI-powered triage)';
  let recommendation: TriageRecommendation = 'INVESTIGATE';

  if (useLLM) {
    try {
      const llm = getLLMClient();
      const llmResult = await llm.analyzeJson<{
        riskLevel: RiskLevel;
        confidence: number;
        reasoning: string;
        recommendation: TriageRecommendation;
        estimatedAnalysisTime?: string;
      }>(TRIAGE_SYSTEM_PROMPT, analysisContext, { temperature: 0 });

      if (llmResult) {
        riskLevel = llmResult.riskLevel;
        confidence = llmResult.confidence;
        reasoning = llmResult.reasoning;
        recommendation = llmResult.recommendation;
      }
    } catch (error) {
      logger.error`LLM analysis failed: ${error}`;
      const fallback = computeFallbackAssessment({
        isPacked,
        entropy,
        suspiciousImports,
        suspiciousStrings,
      });
      riskLevel = fallback.riskLevel;
      recommendation = fallback.recommendation;
      confidence = fallback.confidence;
      reasoning = fallback.reasoning;
    }
  } else {
    // Community Edition: Use heuristic-only analysis
    const heuristic = computeFallbackAssessment({
      isPacked,
      entropy,
      suspiciousImports,
      suspiciousStrings,
    });
    riskLevel = heuristic.riskLevel;
    recommendation = heuristic.recommendation;
    confidence = heuristic.confidence;
    reasoning = `${heuristic.reasoning} [Community Edition - upgrade for AI analysis]`;
  }

  const triageResults: TriageResults = {
    fileType,
    sha256: hashResult.data?.sha256 ?? '',
    md5: hashResult.data?.md5 ?? '',
    entropy,
    riskLevel,
    confidence,
    suspiciousStrings,
    suspiciousImports,
    isPacked,
    packerName,
    recommendation,
    reasoning,
    estimatedAnalysisTime: riskLevel === 'LOW' ? 'N/A' : '3-5 minutes',
  };

  logger.info`Triage complete: risk=${riskLevel}, confidence=${confidence.toFixed(2)}, recommendation=${recommendation}`;

  return {
    triageResults,
    triageComplete: true,
    status:
      recommendation === 'ESCALATE' || recommendation === 'INVESTIGATE' ? 'analyzing' : 'complete',
    errors: [...state.errors, ...errors],
  };
}
