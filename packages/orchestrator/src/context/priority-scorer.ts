/**
 * Priority Scorer
 * Scores functions based on risk factors to prioritize analysis
 *
 * Scoring Algorithm v2:
 * - Base scoring from suspicious API patterns, anti-analysis, crypto, etc.
 * - Section entropy correlation: boost functions in/near high-entropy sections
 * - Entry point distance: boost functions reachable from entry (likely executed)
 * - Behavior clustering: boost functions matching known malicious behavior patterns
 * - Dynamic reprioritization: boost callees of already-analyzed suspicious functions
 */

import { SUSPICIOUS_APIS } from '@sentinel/shared';
import {
  checkNearHighEntropy,
  enrichFunctions,
  getBehaviorClusterBoost,
  getEntryDistanceScore,
  getSectionEntropyScore,
  type ImportInfo,
  type RawFunction,
  type RawSection,
} from './section-correlator.js';
import type { EnrichedFunction, RiskFactors, ScoredFunction } from './types.js';

/**
 * Anti-analysis indicators in function names
 */
const ANTI_ANALYSIS_PATTERNS = [
  /anti.?debug/i,
  /check.?debug/i,
  /is.?debug/i,
  /vm.?detect/i,
  /sandbox/i,
  /virtual.?machine/i,
  /emulat/i,
  /timing.?check/i,
  /sleep.?loop/i,
  /obfuscat/i,
  /decrypt/i,
  /unpack/i,
  /decompress/i,
];

/**
 * Network-related patterns
 */
const NETWORK_PATTERNS = [
  /socket/i,
  /connect/i,
  /send/i,
  /recv/i,
  /http/i,
  /download/i,
  /upload/i,
  /beacon/i,
  /c2/i,
  /command.?control/i,
  /exfil/i,
];

/**
 * Crypto-related patterns
 */
const CRYPTO_PATTERNS = [
  /crypt/i,
  /cipher/i,
  /aes/i,
  /rsa/i,
  /rc4/i,
  /xor/i,
  /encode/i,
  /decode/i,
  /encrypt/i,
  /decrypt/i,
  /hash/i,
  /md5/i,
  /sha/i,
];

/**
 * Weight configuration for scoring
 */
const SCORE_WEIGHTS = {
  // Base behavioral patterns
  hasSuspiciousApis: 25,
  hasAntiAnalysis: 20,
  hasNetworkCalls: 15,
  hasCrypto: 15,
  hasProcessManip: 20,
  hasFileOps: 10,
  hasRegistryOps: 10,
  // Function-level entropy
  highEntropy: 15, // entropy > 7
  mediumEntropy: 8, // entropy > 6
  largeFunction: 5, // size > 1000
  highCallerCount: 10, // callerCount > 5
  highComplexity: 10, // complexity > 20
  veryLargeFunction: 10, // size >= 95th percentile
  largeFunctionPercentile: 5, // size >= 90th percentile
  highCallDegree: 12, // call degree >= 95th percentile
  mediumCallDegree: 6, // call degree >= 90th percentile
  obfuscatedName: 5, // sub_/FUN_/fcn_ with high size/degree
  // Enrichment factors (Phase A)
  sectionHighEntropy: 18, // function in high-entropy section
  sectionMediumEntropy: 10, // function in medium-entropy section
  nearHighEntropy: 12, // adjacent to high-entropy section
  entryPointDirect: 15, // entry point or distance 0
  entryPointClose: 10, // distance 1-2
  entryPointReachable: 5, // distance 3-5
  // Packing-related boosts (Phase 2)
  packedBinaryEntryRegion: 20, // entry point region in packed binary (likely OEP/unpacker)
  packedBinaryHighEntropy: 15, // high entropy function in packed binary
  packedBinaryUnpackerStub: 18, // function matching unpacker stub patterns
  // Behavior cluster boosts are applied via getBehaviorClusterBoost()
};

const OBFUSCATED_NAME_PATTERNS = [/^sub_/i, /^fun_/i, /^fcn_/i, /^func_/i, /^unk_/i];

/**
 * Threshold scoring rule - Matt Pocock style type-safe declarative rules
 */
type ThresholdRule<T extends number> = {
  threshold: T;
  score: number;
};

/**
 * Apply threshold-based scoring rules (checks in order, returns first match)
 */
function applyThresholdScoring(value: number, rules: ThresholdRule<number>[]): number {
  for (const rule of rules) {
    if (value >= rule.threshold) {
      return rule.score;
    }
  }
  return 0;
}

function getPercentileThreshold(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.floor((sorted.length - 1) * percentile);
  return sorted[index] ?? 0;
}

/**
 * Calculate priority score for a function
 */
export function calculatePriorityScore(
  name: string,
  factors: Partial<RiskFactors>,
): { score: number; factors: Partial<RiskFactors> } {
  let score = 0;
  const detectedFactors: Partial<RiskFactors> = { ...factors };

  // Check name patterns
  if (!detectedFactors.hasAntiAnalysis) {
    detectedFactors.hasAntiAnalysis = ANTI_ANALYSIS_PATTERNS.some((p) => p.test(name));
  }
  if (!detectedFactors.hasNetworkCalls) {
    detectedFactors.hasNetworkCalls = NETWORK_PATTERNS.some((p) => p.test(name));
  }
  if (!detectedFactors.hasCrypto) {
    detectedFactors.hasCrypto = CRYPTO_PATTERNS.some((p) => p.test(name));
  }

  // Type-safe factor-to-weight mapping for boolean flags
  const FACTOR_WEIGHT_MAP = {
    hasSuspiciousApis: SCORE_WEIGHTS.hasSuspiciousApis,
    hasAntiAnalysis: SCORE_WEIGHTS.hasAntiAnalysis,
    hasNetworkCalls: SCORE_WEIGHTS.hasNetworkCalls,
    hasCrypto: SCORE_WEIGHTS.hasCrypto,
    hasProcessManip: SCORE_WEIGHTS.hasProcessManip,
    hasFileOps: SCORE_WEIGHTS.hasFileOps,
    hasRegistryOps: SCORE_WEIGHTS.hasRegistryOps,
  } as const satisfies Record<string, number>;

  // Apply boolean factor weights
  for (const [factor, weight] of Object.entries(FACTOR_WEIGHT_MAP)) {
    if (detectedFactors[factor as keyof typeof FACTOR_WEIGHT_MAP]) {
      score += weight;
    }
  }

  // Entropy threshold scoring
  if (detectedFactors.entropy !== undefined) {
    score += applyThresholdScoring(detectedFactors.entropy, [
      { threshold: 7, score: SCORE_WEIGHTS.highEntropy },
      { threshold: 6, score: SCORE_WEIGHTS.mediumEntropy },
    ]);
  }

  // Size scoring
  if (detectedFactors.size !== undefined && detectedFactors.size > 1000) {
    score += SCORE_WEIGHTS.largeFunction;
  }

  // Caller count scoring (more callers = more important)
  if (detectedFactors.callerCount !== undefined && detectedFactors.callerCount > 5) {
    score += SCORE_WEIGHTS.highCallerCount;
  }

  // Complexity scoring
  if (detectedFactors.complexity !== undefined && detectedFactors.complexity > 20) {
    score += SCORE_WEIGHTS.highComplexity;
  }

  // Clamp to 0-100
  score = Math.min(100, Math.max(0, score));

  return { score, factors: detectedFactors };
}

/**
 * Check if a function has suspicious API calls
 */
export function hasSuspiciousApiCalls(
  imports: Array<{ function: string; library?: string }>,
): boolean {
  return imports.some((imp) => SUSPICIOUS_APIS.has(imp.function));
}

/**
 * Extract risk factors from function data
 */
export function extractRiskFactors(func: {
  name: string;
  size?: number;
  callers?: string[];
  callees?: string[];
  decompiled?: string;
  imports?: Array<{ function: string }>;
}): Partial<RiskFactors> {
  const factors: Partial<RiskFactors> = {
    size: func.size ?? 0,
    callerCount: func.callers?.length ?? 0,
    calleeCount: func.callees?.length ?? 0,
  };

  const nameAndCode = `${func.name} ${func.decompiled ?? ''}`;

  // Check patterns in name and decompiled code
  factors.hasAntiAnalysis = ANTI_ANALYSIS_PATTERNS.some((p) => p.test(nameAndCode));
  factors.hasNetworkCalls = NETWORK_PATTERNS.some((p) => p.test(nameAndCode));
  factors.hasCrypto = CRYPTO_PATTERNS.some((p) => p.test(nameAndCode));

  // Check for suspicious APIs in imports
  if (func.imports) {
    factors.hasSuspiciousApis = hasSuspiciousApiCalls(func.imports);
  }

  // Check decompiled code for specific patterns
  if (func.decompiled) {
    factors.hasProcessManip = /CreateProcess|OpenProcess|TerminateProcess|fork|execve/i.test(
      func.decompiled,
    );
    factors.hasFileOps = /CreateFile|WriteFile|DeleteFile|fopen|fwrite|unlink/i.test(
      func.decompiled,
    );
    factors.hasRegistryOps = /RegSetValue|RegCreateKey|RegOpenKey/i.test(func.decompiled);
  }

  return factors;
}

/**
 * Score and sort functions by priority
 */
export function scoreFunctions(
  functions: Array<{
    name: string;
    address: string;
    size?: number;
    callers?: string[];
    callees?: string[];
    decompiled?: string;
    imports?: Array<{ function: string }>;
  }>,
): ScoredFunction[] {
  const sizes = functions.map((func) => func.size ?? 0).filter((v) => v > 0);
  const callDegrees = functions
    .map((func) => (func.callers?.length ?? 0) + (func.callees?.length ?? 0))
    .filter((v) => v > 0);

  const size90 = getPercentileThreshold(sizes, 0.9);
  const size95 = getPercentileThreshold(sizes, 0.95);
  const degree90 = getPercentileThreshold(callDegrees, 0.9);
  const degree95 = getPercentileThreshold(callDegrees, 0.95);

  const scored: ScoredFunction[] = functions.map((func) => {
    const riskFactors = extractRiskFactors(func);
    const { score: baseScore, factors } = calculatePriorityScore(func.name, riskFactors);

    const size = func.size ?? 0;
    const callDegree = (func.callers?.length ?? 0) + (func.callees?.length ?? 0);
    let score = baseScore;

    // Apply threshold-based scoring using declarative rules
    score += applyThresholdScoring(size, [
      { threshold: size95, score: SCORE_WEIGHTS.veryLargeFunction },
      { threshold: size90, score: SCORE_WEIGHTS.largeFunctionPercentile },
    ]);

    score += applyThresholdScoring(callDegree, [
      { threshold: degree95, score: SCORE_WEIGHTS.highCallDegree },
      { threshold: degree90, score: SCORE_WEIGHTS.mediumCallDegree },
    ]);

    const hasObfuscatedName = OBFUSCATED_NAME_PATTERNS.some((p) => p.test(func.name));
    if (hasObfuscatedName && (size >= size90 || callDegree >= degree90)) {
      score += SCORE_WEIGHTS.obfuscatedName;
    }

    score = Math.min(100, Math.max(0, score));

    // Estimate tokens (roughly 4 chars per token)
    const codeLength = func.decompiled?.length ?? 0;
    const estimatedTokens = Math.ceil(codeLength / 4) + 50; // +50 for metadata

    return {
      address: func.address,
      name: func.name,
      score,
      factors,
      estimatedTokens,
      analyzed: false,
    };
  });

  // Sort by score descending
  return scored.sort((a, b) => b.score - a.score);
}

/**
 * Enhanced scoring with section correlation, entry distance, and behavior clusters
 *
 * This is the cutting-edge scoring algorithm that uses structural binary data
 * to make smarter prioritization decisions.
 *
 * @param isPacked - If true, applies packing-aware boosts to entry regions and high-entropy functions
 */
export function scoreFunctionsEnriched(
  functions: RawFunction[],
  sections: RawSection[],
  imports: ImportInfo[],
  entryPointAddress?: string,
  isPacked = false,
): ScoredFunction[] {
  // First, enrich all functions with structural data
  const enrichedFunctions = enrichFunctions(functions, sections, imports, entryPointAddress);

  // Calculate percentile thresholds
  const thresholds = calculatePercentileThresholds(functions);

  // Build address to enriched function map
  const addressToEnriched = new Map<string, EnrichedFunction>();
  for (const ef of enrichedFunctions) {
    addressToEnriched.set(ef.address, ef);
  }

  const scored: ScoredFunction[] = functions.map((func) => {
    const enriched = addressToEnriched.get(func.address);
    return scoreFunction(func, enriched, sections, thresholds, isPacked);
  });

  // Sort by score descending
  return scored.sort((a, b) => b.score - a.score);
}

/**
 * Percentile thresholds for size and call degree scoring
 */
interface PercentileThresholds {
  size90: number;
  size95: number;
  degree90: number;
  degree95: number;
}

/**
 * Calculate percentile thresholds for functions
 */
function calculatePercentileThresholds(functions: RawFunction[]): PercentileThresholds {
  const sizes = functions.map((f) => f.size).filter((v) => v > 0);
  const callDegrees = functions
    .map((f) => f.callers.length + f.callees.length)
    .filter((v) => v > 0);

  return {
    size90: getPercentileThreshold(sizes, 0.9),
    size95: getPercentileThreshold(sizes, 0.95),
    degree90: getPercentileThreshold(callDegrees, 0.9),
    degree95: getPercentileThreshold(callDegrees, 0.95),
  };
}

/**
 * Score a single function with enrichment data
 */
function scoreFunction(
  func: RawFunction,
  enriched: EnrichedFunction | undefined,
  sections: RawSection[],
  thresholds: PercentileThresholds,
  isPacked: boolean,
): ScoredFunction {
  const riskFactors = extractRiskFactors({
    name: func.name,
    size: func.size,
    callers: func.callers,
    callees: func.callees,
  });

  // Add enrichment factors to risk factors
  if (enriched) {
    riskFactors.sectionEntropy = enriched.section?.entropy;
    riskFactors.entryPointDistance = enriched.entryPointDistance;
    riskFactors.isEntryReachable = enriched.isEntryReachable;
    riskFactors.behaviorCluster = enriched.behaviorCluster;
    riskFactors.nearHighEntropy = checkNearHighEntropy(func.address, sections);
  }

  // Base scoring
  const { score: baseScore, factors } = calculatePriorityScore(func.name, riskFactors);
  let score = baseScore;

  // Apply size and call degree scoring
  score += calculateSizeAndDegreeScore(func, thresholds);

  // Apply enrichment scoring
  if (enriched) {
    score += calculateEnrichmentScore(enriched, riskFactors, func.name, isPacked);
  }

  // Clamp score
  score = Math.min(100, Math.max(0, score));

  // Estimate tokens (roughly 4 chars per token, +50 for metadata)
  const estimatedTokens = Math.ceil(func.size / 2) + 50;

  return {
    address: func.address,
    name: func.name,
    score,
    factors: { ...factors, ...riskFactors },
    estimatedTokens,
    analyzed: false,
    enrichment: enriched,
  };
}

/**
 * Calculate score contribution from function size and call degree
 */
function calculateSizeAndDegreeScore(func: RawFunction, thresholds: PercentileThresholds): number {
  const size = func.size;
  const callDegree = func.callers.length + func.callees.length;

  // Apply threshold-based scoring using declarative rules
  let score = applyThresholdScoring(size, [
    { threshold: thresholds.size95, score: SCORE_WEIGHTS.veryLargeFunction },
    { threshold: thresholds.size90, score: SCORE_WEIGHTS.largeFunctionPercentile },
  ]);

  score += applyThresholdScoring(callDegree, [
    { threshold: thresholds.degree95, score: SCORE_WEIGHTS.highCallDegree },
    { threshold: thresholds.degree90, score: SCORE_WEIGHTS.mediumCallDegree },
  ]);

  // Obfuscated name scoring
  const hasObfuscatedName = OBFUSCATED_NAME_PATTERNS.some((p) => p.test(func.name));
  if (hasObfuscatedName && (size >= thresholds.size90 || callDegree >= thresholds.degree90)) {
    score += SCORE_WEIGHTS.obfuscatedName;
  }

  return score;
}

/**
 * Calculate score contribution from enrichment data
 */
function calculateEnrichmentScore(
  enriched: EnrichedFunction,
  riskFactors: Partial<RiskFactors>,
  funcName: string,
  isPacked: boolean,
): number {
  let score = 0;

  // Section entropy scoring using threshold rules
  const sectionEntropyScore = getSectionEntropyScore(enriched);
  score += applyThresholdScoring(sectionEntropyScore, [
    { threshold: 1.0, score: SCORE_WEIGHTS.sectionHighEntropy },
    { threshold: 0.6, score: SCORE_WEIGHTS.sectionMediumEntropy },
  ]);

  // Near high-entropy section
  if (riskFactors.nearHighEntropy) {
    score += SCORE_WEIGHTS.nearHighEntropy;
  }

  // Entry point distance scoring using threshold rules
  const entryScore = getEntryDistanceScore(enriched);
  score += applyThresholdScoring(entryScore, [
    { threshold: 1.0, score: SCORE_WEIGHTS.entryPointDirect },
    { threshold: 0.8, score: SCORE_WEIGHTS.entryPointClose },
    { threshold: 0.5, score: SCORE_WEIGHTS.entryPointReachable },
  ]);

  // Behavior cluster boost
  score += getBehaviorClusterBoost(enriched.behaviorCluster);

  // Packing-aware scoring
  if (isPacked) {
    score += calculatePackingScore(enriched, riskFactors, funcName, entryScore);
  }

  return score;
}

/**
 * Calculate score contribution for packed binaries
 */
function calculatePackingScore(
  _enriched: EnrichedFunction,
  riskFactors: Partial<RiskFactors>,
  funcName: string,
  entryScore: number,
): number {
  let score = 0;

  // In packed binaries, entry point region is critical (likely OEP or unpacker stub)
  if (entryScore >= 1.0) {
    score += SCORE_WEIGHTS.packedBinaryEntryRegion;
  }

  // High entropy functions in packed binary are likely the packed payload
  if (riskFactors.sectionEntropy !== undefined && riskFactors.sectionEntropy > 7.0) {
    score += SCORE_WEIGHTS.packedBinaryHighEntropy;
  }

  // Check for unpacker stub patterns in function name
  const unpackerPatterns = [/unpack/i, /decompress/i, /decrypt/i, /decode/i, /loader/i];
  if (unpackerPatterns.some((p) => p.test(funcName))) {
    score += SCORE_WEIGHTS.packedBinaryUnpackerStub;
  }

  return score;
}

/**
 * Get top N functions by priority score
 */
export function getTopPriorityFunctions(
  scoredFunctions: ScoredFunction[],
  n: number,
  minScore = 0,
): ScoredFunction[] {
  return scoredFunctions.filter((f) => !f.analyzed && f.score >= minScore).slice(0, n);
}

/**
 * Get functions that fit within a token budget
 */
export function getFunctionsWithinBudget(
  scoredFunctions: ScoredFunction[],
  tokenBudget: number,
  minScore = 0,
): ScoredFunction[] {
  const result: ScoredFunction[] = [];
  let tokensUsed = 0;

  for (const func of scoredFunctions) {
    if (func.analyzed) continue;
    if (func.score < minScore) continue;
    if (tokensUsed + func.estimatedTokens > tokenBudget) continue;

    result.push(func);
    tokensUsed += func.estimatedTokens;
  }

  return result;
}

/**
 * Dynamic reprioritization based on analysis discoveries
 *
 * When a suspicious function is analyzed, boost the priority of its callees
 * This ensures we follow interesting execution paths discovered during analysis
 *
 * @param scoredFunctions - Current scored functions list
 * @param suspiciousAddresses - Addresses of functions found to be suspicious
 * @param boostAmount - How much to boost callee scores (default: 15)
 * @returns Updated scored functions list with boosted scores
 */
export function reprioritizeFromDiscoveries(
  scoredFunctions: ScoredFunction[],
  suspiciousAddresses: Set<string>,
  boostAmount = 15,
): ScoredFunction[] {
  // Build address to function map
  const addressToFunc = new Map<string, ScoredFunction>();
  for (const func of scoredFunctions) {
    addressToFunc.set(func.address, func);
  }

  // Collect all callees of suspicious functions
  const calleesToBoost = new Set<string>();

  for (const addr of suspiciousAddresses) {
    const func = addressToFunc.get(addr);
    if (func?.enrichment?.callees) {
      for (const calleeAddr of func.enrichment.callees) {
        // Only boost if not already analyzed
        const callee = addressToFunc.get(calleeAddr);
        if (callee && !callee.analyzed) {
          calleesToBoost.add(calleeAddr);
        }
      }
    }
  }

  // Apply boosts
  return scoredFunctions
    .map((func) => {
      if (calleesToBoost.has(func.address)) {
        const newScore = Math.min(100, func.score + boostAmount);
        return {
          ...func,
          score: newScore,
          dynamicBoost: (func.dynamicBoost ?? 0) + boostAmount,
        };
      }
      return func;
    })
    .sort((a, b) => b.score - a.score); // Re-sort after boost
}

/**
 * Apply decay to scores of functions that have been in queue too long
 * This prevents low-priority functions from blocking analysis forever
 *
 * @param scoredFunctions - Current scored functions list
 * @param decayFactor - How much to reduce scores (default: 0.9, meaning 10% decay)
 * @param minIterationsBeforeDecay - Don't decay until this many iterations (default: 3)
 * @param currentIteration - Current iteration number
 */
export function applyScoreDecay(
  scoredFunctions: ScoredFunction[],
  currentIteration: number,
  decayFactor = 0.9,
  minIterationsBeforeDecay = 3,
): ScoredFunction[] {
  if (currentIteration < minIterationsBeforeDecay) {
    return scoredFunctions;
  }

  return scoredFunctions
    .map((func) => {
      if (!func.analyzed && func.score > 20) {
        // Only decay unanalyzed functions above minimum threshold
        const decayedScore = Math.max(20, Math.floor(func.score * decayFactor));
        return { ...func, score: decayedScore };
      }
      return func;
    })
    .sort((a, b) => b.score - a.score);
}

/**
 * Get statistics about the current scoring state
 */
export function getScoringStats(scoredFunctions: ScoredFunction[]): {
  total: number;
  analyzed: number;
  pending: number;
  highPriority: number;
  mediumPriority: number;
  lowPriority: number;
  avgScore: number;
  byCluster: Record<string, number>;
} {
  const analyzed = scoredFunctions.filter((f) => f.analyzed).length;
  const pending = scoredFunctions.filter((f) => !f.analyzed);
  const highPriority = pending.filter((f) => f.score >= 60).length;
  const mediumPriority = pending.filter((f) => f.score >= 30 && f.score < 60).length;
  const lowPriority = pending.filter((f) => f.score < 30).length;

  const avgScore =
    pending.length > 0 ? pending.reduce((sum, f) => sum + f.score, 0) / pending.length : 0;

  const byCluster: Record<string, number> = {};
  for (const func of pending) {
    const cluster = func.factors.behaviorCluster ?? 'unknown';
    byCluster[cluster] = (byCluster[cluster] ?? 0) + 1;
  }

  return {
    total: scoredFunctions.length,
    analyzed,
    pending: pending.length,
    highPriority,
    mediumPriority,
    lowPriority,
    avgScore: Math.round(avgScore * 10) / 10,
    byCluster,
  };
}
