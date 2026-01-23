/**
 * Analyze Strings Tool
 *
 * MCP tool for enhanced string analysis with categorization,
 * entropy scoring, encoding detection, and suspicious pattern matching.
 *
 * @module tools/analyze-strings
 *
 * @todo Phase 3: Add decryption attempts for common schemes
 * @todo Phase 4: Add threat intel enrichment for extracted IOCs
 */

import { getLogger } from '@logtape/logtape';
import {
  type AnalyzedString,
  getStringAnalyzer,
  type StringAnalysisSummary,
} from '@sentinel/orchestrator';
import { z } from 'zod';

const logger = getLogger(['sentinel', 'tools', 'analyze-strings']);

// ============================================
// INPUT SCHEMA
// ============================================

export const AnalyzeStringsInputSchema = z.object({
  /** Array of strings to analyze */
  strings: z.array(z.string()).describe('Array of strings to analyze'),
  /** Minimum string length to include (default: 4) */
  min_length: z.number().min(1).default(4).describe('Minimum string length to include'),
  /** Maximum number of strings to return (default: 1000) */
  max_strings: z.number().min(1).default(1000).describe('Maximum strings to return'),
  /** Whether to attempt base64/hex decoding (default: true) */
  attempt_decode: z.boolean().default(true).describe('Attempt to decode encoded strings'),
});

export type AnalyzeStringsInput = z.infer<typeof AnalyzeStringsInputSchema>;

// ============================================
// OUTPUT TYPES
// ============================================

export type AnalyzeStringsOutput = {
  success: boolean;
  summary?: StringAnalysisSummary;
  /** Top suspicious/interesting strings */
  highlights?: AnalyzedString[];
  error?: string;
};

// ============================================
// TOOL IMPLEMENTATION
// ============================================

/**
 * Analyze an array of strings for patterns, encoding, and suspicion
 */
export async function analyzeStrings(input: AnalyzeStringsInput): Promise<AnalyzeStringsOutput> {
  logger.info`Analyzing ${input.strings.length} strings`;

  try {
    const analyzer = getStringAnalyzer({
      minLength: input.min_length,
      maxStrings: input.max_strings,
      attemptDecode: input.attempt_decode,
    });

    const summary = analyzer.analyze(input.strings);

    logger.info`Analysis complete: ${summary.uniqueStrings} unique, ${summary.suspiciousCount} suspicious`;

    return {
      success: true,
      summary,
      highlights: summary.highValueStrings.slice(0, 20),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error`String analysis failed: ${message}`;

    return {
      success: false,
      error: message,
    };
  }
}

// ============================================
// TOOL DEFINITION
// ============================================

export const analyzeStringsTool = {
  name: 'analyze_strings',
  description:
    'Analyze an array of extracted strings for patterns, encoding, and suspicious indicators. ' +
    'Categorizes strings (URLs, filepaths, IPs, registry keys, etc.), calculates entropy, ' +
    'detects base64/hex encoding, and identifies suspicious patterns like command shell references.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      strings: {
        type: 'array',
        items: { type: 'string' },
        description: 'Array of strings to analyze',
      },
      min_length: {
        type: 'number',
        description: 'Minimum string length to include (default: 4)',
        default: 4,
      },
      max_strings: {
        type: 'number',
        description: 'Maximum number of strings to return (default: 1000)',
        default: 1000,
      },
      attempt_decode: {
        type: 'boolean',
        description: 'Whether to attempt base64/hex decoding (default: true)',
        default: true,
      },
    },
    required: ['strings'],
  },
  execute: analyzeStrings,
};
