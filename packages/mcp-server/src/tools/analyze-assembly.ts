/**
 * Analyze Assembly Tool
 *
 * MCP tool for analyzing assembly code patterns in binaries.
 * Detects system calls, privilege operations, loops, and anti-debugging.
 *
 * @module tools/analyze-assembly
 *
 * @todo Phase 3: Add decompiler integration for C pseudocode
 * @todo Phase 4: Add graph visualization of control flow
 */

import { getLogger } from '@logtape/logtape';
import {
  type AssemblyAnalysisSummary,
  AssemblyExtractor,
  type AssemblyInstruction,
} from '@sentinel/orchestrator';
import { z } from 'zod';

const logger = getLogger(['sentinel', 'tools', 'analyze-assembly']);

// ============================================
// INPUT SCHEMA
// ============================================

export const AnalyzeAssemblyInputSchema = z.object({
  /** Raw assembly text to analyze (objdump or Ghidra format) */
  assembly_text: z.string().describe('Assembly text to analyze'),
  /** Optional function name for context */
  function_name: z.string().optional().describe('Name of function being analyzed'),
});

export type AnalyzeAssemblyInput = z.infer<typeof AnalyzeAssemblyInputSchema>;

// ============================================
// OUTPUT TYPES
// ============================================

export type AnalyzeAssemblyOutput = {
  success: boolean;
  summary?: AssemblyAnalysisSummary;
  instructions?: AssemblyInstruction[];
  error?: string;
};

// ============================================
// TOOL IMPLEMENTATION
// ============================================

let extractor: AssemblyExtractor | null = null;

/**
 * Get or create extractor instance
 */
function getExtractorInstance(): AssemblyExtractor {
  if (!extractor) {
    extractor = new AssemblyExtractor();
  }
  return extractor;
}

/**
 * Analyze assembly code for patterns and anomalies
 *
 * @param input - Tool input parameters
 * @returns Analysis results with detected patterns
 */
export async function analyzeAssembly(input: AnalyzeAssemblyInput): Promise<AnalyzeAssemblyOutput> {
  const { assembly_text, function_name } = AnalyzeAssemblyInputSchema.parse(input);

  logger.info`Analyzing assembly${function_name ? ` for ${function_name}` : ''}`;

  try {
    const extractorInstance = getExtractorInstance();

    // Parse assembly text into structured instructions
    const instructions = extractorInstance.parseAssemblyText(assembly_text);

    if (instructions.length === 0) {
      return {
        success: false,
        error: 'No valid assembly instructions found in input',
      };
    }

    // Create a synthetic function for summarization
    const syntheticFunction = {
      address: instructions[0]?.address ?? '0x0',
      name: function_name ?? 'analyzed_function',
      size: instructions.length,
      instructions,
    };

    // Generate analysis summary
    const summary = extractorInstance.summarize([syntheticFunction]);

    logger.info`Found ${summary.patterns.length} patterns in ${instructions.length} instructions`;

    return {
      success: true,
      summary,
      instructions,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error`Assembly analysis failed: ${message}`;

    return {
      success: false,
      error: message,
    };
  }
}

// ============================================
// TOOL DEFINITION
// ============================================

export const analyzeAssemblyTool = {
  name: 'analyze_assembly',
  description:
    'Analyze assembly code for patterns including system calls, privilege operations, ' +
    'loops, anti-debugging techniques, and cryptographic instructions. ' +
    'Input can be in objdump or Ghidra disassembly format.',
  inputSchema: AnalyzeAssemblyInputSchema,
  handler: analyzeAssembly,
};
