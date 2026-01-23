/**
 * analyze_binary - Full static analysis using Ghidra headless
 *
 * This tool spawns the Ghidra container and runs the analyze.js script
 * to perform comprehensive binary analysis.
 */

import { stat } from 'node:fs/promises';
import type { AnalyzeBinaryInput, AnalyzeBinaryOutput } from '@sentinel/shared';
import { executeGhidraScript, isGhidraAvailable } from '../utils/ghidra-bridge.js';
import { logToolExecution } from '../utils/logger.js';

// ============================================================================
// Ghidra Script Output Types (match docker/ghidra/scripts/analyze.ts)
// ============================================================================

type GhidraScriptOutput = {
  success: boolean;
  error?: string;
  data?: GhidraAnalysisData;
};

type GhidraAnalysisData = {
  binaryInfo: {
    name: string;
    format: string;
    architecture: string;
    md5: string;
    sha256: string;
  };
  functions: Array<{
    name: string;
    address: string;
    size: number;
    callers: string[];
    callees: string[];
  }>;
  imports: Array<{
    library: string;
    name: string;
    address: string;
  }>;
  exports: Array<{
    name: string;
    address: string;
    type: string;
  }>;
  sections: Array<{
    name: string;
    address: string;
    size: number;
    permissions: string;
    entropy: number;
  }>;
  strings: Array<{
    value: string;
    address: string;
    type: string;
  }>;
  metadata: {
    scriptVersion: string;
    ghidraVersion: string;
    analysisTime: number;
    functionCount: number;
    importCount: number;
    sectionCount: number;
    stringCount: number;
  };
};

// ============================================================================
// Format/Architecture Mapping
// ============================================================================

const FORMAT_MAP: Record<string, AnalyzeBinaryOutput['fileInfo']['format']> = {
  'Portable Executable (PE)': 'PE32',
  PE: 'PE32',
  PE32: 'PE32',
  'PE32+': 'PE32+',
  ELF: 'ELF64',
  'ELF-32': 'ELF32',
  'ELF-64': 'ELF64',
  'Mach-O': 'UNKNOWN', // Mach-O not in current schema
};

const ARCH_MAP: Record<string, AnalyzeBinaryOutput['fileInfo']['architecture']> = {
  x86: 'x86',
  'x86:LE:32:default': 'x86',
  'x86-64': 'x64',
  'x86:LE:64:default': 'x64',
  ARM: 'ARM',
  AARCH64: 'ARM64',
};

// ============================================================================
// Transform Ghidra Output → MCP Schema
// ============================================================================

async function transformGhidraOutput(
  ghidraData: GhidraAnalysisData,
  binaryPath: string,
): Promise<AnalyzeBinaryOutput> {
  // Get file size
  let fileSize = 0;
  try {
    const stats = await stat(binaryPath);
    fileSize = stats.size;
  } catch {
    // Fallback: sum of section sizes
    fileSize = ghidraData.sections.reduce((sum, s) => sum + s.size, 0);
  }

  // Calculate average entropy from sections
  const sectionsWithEntropy = ghidraData.sections.filter((s) => s.entropy >= 0);
  const avgEntropy =
    sectionsWithEntropy.length > 0
      ? sectionsWithEntropy.reduce((sum, s) => sum + s.entropy, 0) / sectionsWithEntropy.length
      : 0;

  // Normalize string type
  const normalizeStringType = (t: string): 'ASCII' | 'UNICODE' | 'UTF8' => {
    const upper = t.toUpperCase();
    if (upper === 'UNICODE' || upper === 'UTF16') return 'UNICODE';
    if (upper === 'UTF8') return 'UTF8';
    return 'ASCII';
  };

  return {
    binaryPath,
    fileInfo: {
      format: FORMAT_MAP[ghidraData.binaryInfo.format] ?? 'UNKNOWN',
      architecture: ARCH_MAP[ghidraData.binaryInfo.architecture] ?? 'UNKNOWN',
      size: fileSize,
      entropy: Math.round(avgEntropy * 1000) / 1000,
    },
    functions: ghidraData.functions.map((f) => ({
      name: f.name,
      address: f.address,
      size: f.size,
      callers: f.callers,
      callees: f.callees,
      decompiled: undefined, // Decompilation requires separate call
    })),
    imports: ghidraData.imports.map((i) => ({
      library: i.library,
      function: i.name,
      address: i.address,
    })),
    exports: ghidraData.exports.map((e) => ({
      name: e.name,
      address: e.address,
    })),
    sections: ghidraData.sections.map((s) => ({
      name: s.name,
      virtualAddress: s.address,
      virtualSize: s.size,
      rawSize: s.size,
      entropy: s.entropy,
      permissions: s.permissions,
    })),
    strings: ghidraData.strings.map((s) => ({
      value: s.value,
      address: s.address,
      type: normalizeStringType(s.type),
    })),
    analysisMetadata: {
      ghidraVersion: ghidraData.metadata.ghidraVersion,
      analysisTime: ghidraData.metadata.analysisTime,
      analyzedAt: new Date().toISOString(),
      functionCount: ghidraData.metadata.functionCount,
    },
  };
}

// ============================================================================
// Main Export
// ============================================================================

/**
 * Perform comprehensive static analysis on a binary file using Ghidra.
 * Returns detailed information about functions, imports, exports, sections, and strings.
 */
export async function analyzeBinary(input: AnalyzeBinaryInput): Promise<AnalyzeBinaryOutput> {
  const { binaryPath } = input;

  logToolExecution('analyze_binary', { binaryPath }, 'start');

  try {
    // Check if Ghidra is available
    const ghidraAvailable = await isGhidraAvailable();
    if (!ghidraAvailable) {
      throw new Error(
        'Ghidra container is not running. Please start it with: docker-compose up -d ghidra',
      );
    }

    // Execute Ghidra analysis
    const result = await executeGhidraScript<GhidraScriptOutput>({
      binaryPath,
      script: 'analyze',
      timeout: 10 * 60 * 1000, // 10 minutes
    });

    if (!result.success || !result.data) {
      throw new Error(result.error ?? 'Ghidra analysis failed');
    }

    // Unwrap the script's {success, data} envelope
    const scriptOutput = result.data;
    if (!scriptOutput.success || !scriptOutput.data) {
      throw new Error(scriptOutput.error ?? 'Ghidra script returned failure');
    }

    // Transform and return result
    const output = await transformGhidraOutput(scriptOutput.data, binaryPath);

    logToolExecution('analyze_binary', { binaryPath }, 'success', {
      functionCount: output.analysisMetadata.functionCount,
      importCount: output.imports.length,
      executionTime: result.executionTime,
    });

    return output;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('analyze_binary', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to analyze binary: ${errorMessage}`);
  }
}
