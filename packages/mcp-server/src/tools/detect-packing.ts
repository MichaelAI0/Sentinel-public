/**
 * detect_packing - Detect if binary is packed or obfuscated
 *
 * Two modes:
 *   1. Fast mode (default): Local entropy + signature checks
 *   2. Deep mode: Uses Ghidra for comprehensive analysis
 *
 * Analyzes entropy, known packer signatures, section names, and import patterns.
 */

import { readFile } from 'node:fs/promises';
import type { DetectPackingInput, DetectPackingOutput } from '@sentinel/shared';
import { executeGhidraScript, isGhidraAvailable } from '../utils/ghidra-bridge.js';
import { logToolExecution } from '../utils/logger.js';

// ============================================================================
// Ghidra Script Output Types (match docker/ghidra/scripts/detect-packers.ts)
// ============================================================================

type GhidraPackerOutput = {
  success: boolean;
  error?: string;
  data?: GhidraPackerData;
};

type GhidraPackerData = {
  binaryName: string;
  likelyPacked: boolean;
  confidence: number;
  guesses: string[];
  indicators: Array<{
    id: string;
    severity: 'low' | 'medium' | 'high';
    message: string;
    score: number;
  }>;
  sections: Array<{
    name: string;
    start: string;
    size: number;
    permissions: string;
    entropy: number;
  }>;
  metadata: {
    scriptVersion: string;
    ghidraVersion: string;
    analysisTimeMs: number;
  };
};

// ============================================================================
// Local (Fast) Detection Helpers
// ============================================================================

// Known packer signatures (first few bytes)
const PACKER_SIGNATURES: Array<{
  name: string;
  signature: Buffer;
  offset: number;
}> = [
  { name: 'UPX', signature: Buffer.from('UPX!'), offset: 0 },
  { name: 'PECompact', signature: Buffer.from([0x4d, 0x5a, 0x4c, 0x00]), offset: 0 },
];

// PE section name patterns indicating packing
const PACKER_SECTION_NAMES = [
  { pattern: /^UPX\d?$/i, packer: 'UPX' },
  { pattern: /^\.aspack$/i, packer: 'ASPack' },
  { pattern: /^\.adata$/i, packer: 'ASPack' },
  { pattern: /^\.petite$/i, packer: 'Petite' },
  { pattern: /^\.packed$/i, packer: 'Generic' },
  { pattern: /^\.vmp\d?$/i, packer: 'VMProtect' },
  { pattern: /^\.themida$/i, packer: 'Themida' },
  { pattern: /^MPRESS\d?$/i, packer: 'MPRESS' },
  { pattern: /^\.enigma\d?$/i, packer: 'Enigma' },
];

function calculateEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;

  const frequency = new Map<number, number>();
  for (const byte of buffer) {
    frequency.set(byte, (frequency.get(byte) ?? 0) + 1);
  }

  let entropy = 0;
  const length = buffer.length;
  for (const count of frequency.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 1000) / 1000;
}

function checkSignatures(buffer: Buffer): Array<{ name: string; confidence: number }> {
  const found: Array<{ name: string; confidence: number }> = [];

  for (const { name, signature, offset } of PACKER_SIGNATURES) {
    if (buffer.length > offset + signature.length) {
      const slice = buffer.subarray(offset, offset + signature.length);
      if (slice.equals(signature)) {
        found.push({ name, confidence: 0.9 });
      }
    }
  }

  return found;
}

function extractPESectionNames(buffer: Buffer): string[] {
  const sections: string[] = [];

  // Check for MZ header
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return sections;
  }

  // Get PE header offset from DOS header
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 4 > buffer.length) return sections;

  // Verify PE signature
  if (buffer.readUInt32LE(peOffset) !== 0x00004550) {
    return sections;
  }

  // Get number of sections
  const numberOfSections = buffer.readUInt16LE(peOffset + 6);
  const sizeOfOptionalHeader = buffer.readUInt16LE(peOffset + 20);
  const sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

  // Parse section names (8 bytes each, 40 bytes per section entry)
  for (let i = 0; i < numberOfSections; i++) {
    const nameOffset = sectionTableOffset + i * 40;
    if (nameOffset + 8 > buffer.length) break;

    const nameBytes = buffer.subarray(nameOffset, nameOffset + 8);
    const nullIndex = nameBytes.indexOf(0);
    const name = nameBytes.subarray(0, nullIndex === -1 ? 8 : nullIndex).toString('ascii');
    sections.push(name);
  }

  return sections;
}

function checkSectionNames(sectionNames: string[]): Array<{ name: string; confidence: number }> {
  const found: Array<{ name: string; confidence: number }> = [];

  for (const sectionName of sectionNames) {
    for (const { pattern, packer } of PACKER_SECTION_NAMES) {
      if (pattern.test(sectionName)) {
        const existing = found.find((f) => f.name === packer);
        if (existing) {
          existing.confidence = Math.min(existing.confidence + 0.2, 0.95);
        } else {
          found.push({ name: packer, confidence: 0.7 });
        }
      }
    }
  }

  return found;
}

// ============================================================================
// Fast (Local) Detection
// ============================================================================

async function detectPackingFast(
  binaryPath: string,
  options: DetectPackingInput['options'],
): Promise<DetectPackingOutput> {
  const buffer = await readFile(binaryPath);
  const indicators: DetectPackingOutput['indicators'] = [];
  const identifiedPackers: DetectPackingOutput['identifiedPackers'] = [];

  let confidence = 0;

  // Check entropy
  if (options?.checkEntropy !== false) {
    const entropy = calculateEntropy(buffer);
    const isSuspicious = entropy > 7.0;

    indicators.push({
      type: 'ENTROPY',
      value: entropy,
      suspicious: isSuspicious,
      description: isSuspicious
        ? `High entropy (${entropy}) suggests compression or encryption`
        : `Normal entropy level (${entropy})`,
    });

    if (isSuspicious) {
      confidence += 0.3;
    }
  }

  // Check signatures
  if (options?.checkSignatures !== false) {
    const signatures = checkSignatures(buffer);
    for (const sig of signatures) {
      indicators.push({
        type: 'SIGNATURE',
        value: sig.name,
        suspicious: true,
        description: `Detected ${sig.name} packer signature`,
      });
      identifiedPackers.push(sig);
      confidence += sig.confidence;
    }
  }

  // Check section names
  if (options?.checkSectionNames !== false) {
    const sectionNames = extractPESectionNames(buffer);
    const sectionPackers = checkSectionNames(sectionNames);

    for (const packer of sectionPackers) {
      indicators.push({
        type: 'SECTION_NAME',
        value: packer.name,
        suspicious: true,
        description: `Section name indicates ${packer.name} packer`,
      });

      const existing = identifiedPackers.find((p) => p.name === packer.name);
      if (existing) {
        existing.confidence = Math.min(existing.confidence + packer.confidence, 0.95);
      } else {
        identifiedPackers.push(packer);
      }
      confidence += 0.2;
    }
  }

  // Clamp confidence
  confidence = Math.min(Math.max(confidence, 0), 1);

  return {
    isPacked: confidence > 0.5,
    confidence: Math.round(confidence * 100) / 100,
    indicators,
    identifiedPackers,
  };
}

// ============================================================================
// Deep (Ghidra) Detection
// ============================================================================

async function detectPackingDeep(binaryPath: string): Promise<DetectPackingOutput> {
  const result = await executeGhidraScript<GhidraPackerOutput>({
    binaryPath,
    script: 'detect-packers',
    timeout: 5 * 60 * 1000, // 5 minutes
  });

  if (!result.success || !result.data) {
    throw new Error(result.error ?? 'Ghidra packer detection failed');
  }

  const scriptOutput = result.data;
  if (!scriptOutput.success || !scriptOutput.data) {
    throw new Error(scriptOutput.error ?? 'Ghidra script returned failure');
  }

  const data = scriptOutput.data;

  // Map Ghidra indicators → MCP schema indicators
  const indicators: DetectPackingOutput['indicators'] = data.indicators.map((ind) => ({
    type: mapIndicatorType(ind.id),
    value: ind.message,
    suspicious: ind.severity !== 'low',
    description: ind.message,
  }));

  // Add section entropy indicators
  for (const section of data.sections) {
    if (section.entropy >= 7.2) {
      indicators.push({
        type: 'ENTROPY',
        value: section.entropy,
        suspicious: true,
        description: `High entropy in section ${section.name}: ${section.entropy}`,
      });
    }
  }

  // Map guesses → identified packers
  const identifiedPackers: DetectPackingOutput['identifiedPackers'] = data.guesses.map((name) => ({
    name,
    confidence: data.confidence,
  }));

  return {
    isPacked: data.likelyPacked,
    confidence: data.confidence,
    indicators,
    identifiedPackers,
  };
}

function mapIndicatorType(id: string): 'ENTROPY' | 'SIGNATURE' | 'SECTION_NAME' | 'IMPORT_RATIO' {
  if (id.includes('entropy')) return 'ENTROPY';
  if (id.includes('section') || id.includes('name')) return 'SECTION_NAME';
  if (id.includes('import')) return 'IMPORT_RATIO';
  return 'SIGNATURE';
}

// ============================================================================
// Main Export
// ============================================================================

/**
 * Detect if a binary is packed or obfuscated.
 *
 * By default uses fast local analysis. If Ghidra is available and the
 * `useGhidra` option is true, performs deeper Ghidra-based analysis.
 */
export async function detectPacking(input: DetectPackingInput): Promise<DetectPackingOutput> {
  const { binaryPath, options } = input;
  const useGhidra = (options as { useGhidra?: boolean } | undefined)?.useGhidra ?? false;

  logToolExecution('detect_packing', { binaryPath, useGhidra }, 'start');

  try {
    let result: DetectPackingOutput;

    if (useGhidra) {
      const ghidraAvailable = await isGhidraAvailable();
      if (!ghidraAvailable) {
        throw new Error('Ghidra requested but container is not running');
      }
      result = await detectPackingDeep(binaryPath);
    } else {
      result = await detectPackingFast(binaryPath, options);
    }

    logToolExecution('detect_packing', { binaryPath }, 'success', {
      isPacked: result.isPacked,
      confidence: result.confidence,
      useGhidra,
    });

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('detect_packing', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to detect packing: ${errorMessage}`);
  }
}
