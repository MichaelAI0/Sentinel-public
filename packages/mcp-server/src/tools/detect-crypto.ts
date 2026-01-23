/**
 * Detect Crypto Tool
 *
 * MCP tool for detecting cryptographic operations in binaries.
 * Identifies crypto constants, entropy patterns, XOR encoding,
 * custom encryption patterns, and extracts certificates/keys.
 *
 * @module tools/detect-crypto
 *
 * @todo Phase 4: Add weak crypto vulnerability detection
 */

import { getLogger } from '@logtape/logtape';
import { type CryptoAnalysisSummary, CryptoDetector } from '@sentinel/orchestrator';
import { z } from 'zod';

const logger = getLogger(['sentinel', 'tools', 'detect-crypto']);

// ============================================
// INPUT SCHEMA
// ============================================

export const DetectCryptoInputSchema = z.object({
  /** Path to binary file to analyze */
  file_path: z.string().describe('Path to binary file to scan for crypto'),
  /** Include XOR detection (can be slow for large files) */
  detect_xor: z.boolean().default(false).describe('Whether to detect single-byte XOR encoding'),
  /** Minimum confidence threshold (0-1) */
  min_confidence: z
    .number()
    .min(0)
    .max(1)
    .default(0.5)
    .describe('Minimum confidence threshold for detections'),
});

export type DetectCryptoInput = z.infer<typeof DetectCryptoInputSchema>;

// ============================================
// OUTPUT TYPES
// ============================================

export type DetectCryptoOutput = {
  success: boolean;
  summary?: CryptoAnalysisSummary;
  fileSize?: number;
  error?: string;
};

// ============================================
// TOOL IMPLEMENTATION
// ============================================

let detector: CryptoDetector | null = null;

/**
 * Get or create detector instance
 */
function getDetectorInstance(minConfidence: number): CryptoDetector {
  if (!detector || detector !== null) {
    // Always create fresh to use provided config
    detector = new CryptoDetector({ minConfidence });
  }
  return detector;
}

/**
 * Detect cryptographic operations in a binary file
 *
 * @param input - Tool input parameters
 * @returns Crypto detection results
 */
export async function detectCrypto(input: DetectCryptoInput): Promise<DetectCryptoOutput> {
  const { file_path, detect_xor, min_confidence } = DetectCryptoInputSchema.parse(input);

  logger.info`Scanning ${file_path} for crypto signatures`;

  try {
    // Check if file exists
    const file = Bun.file(file_path);
    const exists = await file.exists();

    if (!exists) {
      return {
        success: false,
        error: `File not found: ${file_path}`,
      };
    }

    // Read file content
    const buffer = await file.arrayBuffer();
    const data = new Uint8Array(buffer);

    logger.debug`Read ${data.length} bytes from ${file_path}`;

    // Create detector and analyze
    const detectorInstance = getDetectorInstance(min_confidence);
    const summary = detectorInstance.analyze(data);

    // Optionally detect XOR encoding
    if (detect_xor) {
      const xorDetections = detectorInstance.detectXOR(data);
      summary.detections.push(...xorDetections);

      // Update counts
      for (const detection of xorDetections) {
        if (detection.confidence >= min_confidence) {
          summary.algorithmCounts[detection.algorithm] =
            (summary.algorithmCounts[detection.algorithm] || 0) + 1;
          summary.hasCrypto = true;
        }
      }
    }

    logger.info`Found ${summary.detections.length} crypto indicators${summary.likelyEncrypted ? ' (likely encrypted)' : ''}`;

    return {
      success: true,
      summary,
      fileSize: data.length,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error`Crypto detection failed: ${message}`;

    return {
      success: false,
      error: message,
    };
  }
}

// ============================================
// TOOL DEFINITION
// ============================================

export const detectCryptoTool = {
  name: 'detect_crypto',
  description:
    'Detect cryptographic operations in a binary file. Searches for known crypto constants ' +
    '(AES S-box, SHA-256 init values, ChaCha20, etc.), analyzes entropy patterns to identify encrypted ' +
    'sections, detects custom encryption patterns, extracts embedded certificates and cryptographic keys, ' +
    'and optionally detects XOR encoding. Returns detected algorithms with confidence levels.',
  inputSchema: DetectCryptoInputSchema,
  handler: detectCrypto,
};
