/**
 * Unpack Binary Tool
 *
 * MCP tool for unpacking packed/obfuscated binaries.
 * Supports UPX and provides detection for other common packers.
 * Includes multi-layer unpacking for nested packers.
 *
 * @module tools/unpack-binary
 *
 * @todo Phase 4: Add virtualization-based unpacking
 */

import { getLogger } from '@logtape/logtape';
import {
  BinaryUnpacker,
  type MultiLayerUnpackResult,
  type PackerDetection,
  type PackerType,
  type UnpackResult,
} from '@sentinel/orchestrator';
import { z } from 'zod';

const logger = getLogger(['sentinel', 'tools', 'unpack-binary']);

// ============================================
// INPUT SCHEMA
// ============================================

export const UnpackBinaryInputSchema = z.object({
  /** Path to potentially packed binary */
  file_path: z.string().describe('Path to binary file to unpack'),
  /** Packer type (auto-detect if not specified) */
  packer_type: z
    .enum(['upx', 'aspack', 'mpress', 'petite', 'auto'])
    .default('auto')
    .describe('Packer type (auto-detect if not specified)'),
  /** Timeout in seconds */
  timeout: z.number().positive().default(30).describe('Unpack timeout in seconds'),
  /** Enable multi-layer unpacking for nested packers */
  multi_layer: z
    .boolean()
    .default(false)
    .describe('Enable multi-layer unpacking for nested packers'),
  /** Maximum layers to unpack (default: 5) */
  max_layers: z.number().int().positive().max(10).default(5).describe('Maximum layers to unpack'),
});

export type UnpackBinaryInput = z.infer<typeof UnpackBinaryInputSchema>;

// ============================================
// OUTPUT TYPES
// ============================================

export type UnpackBinaryOutput = {
  success: boolean;
  detection: PackerDetection;
  unpack?: UnpackResult;
  multiLayer?: MultiLayerUnpackResult;
  error?: string;
};

// ============================================
// TOOL IMPLEMENTATION
// ============================================

let unpacker: BinaryUnpacker | null = null;
let currentConfig: { timeoutMs: number; maxUnpackLayers: number } | null = null;

/**
 * Get or create unpacker instance with specific config
 */
function getUnpackerInstance(timeoutMs: number, maxUnpackLayers = 5): BinaryUnpacker {
  // Create new instance if config changed or doesn't exist
  if (
    !unpacker ||
    !currentConfig ||
    currentConfig.timeoutMs !== timeoutMs ||
    currentConfig.maxUnpackLayers !== maxUnpackLayers
  ) {
    unpacker = new BinaryUnpacker({ timeoutMs, maxUnpackLayers });
    currentConfig = { timeoutMs, maxUnpackLayers };
  }
  return unpacker;
}

/**
 * Detect and unpack a binary file
 *
 * @param input - Tool input parameters
 * @returns Detection and unpack results
 */
export async function unpackBinary(input: UnpackBinaryInput): Promise<UnpackBinaryOutput> {
  const { file_path, packer_type, timeout, multi_layer, max_layers } =
    UnpackBinaryInputSchema.parse(input);

  logger.info`Processing ${file_path} for unpacking (type: ${packer_type}, multi-layer: ${multi_layer})`;

  try {
    const unpackerInstance = getUnpackerInstance(timeout * 1000, multi_layer ? max_layers : 5);

    // First, detect packer
    const detectionResult = await unpackerInstance.detect(file_path);

    if (!detectionResult.ok) {
      return {
        success: false,
        detection: {
          isPacked: false,
          packerType: 'unknown',
          confidence: 0,
          method: 'none',
        },
        error: detectionResult.error.message,
      };
    }

    const detection = detectionResult.value;

    // If not packed, return early
    if (!detection.isPacked) {
      logger.info`Binary does not appear to be packed`;
      return {
        success: true,
        detection,
      };
    }

    // Use multi-layer unpacking if requested
    if (multi_layer) {
      const multiResult = await unpackerInstance.unpackMultiLayer(file_path);

      if (!multiResult.ok) {
        return {
          success: false,
          detection,
          error: multiResult.error.message,
        };
      }

      logger.info`Multi-layer unpack complete: ${multiResult.value.unpackedLayers}/${multiResult.value.totalLayers} layers`;

      return {
        success: true,
        detection,
        multiLayer: multiResult.value,
      };
    }

    // Single-layer unpacking
    const targetType: PackerType | undefined =
      packer_type === 'auto' ? undefined : (packer_type as PackerType);

    const unpackResult = await unpackerInstance.unpack(file_path, targetType);

    if (!unpackResult.ok) {
      return {
        success: false,
        detection,
        error: unpackResult.error.message,
      };
    }

    logger.info`Unpack complete: success=${unpackResult.value.success}`;

    return {
      success: true,
      detection,
      unpack: unpackResult.value,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error`Unpack operation failed: ${message}`;

    return {
      success: false,
      detection: {
        isPacked: false,
        packerType: 'unknown',
        confidence: 0,
        method: 'none',
      },
      error: message,
    };
  }
}

// ============================================
// TOOL DEFINITION
// ============================================

export const unpackBinaryTool = {
  name: 'unpack_binary',
  description:
    'Detect and unpack packed/obfuscated binaries. ' +
    'Supports UPX packer with auto-detection. ' +
    'Enable multi_layer for nested packers (e.g., UPX + ASPack). ' +
    'Returns both detection results and unpacked file path if successful. ' +
    'The unpacked file is written to a temporary directory.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      file_path: {
        type: 'string',
        description: 'Absolute path to binary file to unpack',
      },
      packer_type: {
        type: 'string',
        description: 'Packer type: upx, aspack, mpress, petite, or auto (default)',
        enum: ['upx', 'aspack', 'mpress', 'petite', 'auto'],
        default: 'auto',
      },
      timeout: {
        type: 'number',
        description: 'Unpack timeout in seconds (default: 30)',
        default: 30,
      },
      multi_layer: {
        type: 'boolean',
        description: 'Enable multi-layer unpacking for nested packers (default: false)',
        default: false,
      },
      max_layers: {
        type: 'number',
        description: 'Maximum layers to unpack when multi_layer is enabled (default: 5, max: 10)',
        default: 5,
      },
    },
    required: ['file_path'],
  },
  execute: unpackBinary,
};

export default unpackBinaryTool;
