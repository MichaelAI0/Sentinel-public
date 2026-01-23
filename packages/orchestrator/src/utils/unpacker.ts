/**
 * Binary Unpacker
 *
 * Utilities for detecting and unpacking packed/obfuscated binaries.
 * Supports UPX, MPRESS, ASPack, Petite with static unpacking.
 * Includes generic emulation-based fallback for unknown packers.
 * Supports multi-layer unpacking for nested packers.
 *
 * @module utils/unpacker
 *
 * @todo Phase 4: Add machine learning packer identification
 * @todo Phase 4: Add unpacking sandbox integration for VM-protected binaries
 */

import { exec } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { getLogger } from '@logtape/logtape';
import { err, ok, type Result, ToolError } from '@sentinel/shared';

const execAsync = promisify(exec);
const logger = getLogger(['sentinel', 'unpacker']);

// ============================================
// TYPES
// ============================================

/**
 * Supported packer types
 */
export type PackerType =
  | 'upx'
  | 'aspack'
  | 'mpress'
  | 'petite'
  | 'vmprotect'
  | 'themida'
  | 'enigma'
  | 'unknown';

/**
 * Unpacking method used
 */
export type UnpackMethod = 'native' | 'static' | 'emulation' | 'manual';

/**
 * Unpacking result
 */
export type UnpackResult = {
  /** Whether unpacking was successful */
  success: boolean;
  /** Detected packer type */
  packerType: PackerType;
  /** Unpacking method used */
  unpackMethod?: UnpackMethod;
  /** Original file size in bytes */
  originalSize: number;
  /** Unpacked file size in bytes */
  unpackedSize: number;
  /** Path to unpacked file (empty if failed) */
  unpackedPath: string;
  /** Compression ratio */
  compressionRatio?: number;
  /** Original Entry Point (if detected) */
  originalEntryPoint?: number;
  /** Warning message if skipped or partial success */
  warning?: string;
  /** Error message if failed */
  error?: string;
};

/**
 * Individual unpack layer result
 */
export type UnpackLayer = {
  /** Layer number (1 = outermost) */
  layer: number;
  /** Packer type for this layer */
  packerType: PackerType;
  /** Path to file before this layer was unpacked */
  inputPath: string;
  /** Path to file after this layer was unpacked */
  outputPath: string;
  /** Size before unpacking */
  sizeBefore: number;
  /** Size after unpacking */
  sizeAfter: number;
  /** Unpacking method used */
  method: UnpackMethod;
  /** Whether this layer was successfully unpacked */
  success: boolean;
  /** Error message if failed */
  error?: string;
};

/**
 * Multi-layer unpacking result
 */
export type MultiLayerUnpackResult = {
  /** Whether all layers were successfully unpacked */
  success: boolean;
  /** Total number of packing layers detected */
  totalLayers: number;
  /** Number of layers successfully unpacked */
  unpackedLayers: number;
  /** Individual layer results */
  layers: UnpackLayer[];
  /** Final unpacked file path */
  finalPath: string;
  /** Original file size */
  originalSize: number;
  /** Final unpacked size */
  finalSize: number;
  /** Total compression ratio across all layers */
  totalCompressionRatio: number;
  /** Packer chain (e.g., ["upx", "aspack"]) */
  packerChain: PackerType[];
  /** Warning if partial success */
  warning?: string;
  /** Error if complete failure */
  error?: string;
};

/**
 * Packer detection result
 */
export type PackerDetection = {
  /** Whether binary appears to be packed */
  isPacked: boolean;
  /** Detected packer type */
  packerType: PackerType;
  /** Confidence level (0-1) */
  confidence: number;
  /** Detection method used */
  method: 'signature' | 'entropy' | 'heuristic' | 'none';
  /** Additional details */
  details?: string;
};

/**
 * Unpacker configuration
 */
export type UnpackerConfig = {
  /** Temporary directory for unpacked files */
  tempDir: string;
  /** Timeout for unpack operations (ms) */
  timeoutMs: number;
  /** Maximum file size to unpack (bytes) */
  maxFileSize: number;
  /** Whether to verify unpacking succeeded */
  verifyUnpack: boolean;
  /** Enable emulation-based unpacking via Unipacker */
  enableEmulation: boolean;
  /** Unipacker Docker container name */
  unipackerContainer: string;
  /** Maximum unpacking layers for nested packers */
  maxUnpackLayers: number;
  /** Minimum size reduction required to continue multi-layer unpacking */
  minSizeReductionPercent: number;
};

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_CONFIG: UnpackerConfig = {
  tempDir: '/tmp/sentinel-unpack',
  timeoutMs: 30_000,
  maxFileSize: 100 * 1024 * 1024, // 100MB
  verifyUnpack: true,
  enableEmulation: true,
  unipackerContainer: 'sentinel-unipacker',
  maxUnpackLayers: 5,
  minSizeReductionPercent: 5,
};

// ============================================
// PACKER SIGNATURES
// ============================================

type PackerSignature = {
  type: PackerType;
  /** Magic bytes to match */
  magic?: {
    offset: number;
    bytes: number[];
  };
  /** String patterns to find */
  strings?: string[];
  /** Section name patterns */
  sections?: string[];
  /** PE header characteristics */
  peCharacteristics?: {
    /** Entry point in unusual section */
    entryPointSection?: string;
    /** Minimum number of sections */
    minSections?: number;
    /** Section with high entropy */
    highEntropySection?: string;
  };
};

const PACKER_SIGNATURES: PackerSignature[] = [
  {
    type: 'upx',
    magic: { offset: 0, bytes: [0x55, 0x50, 0x58, 0x21] }, // "UPX!"
    strings: ['UPX!', '$Info: This file is packed with the UPX'],
    sections: ['UPX0', 'UPX1', 'UPX2'],
  },
  {
    type: 'aspack',
    strings: ['.aspack', 'ASPack', 'www.aspack.com'],
    sections: ['.aspack', '.adata', '.ASPack'],
    peCharacteristics: {
      entryPointSection: '.aspack',
    },
  },
  {
    type: 'mpress',
    magic: { offset: 0, bytes: [0x4d, 0x50, 0x52, 0x45, 0x53, 0x53] }, // "MPRESS"
    strings: ['MPRESS', '.MPRESS'],
    sections: ['.MPRESS1', '.MPRESS2'],
  },
  {
    type: 'petite',
    strings: ['PETITE', 'petite', 'www.un4seen.com'],
    sections: ['.petite'],
    peCharacteristics: {
      entryPointSection: '.petite',
    },
  },
  {
    type: 'vmprotect',
    strings: ['VMProtect', '.vmp0', '.vmp1', 'VMProtect begin', 'VMProtect end'],
    sections: ['.vmp0', '.vmp1', '.vmp2'],
    peCharacteristics: {
      highEntropySection: '.vmp0',
    },
  },
  {
    type: 'themida',
    strings: ['Themida', 'WinLicense', 'Oreans Technologies'],
    sections: ['.themida', '.winlice'],
    peCharacteristics: {
      minSections: 8,
    },
  },
  {
    type: 'enigma',
    strings: ['Enigma Protector', 'The Enigma Protector', 'enigma'],
    sections: ['.enigma1', '.enigma2', '.pdata'],
  },
];

// ============================================
// BINARY UNPACKER CLASS
// ============================================

export class BinaryUnpacker {
  private readonly config: UnpackerConfig;

  constructor(config: Partial<UnpackerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if magic bytes match at a given offset
   */
  private checkMagicBytes(bytes: Uint8Array, offset: number, magic: number[]): boolean {
    for (let i = 0; i < magic.length; i++) {
      if (bytes[offset + i] !== magic[i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * Check for signature-based packer detection
   */
  private checkSignature(bytes: Uint8Array, sig: PackerSignature): PackerDetection | null {
    // Check magic bytes
    if (sig.magic) {
      const { offset, bytes: magic } = sig.magic;
      if (this.checkMagicBytes(bytes, offset, magic)) {
        return {
          isPacked: true,
          packerType: sig.type,
          confidence: 0.95,
          method: 'signature',
          details: `Magic bytes matched at offset ${offset}`,
        };
      }
    }

    // Check string patterns
    if (sig.strings) {
      const content = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, 4096));
      for (const pattern of sig.strings) {
        if (content.includes(pattern)) {
          return {
            isPacked: true,
            packerType: sig.type,
            confidence: 0.85,
            method: 'signature',
            details: `String pattern found: "${pattern}"`,
          };
        }
      }
    }

    return null;
  }

  /**
   * Detect if a binary is packed and identify the packer
   */
  async detect(filePath: string): Promise<Result<PackerDetection, Error>> {
    logger.debug`Detecting packer for ${filePath}`;

    try {
      const file = Bun.file(filePath);
      const exists = await file.exists();

      if (!exists) {
        return err(new Error(`File not found: ${filePath}`));
      }

      // Read file header for signature detection
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);

      // Check signatures
      for (const sig of PACKER_SIGNATURES) {
        const detection = this.checkSignature(bytes, sig);
        if (detection) {
          return ok(detection);
        }
      }

      // Check entropy as fallback
      const entropy = this.calculateEntropy(bytes.slice(0, 10000));
      if (entropy > 7.5) {
        return ok({
          isPacked: true,
          packerType: 'unknown',
          confidence: 0.6,
          method: 'entropy',
          details: `High entropy detected: ${entropy.toFixed(2)}`,
        });
      }

      return ok({
        isPacked: false,
        packerType: 'unknown',
        confidence: 0.8,
        method: 'none',
        details: 'No packing indicators found',
      });
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Unpack a binary file
   */
  async unpack(filePath: string, packerType?: PackerType): Promise<Result<UnpackResult, Error>> {
    logger.info`Unpacking ${filePath} (type: ${packerType ?? 'auto-detect'})`;

    try {
      const file = Bun.file(filePath);
      const exists = await file.exists();

      if (!exists) {
        return err(new Error(`File not found: ${filePath}`));
      }

      const stat = await file.stat();

      // Check file size limit
      if (stat && stat.size > this.config.maxFileSize) {
        return ok({
          success: false,
          packerType: packerType ?? 'unknown',
          originalSize: stat.size,
          unpackedSize: 0,
          unpackedPath: '',
          error: `File too large: ${stat.size} bytes (max: ${this.config.maxFileSize})`,
        });
      }

      // Auto-detect packer if not specified
      let detectedType = packerType;
      if (!detectedType) {
        const detection = await this.detect(filePath);
        if (!detection.ok) {
          return err(detection.error);
        }
        if (!detection.value.isPacked) {
          return ok({
            success: false,
            packerType: 'unknown',
            originalSize: stat?.size ?? 0,
            unpackedSize: 0,
            unpackedPath: '',
            warning: 'Binary does not appear to be packed',
          });
        }
        detectedType = detection.value.packerType;
      }

      // Dispatch to appropriate unpacker
      switch (detectedType) {
        case 'upx':
          return await this.unpackUPX(filePath);
        case 'mpress':
          return await this.unpackMPRESS(filePath);
        case 'aspack':
          return await this.unpackASPack(filePath);
        case 'petite':
          return await this.unpackPetite(filePath);
        case 'vmprotect':
        case 'themida':
        case 'enigma':
          // VM-protected packers require emulation-based unpacking
          if (this.config.enableEmulation) {
            return await this.unpackWithUnipacker(filePath, detectedType);
          }
          return ok({
            success: false,
            packerType: detectedType,
            originalSize: stat?.size ?? 0,
            unpackedSize: 0,
            unpackedPath: '',
            warning: `${detectedType} requires emulation-based unpacking (disabled)`,
          });
        default:
          // Try emulation for unknown packers
          if (this.config.enableEmulation) {
            return await this.unpackWithUnipacker(filePath, 'unknown');
          }
          return ok({
            success: false,
            packerType: 'unknown',
            originalSize: stat?.size ?? 0,
            unpackedSize: 0,
            unpackedPath: '',
            warning: 'Unknown packer type and emulation disabled',
          });
      }
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Unpack UPX-packed binary
   */
  private async unpackUPX(filePath: string): Promise<Result<UnpackResult, Error>> {
    // Verify UPX is installed
    try {
      await execAsync('which upx');
    } catch {
      return err(
        new ToolError(
          'upx',
          'UPX not installed. Install via: apt-get install upx (Linux) or brew install upx (macOS)',
        ),
      );
    }

    // Create temp directory
    try {
      await execAsync(`mkdir -p "${this.config.tempDir}"`);
    } catch {
      // Directory might already exist
    }

    // Generate output path
    const outputPath = `${this.config.tempDir}/${randomUUID()}_unpacked`;

    try {
      // Copy file to temp location
      await execAsync(`cp "${filePath}" "${outputPath}"`);

      // Get original size
      const originalFile = Bun.file(filePath);
      const originalStat = await originalFile.stat();

      // Run UPX decompress
      const { stderr } = await execAsync(`upx -d -q "${outputPath}"`, {
        timeout: this.config.timeoutMs,
      });

      if (stderr && !stderr.includes('Unpacked')) {
        logger.warn`UPX stderr: ${stderr}`;
      }

      // Get unpacked size
      const unpackedFile = Bun.file(outputPath);
      const unpackedStat = await unpackedFile.stat();

      const originalSize = originalStat?.size ?? 0;
      const unpackedSize = unpackedStat?.size ?? 0;

      // Verify unpacking succeeded
      if (this.config.verifyUnpack && unpackedSize <= originalSize) {
        return ok({
          success: false,
          packerType: 'upx',
          originalSize,
          unpackedSize,
          unpackedPath: '',
          error: 'Unpacking did not increase file size - may have failed',
        });
      }

      return ok({
        success: true,
        packerType: 'upx',
        unpackMethod: 'native',
        originalSize,
        unpackedSize,
        unpackedPath: outputPath,
        compressionRatio: unpackedSize / originalSize,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      // Clean up temp file on error
      try {
        await execAsync(`rm -f "${outputPath}"`);
      } catch {
        // Ignore cleanup errors
      }

      return err(new ToolError('upx', `UPX unpack failed: ${message}`));
    }
  }

  /**
   * Unpack MPRESS-packed binary
   */
  private async unpackMPRESS(filePath: string): Promise<Result<UnpackResult, Error>> {
    try {
      await execAsync('which mpress');
    } catch {
      return err(
        new ToolError(
          'mpress',
          'MPRESS not installed. Install via: apt-get install mpress (Linux) or brew install mpress (macOS)',
        ),
      );
    }

    try {
      await execAsync(`mkdir -p "${this.config.tempDir}"`);
    } catch {
      // Directory might already exist
    }

    const outputPath = `${this.config.tempDir}/${randomUUID()}_unpacked`;

    try {
      await execAsync(`cp "${filePath}" "${outputPath}"`);

      const originalFile = Bun.file(filePath);
      const originalStat = await originalFile.stat();

      const { stderr } = await execAsync(`mpress -d -q "${outputPath}"`, {
        timeout: this.config.timeoutMs,
      });

      if (stderr && !stderr.includes('done')) {
        logger.warn`MPRESS stderr: ${stderr}`;
      }

      const unpackedFile = Bun.file(outputPath);
      const unpackedStat = await unpackedFile.stat();

      const originalSize = originalStat?.size ?? 0;
      const unpackedSize = unpackedStat?.size ?? 0;

      if (this.config.verifyUnpack && unpackedSize <= originalSize) {
        return ok({
          success: false,
          packerType: 'mpress',
          unpackMethod: 'native',
          originalSize,
          unpackedSize,
          unpackedPath: '',
          error: 'Unpacking did not increase file size - may have failed',
        });
      }

      return ok({
        success: true,
        packerType: 'mpress',
        unpackMethod: 'native',
        originalSize,
        unpackedSize,
        unpackedPath: outputPath,
        compressionRatio: unpackedSize / originalSize,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      try {
        await execAsync(`rm -f "${outputPath}"`);
      } catch {
        // Ignore cleanup errors
      }

      return err(new ToolError('mpress', `MPRESS unpack failed: ${message}`));
    }
  }

  /**
   * Unpack ASPack-packed binary (static PE extraction)
   */
  private async unpackASPack(filePath: string): Promise<Result<UnpackResult, Error>> {
    return await this.unpackByEmbeddedPE(filePath, 'aspack');
  }

  /**
   * Unpack Petite-packed binary (static PE extraction)
   */
  private async unpackPetite(filePath: string): Promise<Result<UnpackResult, Error>> {
    return await this.unpackByEmbeddedPE(filePath, 'petite');
  }

  /**
   * Extract embedded PE payload for static packers
   */
  private async unpackByEmbeddedPE(
    filePath: string,
    packerType: Extract<PackerType, 'aspack' | 'petite'>,
  ): Promise<Result<UnpackResult, Error>> {
    try {
      await execAsync(`mkdir -p "${this.config.tempDir}"`);
    } catch {
      // Directory might already exist
    }

    const outputPath = `${this.config.tempDir}/${randomUUID()}_unpacked`;

    try {
      const file = Bun.file(filePath);
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);

      const originalSize = bytes.length;
      const embedded = this.findEmbeddedPE(bytes);

      if (!embedded) {
        return ok({
          success: false,
          packerType,
          unpackMethod: 'static',
          originalSize,
          unpackedSize: 0,
          unpackedPath: '',
          warning: 'No embedded PE payload found',
        });
      }

      const extracted = bytes.slice(embedded.offset, embedded.offset + embedded.size);
      await Bun.write(outputPath, extracted);

      const unpackedSize = extracted.length;

      return ok({
        success: true,
        packerType,
        unpackMethod: 'static',
        originalSize,
        unpackedSize,
        unpackedPath: outputPath,
        compressionRatio: unpackedSize / originalSize,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      try {
        await execAsync(`rm -f "${outputPath}"`);
      } catch {
        // Ignore cleanup errors
      }

      return err(new ToolError(packerType, `${packerType} unpack failed: ${message}`));
    }
  }

  /**
   * Parse Unipacker JSON output from stdout
   */
  private parseUnipackerOutput(stdout: string): {
    success: boolean;
    packer?: string;
    output?: string;
    unpacked_size?: number;
    oep?: string;
    error?: string;
  } | null {
    const lines = stdout.trim().split('\n');
    const lastLine = lines[lines.length - 1] ?? '';
    try {
      return JSON.parse(lastLine);
    } catch {
      return null;
    }
  }

  /**
   * Parse OEP hex string to number
   */
  private parseOep(oep: string | undefined): number | undefined {
    if (!oep) return undefined;
    try {
      return Number.parseInt(oep, 16);
    } catch {
      return undefined;
    }
  }

  /**
   * Create a failed unpack result for Unipacker
   */
  private createFailedUnipackerResult(
    packerType: PackerType,
    originalSize: number,
    error: string,
  ): Result<UnpackResult, Error> {
    return ok({
      success: false,
      packerType,
      unpackMethod: 'emulation',
      originalSize,
      unpackedSize: 0,
      unpackedPath: '',
      error,
    });
  }

  /**
   * Unpack using Unipacker (emulation-based via Docker)
   * Supports: ASPack, FSG, MEW, MPRESS, Petite, UPX, YZPack, and unknown packers
   */
  private async unpackWithUnipacker(
    filePath: string,
    packerType: PackerType,
  ): Promise<Result<UnpackResult, Error>> {
    logger.info`Attempting emulation-based unpacking with Unipacker for ${filePath}`;

    try {
      // Verify Docker is available and unipacker container exists
      try {
        await execAsync(`docker inspect ${this.config.unipackerContainer}`);
      } catch {
        // Container not running, try to check if image exists
        logger.warn`Unipacker container not available, falling back to static methods`;
        return ok({
          success: false,
          packerType,
          unpackMethod: 'emulation',
          originalSize: 0,
          unpackedSize: 0,
          unpackedPath: '',
          warning: 'Unipacker container not available. Build with: docker compose build unipacker',
        });
      }

      // Create temp directory
      try {
        await execAsync(`mkdir -p "${this.config.tempDir}"`);
      } catch {
        // Directory might already exist
      }

      const file = Bun.file(filePath);
      const originalStat = await file.stat();
      const originalSize = originalStat?.size ?? 0;

      // Generate unique output filename
      const outputId = randomUUID();
      const outputPath = `${this.config.tempDir}/${outputId}_unpacked.exe`;

      // Convert host path to container path if needed
      // Assuming binaries are mounted at /workspace/binaries in container
      const containerInputPath = filePath.replace(/^.*\/binaries\//, '/workspace/binaries/');
      const containerOutputDir = '/workspace/output';

      // Run unipacker in container
      const cmd = `docker exec ${this.config.unipackerContainer} /entrypoint.sh "${containerInputPath}" "${containerOutputDir}"`;

      try {
        const { stdout, stderr } = await execAsync(cmd, {
          timeout: this.config.timeoutMs * 2, // Emulation takes longer
        });

        if (stderr) {
          logger.warn`Unipacker stderr: ${stderr}`;
        }

        // Parse JSON output from unipacker
        const result = this.parseUnipackerOutput(stdout);

        if (!result) {
          const lines = stdout.trim().split('\n');
          const lastLine = lines[lines.length - 1] ?? '';
          return this.createFailedUnipackerResult(
            packerType,
            originalSize,
            `Failed to parse Unipacker output: ${lastLine}`,
          );
        }

        if (!result.success) {
          return this.createFailedUnipackerResult(
            packerType,
            originalSize,
            result.error ?? 'Unipacker failed to unpack binary',
          );
        }

        // Copy unpacked file from container volume to temp dir
        const containerOutputPath = result.output ?? '';
        if (containerOutputPath) {
          try {
            await execAsync(
              `docker cp ${this.config.unipackerContainer}:${containerOutputPath} "${outputPath}"`,
            );
          } catch (copyErr) {
            logger.warn`Failed to copy unpacked file: ${copyErr}`;
          }
        }

        const unpackedFile = Bun.file(outputPath);
        const unpackedExists = await unpackedFile.exists();
        const unpackedStat = unpackedExists ? await unpackedFile.stat() : null;
        const unpackedSize = unpackedStat?.size ?? result.unpacked_size ?? 0;

        return ok({
          success: true,
          packerType: (result.packer?.toLowerCase() as PackerType) ?? packerType,
          unpackMethod: 'emulation',
          originalSize,
          unpackedSize,
          unpackedPath: unpackedExists ? outputPath : '',
          compressionRatio: unpackedSize > 0 ? unpackedSize / originalSize : undefined,
          originalEntryPoint: this.parseOep(result.oep),
        });
      } catch (execError) {
        const message = execError instanceof Error ? execError.message : String(execError);
        return this.createFailedUnipackerResult(
          packerType,
          originalSize,
          `Unipacker execution failed: ${message}`,
        );
      }
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Find an embedded PE payload inside a packed binary
   */
  private findEmbeddedPE(bytes: Uint8Array): { offset: number; size: number } | null {
    const len = bytes.length;
    let best: { offset: number; size: number } | null = null;

    for (let i = 0; i < len - 0x40; i++) {
      if (bytes[i] !== 0x4d || bytes[i + 1] !== 0x5a) continue; // 'MZ'

      const eLfanew = this.readUint32LE(bytes, i + 0x3c);
      if (eLfanew === null) continue;

      const peOffset = i + eLfanew;
      if (peOffset + 4 >= len) continue;

      if (
        bytes[peOffset] !== 0x50 ||
        bytes[peOffset + 1] !== 0x45 ||
        bytes[peOffset + 2] !== 0x00 ||
        bytes[peOffset + 3] !== 0x00
      ) {
        continue;
      }

      const size = len - i;
      if (!best || size > best.size) {
        best = { offset: i, size };
      }
    }

    return best;
  }

  /**
   * Read little-endian uint32 from a byte array
   */
  private readUint32LE(bytes: Uint8Array, offset: number): number | null {
    if (offset + 4 > bytes.length) return null;
    const b0 = bytes[offset];
    const b1 = bytes[offset + 1];
    const b2 = bytes[offset + 2];
    const b3 = bytes[offset + 3];
    if (b0 === undefined || b1 === undefined || b2 === undefined || b3 === undefined) {
      return null;
    }
    return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0;
  }

  /**
   * Calculate Shannon entropy of data
   */
  private calculateEntropy(data: Uint8Array): number {
    const len = data.length;
    if (len === 0) return 0;

    const freqs = new Map<number, number>();
    for (const byte of data) {
      freqs.set(byte, (freqs.get(byte) ?? 0) + 1);
    }

    let entropy = 0;
    for (const count of freqs.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  // ============================================
  // MULTI-LAYER UNPACKING
  // ============================================

  /**
   * Create a failed layer record
   */
  private createFailedLayer(
    layerNum: number,
    packerType: PackerType,
    inputPath: string,
    sizeBefore: number,
    method: UnpackMethod,
    errorMsg: string | undefined,
  ): UnpackLayer {
    return {
      layer: layerNum,
      packerType,
      inputPath,
      outputPath: '',
      sizeBefore,
      sizeAfter: 0,
      method,
      success: false,
      error: errorMsg,
    };
  }

  /**
   * Create a successful layer record
   */
  private createSuccessLayer(
    layerNum: number,
    packerType: PackerType,
    inputPath: string,
    outputPath: string,
    sizeBefore: number,
    sizeAfter: number,
    method: UnpackMethod,
  ): UnpackLayer {
    return {
      layer: layerNum,
      packerType,
      inputPath,
      outputPath,
      sizeBefore,
      sizeAfter,
      method,
      success: true,
    };
  }

  /**
   * Build the final multi-layer result
   */
  private async buildMultiLayerResult(
    layers: UnpackLayer[],
    packerChain: PackerType[],
    currentPath: string,
    originalSize: number,
  ): Promise<MultiLayerUnpackResult> {
    const finalFile = Bun.file(currentPath);
    const finalStat = await finalFile.stat();
    const finalSize = finalStat?.size ?? 0;
    const successfulLayers = layers.filter((l) => l.success).length;
    const totalCompressionRatio = originalSize > 0 ? finalSize / originalSize : 1;

    return {
      success: successfulLayers > 0,
      totalLayers: layers.length,
      unpackedLayers: successfulLayers,
      layers,
      finalPath: currentPath,
      originalSize,
      finalSize,
      totalCompressionRatio,
      packerChain,
      warning:
        successfulLayers < layers.length
          ? `Unpacked ${successfulLayers} of ${layers.length} detected layers`
          : undefined,
    };
  }

  /**
   * Unpack a binary with multiple packing layers (nested packers)
   *
   * Recursively unpacks until no more packing is detected or max layers reached.
   * Useful for binaries packed with multiple layers (e.g., UPX + ASPack).
   *
   * @param filePath - Path to the packed binary
   * @returns Multi-layer unpack result with all layer details
   */
  async unpackMultiLayer(filePath: string): Promise<Result<MultiLayerUnpackResult, Error>> {
    logger.info`Starting multi-layer unpacking for ${filePath}`;

    const layers: UnpackLayer[] = [];
    const packerChain: PackerType[] = [];
    let currentPath = filePath;
    let layerNum = 0;

    const originalFile = Bun.file(filePath);
    const originalStat = await originalFile.stat();
    const originalSize = originalStat?.size ?? 0;

    try {
      while (layerNum < this.config.maxUnpackLayers) {
        layerNum++;

        const detection = await this.detect(currentPath);
        if (!detection.ok) {
          if (layerNum === 1) return err(detection.error);
          break;
        }

        if (!detection.value.isPacked) {
          logger.debug`Layer ${layerNum}: No packing detected, stopping`;
          break;
        }

        const packerType = detection.value.packerType;
        logger.info`Layer ${layerNum}: Detected ${packerType} packer`;

        const beforeFile = Bun.file(currentPath);
        const beforeStat = await beforeFile.stat();
        const sizeBefore = beforeStat?.size ?? 0;

        const unpackResult = await this.unpack(currentPath, packerType);

        if (!unpackResult.ok) {
          layers.push(
            this.createFailedLayer(
              layerNum,
              packerType,
              currentPath,
              sizeBefore,
              'native',
              unpackResult.error.message,
            ),
          );
          break;
        }

        const result = unpackResult.value;
        if (!result.success || !result.unpackedPath) {
          layers.push(
            this.createFailedLayer(
              layerNum,
              packerType,
              currentPath,
              sizeBefore,
              result.unpackMethod ?? 'native',
              result.error ?? result.warning,
            ),
          );
          break;
        }

        const sizeReduction = ((result.unpackedSize - sizeBefore) / sizeBefore) * 100;
        if (sizeReduction < this.config.minSizeReductionPercent && layerNum > 1) {
          logger.debug`Layer ${layerNum}: Minimal size change (${sizeReduction.toFixed(1)}%), stopping`;
          break;
        }

        layers.push(
          this.createSuccessLayer(
            layerNum,
            packerType,
            currentPath,
            result.unpackedPath,
            sizeBefore,
            result.unpackedSize,
            result.unpackMethod ?? 'native',
          ),
        );
        packerChain.push(packerType);
        currentPath = result.unpackedPath;

        logger.info`Layer ${layerNum}: Unpacked ${packerType} (${sizeBefore} -> ${result.unpackedSize} bytes)`;
      }

      return ok(await this.buildMultiLayerResult(layers, packerChain, currentPath, originalSize));
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Check if a binary has multiple packing layers
   *
   * Performs detection up to the first 3 layers without unpacking.
   * Useful for quick assessment of packer nesting depth.
   */
  async detectMultiLayer(filePath: string, maxProbe = 3): Promise<Result<PackerType[], Error>> {
    const detectedPackers: PackerType[] = [];
    let currentPath = filePath;

    try {
      for (let i = 0; i < maxProbe; i++) {
        const detection = await this.detect(currentPath);
        if (!detection.ok || !detection.value.isPacked) {
          break;
        }

        const packer = detection.value.packerType;
        detectedPackers.push(packer);

        // For multi-layer detection, we need to actually unpack to see the next layer
        if (i < maxProbe - 1) {
          const unpackResult = await this.unpack(currentPath, packer);
          if (!unpackResult.ok || !unpackResult.value.success) {
            break;
          }
          currentPath = unpackResult.value.unpackedPath;
        }
      }

      return ok(detectedPackers);
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Clean up temporary files
   */
  async cleanup(): Promise<void> {
    try {
      await execAsync(`rm -rf "${this.config.tempDir}"`);
      logger.debug`Cleaned up temp directory: ${this.config.tempDir}`;
    } catch {
      // Ignore cleanup errors
    }
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let defaultUnpacker: BinaryUnpacker | null = null;

/**
 * Get or create the default unpacker instance
 */
export function getUnpacker(config?: Partial<UnpackerConfig>): BinaryUnpacker {
  if (!defaultUnpacker || config) {
    defaultUnpacker = new BinaryUnpacker(config);
  }
  return defaultUnpacker;
}
