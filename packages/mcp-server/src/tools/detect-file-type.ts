import { open, stat } from 'node:fs/promises';
import type { DetectFileTypeInputSchema, DetectFileTypeOutputSchema } from '@sentinel/shared';
import type { z } from 'zod';
import { logToolExecution } from '../utils/logger.js';

type DetectFileTypeInput = z.infer<typeof DetectFileTypeInputSchema>;
type DetectFileTypeOutput = z.infer<typeof DetectFileTypeOutputSchema>;

// Magic number signatures for file type detection
const MAGIC_SIGNATURES = {
  // Windows PE: MZ header
  PE: { offset: 0, magic: [0x4d, 0x5a] },
  // Linux ELF: 0x7F ELF
  ELF: { offset: 0, magic: [0x7f, 0x45, 0x4c, 0x46] },
  // macOS Mach-O: Various magic numbers
  MACHO_32: { offset: 0, magic: [0xfe, 0xed, 0xfa, 0xce] },
  MACHO_64: { offset: 0, magic: [0xfe, 0xed, 0xfa, 0xcf] },
  MACHO_FAT: { offset: 0, magic: [0xca, 0xfe, 0xba, 0xbe] },
  // Archives
  ZIP: { offset: 0, magic: [0x50, 0x4b, 0x03, 0x04] },
  RAR: { offset: 0, magic: [0x52, 0x61, 0x72, 0x21] },
  GZIP: { offset: 0, magic: [0x1f, 0x8b] },
  // Scripts
  SHEBANG: { offset: 0, magic: [0x23, 0x21] }, // #!
} as const;

// PE Machine types
const PE_MACHINES: Record<
  number,
  { arch: 'x86' | 'x64' | 'ARM' | 'ARM64' | 'UNKNOWN'; os: 'WINDOWS' }
> = {
  332: { arch: 'x86', os: 'WINDOWS' },
  512: { arch: 'UNKNOWN', os: 'WINDOWS' }, // IA64
  34404: { arch: 'x64', os: 'WINDOWS' },
  43620: { arch: 'ARM64', os: 'WINDOWS' },
  452: { arch: 'ARM', os: 'WINDOWS' },
};

// ELF Machine types
const ELF_MACHINES: Record<number, 'x86' | 'x64' | 'ARM' | 'ARM64' | 'UNKNOWN'> = {
  3: 'x86',
  62: 'x64',
  40: 'ARM',
  183: 'ARM64',
};

/**
 * Detect file type using magic number analysis.
 */
export async function detectFileType(input: DetectFileTypeInput): Promise<DetectFileTypeOutput> {
  const { binaryPath } = input;

  logToolExecution('detect_file_type', { binaryPath }, 'start');

  try {
    const fileStats = await stat(binaryPath);
    const fileHandle = await open(binaryPath, 'r');

    try {
      // Read first 1KB for magic number detection
      const headerBuffer = Buffer.alloc(1024);
      await fileHandle.read(headerBuffer, 0, 1024, 0);

      // Calculate entropy for the entire file
      const entropy = await calculateEntropy(fileHandle, fileStats.size);

      // Detect file format
      const detection = detectFormat(headerBuffer, fileStats.size);

      const result: DetectFileTypeOutput = {
        format: detection.format,
        architecture: detection.architecture,
        endianness: detection.endianness,
        operatingSystem: detection.operatingSystem,
        fileSize: fileStats.size,
        entropy,
        mimeType: detection.mimeType,
      };

      logToolExecution('detect_file_type', { binaryPath }, 'success', {
        format: result.format,
        architecture: result.architecture,
      });

      return result;
    } finally {
      await fileHandle.close();
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('detect_file_type', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to detect file type: ${errorMessage}`);
  }
}

interface FormatDetection {
  format: 'PE32' | 'PE32+' | 'ELF32' | 'ELF64' | 'UNKNOWN';
  architecture: 'x86' | 'x64' | 'ARM' | 'ARM64' | 'UNKNOWN';
  endianness: 'LITTLE' | 'BIG' | 'UNKNOWN';
  operatingSystem: 'WINDOWS' | 'LINUX' | 'MACOS' | 'UNKNOWN';
  mimeType: string;
}

function matchMagic(
  buffer: Buffer,
  signature: { offset: number; magic: readonly number[] },
): boolean {
  for (let i = 0; i < signature.magic.length; i++) {
    if (buffer[signature.offset + i] !== signature.magic[i]) {
      return false;
    }
  }
  return true;
}

function detectPE(header: Buffer): FormatDetection | null {
  if (!matchMagic(header, MAGIC_SIGNATURES.PE)) return null;

  const peOffset = header.readUInt32LE(0x3c);
  if (peOffset >= header.length - 4 || header.readUInt32LE(peOffset) !== 0x00004550) {
    return null;
  }

  const machine = header.readUInt16LE(peOffset + 4);
  const optionalMagic = header.readUInt16LE(peOffset + 24);
  const isPE32Plus = optionalMagic === 0x20b;
  const machineInfo = PE_MACHINES[machine] ?? { arch: 'UNKNOWN' as const, os: 'WINDOWS' as const };

  return {
    format: isPE32Plus ? 'PE32+' : 'PE32',
    architecture: machineInfo.arch,
    endianness: 'LITTLE',
    operatingSystem: 'WINDOWS',
    mimeType: 'application/x-msdownload',
  };
}

function detectELF(header: Buffer): FormatDetection | null {
  if (!matchMagic(header, MAGIC_SIGNATURES.ELF)) return null;

  const elfClass = header[4]; // 1 = 32-bit, 2 = 64-bit
  const elfData = header[5]; // 1 = LE, 2 = BE
  const machine = elfData === 1 ? header.readUInt16LE(18) : header.readUInt16BE(18);

  return {
    format: elfClass === 2 ? 'ELF64' : 'ELF32',
    architecture: ELF_MACHINES[machine] ?? 'UNKNOWN',
    endianness: elfData === 1 ? 'LITTLE' : 'BIG',
    operatingSystem: 'LINUX',
    mimeType: 'application/x-executable',
  };
}

function detectMachO(header: Buffer): FormatDetection | null {
  const isMachO =
    matchMagic(header, MAGIC_SIGNATURES.MACHO_32) ||
    matchMagic(header, MAGIC_SIGNATURES.MACHO_64) ||
    matchMagic(header, MAGIC_SIGNATURES.MACHO_FAT);

  if (!isMachO) return null;

  return {
    format: 'UNKNOWN',
    architecture: matchMagic(header, MAGIC_SIGNATURES.MACHO_64) ? 'x64' : 'x86',
    endianness: 'LITTLE',
    operatingSystem: 'MACOS',
    mimeType: 'application/x-mach-binary',
  };
}

function detectFormat(header: Buffer, _fileSize: number): FormatDetection {
  // Try each format detector in order
  const peResult = detectPE(header);
  if (peResult) return peResult;

  const elfResult = detectELF(header);
  if (elfResult) return elfResult;

  const machOResult = detectMachO(header);
  if (machOResult) return machOResult;

  // Check Archives - Not executable
  if (matchMagic(header, MAGIC_SIGNATURES.ZIP)) {
    return {
      format: 'UNKNOWN',
      architecture: 'UNKNOWN',
      endianness: 'LITTLE',
      operatingSystem: 'UNKNOWN',
      mimeType: 'application/zip',
    };
  }

  // Check Scripts - Not binary
  if (matchMagic(header, MAGIC_SIGNATURES.SHEBANG)) {
    return {
      format: 'UNKNOWN',
      architecture: 'UNKNOWN',
      endianness: 'LITTLE',
      operatingSystem: 'UNKNOWN',
      mimeType: 'text/x-shellscript',
    };
  }

  return {
    format: 'UNKNOWN',
    architecture: 'UNKNOWN',
    endianness: 'UNKNOWN',
    operatingSystem: 'UNKNOWN',
    mimeType: 'application/octet-stream',
  };
}

async function calculateEntropy(
  fileHandle: Awaited<ReturnType<typeof open>>,
  fileSize: number,
): Promise<number> {
  // Sample-based entropy calculation for large files
  const sampleSize = Math.min(65536, fileSize);
  const buffer = Buffer.alloc(sampleSize);
  await fileHandle.read(buffer, 0, sampleSize, 0);

  // Count byte frequencies
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i] as number]++;
  }

  // Calculate Shannon entropy
  let entropy = 0;
  for (const freq of frequencies) {
    if (freq > 0) {
      const p = freq / buffer.length;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 1000) / 1000; // Round to 3 decimal places
}

export default detectFileType;
