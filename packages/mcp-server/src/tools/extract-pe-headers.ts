import { open } from 'node:fs/promises';
import type { ExtractPEHeadersInputSchema, ExtractPEHeadersOutputSchema } from '@sentinel/shared';
import type { z } from 'zod';
import { logToolExecution } from '../utils/logger.js';

type ExtractPEHeadersInput = z.infer<typeof ExtractPEHeadersInputSchema>;
type ExtractPEHeadersOutput = z.infer<typeof ExtractPEHeadersOutputSchema>;

// PE Constants
const DOS_MAGIC = 0x5a4d; // 'MZ'
const PE_SIGNATURE = 0x00004550; // 'PE\0\0'

// PE Machine types
const PE_MACHINES: Record<number, string> = {
  0: 'UNKNOWN',
  332: 'I386',
  358: 'MIPS_R4000',
  512: 'IA64',
  34404: 'AMD64',
  43620: 'ARM64',
  452: 'ARM',
};

// PE Characteristics flags
const PE_CHARACTERISTICS: Record<number, string> = {
  1: 'RELOCS_STRIPPED',
  2: 'EXECUTABLE_IMAGE',
  4: 'LINE_NUMS_STRIPPED',
  8: 'LOCAL_SYMS_STRIPPED',
  32: 'LARGE_ADDRESS_AWARE',
  256: '32BIT_MACHINE',
  512: 'DEBUG_STRIPPED',
  8192: 'DLL',
};

// DLL Characteristics flags
const DLL_CHARACTERISTICS: Record<number, string> = {
  32: 'HIGH_ENTROPY_VA',
  64: 'DYNAMIC_BASE',
  128: 'FORCE_INTEGRITY',
  256: 'NX_COMPAT',
  1024: 'NO_SEH',
  2048: 'NO_BIND',
  4096: 'APPCONTAINER',
  8192: 'WDM_DRIVER',
  16384: 'GUARD_CF',
  32768: 'TERMINAL_SERVER_AWARE',
};

// Subsystem types
const SUBSYSTEMS: Record<number, string> = {
  0: 'UNKNOWN',
  1: 'NATIVE',
  2: 'WINDOWS_GUI',
  3: 'WINDOWS_CUI',
  7: 'POSIX_CUI',
  9: 'WINDOWS_CE_GUI',
  10: 'EFI_APPLICATION',
  11: 'EFI_BOOT_SERVICE_DRIVER',
  12: 'EFI_RUNTIME_DRIVER',
  14: 'XBOX',
};

// Section characteristics
const SECTION_CHARACTERISTICS: Record<number, string> = {
  32: 'CNT_CODE',
  64: 'CNT_INITIALIZED_DATA',
  128: 'CNT_UNINITIALIZED_DATA',
  33554432: 'MEM_DISCARDABLE',
  67108864: 'MEM_NOT_CACHED',
  134217728: 'MEM_NOT_PAGED',
  268435456: 'MEM_SHARED',
  536870912: 'MEM_EXECUTE',
  1073741824: 'MEM_READ',
  2147483648: 'MEM_WRITE',
};

function parseFlags(value: number, flagMap: Record<number, string>): string[] {
  const flags: string[] = [];
  for (const [flag, name] of Object.entries(flagMap)) {
    if (value & Number(flag)) {
      flags.push(name);
    }
  }
  return flags;
}

async function readSectionHeaders(
  fileHandle: Awaited<ReturnType<typeof open>>,
  sectionHeadersOffset: number,
  numberOfSections: number,
): Promise<ExtractPEHeadersOutput['sections']> {
  const sectionHeaders: ExtractPEHeadersOutput['sections'] = [];

  for (let i = 0; i < numberOfSections; i++) {
    const sectionBuffer = Buffer.alloc(40);
    await fileHandle.read(sectionBuffer, 0, 40, sectionHeadersOffset + i * 40);

    const nameBytes = sectionBuffer.subarray(0, 8);
    const name = nameBytes.toString('utf8').replace(/\0/g, '');
    const virtualSize = sectionBuffer.readUInt32LE(8);
    const virtualAddress = sectionBuffer.readUInt32LE(12);
    const rawSize = sectionBuffer.readUInt32LE(16);
    const rawAddress = sectionBuffer.readUInt32LE(20);
    const sectionCharacteristics = sectionBuffer.readUInt32LE(36);

    sectionHeaders.push({
      name,
      virtualAddress: `0x${virtualAddress.toString(16).padStart(8, '0')}`,
      virtualSize,
      rawAddress: `0x${rawAddress.toString(16).padStart(8, '0')}`,
      rawSize,
      characteristics: parseFlags(sectionCharacteristics, SECTION_CHARACTERISTICS),
    });
  }

  return sectionHeaders;
}

// Simplified import table parsing
async function parseImports(
  _fileHandle: Awaited<ReturnType<typeof open>>,
  _optionalHeader: Buffer,
  _isPE32Plus: boolean,
  _sections: ExtractPEHeadersOutput['sections'],
): Promise<ExtractPEHeadersOutput['imports']> {
  // Full import parsing requires RVA to file offset conversion
  // and reading import descriptors - implement in Phase 3 with Ghidra
  return [];
}

// Simplified export table parsing
async function parseExports(
  _fileHandle: Awaited<ReturnType<typeof open>>,
  _optionalHeader: Buffer,
  _isPE32Plus: boolean,
  _sections: ExtractPEHeadersOutput['sections'],
): Promise<ExtractPEHeadersOutput['exports']> {
  // Full export parsing requires RVA to file offset conversion
  return [];
}

function parseOptionalHeaderFields(
  optionalHeader: Buffer,
  isPE32Plus: boolean,
): {
  entryPoint: number;
  imageBase: bigint;
  subsystem: number;
  dllCharacteristics: number;
} {
  const entryPoint = optionalHeader.readUInt32LE(16);
  const imageBase = isPE32Plus
    ? optionalHeader.readBigUInt64LE(24)
    : BigInt(optionalHeader.readUInt32LE(28));
  const subsystem = optionalHeader.readUInt16LE(68);
  const dllCharacteristics = optionalHeader.readUInt16LE(70);
  return { entryPoint, imageBase, subsystem, dllCharacteristics };
}

/**
 * Extract headers from a Windows PE (Portable Executable) file.
 */
export async function extractPEHeaders(
  input: ExtractPEHeadersInput,
): Promise<ExtractPEHeadersOutput> {
  const { binaryPath, options } = input;
  const includeDetailedSections = options?.includeDetailedSections ?? true;
  const parseImportTable = options?.parseImportTable ?? true;
  const parseExportTable = options?.parseExportTable ?? true;

  logToolExecution('extract_pe_headers', { binaryPath, options }, 'start');

  const fileHandle = await open(binaryPath, 'r');

  try {
    // Read DOS header (64 bytes)
    const dosHeader = Buffer.alloc(64);
    await fileHandle.read(dosHeader, 0, 64, 0);

    // Verify DOS magic
    const dosMagic = dosHeader.readUInt16LE(0);
    if (dosMagic !== DOS_MAGIC) {
      throw new Error('Invalid PE file: Missing MZ signature');
    }

    const peOffset = dosHeader.readUInt32LE(0x3c);

    // Read PE signature (4 bytes)
    const peSignature = Buffer.alloc(4);
    await fileHandle.read(peSignature, 0, 4, peOffset);

    if (peSignature.readUInt32LE(0) !== PE_SIGNATURE) {
      throw new Error('Invalid PE file: Missing PE signature');
    }

    // Read COFF File Header (20 bytes)
    const coffHeader = Buffer.alloc(20);
    await fileHandle.read(coffHeader, 0, 20, peOffset + 4);

    const machine = coffHeader.readUInt16LE(0);
    const numberOfSections = coffHeader.readUInt16LE(2);
    const timeDateStamp = coffHeader.readUInt32LE(4);
    const sizeOfOptionalHeader = coffHeader.readUInt16LE(16);
    const characteristics = coffHeader.readUInt16LE(18);

    // Read Optional Header
    const optionalHeader = Buffer.alloc(sizeOfOptionalHeader);
    await fileHandle.read(optionalHeader, 0, sizeOfOptionalHeader, peOffset + 24);

    const optionalMagic = optionalHeader.readUInt16LE(0);
    const isPE32Plus = optionalMagic === 0x20b;
    const majorLinkerVersion = optionalHeader.readUInt8(2);
    const minorLinkerVersion = optionalHeader.readUInt8(3);

    const { entryPoint, imageBase, subsystem, dllCharacteristics } = parseOptionalHeaderFields(
      optionalHeader,
      isPE32Plus,
    );

    // Read Section Headers
    const sectionHeadersOffset = peOffset + 24 + sizeOfOptionalHeader;
    const sectionHeaders = includeDetailedSections
      ? await readSectionHeaders(fileHandle, sectionHeadersOffset, numberOfSections)
      : [];

    // Parse Import Table (simplified)
    const imports = parseImportTable
      ? await parseImports(fileHandle, optionalHeader, isPE32Plus, sectionHeaders)
      : undefined;

    // Parse Export Table (simplified)
    const exports = parseExportTable
      ? await parseExports(fileHandle, optionalHeader, isPE32Plus, sectionHeaders)
      : undefined;

    const result: ExtractPEHeadersOutput = {
      dosHeader: {
        magic: 'MZ',
        peOffset,
      },
      peHeader: {
        machine: PE_MACHINES[machine] ?? `UNKNOWN(0x${machine.toString(16)})`,
        numberOfSections,
        timeDateStamp,
        characteristics: parseFlags(characteristics, PE_CHARACTERISTICS),
      },
      optionalHeader: {
        magic: isPE32Plus ? 'PE32+' : 'PE32',
        majorLinkerVersion,
        minorLinkerVersion,
        entryPoint: `0x${entryPoint.toString(16).padStart(8, '0')}`,
        imageBase: `0x${imageBase.toString(16).padStart(isPE32Plus ? 16 : 8, '0')}`,
        subsystem: SUBSYSTEMS[subsystem] ?? `UNKNOWN(${subsystem})`,
        dllCharacteristics: parseFlags(dllCharacteristics, DLL_CHARACTERISTICS),
      },
      sections: sectionHeaders,
      imports,
      exports,
    };

    logToolExecution('extract_pe_headers', { binaryPath }, 'success', {
      sections: numberOfSections,
      isPE32Plus,
    });

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('extract_pe_headers', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to extract PE headers: ${errorMessage}`);
  } finally {
    await fileHandle.close();
  }
}

export default extractPEHeaders;
