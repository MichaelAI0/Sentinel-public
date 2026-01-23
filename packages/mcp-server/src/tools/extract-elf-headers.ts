import { open } from 'node:fs/promises';
import type { ExtractELFHeadersInputSchema, ExtractELFHeadersOutputSchema } from '@sentinel/shared';
import type { z } from 'zod';
import { logToolExecution } from '../utils/logger.js';

type ExtractELFHeadersInput = z.infer<typeof ExtractELFHeadersInputSchema>;
type ExtractELFHeadersOutput = z.infer<typeof ExtractELFHeadersOutputSchema>;

// ELF Constants
const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46]; // '\x7fELF'

// ELF Class
const ELF_CLASS: Record<number, 'ELF32' | 'ELF64'> = {
  1: 'ELF32',
  2: 'ELF64',
};

// ELF Data encoding
const ELF_DATA: Record<number, 'LITTLE_ENDIAN' | 'BIG_ENDIAN'> = {
  1: 'LITTLE_ENDIAN',
  2: 'BIG_ENDIAN',
};

// ELF OS/ABI
const ELF_OSABI: Record<number, string> = {
  0: 'SYSV',
  1: 'HPUX',
  2: 'NETBSD',
  3: 'LINUX',
  6: 'SOLARIS',
  7: 'AIX',
  8: 'IRIX',
  9: 'FREEBSD',
  12: 'OPENBSD',
};

// ELF Type
const ELF_TYPE: Record<number, 'EXEC' | 'DYN' | 'REL' | 'CORE'> = {
  1: 'REL',
  2: 'EXEC',
  3: 'DYN',
  4: 'CORE',
};

// ELF Machine
const ELF_MACHINE: Record<number, string> = {
  0: 'NONE',
  3: 'I386',
  8: 'MIPS',
  20: 'POWERPC',
  40: 'ARM',
  62: 'X86_64',
  183: 'AARCH64',
  243: 'RISCV',
};

// Program Header Types
const PT_TYPES: Record<number, string> = {
  0: 'PT_NULL',
  1: 'PT_LOAD',
  2: 'PT_DYNAMIC',
  3: 'PT_INTERP',
  4: 'PT_NOTE',
  5: 'PT_SHLIB',
  6: 'PT_PHDR',
  7: 'PT_TLS',
  1685382480: 'PT_GNU_EH_FRAME',
  1685382481: 'PT_GNU_STACK',
  1685382482: 'PT_GNU_RELRO',
};

// Section Header Types
const SHT_TYPES: Record<number, string> = {
  0: 'SHT_NULL',
  1: 'SHT_PROGBITS',
  2: 'SHT_SYMTAB',
  3: 'SHT_STRTAB',
  4: 'SHT_RELA',
  5: 'SHT_HASH',
  6: 'SHT_DYNAMIC',
  7: 'SHT_NOTE',
  8: 'SHT_NOBITS',
  9: 'SHT_REL',
  11: 'SHT_DYNSYM',
  14: 'SHT_INIT_ARRAY',
  15: 'SHT_FINI_ARRAY',
};

// Program Header Flags
const PF_FLAGS: Record<number, string> = {
  1: 'PF_X',
  2: 'PF_W',
  4: 'PF_R',
};

// Section Header Flags
const SHF_FLAGS: Record<number, string> = {
  1: 'SHF_WRITE',
  2: 'SHF_ALLOC',
  4: 'SHF_EXECINSTR',
  16: 'SHF_MERGE',
  32: 'SHF_STRINGS',
};

// Helper type for endian readers
type EndianReaders = {
  readU16: (buf: Buffer, offset: number) => number;
  readU32: (buf: Buffer, offset: number) => number;
  readU64: (buf: Buffer, offset: number) => bigint;
};

function createEndianReaders(isLittleEndian: boolean): EndianReaders {
  return {
    readU16: (buf: Buffer, offset: number) =>
      isLittleEndian ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset),
    readU32: (buf: Buffer, offset: number) =>
      isLittleEndian ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset),
    readU64: (buf: Buffer, offset: number) =>
      isLittleEndian ? buf.readBigUInt64LE(offset) : buf.readBigUInt64BE(offset),
  };
}

function parseFlags(value: number, flagMap: Record<number, string>): string[] {
  const flags: string[] = [];
  for (const [flag, name] of Object.entries(flagMap)) {
    if (value & Number(flag)) {
      flags.push(name);
    }
  }
  return flags;
}

function parseElfHeaderFields(
  elfHeader: Buffer,
  is64Bit: boolean,
  readers: EndianReaders,
): {
  type: number;
  machine: number;
  entry: bigint;
  phoff: bigint;
  shoff: bigint;
  phentsize: number;
  phnum: number;
  shentsize: number;
  shnum: number;
  shstrndx: number;
} {
  const { readU16, readU32, readU64 } = readers;
  if (is64Bit) {
    return {
      type: readU16(elfHeader, 16),
      machine: readU16(elfHeader, 18),
      entry: readU64(elfHeader, 24),
      phoff: readU64(elfHeader, 32),
      shoff: readU64(elfHeader, 40),
      phentsize: readU16(elfHeader, 54),
      phnum: readU16(elfHeader, 56),
      shentsize: readU16(elfHeader, 58),
      shnum: readU16(elfHeader, 60),
      shstrndx: readU16(elfHeader, 62),
    };
  }
  return {
    type: readU16(elfHeader, 16),
    machine: readU16(elfHeader, 18),
    entry: BigInt(readU32(elfHeader, 24)),
    phoff: BigInt(readU32(elfHeader, 28)),
    shoff: BigInt(readU32(elfHeader, 32)),
    phentsize: readU16(elfHeader, 42),
    phnum: readU16(elfHeader, 44),
    shentsize: readU16(elfHeader, 46),
    shnum: readU16(elfHeader, 48),
    shstrndx: readU16(elfHeader, 50),
  };
}

async function readProgramHeaders(
  fileHandle: Awaited<ReturnType<typeof open>>,
  phoff: bigint,
  phnum: number,
  phentsize: number,
  is64Bit: boolean,
  readers: EndianReaders,
): Promise<ExtractELFHeadersOutput['programHeaders']> {
  const { readU32, readU64 } = readers;
  const programHeaders: ExtractELFHeadersOutput['programHeaders'] = [];

  for (let i = 0; i < phnum; i++) {
    const phBuffer = Buffer.alloc(phentsize);
    await fileHandle.read(phBuffer, 0, phentsize, Number(phoff) + i * phentsize);

    const parsed = is64Bit
      ? {
          pType: readU32(phBuffer, 0),
          pFlags: readU32(phBuffer, 4),
          pOffset: readU64(phBuffer, 8),
          pVaddr: readU64(phBuffer, 16),
          pPaddr: readU64(phBuffer, 24),
          pFilesz: readU64(phBuffer, 32),
          pMemsz: readU64(phBuffer, 40),
        }
      : {
          pType: readU32(phBuffer, 0),
          pOffset: BigInt(readU32(phBuffer, 4)),
          pVaddr: BigInt(readU32(phBuffer, 8)),
          pPaddr: BigInt(readU32(phBuffer, 12)),
          pFilesz: BigInt(readU32(phBuffer, 16)),
          pMemsz: BigInt(readU32(phBuffer, 20)),
          pFlags: readU32(phBuffer, 24),
        };

    programHeaders.push({
      type: PT_TYPES[parsed.pType] ?? `UNKNOWN(0x${parsed.pType.toString(16)})`,
      offset: Number(parsed.pOffset),
      virtualAddress: `0x${parsed.pVaddr.toString(16)}`,
      physicalAddress: `0x${parsed.pPaddr.toString(16)}`,
      fileSize: Number(parsed.pFilesz),
      memorySize: Number(parsed.pMemsz),
      flags: parseFlags(parsed.pFlags, PF_FLAGS),
    });
  }

  return programHeaders;
}

async function readSectionHeaders(
  fileHandle: Awaited<ReturnType<typeof open>>,
  shoff: bigint,
  shnum: number,
  shentsize: number,
  shstrndx: number,
  is64Bit: boolean,
  readers: EndianReaders,
): Promise<ExtractELFHeadersOutput['sectionHeaders']> {
  const { readU32, readU64 } = readers;
  const sectionHeaders: ExtractELFHeadersOutput['sectionHeaders'] = [];

  if (shnum === 0) return sectionHeaders;

  // First, read the section string table
  const shstrtabHeader = Buffer.alloc(shentsize);
  await fileHandle.read(shstrtabHeader, 0, shentsize, Number(shoff) + shstrndx * shentsize);

  const strtabOffset = is64Bit ? readU64(shstrtabHeader, 24) : BigInt(readU32(shstrtabHeader, 16));
  const strtabSize = is64Bit ? Number(readU64(shstrtabHeader, 32)) : readU32(shstrtabHeader, 20);

  const shstrtab = Buffer.alloc(strtabSize);
  await fileHandle.read(shstrtab, 0, strtabSize, Number(strtabOffset));

  // Read all section headers
  for (let i = 0; i < shnum; i++) {
    const shBuffer = Buffer.alloc(shentsize);
    await fileHandle.read(shBuffer, 0, shentsize, Number(shoff) + i * shentsize);

    const parsed = is64Bit
      ? {
          shName: readU32(shBuffer, 0),
          shType: readU32(shBuffer, 4),
          shFlags: readU64(shBuffer, 8),
          shAddr: readU64(shBuffer, 16),
          shOffset: readU64(shBuffer, 24),
          shSize: readU64(shBuffer, 32),
        }
      : {
          shName: readU32(shBuffer, 0),
          shType: readU32(shBuffer, 4),
          shFlags: BigInt(readU32(shBuffer, 8)),
          shAddr: BigInt(readU32(shBuffer, 12)),
          shOffset: BigInt(readU32(shBuffer, 16)),
          shSize: BigInt(readU32(shBuffer, 20)),
        };

    // Get section name from string table
    let name = '';
    if (parsed.shName < shstrtab.length) {
      const nameEnd = shstrtab.indexOf(0, parsed.shName);
      name = shstrtab
        .subarray(parsed.shName, nameEnd > parsed.shName ? nameEnd : undefined)
        .toString('utf8');
    }

    sectionHeaders.push({
      name: name || `section_${i}`,
      type: SHT_TYPES[parsed.shType] ?? `UNKNOWN(0x${parsed.shType.toString(16)})`,
      address: `0x${parsed.shAddr.toString(16)}`,
      offset: Number(parsed.shOffset),
      size: Number(parsed.shSize),
      flags: parseFlags(Number(parsed.shFlags), SHF_FLAGS),
    });
  }

  return sectionHeaders;
}

function validateElfMagic(ident: Buffer): void {
  for (let i = 0; i < 4; i++) {
    if (ident[i] !== ELF_MAGIC[i]) {
      throw new Error('Invalid ELF file: Missing ELF magic');
    }
  }
}

/**
 * Extract headers from a Linux ELF (Executable and Linkable Format) file.
 */
export async function extractELFHeaders(
  input: ExtractELFHeadersInput,
): Promise<ExtractELFHeadersOutput> {
  const { binaryPath, options } = input;
  const includeDetailedSections = options?.includeDetailedSections ?? true;
  const parseDynamicSection = options?.parseDynamicSection ?? true;

  logToolExecution('extract_elf_headers', { binaryPath, options }, 'start');

  const fileHandle = await open(binaryPath, 'r');

  try {
    // Read ELF identification (16 bytes)
    const ident = Buffer.alloc(16);
    await fileHandle.read(ident, 0, 16, 0);
    validateElfMagic(ident);

    const elfClass = ident[4] ?? 2;
    const elfData = ident[5] ?? 1;
    const elfVersion = ident[6] ?? 1;
    const elfOsAbi = ident[7] ?? 0;

    const is64Bit = elfClass === 2;
    const readers = createEndianReaders(elfData === 1);

    // Read rest of ELF header
    const headerSize = is64Bit ? 64 : 52;
    const elfHeader = Buffer.alloc(headerSize);
    await fileHandle.read(elfHeader, 0, headerSize, 0);

    const fields = parseElfHeaderFields(elfHeader, is64Bit, readers);

    // Read Program Headers
    const programHeaders = await readProgramHeaders(
      fileHandle,
      fields.phoff,
      fields.phnum,
      fields.phentsize,
      is64Bit,
      readers,
    );

    // Read Section Headers
    const sectionHeaders = includeDetailedSections
      ? await readSectionHeaders(
          fileHandle,
          fields.shoff,
          fields.shnum,
          fields.shentsize,
          fields.shstrndx,
          is64Bit,
          readers,
        )
      : [];

    // Parse Dynamic Section (simplified)
    const dynamicEntries = parseDynamicSection ? [] : undefined;

    const result: ExtractELFHeadersOutput = {
      elfHeader: {
        class: ELF_CLASS[elfClass] ?? 'ELF64',
        data: ELF_DATA[elfData] ?? 'LITTLE_ENDIAN',
        version: elfVersion,
        osAbi: ELF_OSABI[elfOsAbi] ?? `UNKNOWN(${elfOsAbi})`,
        type: ELF_TYPE[fields.type] ?? 'EXEC',
        machine: ELF_MACHINE[fields.machine] ?? `UNKNOWN(0x${fields.machine.toString(16)})`,
        entryPoint: `0x${fields.entry.toString(16)}`,
      },
      programHeaders,
      sectionHeaders,
      dynamicEntries,
    };

    logToolExecution('extract_elf_headers', { binaryPath }, 'success', {
      class: result.elfHeader.class,
      sections: sectionHeaders.length,
      programHeaders: programHeaders.length,
    });

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('extract_elf_headers', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to extract ELF headers: ${errorMessage}`);
  } finally {
    await fileHandle.close();
  }
}

export default extractELFHeaders;
