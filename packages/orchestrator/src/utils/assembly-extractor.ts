/**
 * Assembly Extractor
 *
 * Extracts and analyzes assembly code from binaries using Ghidra.
 * Provides pattern matching for system calls, loops, external references,
 * and control flow graph generation.
 * Supports x86, x86_64, ARM, and ARM64 architectures.
 *
 * @module utils/assembly-extractor
 *
 * @todo Phase 4: Add symbolic execution for path analysis
 * @todo Phase 4: Add ROP gadget detection
 */

import { getLogger } from '@logtape/logtape';
import { err, ok, type Result } from '@sentinel/shared';

const logger = getLogger(['sentinel', 'assembly-extractor']);

// ============================================
// TYPES
// ============================================

/**
 * Individual assembly instruction
 */
export type AssemblyInstruction = {
  /** Memory address of instruction */
  address: string;
  /** Raw bytes as hex string */
  bytes: string;
  /** Instruction mnemonic (e.g., 'mov', 'call') */
  mnemonic: string;
  /** Instruction operands */
  operands: string;
  /** Optional comment from analysis */
  comment?: string;
};

/**
 * Basic block in control flow graph
 */
export type BasicBlock = {
  /** Unique block identifier */
  id: string;
  /** Starting address of block */
  startAddress: string;
  /** Ending address of block */
  endAddress: string;
  /** Instructions in this block */
  instructions: AssemblyInstruction[];
  /** Block type/role */
  type: 'entry' | 'exit' | 'normal' | 'loop-header' | 'switch' | 'exception';
  /** Successor block IDs */
  successors: string[];
  /** Predecessor block IDs */
  predecessors: string[];
  /** Whether block ends with conditional branch */
  isConditional: boolean;
  /** Whether block ends with call instruction */
  hasCall: boolean;
  /** Called function address if hasCall */
  callTarget?: string;
};

/**
 * Edge type in control flow graph
 */
export type CfgEdgeType =
  | 'fallthrough'
  | 'unconditional'
  | 'conditional-true'
  | 'conditional-false'
  | 'call'
  | 'return'
  | 'exception';

/**
 * Edge in control flow graph
 */
export type CfgEdge = {
  /** Source block ID */
  from: string;
  /** Target block ID */
  to: string;
  /** Edge type */
  type: CfgEdgeType;
  /** Condition for conditional edges */
  condition?: string;
};

/**
 * Control flow graph for a function
 */
export type ControlFlowGraph = {
  /** Function this CFG represents */
  functionAddress: string;
  /** Function name */
  functionName: string;
  /** Entry block ID */
  entryBlockId: string;
  /** Exit block IDs (may have multiple returns) */
  exitBlockIds: string[];
  /** All basic blocks */
  blocks: BasicBlock[];
  /** All edges */
  edges: CfgEdge[];
  /** Cyclomatic complexity (edges - nodes + 2) */
  cyclomaticComplexity: number;
  /** Detected loop headers */
  loopHeaders: string[];
  /** Dominance information (if computed) */
  dominators?: Map<string, string[]>;
};

/**
 * Assembly function with all instructions
 */
export type AssemblyFunction = {
  /** Entry point address */
  address: string;
  /** Function name (or generated name) */
  name: string;
  /** Size in bytes */
  size: number;
  /** All instructions in function */
  instructions: AssemblyInstruction[];
  /** Optional documentation/analysis notes */
  documentation?: string;
};

/**
 * Assembly pattern categories
 */
export type AssemblyPatternType =
  | 'syscall'
  | 'privilege'
  | 'memory'
  | 'crypto'
  | 'antiDebug'
  | 'network'
  | 'process'
  | 'file'
  | 'loop'
  | 'xref'
  | 'obfuscation';

/**
 * Detected assembly pattern
 */
export type AssemblyPattern = {
  /** Pattern category */
  type: AssemblyPatternType;
  /** Instructions that matched */
  instructions: AssemblyInstruction[];
  /** Description of the pattern */
  description: string;
  /** Risk level */
  severity: 'high' | 'medium' | 'low';
};

/**
 * Assembly analysis summary
 */
export type AssemblyAnalysisSummary = {
  /** Total functions analyzed */
  totalFunctions: number;
  /** Total instructions */
  totalInstructions: number;
  /** Detected patterns */
  patterns: AssemblyPattern[];
  /** High-interest functions */
  interestingFunctions: AssemblyFunction[];
  /** Architecture detected */
  architecture: string;
  /** Control flow graphs for analyzed functions */
  controlFlowGraphs?: ControlFlowGraph[];
  /** Average cyclomatic complexity */
  avgComplexity?: number;
};

/**
 * Extractor configuration
 */
export type AssemblyExtractorConfig = {
  /** Ghidra project path */
  ghidraProject?: string;
  /** Maximum functions to analyze */
  maxFunctions: number;
  /** Maximum instructions per function */
  maxInstructions: number;
  /** Timeout for extraction (ms) */
  timeoutMs: number;
};

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_CONFIG: AssemblyExtractorConfig = {
  maxFunctions: 100,
  maxInstructions: 1000,
  timeoutMs: 60_000,
};

// ============================================
// PATTERN DEFINITIONS
// ============================================

/**
 * Supported architectures
 */
export type SupportedArchitecture = 'x86' | 'x86_64' | 'arm' | 'arm64' | 'unknown';

/**
 * Mnemonic patterns for suspicious operations
 */
type MnemonicPattern = {
  type: AssemblyPatternType;
  mnemonics: string[];
  description: string;
  severity: 'high' | 'medium' | 'low';
  architectures?: SupportedArchitecture[];
};

/**
 * x86/x64 specific suspicious patterns
 */
const X86_PATTERNS: MnemonicPattern[] = [
  // System calls
  {
    type: 'syscall',
    mnemonics: ['syscall', 'sysenter', 'int 0x80', 'int 0x2e'],
    description: 'System call invocation (x86)',
    severity: 'medium',
    architectures: ['x86', 'x86_64'],
  },

  // Privilege operations
  {
    type: 'privilege',
    mnemonics: ['cli', 'sti', 'hlt', 'lgdt', 'lidt', 'ltr', 'in', 'out', 'invd', 'wbinvd'],
    description: 'Privileged instruction (x86)',
    severity: 'high',
    architectures: ['x86', 'x86_64'],
  },

  // Anti-debugging (x86 specific)
  {
    type: 'antiDebug',
    mnemonics: ['rdtsc', 'cpuid', 'int 3', 'icebp', 'ud2'],
    description: 'Anti-debugging technique (x86)',
    severity: 'high',
    architectures: ['x86', 'x86_64'],
  },

  // Memory manipulation (x86)
  {
    type: 'memory',
    mnemonics: ['lock cmpxchg', 'xchg', 'prefetch', 'clflush', 'mfence', 'lfence', 'sfence'],
    description: 'Memory manipulation (x86)',
    severity: 'low',
    architectures: ['x86', 'x86_64'],
  },

  // Crypto-related (AES-NI, SHA, etc.)
  {
    type: 'crypto',
    mnemonics: [
      'aesenc',
      'aesdec',
      'aesenclast',
      'aesdeclast',
      'aesimc',
      'aeskeygenassist',
      'pclmulqdq',
      'sha1rnds4',
      'sha1nexte',
      'sha256rnds2',
      'sha256msg1',
      'sha256msg2',
    ],
    description: 'Cryptographic operation (x86)',
    severity: 'medium',
    architectures: ['x86', 'x86_64'],
  },
];

/**
 * ARM/ARM64 specific suspicious patterns
 */
const ARM_PATTERNS: MnemonicPattern[] = [
  // System calls (ARM)
  {
    type: 'syscall',
    mnemonics: ['svc', 'swi', 'hvc', 'smc'],
    description: 'System call invocation (ARM)',
    severity: 'medium',
    architectures: ['arm', 'arm64'],
  },

  // Privilege operations (ARM)
  {
    type: 'privilege',
    mnemonics: ['msr', 'mrs', 'cps', 'smc', 'hvc', 'eret', 'wfi', 'wfe', 'sev'],
    description: 'Privileged instruction (ARM)',
    severity: 'high',
    architectures: ['arm', 'arm64'],
  },

  // Anti-debugging (ARM specific)
  {
    type: 'antiDebug',
    mnemonics: ['bkpt', 'brk', 'dcps1', 'dcps2', 'dcps3', 'drps'],
    description: 'Anti-debugging technique (ARM)',
    severity: 'high',
    architectures: ['arm', 'arm64'],
  },

  // Memory barriers and synchronization (ARM)
  {
    type: 'memory',
    mnemonics: ['dmb', 'dsb', 'isb', 'ldrex', 'strex', 'ldxr', 'stxr', 'ldaex', 'stlex', 'clrex'],
    description: 'Memory synchronization (ARM)',
    severity: 'low',
    architectures: ['arm', 'arm64'],
  },

  // Crypto-related (ARM crypto extensions)
  {
    type: 'crypto',
    mnemonics: [
      'aese',
      'aesd',
      'aesmc',
      'aesimc',
      'sha1c',
      'sha1p',
      'sha1m',
      'sha1h',
      'sha1su0',
      'sha1su1',
      'sha256h',
      'sha256h2',
      'sha256su0',
      'sha256su1',
      'sha512h',
      'sha512h2',
      'sha512su0',
      'sha512su1',
      'pmull',
      'pmull2',
      'sm3',
      'sm4e',
      'sm4ekey',
    ],
    description: 'Cryptographic operation (ARM)',
    severity: 'medium',
    architectures: ['arm', 'arm64'],
  },

  // NEON SIMD operations (common in obfuscation)
  {
    type: 'obfuscation',
    mnemonics: ['tbl', 'tbx', 'ext', 'zip1', 'zip2', 'uzp1', 'uzp2', 'trn1', 'trn2'],
    description: 'SIMD permutation (possible obfuscation)',
    severity: 'low',
    architectures: ['arm', 'arm64'],
  },
];

/**
 * Combined patterns for all architectures
 */
const SUSPICIOUS_PATTERNS: MnemonicPattern[] = [...X86_PATTERNS, ...ARM_PATTERNS];

/**
 * Architecture-specific register patterns
 */
const ARCHITECTURE_REGISTERS = {
  x86: ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'],
  x86_64: [
    'rax',
    'rbx',
    'rcx',
    'rdx',
    'rsi',
    'rdi',
    'rbp',
    'rsp',
    'rip',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
  ],
  arm: [
    'r0',
    'r1',
    'r2',
    'r3',
    'r4',
    'r5',
    'r6',
    'r7',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'sp',
    'lr',
    'pc',
    'cpsr',
  ],
  arm64: [
    'x0',
    'x1',
    'x2',
    'x3',
    'x4',
    'x5',
    'x6',
    'x7',
    'x8',
    'x9',
    'x10',
    'x11',
    'x12',
    'x13',
    'x14',
    'x15',
    'x16',
    'x17',
    'x18',
    'x19',
    'x20',
    'x21',
    'x22',
    'x23',
    'x24',
    'x25',
    'x26',
    'x27',
    'x28',
    'x29',
    'x30',
    'sp',
    'lr',
    'pc',
    'xzr',
    'wzr',
    'nzcv',
  ],
};

// ============================================
// ARCHITECTURE DETECTION HELPERS
// ============================================

/** Read 16-bit little-endian value from byte array */
function readU16LE(bytes: Uint8Array, offset: number): number {
  const b0 = bytes[offset] ?? 0;
  const b1 = bytes[offset + 1] ?? 0;
  return b0 | (b1 << 8);
}

/** Read 32-bit little-endian value from byte array */
function readU32LE(bytes: Uint8Array, offset: number): number {
  const b0 = bytes[offset] ?? 0;
  const b1 = bytes[offset + 1] ?? 0;
  const b2 = bytes[offset + 2] ?? 0;
  const b3 = bytes[offset + 3] ?? 0;
  return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

/** ELF machine type constants */
const ELF_MACHINES = {
  EM_386: 3,
  EM_X86_64: 62,
  EM_ARM: 40,
  EM_AARCH64: 183,
} as const;

/** PE machine type constants */
const PE_MACHINES = {
  I386: 0x014c,
  AMD64: 0x8664,
  ARM: 0x01c0,
  ARM64: 0xaa64,
} as const;

/** Detect architecture from ELF header */
function detectElfArchitecture(bytes: Uint8Array): SupportedArchitecture {
  const elfClass = bytes[4] ?? 0;
  const eMachine = readU16LE(bytes, 18);

  if (eMachine === ELF_MACHINES.EM_X86_64) return 'x86_64';
  if (eMachine === ELF_MACHINES.EM_386) return 'x86';
  if (eMachine === ELF_MACHINES.EM_AARCH64) return 'arm64';
  if (eMachine === ELF_MACHINES.EM_ARM) return 'arm';

  // Fallback to class-based detection
  if (elfClass === 2) return 'x86_64';
  if (elfClass === 1) return 'x86';

  logger.debug`Unknown ELF machine type: ${eMachine}`;
  return 'unknown';
}

/** Detect architecture from PE header */
function detectPeArchitecture(bytes: Uint8Array): SupportedArchitecture {
  const peOffset = readU32LE(bytes, 0x3c);

  if (peOffset + 6 < bytes.length) {
    const machine = readU16LE(bytes, peOffset + 4);

    if (machine === PE_MACHINES.AMD64) return 'x86_64';
    if (machine === PE_MACHINES.I386) return 'x86';
    if (machine === PE_MACHINES.ARM64) return 'arm64';
    if (machine === PE_MACHINES.ARM) return 'arm';

    logger.debug`Unknown PE machine type: 0x${machine.toString(16)}`;
  }

  return 'x86'; // Default PE to x86
}

/** Detect architecture from Mach-O header */
function detectMachOArchitecture(bytes: Uint8Array): SupportedArchitecture | null {
  const magic32 = readU32LE(bytes, 0);
  const MACH_O_64 = 0xfeedfacf;
  const MACH_O_32 = 0xfeedface;
  const MACH_O_64_REV = 0xcffaedfe;
  const MACH_O_32_REV = 0xcefaedfe;

  if (magic32 === MACH_O_64 || magic32 === MACH_O_64_REV) {
    const cpuType = readU32LE(bytes, 4);
    const CPU_TYPE_ARM64 = 0x0100000c;
    const CPU_TYPE_X86_64 = 0x01000007;

    if (cpuType === CPU_TYPE_ARM64) return 'arm64';
    if (cpuType === CPU_TYPE_X86_64) return 'x86_64';
    return 'x86_64';
  }

  if (magic32 === MACH_O_32 || magic32 === MACH_O_32_REV) {
    return 'x86';
  }

  return null; // Not Mach-O
}

// ============================================
// ASSEMBLY EXTRACTOR CLASS
// ============================================

export class AssemblyExtractor {
  private readonly config: AssemblyExtractorConfig;

  constructor(config: Partial<AssemblyExtractorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Detect architecture from binary file header (ELF/PE/Mach-O)
   *
   * Reads the first bytes of the binary to determine architecture
   * based on file format magic bytes and machine type fields.
   */
  async detectArchitectureFromBinary(binaryPath: string): Promise<SupportedArchitecture> {
    try {
      const file = Bun.file(binaryPath);
      const buffer = await file.slice(0, 64).arrayBuffer();
      const bytes = new Uint8Array(buffer);

      // Check ELF magic: 0x7F 'E' 'L' 'F'
      if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
        return detectElfArchitecture(bytes);
      }

      // Check PE magic: 'M' 'Z' (DOS header)
      if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
        return detectPeArchitecture(bytes);
      }

      // Check Mach-O
      const machResult = detectMachOArchitecture(bytes);
      if (machResult !== null) {
        return machResult;
      }

      logger.debug`Unknown binary format for: ${binaryPath}`;
      return 'unknown';
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.warn`Failed to detect architecture from binary: ${message}`;
      return 'unknown';
    }
  }

  /**
   * Check if operands contain a specific register (word boundary aware)
   * Prevents false positives like '0x80' matching 'x0'
   */
  private operandsContainRegister(operands: string, register: string): boolean {
    // Use word boundary regex to avoid false positives
    const pattern = new RegExp(`\\b${register}\\b`, 'i');
    return pattern.test(operands);
  }

  /**
   * Detect architecture from instructions
   */
  detectArchitecture(instructions: AssemblyInstruction[]): SupportedArchitecture {
    const sample = instructions.slice(0, 50);
    let x86Score = 0;
    let x64Score = 0;
    let armScore = 0;
    let arm64Score = 0;

    for (const instr of sample) {
      const operands = instr.operands.toLowerCase();
      const mnemonic = instr.mnemonic.toLowerCase();

      // Check for x86_64 registers
      if (ARCHITECTURE_REGISTERS.x86_64.some((r) => this.operandsContainRegister(operands, r))) {
        x64Score++;
      }
      // Check for x86 registers (but not overlapping with x64)
      else if (ARCHITECTURE_REGISTERS.x86.some((r) => this.operandsContainRegister(operands, r))) {
        x86Score++;
      }
      // Check for ARM64 registers
      else if (
        ARCHITECTURE_REGISTERS.arm64.some(
          (r) => this.operandsContainRegister(operands, r) && !r.startsWith('w'),
        )
      ) {
        arm64Score++;
      }
      // Check for ARM32 registers
      else if (ARCHITECTURE_REGISTERS.arm.some((r) => this.operandsContainRegister(operands, r))) {
        armScore++;
      }

      // Check ARM-specific mnemonics
      if (['ldm', 'stm', 'ldr', 'str', 'adr', 'bic', 'orr', 'tst', 'teq'].includes(mnemonic)) {
        armScore++;
        arm64Score++;
      }

      // Check x86-specific mnemonics
      if (
        ['movzx', 'movsx', 'cdq', 'cwde', 'pushad', 'popad', 'pusha', 'popa'].includes(mnemonic)
      ) {
        x86Score++;
        x64Score++;
      }
    }

    // Determine most likely architecture
    const scores = [
      { arch: 'x86_64' as SupportedArchitecture, score: x64Score },
      { arch: 'x86' as SupportedArchitecture, score: x86Score },
      { arch: 'arm64' as SupportedArchitecture, score: arm64Score },
      { arch: 'arm' as SupportedArchitecture, score: armScore },
    ];

    scores.sort((a, b) => b.score - a.score);
    const topScore = scores[0];
    return topScore && topScore.score > 0 ? topScore.arch : 'unknown';
  }

  /**
   * Get patterns for a specific architecture
   */
  private getPatternsForArchitecture(architecture: SupportedArchitecture): MnemonicPattern[] {
    return SUSPICIOUS_PATTERNS.filter((p) => {
      // If no architecture restriction or architecture is unknown, include all patterns
      if (!p.architectures || architecture === 'unknown') return true;
      return p.architectures.includes(architecture);
    });
  }

  /**
   * Extract assembly for a specific function via MCP server's get_functions tool
   *
   * Integrates with Ghidra through the MCP server's extract-functions script.
   * Falls back to error if MCP server is unavailable.
   */
  async extractFunction(
    binaryPath: string,
    functionAddress: string,
  ): Promise<Result<AssemblyFunction, Error>> {
    const mcpUrl = process.env.MCP_SERVER_URL ?? 'http://localhost:3000';

    try {
      logger.info`Extracting function at ${functionAddress} from ${binaryPath}`;

      // Call the MCP server's get_functions tool
      const response = await fetch(`${mcpUrl}/tools/get_functions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          binary_path: binaryPath,
          addresses: [functionAddress],
          include_call_graph: true,
          include_decompilation: false,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        logger.error`MCP server error: ${response.status} ${errorText}`;
        return err(new Error(`MCP server error: ${response.status}`));
      }

      const result = (await response.json()) as {
        success?: boolean;
        functions?: Array<{
          name: string;
          address: string;
          size: number;
        }>;
      };

      const functions = result.functions ?? [];
      const fn = functions[0];
      if (!result.success || !fn) {
        return err(new Error('Function not found or extraction failed'));
      }

      // Map MCP response to AssemblyFunction format
      const assemblyFunction: AssemblyFunction = {
        name: fn.name,
        address: fn.address,
        size: fn.size,
        instructions: [], // Instructions from disassembly would need separate call
      };

      logger.info`Extracted function ${fn.name} at ${fn.address}`;
      return ok(assemblyFunction);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      logger.error`Failed to extract function: ${message}`;
      return err(new Error(`Ghidra extraction failed: ${message}`));
    }
  }

  /**
   * Analyze assembly instructions for patterns
   * @param instructions - Instructions to analyze
   * @param architecture - Optional architecture hint (auto-detected if not provided)
   */
  analyzeInstructions(
    instructions: AssemblyInstruction[],
    architecture?: SupportedArchitecture,
  ): AssemblyPattern[] {
    const patterns: AssemblyPattern[] = [];

    // Auto-detect architecture if not provided
    const arch = architecture ?? this.detectArchitecture(instructions);
    const relevantPatterns = this.getPatternsForArchitecture(arch);

    for (const instruction of instructions) {
      const mnemonic = instruction.mnemonic.toLowerCase();
      const fullInstruction = `${mnemonic} ${instruction.operands}`.toLowerCase().trim();

      for (const patternDef of relevantPatterns) {
        for (const patternMnemonic of patternDef.mnemonics) {
          const patternLower = patternMnemonic.toLowerCase();
          if (
            mnemonic === patternLower ||
            mnemonic.startsWith(patternLower) ||
            fullInstruction === patternLower ||
            fullInstruction.startsWith(patternLower)
          ) {
            // Check if we already have this pattern
            const existing = patterns.find(
              (p) => p.type === patternDef.type && p.description === patternDef.description,
            );

            if (existing) {
              existing.instructions.push(instruction);
            } else {
              patterns.push({
                type: patternDef.type,
                instructions: [instruction],
                description: patternDef.description,
                severity: patternDef.severity,
              });
            }
            break;
          }
        }
      }
    }

    return patterns;
  }

  /**
   * Detect loops in instruction sequence
   * Uses basic backward jump detection
   */
  detectLoops(instructions: AssemblyInstruction[]): AssemblyPattern[] {
    const loops: AssemblyPattern[] = [];
    const jumpMnemonics = [
      'jmp',
      'je',
      'jne',
      'jz',
      'jnz',
      'jl',
      'jle',
      'jg',
      'jge',
      'ja',
      'jae',
      'jb',
      'jbe',
      'loop',
      'loope',
      'loopne',
    ];

    // Build address map
    const addressMap = new Map<string, number>();
    for (let i = 0; i < instructions.length; i++) {
      const instr = instructions[i];
      if (instr) {
        addressMap.set(instr.address.toLowerCase(), i);
      }
    }

    for (let i = 0; i < instructions.length; i++) {
      const instruction = instructions[i];
      if (!instruction) continue;

      const mnemonic = instruction.mnemonic.toLowerCase();

      if (jumpMnemonics.includes(mnemonic)) {
        // Check if target is before current instruction (back jump = likely loop)
        const targetAddr = instruction.operands.trim().toLowerCase();
        const targetIndex = addressMap.get(targetAddr);

        if (targetIndex !== undefined && targetIndex < i) {
          loops.push({
            type: 'loop',
            instructions: instructions.slice(targetIndex, i + 1),
            description: `Loop detected: ${instruction.address} jumps back to ${targetAddr}`,
            severity: 'low',
          });
        }
      }
    }

    return loops;
  }

  /**
   * Parse raw assembly text output into structured format
   * Handles common objdump/Ghidra output formats
   */
  parseAssemblyText(text: string): AssemblyInstruction[] {
    const instructions: AssemblyInstruction[] = [];
    const lines = text.split('\n');

    // Common format: "  400123:	48 89 e5             	mov    rbp,rsp"
    const objdumpRegex = /^\s*([0-9a-f]+):\s+([0-9a-f\s]+)\s+(\w+)\s*(.*)$/i;

    // Ghidra format: "00400123  MOV  RBP,RSP"
    const ghidraRegex = /^\s*([0-9a-f]+)\s+(\w+)\s*(.*)$/i;

    for (const line of lines) {
      let match = objdumpRegex.exec(line);
      if (match?.[1] && match[2] && match[3]) {
        instructions.push({
          address: match[1],
          bytes: match[2].trim(),
          mnemonic: match[3],
          operands: (match[4] ?? '').trim(),
        });
        continue;
      }

      match = ghidraRegex.exec(line);
      if (match?.[1] && match[2]) {
        instructions.push({
          address: match[1],
          bytes: '',
          mnemonic: match[2],
          operands: (match[3] ?? '').trim(),
        });
      }
    }

    return instructions;
  }

  /**
   * Generate control flow graph for a function
   */
  generateCFG(func: AssemblyFunction): ControlFlowGraph {
    const blocks: BasicBlock[] = [];
    const edges: CfgEdge[] = [];
    const loopHeaders: string[] = [];

    const addressToIndex = this.buildAddressMap(func.instructions);
    const leaders = this.findBlockLeaders(func.instructions, addressToIndex);
    const sortedLeaders = [...leaders].sort((a, b) => a - b);

    // Create basic blocks
    this.createBasicBlocks(func.instructions, sortedLeaders, blocks);

    // Create edges and detect loops
    this.createEdges(blocks, loopHeaders);

    // Calculate cyclomatic complexity
    const cyclomaticComplexity = edges.length - blocks.length + 2;

    // Build edges array from block connections
    for (const block of blocks) {
      for (const successor of block.successors) {
        const edgeType: CfgEdgeType = block.isConditional ? 'conditional-true' : 'fallthrough';
        edges.push({ from: block.id, to: successor, type: edgeType });
      }
    }

    return {
      functionAddress: func.address,
      functionName: func.name,
      entryBlockId: blocks[0]?.id ?? '',
      exitBlockIds: blocks.filter((b) => b.type === 'exit').map((b) => b.id),
      blocks,
      edges,
      cyclomaticComplexity: Math.max(1, cyclomaticComplexity),
      loopHeaders: [...new Set(loopHeaders)],
    };
  }

  /**
   * Build map of instruction addresses to indices
   */
  private buildAddressMap(instructions: AssemblyInstruction[]): Map<string, number> {
    const map = new Map<string, number>();
    for (let i = 0; i < instructions.length; i++) {
      const instr = instructions[i];
      if (instr) {
        map.set(instr.address.toLowerCase(), i);
      }
    }
    return map;
  }

  /**
   * Find basic block leaders
   */
  private findBlockLeaders(
    instructions: AssemblyInstruction[],
    addressMap: Map<string, number>,
  ): Set<number> {
    const leaders = new Set<number>([0]);
    const unconditionalJumps = ['jmp', 'br', 'b'];
    const conditionalJumps = [
      'je',
      'jne',
      'jz',
      'jnz',
      'jl',
      'jle',
      'jg',
      'jge',
      'ja',
      'jae',
      'jb',
      'jbe',
      'jo',
      'jno',
      'js',
      'jns',
      'loop',
      'loope',
      'loopne',
      'beq',
      'bne',
      'blt',
      'bgt',
      'ble',
      'bge',
    ];
    const returnMnemonics = ['ret', 'retn', 'retf', 'bx lr'];

    for (let i = 0; i < instructions.length; i++) {
      const instr = instructions[i];
      if (!instr) continue;

      const mnemonic = instr.mnemonic.toLowerCase();

      if (
        unconditionalJumps.includes(mnemonic) ||
        conditionalJumps.includes(mnemonic) ||
        returnMnemonics.some((r) => mnemonic.startsWith(r))
      ) {
        if (i + 1 < instructions.length) {
          leaders.add(i + 1);
        }
      }

      if (unconditionalJumps.includes(mnemonic) || conditionalJumps.includes(mnemonic)) {
        const targetAddr = instr.operands.split(',')[0]?.trim().toLowerCase();
        if (targetAddr) {
          const targetIndex = addressMap.get(targetAddr);
          if (targetIndex !== undefined) {
            leaders.add(targetIndex);
          }
        }
      }
    }

    return leaders;
  }

  /**
   * Create basic blocks from leaders
   */
  private createBasicBlocks(
    instructions: AssemblyInstruction[],
    leaders: number[],
    blocks: BasicBlock[],
  ): void {
    const conditionalJumps = [
      'je',
      'jne',
      'jz',
      'jnz',
      'jl',
      'jle',
      'jg',
      'jge',
      'ja',
      'jae',
      'jb',
      'jbe',
      'jo',
      'jno',
      'js',
      'jns',
      'loop',
      'loope',
      'loopne',
      'beq',
      'bne',
      'blt',
      'bgt',
      'ble',
      'bge',
    ];
    const callMnemonics = ['call', 'bl', 'blx'];
    const returnMnemonics = ['ret', 'retn', 'retf', 'bx lr'];

    for (let i = 0; i < leaders.length; i++) {
      const startIdx = leaders[i];
      if (startIdx === undefined) continue;

      const endIdx =
        i + 1 < leaders.length
          ? (leaders[i + 1] ?? instructions.length) - 1
          : instructions.length - 1;

      const blockInstructions = instructions.slice(startIdx, endIdx + 1);
      const startInstr = blockInstructions[0];
      const endInstr = blockInstructions[blockInstructions.length - 1];

      if (!startInstr || !endInstr) continue;

      const blockId = `block_${startInstr.address}`;
      const lastMnemonic = endInstr.mnemonic.toLowerCase();
      const isConditional = conditionalJumps.includes(lastMnemonic);
      const hasCall = callMnemonics.some((c) => lastMnemonic.startsWith(c));
      const isReturn = returnMnemonics.some((r) => lastMnemonic.startsWith(r));

      let blockType: BasicBlock['type'] = 'normal';
      if (startIdx === 0) blockType = 'entry';
      else if (isReturn) blockType = 'exit';

      blocks.push({
        id: blockId,
        startAddress: startInstr.address,
        endAddress: endInstr.address,
        instructions: blockInstructions,
        type: blockType,
        successors: [],
        predecessors: [],
        isConditional,
        hasCall,
        callTarget: hasCall ? endInstr.operands.split(',')[0]?.trim() : undefined,
      });
    }
  }

  /** Jump mnemonics for CFG analysis (combined x86 + ARM) */
  private readonly cfgMnemonics = {
    unconditional: [
      // x86
      'jmp',
      // ARM
      'b',
      'bl',
      'blx',
      'bx',
      'blr',
      'br',
    ],
    conditional: [
      // x86
      'je',
      'jne',
      'jz',
      'jnz',
      'jl',
      'jle',
      'jg',
      'jge',
      'ja',
      'jae',
      'jb',
      'jbe',
      'jo',
      'jno',
      'js',
      'jns',
      'loop',
      'loope',
      'loopne',
      'jcxz',
      'jecxz',
      'jrcxz',
      // ARM condition codes
      'beq',
      'bne',
      'bcs',
      'bhs',
      'bcc',
      'blo',
      'bmi',
      'bpl',
      'bvs',
      'bvc',
      'bhi',
      'bls',
      'bge',
      'blt',
      'bgt',
      'ble',
      'bal',
      // ARM64 compare-and-branch
      'cbnz',
      'cbz',
      'tbnz',
      'tbz',
    ],
    returns: [
      // x86
      'ret',
      'retn',
      'retf',
      'iret',
      'iretd',
      'iretq',
      // ARM
      'bx lr',
      'ldmfd sp!, {pc}',
      'pop {pc}',
      'eret',
    ],
  };

  /**
   * Check if mnemonic is a jump instruction
   */
  private isJumpMnemonic(mnemonic: string): boolean {
    return (
      this.cfgMnemonics.unconditional.includes(mnemonic) ||
      this.cfgMnemonics.conditional.includes(mnemonic)
    );
  }

  /**
   * Check if mnemonic is a return instruction
   */
  private isReturnMnemonic(mnemonic: string): boolean {
    return this.cfgMnemonics.returns.some((r) => mnemonic.startsWith(r));
  }

  /**
   * Handle jump target edge creation
   */
  private handleJumpTarget(
    block: BasicBlock,
    blocks: BasicBlock[],
    blockIndex: number,
    targetAddr: string,
    loopHeaders: string[],
  ): void {
    const targetBlock = blocks.find((b) => b.startAddress.toLowerCase() === targetAddr);
    if (!targetBlock) return;

    block.successors.push(targetBlock.id);
    targetBlock.predecessors.push(block.id);

    // Detect back edge (loop)
    const targetIndex = blocks.indexOf(targetBlock);
    if (targetIndex < blockIndex && targetBlock.type === 'normal') {
      loopHeaders.push(targetBlock.id);
      targetBlock.type = 'loop-header';
    }
  }

  /**
   * Add fallthrough edge to next block
   */
  private addFallthroughEdge(block: BasicBlock, nextBlock: BasicBlock | undefined): void {
    if (nextBlock) {
      block.successors.push(nextBlock.id);
      nextBlock.predecessors.push(block.id);
    }
  }

  /**
   * Create edges between blocks
   */
  private createEdges(blocks: BasicBlock[], loopHeaders: string[]): void {
    for (let i = 0; i < blocks.length; i++) {
      const block = blocks[i];
      if (!block) continue;

      const lastInstr = block.instructions[block.instructions.length - 1];
      if (!lastInstr) continue;

      const mnemonic = lastInstr.mnemonic.toLowerCase();

      if (this.isJumpMnemonic(mnemonic)) {
        const targetAddr = lastInstr.operands.split(',')[0]?.trim().toLowerCase();
        if (targetAddr) {
          this.handleJumpTarget(block, blocks, i, targetAddr, loopHeaders);
        }

        // Conditional jumps also fall through
        if (this.cfgMnemonics.conditional.includes(mnemonic)) {
          this.addFallthroughEdge(block, blocks[i + 1]);
        }
      } else if (!this.isReturnMnemonic(mnemonic)) {
        // Non-jump, non-return: fallthrough
        this.addFallthroughEdge(block, blocks[i + 1]);
      }
    }
  }

  /**
   * Create analysis summary from functions
   * @param functions - Assembly functions to summarize
   * @param architecture - Binary architecture (auto-detect if 'auto' or not specified)
   * @param generateCfgs - Whether to generate control flow graphs (default: true)
   */
  summarize(
    functions: AssemblyFunction[],
    architecture: string | 'auto' = 'auto',
    generateCfgs = true,
  ): AssemblyAnalysisSummary {
    const allInstructions = functions.flatMap((f) => f.instructions);

    // Auto-detect architecture if needed
    const detectedArch =
      architecture === 'auto'
        ? this.detectArchitecture(allInstructions)
        : (architecture as SupportedArchitecture);

    const patterns = this.analyzeInstructions(allInstructions, detectedArch);
    const loops = this.detectLoops(allInstructions);

    // Add loops to patterns
    patterns.push(...loops);

    // Find interesting functions (those with high-severity patterns)
    const interestingFunctions = functions.filter((func) => {
      const funcPatterns = this.analyzeInstructions(func.instructions, detectedArch);
      return funcPatterns.some((p) => p.severity === 'high');
    });

    // Generate control flow graphs if requested
    let controlFlowGraphs: ControlFlowGraph[] | undefined;
    let avgComplexity: number | undefined;

    if (generateCfgs && functions.length > 0) {
      controlFlowGraphs = functions
        .slice(0, this.config.maxFunctions)
        .map((func) => this.generateCFG(func));

      const totalComplexity = controlFlowGraphs.reduce(
        (sum, cfg) => sum + cfg.cyclomaticComplexity,
        0,
      );
      avgComplexity = Math.round((totalComplexity / controlFlowGraphs.length) * 100) / 100;
    }

    return {
      totalFunctions: functions.length,
      totalInstructions: allInstructions.length,
      patterns,
      interestingFunctions: interestingFunctions.slice(0, this.config.maxFunctions),
      architecture: detectedArch,
      controlFlowGraphs,
      avgComplexity,
    };
  }
}

// ============================================
// SINGLETON ACCESSOR
// ============================================

let extractorInstance: AssemblyExtractor | null = null;

/**
 * Get or create assembly extractor instance
 */
export function getAssemblyExtractor(config?: Partial<AssemblyExtractorConfig>): AssemblyExtractor {
  if (!extractorInstance || config) {
    extractorInstance = new AssemblyExtractor(config);
  }
  return extractorInstance;
}
