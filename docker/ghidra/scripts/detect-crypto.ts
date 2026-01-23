/**
 * SENTINEL Cryptographic Constant Detection Script
 *
 * Detects cryptographic algorithms by identifying known constants and patterns
 * in the binary. Searches for AES S-boxes, SHA/MD5 initialization vectors,
 * RC4 permutation tables, and other crypto signatures.
 *
 * Usage:
 *   analyzeHeadless /projects temp -import /path/to/binary \
 *     -postScript detect-crypto.js -scriptPath /scripts -deleteProject
 *
 * Arguments (optional):
 *   --verbose       Include detailed pattern matches
 *   --min-confidence=0.7   Minimum confidence threshold (0.0-1.0)
 *
 * Output is printed with markers for parsing by the MCP server.
 */

/// <reference path="./ghidra-api.d.ts" />

(() => {
  // ============================================================================
  // Output Types
  // ============================================================================

  type CryptoOutput = {
    success: boolean;
    error?: string;
    data?: CryptoData;
  };

  type CryptoData = {
    binaryName: string;
    findings: CryptoFinding[];
    metadata: CryptoMetadata;
  };

  type CryptoFinding = {
    algorithm: string;
    type: 'sbox' | 'constants' | 'permutation' | 'key_schedule' | 'pattern';
    address: string;
    size: number;
    confidence: number;
    description: string;
    nearbyFunctions: string[];
  };

  type CryptoMetadata = {
    scriptVersion: string;
    scanTime: number;
    findingCount: number;
    scannedBytes: number;
  };

  // ============================================================================
  // Argument Parsing
  // ============================================================================

  type ScriptArgs = {
    verbose: boolean;
    minConfidence: number;
  };

  function parseArgs(): ScriptArgs {
    const args: ScriptArgs = {
      verbose: false,
      minConfidence: 0.7,
    };

    for (const arg of getScriptArgs()) {
      if (arg === '--verbose') {
        args.verbose = true;
      } else if (arg.startsWith('--min-confidence=')) {
        const conf = Number.parseFloat(arg.substring(17));
        if (!Number.isNaN(conf) && conf >= 0 && conf <= 1) {
          args.minConfidence = conf;
        }
      }
    }

    return args;
  }

  // ============================================================================
  // Cryptographic Constants
  // ============================================================================

  /**
   * AES S-box (SubBytes transformation)
   * First 16 bytes for quick identification
   */
  const AES_SBOX_SIGNATURE = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  ];

  /**
   * AES Inverse S-box
   */
  const AES_INV_SBOX_SIGNATURE = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  ];

  /**
   * MD5 Initialization Vector (A, B, C, D)
   * Little-endian representation
   */
  const MD5_IV = [
    0x01,
    0x23,
    0x45,
    0x67, // 0x67452301
    0x89,
    0xab,
    0xcd,
    0xef, // 0xefcdab89
    0xfe,
    0xdc,
    0xba,
    0x98, // 0x98badcfe
    0x76,
    0x54,
    0x32,
    0x10, // 0x10325476
  ];

  /**
   * SHA-1 Initialization Vector (H0-H4)
   * Big-endian representation
   */
  const SHA1_IV = [
    0x67,
    0x45,
    0x23,
    0x01, // 0x67452301
    0xef,
    0xcd,
    0xab,
    0x89, // 0xefcdab89
    0x98,
    0xba,
    0xdc,
    0xfe, // 0x98badcfe
    0x10,
    0x32,
    0x54,
    0x76, // 0x10325476
    0xc3,
    0xd2,
    0xe1,
    0xf0, // 0xc3d2e1f0
  ];

  /**
   * SHA-256 Initialization Vector (first 4 values)
   */
  const SHA256_IV_PARTIAL = [
    0x6a,
    0x09,
    0xe6,
    0x67, // 0x6a09e667
    0xbb,
    0x67,
    0xae,
    0x85, // 0xbb67ae85
    0x3c,
    0x6e,
    0xf3,
    0x72, // 0x3c6ef372
    0xa5,
    0x4f,
    0xf5,
    0x3a, // 0xa54ff53a
  ];

  /**
   * ChaCha20/Salsa20 constants "expand 32-byte k"
   */
  const CHACHA20_CONSTANTS = [
    0x61,
    0x70,
    0x78,
    0x65, // "expa"
    0x33,
    0x32,
    0x2d,
    0x62, // "nd 3"
    0x79,
    0x74,
    0x65,
    0x20, // "2-by"
    0x6b,
    0x00,
    0x00,
    0x00, // "te k" (with padding tolerance)
  ];

  /**
   * RC4 initial permutation (first 16 bytes: 0x00-0x0f)
   */
  const RC4_INIT_PERMUTATION = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ];

  // ============================================================================
  // Detection Functions
  // ============================================================================

  /**
   * Compare byte arrays with tolerance for partial matches
   */
  function compareBytes(
    memory: GhidraMemory,
    addr: GhidraAddress,
    pattern: number[],
    _tolerance: number = 0,
  ): number {
    const buffer: number[] = new Array(pattern.length);
    try {
      const bytesRead = memory.getBytes(addr, buffer);
      if (bytesRead < pattern.length) {
        return 0;
      }

      let matches = 0;
      for (let i = 0; i < pattern.length; i++) {
        if (buffer[i] === pattern[i]) {
          matches++;
        }
      }

      return matches / pattern.length;
    } catch {
      return 0;
    }
  }

  /**
   * Find nearby functions for context
   */
  function findNearbyFunctions(addr: GhidraAddress, maxDistance: number = 1024): string[] {
    const fm = currentProgram.getFunctionManager();
    const nearbyFuncs: string[] = [];

    // Search backward
    for (let offset = 0; offset < maxDistance; offset += 4) {
      try {
        const checkAddr = addr.subtract(offset);
        const func = fm.getFunctionContaining(checkAddr);
        if (func) {
          const funcName = `${func.getName()}@${func.getEntryPoint().toString()}`;
          if (!nearbyFuncs.includes(funcName)) {
            nearbyFuncs.push(funcName);
          }
          break;
        }
      } catch {
        break;
      }
    }

    // Search forward
    for (let offset = 0; offset < maxDistance; offset += 4) {
      try {
        const checkAddr = addr.add(offset);
        const func = fm.getFunctionContaining(checkAddr);
        if (func) {
          const funcName = `${func.getName()}@${func.getEntryPoint().toString()}`;
          if (!nearbyFuncs.includes(funcName)) {
            nearbyFuncs.push(funcName);
          }
          break;
        }
      } catch {
        break;
      }
    }

    return nearbyFuncs;
  }

  /** Crypto pattern definition */
  type CryptoPattern = {
    name: string;
    pattern: number[];
    type: CryptoFinding['type'];
    size: number;
    description: string;
    tolerance?: number;
  };

  /** All crypto patterns to search for */
  const CRYPTO_PATTERNS: readonly CryptoPattern[] = [
    {
      name: 'AES',
      pattern: AES_SBOX_SIGNATURE,
      type: 'sbox',
      size: 256,
      description: 'AES S-box (SubBytes transformation)',
    },
    {
      name: 'AES',
      pattern: AES_INV_SBOX_SIGNATURE,
      type: 'sbox',
      size: 256,
      description: 'AES Inverse S-box',
    },
    {
      name: 'MD5',
      pattern: MD5_IV,
      type: 'constants',
      size: 16,
      description: 'MD5 initialization vector',
    },
    {
      name: 'SHA-1',
      pattern: SHA1_IV,
      type: 'constants',
      size: 20,
      description: 'SHA-1 initialization vector',
    },
    {
      name: 'SHA-256',
      pattern: SHA256_IV_PARTIAL,
      type: 'constants',
      size: 32,
      description: 'SHA-256 initialization vector',
    },
    {
      name: 'ChaCha20/Salsa20',
      pattern: CHACHA20_CONSTANTS,
      type: 'constants',
      size: 16,
      description: 'ChaCha20/Salsa20 "expand 32-byte k" constant',
      tolerance: 2,
    },
    {
      name: 'RC4',
      pattern: RC4_INIT_PERMUTATION,
      type: 'permutation',
      size: 256,
      description: 'RC4 initial permutation table',
    },
  ] as const;

  /** Try to match a pattern at an address and return finding if confident */
  function matchPatternAtAddress(
    memory: Memory,
    addr: Address,
    pattern: CryptoPattern,
    minConfidence: number,
  ): CryptoFinding | null {
    const confidence = compareBytes(memory, addr, pattern.pattern, pattern.tolerance ?? 0);
    if (confidence < minConfidence) return null;

    return {
      algorithm: pattern.name,
      type: pattern.type,
      address: addr.toString(),
      size: pattern.size,
      confidence,
      description: pattern.description,
      nearbyFunctions: findNearbyFunctions(addr),
    };
  }

  /** Scan a single memory block for crypto patterns */
  function scanBlockForCrypto(
    block: MemoryBlock,
    memory: Memory,
    minConfidence: number,
    seenAddresses: Set<string>,
  ): CryptoFinding[] {
    const findings: CryptoFinding[] = [];
    if (!block.isInitialized() || monitor.isCancelled()) return findings;

    const blockStart = block.getStart();
    const blockSize = block.getSize();
    const stride = 4; // Word-aligned

    for (let offset = 0; offset < blockSize - 16; offset += stride) {
      try {
        const addr = blockStart.add(offset);
        const addrStr = addr.toString();
        if (seenAddresses.has(addrStr)) continue;

        for (const pattern of CRYPTO_PATTERNS) {
          const finding = matchPatternAtAddress(memory, addr, pattern, minConfidence);
          if (finding) {
            seenAddresses.add(addrStr);
            findings.push(finding);
            offset += pattern.pattern.length;
            break;
          }
        }
      } catch {
        // Address error, continue
      }
    }

    return findings;
  }

  /**
   * Scan memory for cryptographic patterns
   */
  function scanForCrypto(minConfidence: number): CryptoFinding[] {
    const memory = currentProgram.getMemory();
    const seenAddresses = new Set<string>();
    const findings: CryptoFinding[] = [];

    for (const block of memory.getBlocks()) {
      findings.push(...scanBlockForCrypto(block, memory, minConfidence, seenAddresses));
    }

    return findings;
  }

  /**
   * Scan for common crypto API imports/exports
   */
  function scanForCryptoAPIs(): CryptoFinding[] {
    const findings: CryptoFinding[] = [];
    const symbolTable = currentProgram.getSymbolTable();

    // Common crypto API patterns
    const cryptoAPIs = [
      { pattern: /crypt|cipher|hash|digest/i, algorithm: 'Generic Crypto' },
      { pattern: /aes|rijndael/i, algorithm: 'AES' },
      { pattern: /md5/i, algorithm: 'MD5' },
      { pattern: /sha1|sha2|sha256|sha512/i, algorithm: 'SHA' },
      { pattern: /rsa/i, algorithm: 'RSA' },
      { pattern: /des|3des/i, algorithm: 'DES' },
      { pattern: /rc4|arcfour/i, algorithm: 'RC4' },
      { pattern: /chacha|salsa/i, algorithm: 'ChaCha/Salsa' },
      { pattern: /bcrypt|scrypt|argon/i, algorithm: 'Key Derivation' },
      { pattern: /hmac/i, algorithm: 'HMAC' },
    ];

    const externals = symbolTable.getExternalSymbols();
    while (externals.hasNext()) {
      const symbol = externals.next();
      const name = symbol.getName();

      for (const crypto of cryptoAPIs) {
        if (crypto.pattern.test(name)) {
          findings.push({
            algorithm: crypto.algorithm,
            type: 'pattern',
            address: symbol.getAddress().toString(),
            size: 0,
            confidence: 0.9,
            description: `External crypto API: ${name}`,
            nearbyFunctions: [],
          });
        }
      }
    }

    return findings;
  }

  // ============================================================================
  // Main Execution
  // ============================================================================

  function main(): void {
    const startTime = Date.now();
    const args = parseArgs();
    const output: CryptoOutput = { success: false };

    try {
      // Scan for crypto constants in memory
      const constantFindings = scanForCrypto(args.minConfidence);

      // Scan for crypto API references
      const apiFindings = scanForCryptoAPIs();

      // Combine findings
      const allFindings = [...constantFindings, ...apiFindings];

      // Sort by confidence
      allFindings.sort((a, b) => b.confidence - a.confidence);

      const memory = currentProgram.getMemory();
      const scannedBytes = Array.from(memory.getBlocks())
        .filter((b) => b.isInitialized())
        .reduce((sum, b) => sum + b.getSize(), 0);

      output.success = true;
      output.data = {
        binaryName: currentProgram.getName(),
        findings: allFindings,
        metadata: {
          scriptVersion: '1.0.0',
          scanTime: Date.now() - startTime,
          findingCount: allFindings.length,
          scannedBytes,
        },
      };
    } catch (error) {
      output.success = false;
      output.error = error instanceof Error ? error.message : String(error);
    }

    // Output with markers for parsing
    println('---SENTINEL_CRYPTO_START---');
    println(JSON.stringify(output, null, 2));
    println('---SENTINEL_CRYPTO_END---');
  }

  main();
})();
