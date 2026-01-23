/**
 * SENTINEL Packer Detection Script
 *
 * Heuristically detects packed/obfuscated binaries by analyzing:
 * - Section entropy
 * - Suspicious section names
 * - Import patterns
 * - RWX memory blocks
 *
 * Output is printed with markers for parsing by the MCP server.
 */

/// <reference path="./ghidra-api.d.ts" />

(() => {
  // ============================================================================
  // Output Types
  // ============================================================================

  type PackerDetectionOutput = {
    success: boolean;
    error?: string;
    data?: PackerDetectionData;
  };

  type PackerDetectionData = {
    binaryName: string;
    likelyPacked: boolean;
    confidence: number; // 0..1
    guesses: string[];
    indicators: Indicator[];
    sections: SectionEntropy[];
    metadata: {
      scriptVersion: string;
      ghidraVersion: string;
      analysisTimeMs: number;
    };
  };

  type Indicator = {
    id: string;
    severity: 'low' | 'medium' | 'high';
    message: string;
    score: number; // contribution to confidence
  };

  type SectionEntropy = {
    name: string;
    start: string;
    size: number;
    permissions: string;
    entropy: number;
  };

  // ============================================================================
  // Utilities
  // ============================================================================

  /**
   * Get Ghidra version dynamically from Application class
   */
  function getGhidraVersion(): string {
    try {
      type GhidraApplication = { getApplicationVersion: () => string };
      const Application = JavaHelper.getClass<GhidraApplication>('ghidra.framework.Application');
      return Application.getApplicationVersion() || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  function clamp01(value: number): number {
    if (value < 0) return 0;
    if (value > 1) return 1;
    return value;
  }

  function calculateEntropy(bytes: number[]): number {
    if (!bytes || bytes.length === 0) return 0;

    const freq = new Map<number, number>();
    for (const b of bytes) {
      freq.set(b, (freq.get(b) || 0) + 1);
    }

    let entropy = 0;
    const len = bytes.length;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * 1000) / 1000;
  }

  function readBlockBytes(block: GhidraMemoryBlock, maxBytes = 131072): number[] {
    try {
      const size = Math.min(block.getSize(), maxBytes);
      const bytes: number[] = new Array(size).fill(0);
      block.getBytes(block.getStart(), bytes);
      return bytes;
    } catch {
      return [];
    }
  }

  function permsString(block: GhidraMemoryBlock): string {
    let perms = '';
    if (block.isRead()) perms += 'R';
    if (block.isWrite()) perms += 'W';
    if (block.isExecute()) perms += 'X';
    return perms;
  }

  function pushIndicator(indicators: Indicator[], indicator: Indicator): void {
    indicators.push(indicator);
  }

  // ============================================================================
  // Heuristics
  // ============================================================================

  function analyzeSections(indicators: Indicator[]): SectionEntropy[] {
    const sections: SectionEntropy[] = [];

    const mem = currentProgram.getMemory();
    const blocks = mem.getBlocks();

    // Common packer/obfuscator section names (best-effort heuristics)
    const suspiciousNames = new Set([
      '.upx',
      'upx0',
      'upx1',
      'upx2',
      '.aspack',
      '.adata',
      '.packed',
      '.petite',
      '.themida',
      '.vmp',
      '.vmprotect',
      '.mpress',
      '.fsg',
      '.boom',
      '.protect',
      '.shrink',
      '.stub',
    ]);

    let highEntropyCount = 0;
    let rwxCount = 0;

    for (const block of blocks) {
      if (monitor.isCancelled()) break;

      const name = block.getName();
      const nameLower = name.toLowerCase();
      const perms = permsString(block);

      const bytes = readBlockBytes(block);
      const entropy = calculateEntropy(bytes);

      sections.push({
        name,
        start: block.getStart().toString(),
        size: block.getSize(),
        permissions: perms,
        entropy,
      });

      // High entropy threshold heuristic
      if (block.isInitialized() && block.getSize() >= 4096 && entropy >= 7.2) {
        highEntropyCount++;
      }

      // RWX blocks are suspicious
      if (block.isRead() && block.isWrite() && block.isExecute()) {
        rwxCount++;
      }

      // Suspicious name heuristic
      if (suspiciousNames.has(nameLower) || suspiciousNames.has(nameLower.replace(/^\./, ''))) {
        pushIndicator(indicators, {
          id: 'suspicious_section_name',
          severity: 'high',
          message: `Suspicious section/block name: ${name}`,
          score: 0.35,
        });
      }
    }

    if (highEntropyCount >= 2) {
      pushIndicator(indicators, {
        id: 'high_entropy_sections',
        severity: 'high',
        message: `Multiple high-entropy blocks detected (${highEntropyCount})`,
        score: 0.45,
      });
    } else if (highEntropyCount === 1) {
      pushIndicator(indicators, {
        id: 'high_entropy_section',
        severity: 'medium',
        message: 'One high-entropy block detected',
        score: 0.25,
      });
    }

    if (rwxCount >= 1) {
      pushIndicator(indicators, {
        id: 'rwx_block',
        severity: 'high',
        message: `RWX memory block(s) detected (${rwxCount})`,
        score: 0.35,
      });
    }

    // Many blocks can be suspicious (some packers split)
    if (sections.length >= 20) {
      pushIndicator(indicators, {
        id: 'many_sections',
        severity: 'medium',
        message: `Large number of memory blocks (${sections.length})`,
        score: 0.15,
      });
    }

    return sections;
  }

  function analyzeImports(indicators: Indicator[]): void {
    // Packer/unpacking-related APIs (Windows-centric heuristics)
    const suspiciousImportFragments = [
      'virtualalloc',
      'virtualprotect',
      'writeprocessmemory',
      'createremotethread',
      'getprocaddress',
      'loadlibrary',
      'rtlmovememory',
      'ntunmapviewofsection',
      'zwunmapviewofsection',
    ];

    try {
      const st = currentProgram.getSymbolTable();
      const iter = st.getExternalSymbols();

      let found = 0;

      while (iter.hasNext()) {
        if (monitor.isCancelled()) break;

        const sym = iter.next();
        const name = sym.getName().toLowerCase();

        for (const fragment of suspiciousImportFragments) {
          if (name.includes(fragment)) {
            found++;
            break;
          }
        }

        if (found >= 6) break;
      }

      if (found >= 4) {
        pushIndicator(indicators, {
          id: 'suspicious_imports',
          severity: 'medium',
          message: `Suspicious import pattern count: ${found}`,
          score: 0.2,
        });
      } else if (found >= 1) {
        pushIndicator(indicators, {
          id: 'some_suspicious_imports',
          severity: 'low',
          message: `Some suspicious imports detected: ${found}`,
          score: 0.1,
        });
      }
    } catch (e) {
      println(`[!] Import analysis failed: ${e}`);
    }
  }

  /** Packer name patterns to detect in section names */
  const PACKER_SECTION_PATTERNS: ReadonlyArray<readonly [pattern: string, packer: string]> = [
    ['upx', 'UPX'],
    ['themida', 'Themida'],
    ['vmp', 'VMProtect'],
    ['vmprotect', 'VMProtect'],
    ['aspack', 'ASPack'],
    ['mpress', 'MPRESS'],
    ['fsg', 'FSG'],
    ['petite', 'Petite'],
  ] as const;

  function guessPackers(sections: SectionEntropy[], indicators: Indicator[]): string[] {
    const guesses = new Set<string>();

    // Check section names against known packer patterns
    for (const s of sections) {
      const nameLower = s.name.toLowerCase();
      for (const [pattern, packer] of PACKER_SECTION_PATTERNS) {
        if (nameLower.includes(pattern)) {
          guesses.add(packer);
        }
      }
    }

    // If entropy is very high but no signature names, guess generic
    const veryHighEntropy = sections.some((s) => s.entropy >= 7.6 && s.size >= 4096);
    if (veryHighEntropy && guesses.size === 0) {
      guesses.add('Generic packer/cryptor (high entropy)');
    }

    // If RWX present, suggest runtime unpacking
    if (indicators.some((i) => i.id === 'rwx_block')) {
      guesses.add('Runtime unpacking / self-modifying code');
    }

    return Array.from(guesses);
  }

  // ============================================================================
  // Main
  // ============================================================================

  function main(): void {
    const start = Date.now();

    monitor.setMessage('SENTINEL Packer Detection Starting...');
    println('[*] SENTINEL Packer Detection Script v1.0.0');
    println(`[*] Binary: ${currentProgram.getName()}`);

    let output: PackerDetectionOutput;

    try {
      const indicators: Indicator[] = [];

      const sections = analyzeSections(indicators);
      analyzeImports(indicators);

      const guesses = guessPackers(sections, indicators);

      // Combine indicator scores → confidence
      const totalScore = indicators.reduce((sum, i) => sum + i.score, 0);
      const confidence = clamp01(totalScore);
      const likelyPacked = confidence >= 0.45;

      output = {
        success: true,
        data: {
          binaryName: currentProgram.getName(),
          likelyPacked,
          confidence,
          guesses,
          indicators,
          sections,
          metadata: {
            scriptVersion: '1.0.0',
            ghidraVersion: getGhidraVersion(),
            analysisTimeMs: Date.now() - start,
          },
        },
      };

      println(`[*] likelyPacked=${likelyPacked} confidence=${confidence}`);
    } catch (e) {
      output = {
        success: false,
        error: String(e),
      };
      println(`[!] Packer detection failed: ${e}`);
    }

    println('---SENTINEL_PACKER_START---');
    println(JSON.stringify(output));
    println('---SENTINEL_PACKER_END---');
  }

  main();
})();
