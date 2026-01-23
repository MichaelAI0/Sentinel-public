/**
 * SENTINEL Ghidra Analysis Script
 *
 * Main analysis script that runs inside Ghidra via Ghidra.js.
 * Extracts comprehensive binary information and outputs structured JSON.
 *
 * Usage:
 *   analyzeHeadless /projects temp -import /path/to/binary \
 *     -postScript analyze.js -scriptPath /scripts -deleteProject
 *
 * Output is printed with markers for parsing by the MCP server.
 */

/// <reference path="./ghidra-api.d.ts" />

(() => {
  // ============================================================================
  // Output Types
  // ============================================================================

  type AnalysisOutput = {
    success: boolean;
    error?: string;
    data?: AnalysisData;
  };

  type AnalysisData = {
    binaryInfo: BinaryInfo;
    functions: FunctionInfo[];
    imports: ImportInfo[];
    exports: ExportInfo[];
    sections: SectionInfo[];
    strings: StringInfo[];
    metadata: AnalysisMetadata;
  };

  type BinaryInfo = {
    name: string;
    format: string;
    architecture: string;
    md5: string;
    sha256: string;
  };

  type FunctionInfo = {
    name: string;
    address: string;
    size: number;
    callers: string[];
    callees: string[];
  };

  type ImportInfo = {
    library: string;
    name: string;
    address: string;
  };

  type ExportInfo = {
    name: string;
    address: string;
    type: string;
  };

  type SectionInfo = {
    name: string;
    address: string;
    size: number;
    permissions: string;
    entropy: number;
  };

  type StringInfo = {
    value: string;
    address: string;
    type: string;
  };

  type AnalysisMetadata = {
    scriptVersion: string;
    ghidraVersion: string;
    analysisTime: number;
    functionCount: number;
    importCount: number;
    sectionCount: number;
    stringCount: number;
  };

  // ============================================================================
  // Utility Functions
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

  /**
   * Calculate Shannon entropy of byte data
   * High entropy (>7.0) suggests encryption/compression
   */
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

  /**
   * Safely read bytes from a memory block
   */
  function readBlockBytes(block: GhidraMemoryBlock, maxBytes = 65536): number[] {
    try {
      const size = Math.min(block.getSize(), maxBytes);
      const bytes: number[] = new Array(size).fill(0);
      block.getBytes(block.getStart(), bytes);
      return bytes;
    } catch {
      return [];
    }
  }

  // ============================================================================
  // Extraction Functions
  // ============================================================================

  function extractBinaryInfo(): BinaryInfo {
    return {
      name: currentProgram.getName(),
      format: currentProgram.getExecutableFormat(),
      architecture: currentProgram.getLanguage().getProcessor().toString(),
      md5: currentProgram.getExecutableMD5() || '',
      sha256: currentProgram.getExecutableSHA256() || '',
    };
  }

  function extractFunctions(maxFunctions = 1000): FunctionInfo[] {
    const results: FunctionInfo[] = [];

    try {
      const fm = currentProgram.getFunctionManager();
      const iter = fm.getFunctions(true);

      let count = 0;
      while (iter.hasNext() && count < maxFunctions) {
        if (monitor.isCancelled()) break;

        const func = iter.next();
        const callers: string[] = [];
        const callees: string[] = [];

        // Get call relationships
        try {
          for (const caller of func.getCallingFunctions(monitor)) {
            callers.push(caller.getName());
          }
          for (const callee of func.getCalledFunctions(monitor)) {
            callees.push(callee.getName());
          }
        } catch {
          // Skip if call analysis fails
        }

        results.push({
          name: func.getName(),
          address: func.getEntryPoint().toString(),
          size: func.getBody().getNumAddresses(),
          callers,
          callees,
        });

        count++;
      }
    } catch (e) {
      println(`[!] Error extracting functions: ${e}`);
    }

    return results;
  }

  function extractImports(): ImportInfo[] {
    const results: ImportInfo[] = [];

    try {
      const st = currentProgram.getSymbolTable();
      const iter = st.getExternalSymbols();

      while (iter.hasNext()) {
        if (monitor.isCancelled()) break;

        const sym = iter.next();
        results.push({
          library: sym.getParentNamespace().getName(),
          name: sym.getName(),
          address: sym.getAddress().toString(),
        });
      }
    } catch (e) {
      println(`[!] Error extracting imports: ${e}`);
    }

    return results;
  }

  function extractExports(): ExportInfo[] {
    const results: ExportInfo[] = [];

    try {
      const st = currentProgram.getSymbolTable();
      const iter = st.getDefinedSymbols();

      while (iter.hasNext()) {
        if (monitor.isCancelled()) break;

        const sym = iter.next();
        const symType = sym.getSymbolType().toString();

        // Only include function exports
        if (symType === 'Function' && sym.isGlobal()) {
          results.push({
            name: sym.getName(),
            address: sym.getAddress().toString(),
            type: symType,
          });
        }
      }
    } catch (e) {
      println(`[!] Error extracting exports: ${e}`);
    }

    return results;
  }

  function extractSections(): SectionInfo[] {
    const results: SectionInfo[] = [];

    try {
      const mem = currentProgram.getMemory();
      const blocks = mem.getBlocks();

      for (const block of blocks) {
        if (monitor.isCancelled()) break;

        // Build permission string
        let perms = '';
        if (block.isRead()) perms += 'R';
        if (block.isWrite()) perms += 'W';
        if (block.isExecute()) perms += 'X';

        // Calculate entropy
        const bytes = readBlockBytes(block);
        const entropy = calculateEntropy(bytes);

        results.push({
          name: block.getName(),
          address: block.getStart().toString(),
          size: block.getSize(),
          permissions: perms,
          entropy,
        });
      }
    } catch (e) {
      println(`[!] Error extracting sections: ${e}`);
    }

    return results;
  }

  /** Detects string encoding from type name */
  function detectStringEncoding(typeName: string): string {
    if (typeName.includes('unicode') || typeName.includes('utf16')) return 'UNICODE';
    if (typeName.includes('utf8')) return 'UTF8';
    return 'ASCII';
  }

  /** Checks if type represents a string type */
  function isStringType(typeName: string): boolean {
    return typeName.includes('string') || typeName.includes('char');
  }

  /** Extracts string value from data item if valid */
  function extractStringValue(data: Data, typeName: string): StringInfo | null {
    try {
      const value = data.getValue();
      if (typeof value === 'string' && value.length >= 4) {
        return {
          value: value.substring(0, 500), // Limit length
          address: data.getAddress().toString(),
          type: detectStringEncoding(typeName),
        };
      }
    } catch {
      // Skip unreadable
    }
    return null;
  }

  function extractStrings(maxStrings = 5000): StringInfo[] {
    const results: StringInfo[] = [];

    try {
      const listing = currentProgram.getListing();
      const iter = listing.getDefinedData(true);

      while (iter.hasNext() && results.length < maxStrings) {
        if (monitor.isCancelled()) break;

        const data = iter.next();
        const typeName = data.getDataType().getName().toLowerCase();

        if (isStringType(typeName)) {
          const stringInfo = extractStringValue(data, typeName);
          if (stringInfo) results.push(stringInfo);
        }
      }
    } catch (e) {
      println(`[!] Error extracting strings: ${e}`);
    }

    return results;
  }

  // ============================================================================
  // Main Entry Point
  // ============================================================================

  function main(): void {
    const startTime = Date.now();

    monitor.setMessage('SENTINEL Analysis Starting...');
    println('[*] SENTINEL Analysis Script v1.0.0');
    println(`[*] Binary: ${currentProgram.getName()}`);

    let output: AnalysisOutput;

    try {
      // Extract all data
      monitor.setMessage('Extracting binary info...');
      const binaryInfo = extractBinaryInfo();

      monitor.setMessage('Extracting functions...');
      const functions = extractFunctions(1000);

      monitor.setMessage('Extracting imports...');
      const imports = extractImports();

      monitor.setMessage('Extracting exports...');
      const exports = extractExports();

      monitor.setMessage('Analyzing sections...');
      const sections = extractSections();

      monitor.setMessage('Extracting strings...');
      const strings = extractStrings(5000);

      const analysisTime = Date.now() - startTime;

      output = {
        success: true,
        data: {
          binaryInfo,
          functions,
          imports,
          exports,
          sections,
          strings,
          metadata: {
            scriptVersion: '1.0.0',
            ghidraVersion: getGhidraVersion(),
            analysisTime,
            functionCount: functions.length,
            importCount: imports.length,
            sectionCount: sections.length,
            stringCount: strings.length,
          },
        },
      };

      println(`[*] Analysis complete in ${analysisTime}ms`);
      println(`[*] Functions: ${functions.length}`);
      println(`[*] Imports: ${imports.length}`);
      println(`[*] Exports: ${exports.length}`);
      println(`[*] Sections: ${sections.length}`);
      println(`[*] Strings: ${strings.length}`);
    } catch (e) {
      output = {
        success: false,
        error: String(e),
      };
      println(`[!] Analysis failed: ${e}`);
    }

    // Output JSON with markers for MCP server parsing
    println('---SENTINEL_ANALYSIS_START---');
    println(JSON.stringify(output));
    println('---SENTINEL_ANALYSIS_END---');
  }

  // Execute
  main();
})();
