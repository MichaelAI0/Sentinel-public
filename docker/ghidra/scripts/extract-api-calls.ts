/**
 * SENTINEL API Call Extraction Script
 *
 * Extracts all external API calls, imports, and library references.
 * Provides comprehensive mapping of which functions call which APIs.
 *
 * Usage:
 *   analyzeHeadless /projects temp -import /path/to/binary \
 *     -postScript extract-api-calls.js -scriptPath /scripts -deleteProject
 *
 * Arguments (optional):
 *   --include-internal    Include calls between internal functions
 *   --group-by-lib        Group results by library
 *
 * Output is printed with markers for parsing by the MCP server.
 */

/// <reference path="./ghidra-api.d.ts" />

(() => {
  // ============================================================================
  // Output Types
  // ============================================================================

  type APICallOutput = {
    success: boolean;
    error?: string;
    data?: APICallData;
  };

  type APICallData = {
    binaryName: string;
    imports: ImportInfo[];
    exports: ExportInfo[];
    apiCalls: APICall[];
    libraryGroups?: LibraryGroup[];
    metadata: APICallMetadata;
  };

  type ImportInfo = {
    library: string;
    functionName: string;
    address: string;
    ordinal?: number;
    calledBy: string[];
  };

  type ExportInfo = {
    functionName: string;
    address: string;
    ordinal?: number;
  };

  type APICall = {
    callerFunction: string;
    callerAddress: string;
    targetAPI: string;
    targetLibrary: string;
    callSites: CallSite[];
  };

  type CallSite = {
    address: string;
    instruction: string;
    context: string;
  };

  type LibraryGroup = {
    libraryName: string;
    functionCount: number;
    functions: string[];
    callerCount: number;
  };

  type APICallMetadata = {
    scriptVersion: string;
    extractionTime: number;
    importCount: number;
    exportCount: number;
    callCount: number;
    libraryCount: number;
  };

  // ============================================================================
  // Argument Parsing
  // ============================================================================

  type ScriptArgs = {
    includeInternal: boolean;
    groupByLib: boolean;
  };

  function parseArgs(): ScriptArgs {
    const args: ScriptArgs = {
      includeInternal: false,
      groupByLib: true,
    };

    for (const arg of getScriptArgs()) {
      if (arg === '--include-internal') {
        args.includeInternal = true;
      } else if (arg === '--group-by-lib') {
        args.groupByLib = true;
      }
    }

    return args;
  }

  // ============================================================================
  // Import/Export Extraction
  // ============================================================================

  /**
   * Extract all external imports
   */
  function extractImports(): Map<string, ImportInfo> {
    const symbolTable = currentProgram.getSymbolTable();
    const imports = new Map<string, ImportInfo>();

    const externals = symbolTable.getExternalSymbols();
    while (externals.hasNext()) {
      if (monitor.isCancelled()) break;

      const symbol = externals.next();
      const name = symbol.getName();
      const address = symbol.getAddress().toString();

      // Try to determine library name from namespace
      let library = 'EXTERNAL';
      const namespace = symbol.getParentNamespace();
      if (namespace && !namespace.isGlobal()) {
        library = namespace.getName();
      }

      imports.set(address, {
        library,
        functionName: name,
        address,
        calledBy: [],
      });
    }

    return imports;
  }

  /**
   * Extract all exports
   */
  function extractExports(): ExportInfo[] {
    const symbolTable = currentProgram.getSymbolTable();
    const exports: ExportInfo[] = [];

    // Look for symbols marked as exports or in export namespace
    const allSymbols = symbolTable.getDefinedSymbols();
    while (allSymbols.hasNext()) {
      if (monitor.isCancelled()) break;

      const symbol = allSymbols.next();

      // Typically exports are global symbols that are functions
      if (symbol.isGlobal() && !symbol.isExternal()) {
        const fm = currentProgram.getFunctionManager();
        const func = fm.getFunctionAt(symbol.getAddress());

        if (func && !func.isThunk()) {
          exports.push({
            functionName: symbol.getName(),
            address: symbol.getAddress().toString(),
          });
        }
      }
    }

    return exports;
  }

  // ============================================================================
  // API Call Extraction
  // ============================================================================

  /**
   * Get instruction context (nearby instructions for context)
   */
  function getInstructionContext(addr: GhidraAddress, contextSize: number = 2): string {
    const listing = currentProgram.getListing();
    const instructions: string[] = [];

    // Get instructions before
    let current = addr;
    for (let i = 0; i < contextSize; i++) {
      try {
        const prev = listing.getInstructionAt(current);
        if (!prev) break;

        const prevAddr = prev.getAddress();
        if (!prevAddr.equals(addr)) {
          instructions.unshift(`${prevAddr.toString()}: ${prev.toString()}`);
        }

        // Move to previous instruction
        const minAddr = prev.getAddress().subtract(1);
        current = listing.getInstructionAt(minAddr)?.getAddress() || minAddr;
        if (current.equals(prevAddr)) break;
      } catch {
        break;
      }
    }

    // Current instruction
    const instr = listing.getInstructionAt(addr);
    if (instr) {
      instructions.push(`>>> ${addr.toString()}: ${instr.toString()}`);
    }

    return instructions.join('\n');
  }

  /** Find all call sites within a function that target a specific address */
  function findCallSitesInFunction(
    func: GhidraFunction,
    targetAddress: Address,
    listing: Listing,
  ): CallSite[] {
    const callSites: CallSite[] = [];
    const body = func.getBody();
    const instrIter = listing.getInstructions(body, true);

    while (instrIter.hasNext()) {
      const instr = instrIter.next();
      const flowType = instr.getFlowType();

      if (flowType.isCall()) {
        for (const target of instr.getFlows()) {
          if (target.equals(targetAddress)) {
            callSites.push({
              address: instr.getAddress().toString(),
              instruction: instr.toString(),
              context: getInstructionContext(instr.getAddress(), 1),
            });
          }
        }
      }
    }

    return callSites;
  }

  /** Process a single called function and record API call if external */
  function processCalledFunction(
    calledFunc: GhidraFunction,
    callerFunc: GhidraFunction,
    imports: Map<string, ImportInfo>,
    callMap: Map<string, APICall>,
    listing: Listing,
  ): void {
    const calledAddrStr = calledFunc.getEntryPoint().toString();
    const isExternalAPI = calledFunc.isExternal() || imports.has(calledAddrStr);

    if (!isExternalAPI) return;

    const importInfo = imports.get(calledAddrStr);
    const targetAPI = calledFunc.getName();
    const targetLibrary = importInfo?.library || 'EXTERNAL';
    const funcAddr = callerFunc.getEntryPoint();
    const callKey = `${funcAddr.toString()}->${calledAddrStr}`;

    if (!callMap.has(callKey)) {
      const callSites = findCallSitesInFunction(callerFunc, calledFunc.getEntryPoint(), listing);
      callMap.set(callKey, {
        callerFunction: callerFunc.getName(),
        callerAddress: funcAddr.toString(),
        targetAPI,
        targetLibrary,
        callSites,
      });
    }

    // Update import's calledBy list
    if (importInfo && !importInfo.calledBy.includes(callerFunc.getName())) {
      importInfo.calledBy.push(callerFunc.getName());
    }
  }

  /**
   * Extract all API calls from functions
   */
  function extractAPICalls(imports: Map<string, ImportInfo>): APICall[] {
    const fm = currentProgram.getFunctionManager();
    const listing = currentProgram.getListing();
    const callMap = new Map<string, APICall>();

    const funcIter = fm.getFunctions(true);
    while (funcIter.hasNext()) {
      if (monitor.isCancelled()) break;

      const func = funcIter.next();

      // Skip thunks and externals
      if (func.isThunk() || func.isExternal()) continue;

      // Process all called functions
      for (const calledFunc of func.getCalledFunctions(monitor)) {
        processCalledFunction(calledFunc, func, imports, callMap, listing);
      }
    }

    return Array.from(callMap.values());
  }

  /**
   * Group API calls by library
   */
  function groupByLibrary(imports: Map<string, ImportInfo>, _apiCalls: APICall[]): LibraryGroup[] {
    const libMap = new Map<string, LibraryGroup>();

    // Group imports by library
    for (const imp of imports.values()) {
      if (!libMap.has(imp.library)) {
        libMap.set(imp.library, {
          libraryName: imp.library,
          functionCount: 0,
          functions: [],
          callerCount: 0,
        });
      }

      const group = libMap.get(imp.library);
      if (group) {
        group.functionCount++;
        group.functions.push(imp.functionName);
        group.callerCount += imp.calledBy.length;
      }
    }

    return Array.from(libMap.values()).sort((a, b) => b.functionCount - a.functionCount);
  }

  // ============================================================================
  // Main Execution
  // ============================================================================

  function main(): void {
    const startTime = Date.now();
    const args = parseArgs();
    const output: APICallOutput = { success: false };

    try {
      // Extract imports and exports
      const imports = extractImports();
      const exports = extractExports();

      // Extract API calls
      const apiCalls = extractAPICalls(imports);

      // Group by library if requested
      const libraryGroups = args.groupByLib ? groupByLibrary(imports, apiCalls) : undefined;

      const libraryCount = new Set(Array.from(imports.values()).map((imp) => imp.library)).size;

      output.success = true;
      output.data = {
        binaryName: currentProgram.getName(),
        imports: Array.from(imports.values()),
        exports,
        apiCalls,
        libraryGroups,
        metadata: {
          scriptVersion: '1.0.0',
          extractionTime: Date.now() - startTime,
          importCount: imports.size,
          exportCount: exports.length,
          callCount: apiCalls.length,
          libraryCount,
        },
      };
    } catch (error) {
      output.success = false;
      output.error = error instanceof Error ? error.message : String(error);
    }

    // Output with markers for parsing
    println('---SENTINEL_API_CALLS_START---');
    println(JSON.stringify(output, null, 2));
    println('---SENTINEL_API_CALLS_END---');
  }

  main();
})();
