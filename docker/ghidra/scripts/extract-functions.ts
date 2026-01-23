/**
 * SENTINEL Function Extraction Script
 *
 * Detailed function analysis script that runs inside Ghidra via Ghidra.js.
 * Extracts in-depth function information including call graphs and parameters.
 *
 * Usage:
 *   analyzeHeadless /projects temp -import /path/to/binary \
 *     -postScript extract-functions.js -scriptPath /scripts -deleteProject
 *
 * Arguments (optional):
 *   --addresses=0x401000,0x402000   Specific function addresses to analyze
 *   --max=100                        Maximum functions to extract
 *
 * Output is printed with markers for parsing by the MCP server.
 */

/// <reference path="./ghidra-api.d.ts" />

(() => {
  // ============================================================================
  // Output Types
  // ============================================================================

  type ExtractionOutput = {
    success: boolean;
    error?: string;
    data?: ExtractionData;
  };

  type ExtractionData = {
    binaryName: string;
    functions: DetailedFunctionInfo[];
    callGraph: CallGraphEdge[];
    metadata: ExtractionMetadata;
  };

  type DetailedFunctionInfo = {
    name: string;
    address: string;
    endAddress: string;
    size: number;
    isEntryPoint: boolean;
    isThunk: boolean;
    isExternal: boolean;
    callingConvention: string;
    returnType: string;
    parameters: ParameterInfo[];
    localVariables: VariableInfo[];
    callers: CallerInfo[];
    callees: CalleeInfo[];
    basicBlockCount: number;
    instructionCount: number;
    stackDepth: number;
  };

  type ParameterInfo = {
    name: string;
    type: string;
    ordinal: number;
  };

  type VariableInfo = {
    name: string;
    type: string;
    stackOffset: number;
  };

  type CallerInfo = {
    name: string;
    address: string;
    callSites: string[];
  };

  type CalleeInfo = {
    name: string;
    address: string;
    isImport: boolean;
    callCount: number;
  };

  type CallGraphEdge = {
    from: string;
    to: string;
    callSites: string[];
  };

  type ExtractionMetadata = {
    scriptVersion: string;
    extractionTime: number;
    functionCount: number;
    edgeCount: number;
    targetAddresses: string[];
  };

  // ============================================================================
  // Argument Parsing
  // ============================================================================

  type ScriptArgs = {
    addresses: string[];
    maxFunctions: number;
  };

  function parseArgs(): ScriptArgs {
    const args: ScriptArgs = {
      addresses: [],
      maxFunctions: 500,
    };

    try {
      const scriptArgs = getScriptArgs();
      for (const arg of scriptArgs) {
        if (arg.startsWith('--addresses=')) {
          args.addresses = arg.substring(12).split(',').filter(Boolean);
        } else if (arg.startsWith('--max=')) {
          args.maxFunctions = parseInt(arg.substring(6), 10) || 500;
        }
      }
    } catch {
      // Use defaults
    }

    return args;
  }

  // ============================================================================
  // Extraction Helper Functions
  // ============================================================================

  function extractCallerInfo(func: GhidraFunction): CallerInfo[] {
    const callers: CallerInfo[] = [];
    try {
      for (const caller of func.getCallingFunctions(monitor)) {
        const callSites = findCallSites(caller, func.getEntryPoint());
        callers.push({
          name: caller.getName(),
          address: caller.getEntryPoint().toString(),
          callSites,
        });
      }
    } catch {
      // Skip if caller analysis fails
    }
    return callers;
  }

  function findCallSites(caller: GhidraFunction, targetEntry: Address): string[] {
    const callSites: string[] = [];
    try {
      const callerBody = caller.getBody();
      const listing = currentProgram.getListing();
      const iter = listing.getInstructions(callerBody, true);

      while (iter.hasNext()) {
        const insn = iter.next();
        const flows = insn.getFlows();
        for (const flow of flows) {
          if (flow.equals(targetEntry)) {
            callSites.push(insn.getAddress().toString());
          }
        }
      }
    } catch {
      // Skip if can't get call sites
    }
    return callSites;
  }

  function extractCalleeInfo(func: GhidraFunction): CalleeInfo[] {
    const calleeMap = new Map<string, CalleeInfo>();
    try {
      for (const callee of func.getCalledFunctions(monitor)) {
        const addr = callee.getEntryPoint().toString();
        const existing = calleeMap.get(addr);

        if (existing) {
          existing.callCount++;
        } else {
          calleeMap.set(addr, {
            name: callee.getName(),
            address: addr,
            isImport: callee.isExternal(),
            callCount: 1,
          });
        }
      }
    } catch {
      // Skip if callee analysis fails
    }
    return Array.from(calleeMap.values());
  }

  function extractParameters(func: GhidraFunction): ParameterInfo[] {
    const parameters: ParameterInfo[] = [];
    try {
      const params = func.getParameters();
      for (let i = 0; i < params.length; i++) {
        const param = params[i];
        if (param) {
          parameters.push({
            name: param.getName(),
            type: param.getDataType().getName(),
            ordinal: param.getOrdinal(),
          });
        }
      }
    } catch {
      // Skip if parameter extraction fails
    }
    return parameters;
  }

  function extractLocalVariables(func: GhidraFunction): VariableInfo[] {
    const localVariables: VariableInfo[] = [];
    try {
      const locals = func.getLocalVariables();
      for (const local of locals) {
        localVariables.push({
          name: local.getName(),
          type: local.getDataType().getName(),
          stackOffset: local.getStackOffset(),
        });
      }
    } catch {
      // Skip if local variable extraction fails
    }
    return localVariables;
  }

  function countBlocksAndInstructions(func: GhidraFunction): {
    basicBlockCount: number;
    instructionCount: number;
  } {
    let basicBlockCount = 0;
    let instructionCount = 0;
    try {
      const listing = currentProgram.getListing();
      const iter = listing.getInstructions(func.getBody(), true);
      const blockStarts = new Set<string>();
      blockStarts.add(func.getEntryPoint().toString());

      while (iter.hasNext()) {
        const insn = iter.next();
        instructionCount++;
        const flows = insn.getFlows();
        for (const flow of flows) {
          blockStarts.add(flow.toString());
        }
      }
      basicBlockCount = blockStarts.size;
    } catch {
      // Skip if counting fails
    }
    return { basicBlockCount, instructionCount };
  }

  function getStackDepth(func: GhidraFunction): number {
    try {
      return func.getStackFrame().getFrameSize();
    } catch {
      return 0;
    }
  }

  const ENTRY_POINT_NAMES = new Set([
    'main',
    '_main',
    'WinMain',
    'DllMain',
    '_start',
    'start',
    'entry',
  ]);

  function extractDetailedFunction(func: GhidraFunction): DetailedFunctionInfo {
    const callers = extractCallerInfo(func);
    const callees = extractCalleeInfo(func);
    const parameters = extractParameters(func);
    const localVariables = extractLocalVariables(func);
    const { basicBlockCount, instructionCount } = countBlocksAndInstructions(func);
    const stackDepth = getStackDepth(func);
    const isEntryPoint = !func.isThunk() && ENTRY_POINT_NAMES.has(func.getName());

    return {
      name: func.getName(),
      address: func.getEntryPoint().toString(),
      endAddress: func.getBody().getMaxAddress().toString(),
      size: func.getBody().getNumAddresses(),
      isEntryPoint,
      isThunk: func.isThunk(),
      isExternal: func.isExternal(),
      callingConvention: func.getCallingConventionName() || 'unknown',
      returnType: func.getReturnType().getName(),
      parameters,
      localVariables,
      callers,
      callees,
      basicBlockCount,
      instructionCount,
      stackDepth,
    };
  }

  function buildCallGraph(functions: DetailedFunctionInfo[]): CallGraphEdge[] {
    const edges: CallGraphEdge[] = [];

    for (const func of functions) {
      for (const callee of func.callees) {
        edges.push({
          from: func.address,
          to: callee.address,
          callSites: [],
        });
      }
    }

    return edges;
  }

  // ============================================================================
  // Main Entry Point
  // ============================================================================

  function extractFunctionsAtAddresses(
    fm: FunctionManager,
    addresses: string[],
  ): DetailedFunctionInfo[] {
    const functions: DetailedFunctionInfo[] = [];
    const af = currentProgram.getAddressFactory();

    for (const addrStr of addresses) {
      if (monitor.isCancelled()) break;

      try {
        const addr = af.getAddress(addrStr);
        if (addr === null) {
          println(`[!] Invalid address: ${addrStr}`);
          continue;
        }

        const func = fm.getFunctionAt(addr);
        if (func !== null) {
          monitor.setMessage(`Extracting: ${func.getName()}`);
          functions.push(extractDetailedFunction(func));
        } else {
          println(`[!] No function at address: ${addrStr}`);
        }
      } catch (e) {
        println(`[!] Error processing address ${addrStr}: ${e}`);
      }
    }

    return functions;
  }

  function extractAllFunctions(fm: FunctionManager, maxFunctions: number): DetailedFunctionInfo[] {
    const functions: DetailedFunctionInfo[] = [];
    const iter = fm.getFunctions(true);
    let count = 0;

    while (iter.hasNext() && count < maxFunctions) {
      if (monitor.isCancelled()) break;

      const func = iter.next();
      monitor.setMessage(`Extracting: ${func.getName()}`);
      functions.push(extractDetailedFunction(func));
      count++;

      if (count % 100 === 0) {
        println(`[*] Processed ${count} functions...`);
      }
    }

    return functions;
  }

  function main(): void {
    const startTime = Date.now();
    const args = parseArgs();

    monitor.setMessage('SENTINEL Function Extraction Starting...');
    println('[*] SENTINEL Function Extraction Script v1.0.0');
    println(`[*] Binary: ${currentProgram.getName()}`);
    println(
      `[*] Target addresses: ${args.addresses.length > 0 ? args.addresses.join(', ') : 'all'}`,
    );
    println(`[*] Max functions: ${args.maxFunctions}`);

    let output: ExtractionOutput;

    try {
      const fm = currentProgram.getFunctionManager();
      const functions =
        args.addresses.length > 0
          ? extractFunctionsAtAddresses(fm, args.addresses)
          : extractAllFunctions(fm, args.maxFunctions);

      const callGraph = buildCallGraph(functions);
      const extractionTime = Date.now() - startTime;

      output = {
        success: true,
        data: {
          binaryName: currentProgram.getName(),
          functions,
          callGraph,
          metadata: {
            scriptVersion: '1.0.0',
            extractionTime,
            functionCount: functions.length,
            edgeCount: callGraph.length,
            targetAddresses: args.addresses,
          },
        },
      };

      println(`[*] Extraction complete in ${extractionTime}ms`);
      println(`[*] Functions: ${functions.length}`);
      println(`[*] Call graph edges: ${callGraph.length}`);
    } catch (e) {
      output = {
        success: false,
        error: String(e),
      };
      println(`[!] Extraction failed: ${e}`);
    }

    // Output JSON with markers for MCP server parsing
    println('---SENTINEL_FUNCTIONS_START---');
    println(JSON.stringify(output));
    println('---SENTINEL_FUNCTIONS_END---');
  }

  // Execute
  main();
})();
