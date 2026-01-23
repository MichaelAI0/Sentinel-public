/**
 * SENTINEL Control Flow Graph Extraction Script
 *
 * Extracts control flow graphs (CFGs) from functions for visualization
 * and analysis. Outputs basic blocks, edges, and flow types.
 *
 * Usage:
 *   analyzeHeadless /projects temp -import /path/to/binary \
 *     -postScript extract-cfg.js -scriptPath /scripts -deleteProject
 *
 * Arguments (optional):
 *   --addresses=0x401000,0x402000   Specific function addresses to analyze
 *   --max=20                        Maximum functions to extract CFGs for
 *   --format=mermaid|json           Output format (default: json)
 *
 * Output is printed with markers for parsing by the MCP server.
 */

/// <reference path="./ghidra-api.d.ts" />

(() => {
  // ============================================================================
  // Output Types
  // ============================================================================

  type CFGOutput = {
    success: boolean;
    error?: string;
    data?: CFGData;
  };

  type CFGData = {
    binaryName: string;
    functionCFGs: FunctionCFG[];
    metadata: CFGMetadata;
  };

  type FunctionCFG = {
    functionName: string;
    functionAddress: string;
    basicBlocks: BasicBlock[];
    edges: CFGEdge[];
    mermaidDiagram?: string;
    graphvizDot?: string;
  };

  type BasicBlock = {
    id: string;
    startAddress: string;
    endAddress: string;
    instructionCount: number;
    instructions: InstructionInfo[];
    isEntryBlock: boolean;
    isExitBlock: boolean;
  };

  type InstructionInfo = {
    address: string;
    mnemonic: string;
    operands: string;
  };

  type CFGEdge = {
    fromBlock: string;
    toBlock: string;
    edgeType:
      | 'unconditional'
      | 'conditional-true'
      | 'conditional-false'
      | 'fallthrough'
      | 'call'
      | 'return';
  };

  type CFGMetadata = {
    scriptVersion: string;
    extractionTime: number;
    functionCount: number;
    totalBlocks: number;
    totalEdges: number;
    targetAddresses: string[];
  };

  // ============================================================================
  // Argument Parsing
  // ============================================================================

  type ScriptArgs = {
    addresses: string[];
    maxFunctions: number;
    format: 'json' | 'mermaid';
  };

  function parseArgs(): ScriptArgs {
    const args: ScriptArgs = {
      addresses: [],
      maxFunctions: 20,
      format: 'json',
    };

    for (const arg of getScriptArgs()) {
      if (arg.startsWith('--addresses=')) {
        args.addresses = arg.substring(12).split(',').filter(Boolean);
      } else if (arg.startsWith('--max=')) {
        const max = Number.parseInt(arg.substring(6), 10);
        if (!Number.isNaN(max) && max > 0) {
          args.maxFunctions = max;
        }
      } else if (arg.startsWith('--format=')) {
        const fmt = arg.substring(9);
        if (fmt === 'mermaid' || fmt === 'json') {
          args.format = fmt;
        }
      }
    }

    return args;
  }

  // ============================================================================
  // CFG Extraction
  // ============================================================================

  /** Collects all instructions from a function body */
  function collectInstructions(listing: Listing, body: AddressSetView): GhidraInstruction[] {
    const instructions: GhidraInstruction[] = [];
    const iter = listing.getInstructions(body, true);
    while (iter.hasNext()) {
      instructions.push(iter.next());
    }
    return instructions;
  }

  /** Identifies block start addresses from instructions */
  function identifyBlockStarts(
    instructions: GhidraInstruction[],
    body: AddressSetView,
    entryPoint: string,
  ): Set<string> {
    const blockStarts = new Set<string>();
    blockStarts.add(entryPoint);

    for (const instr of instructions) {
      const flowType = instr.getFlowType();

      // Jump/call targets are block starts
      if (flowType.isJump() || flowType.isCall()) {
        for (const target of instr.getFlows()) {
          if (body.contains(target)) {
            blockStarts.add(target.toString());
          }
        }
      }

      // Fall-through after conditional jump is a block start
      const fallThrough = instr.getFallThrough();
      if (fallThrough && flowType.isJump() && body.contains(fallThrough)) {
        blockStarts.add(fallThrough.toString());
      }
    }

    return blockStarts;
  }

  /** Converts instruction to simplified format for output */
  function instructionToOutput(instr: GhidraInstruction): {
    address: string;
    mnemonic: string;
    operands: string;
  } {
    const operands: string[] = [];
    for (let i = 0; i < instr.getNumOperands(); i++) {
      operands.push(instr.getDefaultOperandRepresentation(i));
    }
    return {
      address: instr.getAddress().toString(),
      mnemonic: instr.getMnemonicString(),
      operands: operands.join(', '),
    };
  }

  /** Build basic blocks from instructions and block start addresses */
  function buildBlocks(
    instructions: GhidraInstruction[],
    blockStarts: Set<string>,
    entryPoint: string,
  ): BasicBlock[] {
    const blocks: BasicBlock[] = [];
    let currentBlock: BasicBlock | null = null;

    for (const instr of instructions) {
      const addr = instr.getAddress().toString();

      // Check if this instruction starts a new block
      if (blockStarts.has(addr)) {
        if (currentBlock) {
          blocks.push(currentBlock);
        }
        currentBlock = {
          id: `block_${addr}`,
          startAddress: addr,
          endAddress: addr,
          instructionCount: 0,
          instructions: [],
          isEntryBlock: addr === entryPoint,
          isExitBlock: false,
        };
      }

      if (currentBlock) {
        currentBlock.endAddress = addr;
        currentBlock.instructionCount++;

        // Only store first few instructions to keep output manageable
        if (currentBlock.instructions.length < 10) {
          currentBlock.instructions.push(instructionToOutput(instr));
        }

        // Mark exit blocks
        const flowType = instr.getFlowType();
        if (flowType.isTerminal() || instr.getMnemonicString().toUpperCase() === 'RET') {
          currentBlock.isExitBlock = true;
        }
      }
    }

    // Don't forget the last block
    if (currentBlock) {
      blocks.push(currentBlock);
    }

    return blocks;
  }

  /**
   * Get basic blocks for a function by analyzing instruction flow
   */
  function extractBasicBlocks(func: GhidraFunction): BasicBlock[] {
    const listing = currentProgram.getListing();
    const body = func.getBody();
    const entryPoint = func.getEntryPoint().toString();

    const instructions = collectInstructions(listing, body);
    const blockStarts = identifyBlockStarts(instructions, body, entryPoint);
    return buildBlocks(instructions, blockStarts, entryPoint);
  }

  /** Determines edge type based on flow characteristics */
  function determineJumpEdgeType(flowType: FlowType, hasFallThrough: boolean): CFGEdge['edgeType'] {
    if (flowType.isCall()) return 'call';
    if (hasFallThrough) return 'conditional-true';
    return 'unconditional';
  }

  /** Extracts edges from jump targets */
  function extractJumpEdges(
    block: BasicBlock,
    flows: Address[],
    flowType: FlowType,
    hasFallThrough: boolean,
    body: AddressSetView,
    blockMap: Map<string, BasicBlock>,
  ): CFGEdge[] {
    const edges: CFGEdge[] = [];
    for (const target of flows) {
      if (body.contains(target)) {
        const targetBlock = blockMap.get(target.toString());
        if (targetBlock) {
          edges.push({
            fromBlock: block.id,
            toBlock: targetBlock.id,
            edgeType: determineJumpEdgeType(flowType, hasFallThrough),
          });
        }
      }
    }
    return edges;
  }

  /** Extracts fall-through edge if applicable */
  function extractFallThroughEdge(
    block: BasicBlock,
    fallThrough: Address | null,
    hasJumpFlows: boolean,
    body: AddressSetView,
    blockMap: Map<string, BasicBlock>,
  ): CFGEdge | null {
    if (!fallThrough || !body.contains(fallThrough)) return null;
    const fallBlock = blockMap.get(fallThrough.toString());
    if (!fallBlock) return null;
    return {
      fromBlock: block.id,
      toBlock: fallBlock.id,
      edgeType: hasJumpFlows ? 'conditional-false' : 'fallthrough',
    };
  }

  /**
   * Extract edges between basic blocks
   */
  function extractEdges(func: GhidraFunction, blocks: BasicBlock[]): CFGEdge[] {
    const listing = currentProgram.getListing();
    const body = func.getBody();
    const edges: CFGEdge[] = [];

    // Build address-to-block map for quick lookup
    const blockMap = new Map<string, BasicBlock>();
    for (const block of blocks) {
      blockMap.set(block.startAddress, block);
    }

    // Analyze each block's exit to find edges
    for (const block of blocks) {
      const factory = currentProgram.getAddressFactory();
      const endAddr = factory.getAddress(block.endAddress);
      if (!endAddr) continue;

      const lastInstr = listing.getInstructionAt(endAddr);
      if (!lastInstr) continue;

      const flowType = lastInstr.getFlowType();
      const flows = lastInstr.getFlows();
      const fallThrough = lastInstr.getFallThrough();

      // Collect jump edges
      const jumpEdges = extractJumpEdges(block, flows, flowType, !!fallThrough, body, blockMap);
      edges.push(...jumpEdges);

      // Collect fall-through edge
      const fallEdge = extractFallThroughEdge(block, fallThrough, flows.length > 0, body, blockMap);
      if (fallEdge) edges.push(fallEdge);
    }

    return edges;
  }

  /**
   * Generate Mermaid diagram syntax for a CFG
   */
  function generateMermaidDiagram(cfg: FunctionCFG): string {
    const lines: string[] = [];
    lines.push('flowchart TD');
    lines.push(`  subgraph "${cfg.functionName} @ ${cfg.functionAddress}"`);

    // Add nodes (blocks)
    for (const block of cfg.basicBlocks) {
      const label = block.isEntryBlock
        ? `ENTRY\\n${block.startAddress}`
        : block.isExitBlock
          ? `EXIT\\n${block.startAddress}`
          : `${block.startAddress}\\n${block.instructionCount} instrs`;

      const shape = block.isEntryBlock
        ? `([${label}])`
        : block.isExitBlock
          ? `[[${label}]]`
          : `[${label}]`;

      lines.push(`    ${block.id}${shape}`);
    }

    // Add edges
    for (const edge of cfg.edges) {
      let arrow = '-->';

      switch (edge.edgeType) {
        case 'conditional-true':
          arrow = '-->|T|';
          break;
        case 'conditional-false':
          arrow = '-->|F|';
          break;
        case 'call':
          arrow = '-.->|call|';
          break;
        case 'return':
          arrow = '-.->|ret|';
          break;
      }

      lines.push(`    ${edge.fromBlock} ${arrow} ${edge.toBlock}`);
    }

    lines.push('  end');
    return lines.join('\n');
  }

  /**
   * Generate Graphviz DOT syntax for a CFG
   */
  function generateGraphvizDot(cfg: FunctionCFG): string {
    const lines: string[] = [];
    lines.push(`digraph "${cfg.functionName}" {`);
    lines.push('  node [shape=box, fontname="monospace"];');
    lines.push('  edge [fontname="monospace"];');

    // Add nodes
    for (const block of cfg.basicBlocks) {
      const attrs: string[] = [];

      if (block.isEntryBlock) {
        attrs.push('style=filled', 'fillcolor=lightgreen');
      } else if (block.isExitBlock) {
        attrs.push('style=filled', 'fillcolor=lightcoral');
      }

      const label = `${block.startAddress}\\n${block.instructionCount} instructions`;
      attrs.push(`label="${label}"`);

      lines.push(`  ${block.id} [${attrs.join(', ')}];`);
    }

    // Add edges
    for (const edge of cfg.edges) {
      const attrs: string[] = [];

      switch (edge.edgeType) {
        case 'conditional-true':
          attrs.push('label="T"', 'color=green');
          break;
        case 'conditional-false':
          attrs.push('label="F"', 'color=red');
          break;
        case 'call':
          attrs.push('style=dashed', 'label="call"');
          break;
      }

      const attrStr = attrs.length > 0 ? ` [${attrs.join(', ')}]` : '';
      lines.push(`  ${edge.fromBlock} -> ${edge.toBlock}${attrStr};`);
    }

    lines.push('}');
    return lines.join('\n');
  }

  /**
   * Extract CFG for a single function
   */
  function extractFunctionCFG(func: GhidraFunction): FunctionCFG {
    const blocks = extractBasicBlocks(func);
    const edges = extractEdges(func, blocks);

    const cfg: FunctionCFG = {
      functionName: func.getName(),
      functionAddress: func.getEntryPoint().toString(),
      basicBlocks: blocks,
      edges,
    };

    // Generate visualizations
    cfg.mermaidDiagram = generateMermaidDiagram(cfg);
    cfg.graphvizDot = generateGraphvizDot(cfg);

    return cfg;
  }

  // ============================================================================
  // Main Execution
  // ============================================================================

  /** Extract CFGs from specific addresses */
  function extractCFGsAtAddresses(fm: FunctionManager, addresses: string[]): FunctionCFG[] {
    const cfgs: FunctionCFG[] = [];
    const factory = currentProgram.getAddressFactory();

    for (const addrStr of addresses) {
      if (monitor.isCancelled()) break;

      const addr = factory.getAddress(addrStr);
      if (!addr) {
        println(`Warning: Invalid address ${addrStr}`);
        continue;
      }

      const func = fm.getFunctionAt(addr);
      if (!func) {
        println(`Warning: No function at ${addrStr}`);
        continue;
      }

      cfgs.push(extractFunctionCFG(func));
    }

    return cfgs;
  }

  /** Extract CFGs from all functions, prioritizing non-thunks/externals */
  function extractAllCFGs(fm: FunctionManager, maxFunctions: number): FunctionCFG[] {
    const funcIter = fm.getFunctions(true);
    const candidates: GhidraFunction[] = [];

    while (funcIter.hasNext() && candidates.length < maxFunctions * 2) {
      candidates.push(funcIter.next());
    }

    // Sort: prefer real functions over thunks/externals
    candidates.sort((a, b) => {
      const aScore = (a.isThunk() ? 2 : 0) + (a.isExternal() ? 2 : 0);
      const bScore = (b.isThunk() ? 2 : 0) + (b.isExternal() ? 2 : 0);
      return aScore - bScore;
    });

    const cfgs: FunctionCFG[] = [];
    for (const func of candidates.slice(0, maxFunctions)) {
      if (monitor.isCancelled()) break;
      cfgs.push(extractFunctionCFG(func));
    }

    return cfgs;
  }

  function main(): void {
    const startTime = Date.now();
    const args = parseArgs();
    const output: CFGOutput = { success: false };

    try {
      const fm = currentProgram.getFunctionManager();
      const cfgs =
        args.addresses.length > 0
          ? extractCFGsAtAddresses(fm, args.addresses)
          : extractAllCFGs(fm, args.maxFunctions);

      const totalBlocks = cfgs.reduce((sum, cfg) => sum + cfg.basicBlocks.length, 0);
      const totalEdges = cfgs.reduce((sum, cfg) => sum + cfg.edges.length, 0);

      output.success = true;
      output.data = {
        binaryName: currentProgram.getName(),
        functionCFGs: cfgs,
        metadata: {
          scriptVersion: '1.0.0',
          extractionTime: Date.now() - startTime,
          functionCount: cfgs.length,
          totalBlocks,
          totalEdges,
          targetAddresses: args.addresses,
        },
      };
    } catch (error) {
      output.success = false;
      output.error = error instanceof Error ? error.message : String(error);
    }

    // Output with markers for parsing
    println('---SENTINEL_CFG_START---');
    println(JSON.stringify(output, null, 2));
    println('---SENTINEL_CFG_END---');
  }

  main();
})();
