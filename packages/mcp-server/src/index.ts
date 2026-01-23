#!/usr/bin/env bun
/**
 * SENTINEL MCP Server
 *
 * Model Context Protocol server providing binary analysis tools.
 * Phase 2: Binary Utils (calculate_hashes, detect_file_type, extract_pe_headers, extract_elf_headers)
 * Phase 3: Advanced Analysis (CFG extraction, crypto detection, API mapping)
 *
 * Implements MCP 2025-06-18 spec with outputSchema for structured content validation.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import {
  AnalyzeBinaryInputSchema,
  CalculateHashesInputSchema,
  DetectFileTypeInputSchema,
  DetectPackingInputSchema,
  ExtractELFHeadersInputSchema,
  ExtractPEHeadersInputSchema,
  ExtractStringsInputSchema,
  TOOL_NAMES,
} from '@sentinel/shared';

import {
  analyzeBinary,
  calculateHashes,
  detectFileType,
  detectPacking,
  extractELFHeaders,
  extractPEHeaders,
  extractStrings,
} from './tools/index.js';
import { executeGhidraScript } from './utils/ghidra-bridge.js';
import { logger, mcpLogger } from './utils/logger.js';

// =============================================================================
// Output Schemas (MCP 2025-06-18 spec - structured content validation)
// =============================================================================

// Helper type to convert readonly arrays to mutable (for MCP SDK compatibility)
type Mutable<T> =
  T extends ReadonlyArray<infer U> ? U[] : { -readonly [K in keyof T]: Mutable<T[K]> };

const HashOutputSchema = {
  type: 'object',
  properties: {
    md5: { type: 'string', description: 'MD5 hash (32 hex chars)' },
    sha1: { type: 'string', description: 'SHA1 hash (40 hex chars)' },
    sha256: { type: 'string', description: 'SHA256 hash (64 hex chars)' },
    ssdeep: { type: 'string', description: 'SSDEEP fuzzy hash' },
    size: { type: 'number', description: 'File size in bytes' },
  },
  required: ['sha256', 'size'],
} as const;

const FileTypeOutputSchema = {
  type: 'object',
  properties: {
    format: {
      type: 'string',
      enum: ['PE32', 'PE32+', 'ELF32', 'ELF64', 'MACHO', 'SCRIPT', 'ARCHIVE', 'UNKNOWN'],
      description: 'Detected file format',
    },
    architecture: {
      type: 'string',
      enum: ['x86', 'x86-64', 'ARM', 'ARM64', 'MIPS', 'UNKNOWN'],
      description: 'CPU architecture',
    },
    os: { type: 'string', description: 'Target operating system' },
    entropy: { type: 'number', description: 'Shannon entropy (0-8)' },
    mimeType: { type: 'string', description: 'MIME type' },
  },
  required: ['format', 'architecture', 'entropy'],
} as const;

const AnalyzeBinaryOutputSchema = {
  type: 'object',
  properties: {
    success: { type: 'boolean', description: 'Whether analysis succeeded' },
    functions: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          address: { type: 'string' },
          size: { type: 'number' },
        },
      },
      description: 'Analyzed functions',
    },
    imports: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          library: { type: 'string' },
          function: { type: 'string' },
        },
      },
      description: 'Import table entries',
    },
    exports: {
      type: 'array',
      items: { type: 'string' },
      description: 'Export table entries',
    },
    strings: {
      type: 'array',
      items: { type: 'string' },
      description: 'Extracted strings',
    },
    metadata: {
      type: 'object',
      properties: {
        analysisTime: { type: 'number', description: 'Analysis duration in ms' },
        ghidraVersion: { type: 'string', description: 'Ghidra version used' },
      },
    },
  },
  required: ['success', 'functions', 'imports', 'strings'],
} as const;

// Cast helper for MCP SDK compatibility (readonly → mutable)
const toMutableSchema = <T>(schema: T): Mutable<T> => schema as Mutable<T>;

/**
 * Generate HTML page with embedded Mermaid diagrams for CFG visualization
 */
function generateMermaidHtml(diagrams: Array<{ functionName: string; diagram?: string }>): string {
  const diagramsHtml = diagrams
    .map(
      (d, i) => `
    <div class="diagram-container">
      <h3>${d.functionName}</h3>
      <div class="mermaid" id="diagram-${i}">
${d.diagram ?? 'No diagram available'}
      </div>
    </div>
  `,
    )
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SENTINEL CFG Visualization</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
  <style>
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #1a1a2e; 
      color: #eee; 
      padding: 20px;
      margin: 0;
    }
    h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
    h3 { color: #ff6b6b; margin-top: 30px; }
    .diagram-container { 
      background: #16213e; 
      padding: 20px; 
      border-radius: 8px; 
      margin: 20px 0;
      box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    .mermaid { background: #0f3460; padding: 20px; border-radius: 4px; overflow-x: auto; }
    .mermaid svg { max-width: 100%; }
  </style>
</head>
<body>
  <h1>🔍 SENTINEL Control Flow Graph</h1>
  <p>Generated: ${new Date().toISOString()}</p>
  ${diagramsHtml}
  <script>
    mermaid.initialize({ 
      startOnLoad: true, 
      theme: 'dark',
      securityLevel: 'loose',
      flowchart: { curve: 'basis' }
    });
  </script>
</body>
</html>`;
}

// Tool definitions for MCP
const TOOLS: Tool[] = [
  {
    name: TOOL_NAMES.CALCULATE_HASHES,
    description:
      'Calculate cryptographic hashes (MD5, SHA1, SHA256, SSDEEP) for a binary file. Essential for malware identification and threat intelligence lookups.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file to hash',
        },
        algorithms: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['MD5', 'SHA1', 'SHA256', 'SSDEEP'],
          },
          default: ['MD5', 'SHA256'],
          description: 'Hash algorithms to compute',
        },
      },
      required: ['binaryPath'],
    },
    outputSchema: toMutableSchema(HashOutputSchema),
  },
  {
    name: TOOL_NAMES.DETECT_FILE_TYPE,
    description:
      'Detect file type using magic number analysis. Returns format (PE/ELF/Mach-O/Script/Archive), architecture, OS, and entropy.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file to analyze',
        },
      },
      required: ['binaryPath'],
    },
    outputSchema: toMutableSchema(FileTypeOutputSchema),
  },
  {
    name: TOOL_NAMES.EXTRACT_PE_HEADERS,
    description:
      'Extract headers from a Windows PE (Portable Executable) file. Returns DOS header, PE header, optional header, sections, imports, and exports.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the PE file',
        },
        options: {
          type: 'object',
          properties: {
            includeDetailedSections: {
              type: 'boolean',
              default: true,
              description: 'Include detailed section information',
            },
            parseImportTable: {
              type: 'boolean',
              default: true,
              description: 'Parse the import table',
            },
            parseExportTable: {
              type: 'boolean',
              default: true,
              description: 'Parse the export table',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
  },
  {
    name: TOOL_NAMES.EXTRACT_ELF_HEADERS,
    description:
      'Extract headers from a Linux ELF (Executable and Linkable Format) file. Returns ELF header, program headers, section headers, and dynamic entries.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the ELF file',
        },
        options: {
          type: 'object',
          properties: {
            includeDetailedSections: {
              type: 'boolean',
              default: true,
              description: 'Include detailed section information',
            },
            parseDynamicSection: {
              type: 'boolean',
              default: true,
              description: 'Parse the dynamic section',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
  },
  {
    name: TOOL_NAMES.ANALYZE_BINARY,
    description:
      'Perform comprehensive static analysis on a binary using Ghidra headless analyzer. Returns functions, imports, exports, sections, strings, and metadata. Requires Ghidra container to be running.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file',
        },
        options: {
          type: 'object',
          properties: {
            maxFunctions: {
              type: 'number',
              default: 1000,
              description: 'Maximum number of functions to analyze',
            },
            includeDecompilation: {
              type: 'boolean',
              default: true,
              description: 'Include decompiled code for functions',
            },
            analyzeStrings: {
              type: 'boolean',
              default: true,
              description: 'Extract and analyze strings',
            },
            detectPackers: {
              type: 'boolean',
              default: true,
              description: 'Run packer detection',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
    outputSchema: toMutableSchema(AnalyzeBinaryOutputSchema),
  },
  {
    name: TOOL_NAMES.EXTRACT_STRINGS,
    description:
      'Fast string extraction from a binary file. Extracts ASCII and Unicode strings without Ghidra. Identifies suspicious strings like URLs, IPs, API names.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file',
        },
        options: {
          type: 'object',
          properties: {
            minLength: {
              type: 'number',
              default: 4,
              description: 'Minimum string length to extract',
            },
            includeUnicode: {
              type: 'boolean',
              default: true,
              description: 'Include Unicode (UTF-16) strings',
            },
            limit: {
              type: 'number',
              default: 10000,
              description: 'Maximum number of strings to return',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
  },
  {
    name: TOOL_NAMES.DETECT_PACKING,
    description:
      'Detect if a binary is packed or obfuscated. Analyzes entropy, known packer signatures, and section names. Returns confidence score and identified packers.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file',
        },
        options: {
          type: 'object',
          properties: {
            checkEntropy: {
              type: 'boolean',
              default: true,
              description: 'Check file entropy for compression/encryption',
            },
            checkSignatures: {
              type: 'boolean',
              default: true,
              description: 'Check for known packer signatures',
            },
            checkSectionNames: {
              type: 'boolean',
              default: true,
              description: 'Check section names for packer indicators',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
  },
  // ==========================================================================
  // Phase 3: Advanced Ghidra Analysis Tools
  // ==========================================================================
  {
    name: 'extract_cfg',
    description:
      'Extract control flow graphs (CFGs) from binary functions using Ghidra. Returns basic blocks, edges, and generates Mermaid/GraphViz visualization code.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file',
        },
        options: {
          type: 'object',
          properties: {
            maxFunctions: {
              type: 'number',
              default: 10,
              description: 'Maximum number of functions to extract CFGs for',
            },
            functionAddress: {
              type: 'string',
              description: 'Specific function address to analyze (optional)',
            },
            outputFormat: {
              type: 'string',
              enum: ['mermaid', 'graphviz', 'both'],
              default: 'both',
              description: 'Visualization output format',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        functionCFGs: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              functionName: { type: 'string' },
              functionAddress: { type: 'string' },
              basicBlocks: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    id: { type: 'string' },
                    startAddress: { type: 'string' },
                    instructionCount: { type: 'number' },
                    isEntryBlock: { type: 'boolean' },
                    isExitBlock: { type: 'boolean' },
                  },
                },
              },
              edges: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    fromBlock: { type: 'string' },
                    toBlock: { type: 'string' },
                    edgeType: { type: 'string' },
                  },
                },
              },
              mermaidDiagram: { type: 'string' },
              graphvizDot: { type: 'string' },
            },
          },
        },
        metadata: {
          type: 'object',
          properties: {
            totalBlocks: { type: 'number' },
            totalEdges: { type: 'number' },
            analysisTime: { type: 'number' },
          },
        },
      },
      required: ['functionCFGs', 'metadata'],
    },
  },
  {
    name: 'detect_crypto',
    description:
      'Detect cryptographic constants and algorithms in a binary using Ghidra. Identifies AES S-boxes, MD5/SHA IVs, ChaCha20 constants, and crypto API imports.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file',
        },
        options: {
          type: 'object',
          properties: {
            minConfidence: {
              type: 'number',
              default: 0.7,
              description: 'Minimum confidence threshold (0-1)',
            },
            scanImports: {
              type: 'boolean',
              default: true,
              description: 'Scan for crypto-related API imports',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        findings: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              algorithm: { type: 'string', description: 'e.g., AES, MD5, SHA256' },
              type: { type: 'string', enum: ['constant', 'import', 'pattern'] },
              address: { type: 'string' },
              confidence: { type: 'number' },
              nearbyFunctions: { type: 'array', items: { type: 'string' } },
            },
          },
        },
        metadata: {
          type: 'object',
          properties: {
            totalFindings: { type: 'number' },
            algorithmsFound: { type: 'array', items: { type: 'string' } },
          },
        },
      },
      required: ['findings', 'metadata'],
    },
  },
  {
    name: 'extract_api_calls',
    description:
      'Extract and map API/import calls from a binary using Ghidra. Shows which functions call which external APIs, grouped by library.',
    inputSchema: {
      type: 'object',
      properties: {
        binaryPath: {
          type: 'string',
          description: 'Absolute path to the binary file',
        },
        options: {
          type: 'object',
          properties: {
            groupByLib: {
              type: 'boolean',
              default: true,
              description: 'Group API calls by library',
            },
            includeSuspiciousOnly: {
              type: 'boolean',
              default: false,
              description: 'Only return security-relevant APIs',
            },
          },
        },
      },
      required: ['binaryPath'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        imports: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              library: { type: 'string' },
              functionName: { type: 'string' },
              calledBy: { type: 'array', items: { type: 'string' } },
            },
          },
        },
        exports: {
          type: 'array',
          items: { type: 'string' },
        },
        libraryGroups: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              libraryName: { type: 'string' },
              functionCount: { type: 'number' },
              functions: { type: 'array', items: { type: 'string' } },
            },
          },
        },
        metadata: {
          type: 'object',
          properties: {
            totalImports: { type: 'number' },
            libraryCount: { type: 'number' },
            suspiciousAPIs: { type: 'array', items: { type: 'string' } },
          },
        },
      },
      required: ['imports', 'metadata'],
    },
  },
];

// Create MCP Server
const server = new Server(
  {
    name: 'sentinel-mcp-server',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

// Handle list_tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  mcpLogger.info`Listing ${TOOLS.length} available tools`;
  return { tools: TOOLS };
});

// Handle call_tool request
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  mcpLogger.info`Tool call received: ${name}`;

  try {
    let result: unknown;

    switch (name) {
      case TOOL_NAMES.CALCULATE_HASHES: {
        const input = CalculateHashesInputSchema.parse(args);
        result = await calculateHashes(input);
        break;
      }

      case TOOL_NAMES.DETECT_FILE_TYPE: {
        const input = DetectFileTypeInputSchema.parse(args);
        result = await detectFileType(input);
        break;
      }

      case TOOL_NAMES.EXTRACT_PE_HEADERS: {
        const input = ExtractPEHeadersInputSchema.parse(args);
        result = await extractPEHeaders(input);
        break;
      }

      case TOOL_NAMES.EXTRACT_ELF_HEADERS: {
        const input = ExtractELFHeadersInputSchema.parse(args);
        result = await extractELFHeaders(input);
        break;
      }

      case TOOL_NAMES.ANALYZE_BINARY: {
        const input = AnalyzeBinaryInputSchema.parse(args);
        result = await analyzeBinary(input);
        break;
      }

      case TOOL_NAMES.EXTRACT_STRINGS: {
        const input = ExtractStringsInputSchema.parse(args);
        result = await extractStrings(input);
        break;
      }

      case TOOL_NAMES.DETECT_PACKING: {
        const input = DetectPackingInputSchema.parse(args);
        result = await detectPacking(input);
        break;
      }

      // Phase 3: Advanced Ghidra Analysis Tools
      case 'extract_cfg': {
        const binaryPath = (args as { binaryPath: string }).binaryPath;
        const options = (args as { options?: { maxFunctions?: number; functionAddress?: string } })
          .options;
        result = await executeGhidraScript({
          binaryPath,
          script: 'extract-cfg',
          args: options?.maxFunctions ? [`--maxFunctions=${options.maxFunctions}`] : undefined,
        });
        break;
      }

      case 'detect_crypto': {
        const binaryPath = (args as { binaryPath: string }).binaryPath;
        const options = (args as { options?: { minConfidence?: number; scanImports?: boolean } })
          .options;
        result = await executeGhidraScript({
          binaryPath,
          script: 'detect-crypto',
          args: options?.minConfidence ? [`--minConfidence=${options.minConfidence}`] : undefined,
        });
        break;
      }

      case 'extract_api_calls': {
        const binaryPath = (args as { binaryPath: string }).binaryPath;
        const options = (
          args as { options?: { groupByLib?: boolean; includeSuspiciousOnly?: boolean } }
        ).options;
        result = await executeGhidraScript({
          binaryPath,
          script: 'extract-api-calls',
          args: options?.groupByLib === false ? ['--noGroup'] : undefined,
        });
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    mcpLogger.error`Tool execution failed: ${name} - ${errorMessage}`;

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: errorMessage }),
        },
      ],
      isError: true,
    };
  }
});

// Tool executor function for HTTP mode
async function executeToolByName(
  toolName: string,
  args: Record<string, unknown>,
): Promise<{ content: { type: string; text: string }[]; isError?: boolean }> {
  const binaryPath = (args.binaryPath || args.filePath) as string | undefined;
  const options = args.options as Record<string, unknown> | undefined;

  switch (toolName) {
    case TOOL_NAMES.CALCULATE_HASHES: {
      const input = CalculateHashesInputSchema.parse({
        binaryPath,
        algorithms: args.algorithms,
      });
      const result = await calculateHashes(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case TOOL_NAMES.DETECT_FILE_TYPE: {
      const input = DetectFileTypeInputSchema.parse({ binaryPath });
      const result = await detectFileType(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case TOOL_NAMES.EXTRACT_PE_HEADERS: {
      const input = ExtractPEHeadersInputSchema.parse({ binaryPath, options });
      const result = await extractPEHeaders(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case TOOL_NAMES.EXTRACT_ELF_HEADERS: {
      const input = ExtractELFHeadersInputSchema.parse({ binaryPath, options });
      const result = await extractELFHeaders(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case TOOL_NAMES.ANALYZE_BINARY: {
      const input = AnalyzeBinaryInputSchema.parse({ binaryPath, options });
      const result = await analyzeBinary(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case TOOL_NAMES.EXTRACT_STRINGS: {
      const input = ExtractStringsInputSchema.parse({ binaryPath, options });
      const result = await extractStrings(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case TOOL_NAMES.DETECT_PACKING: {
      const input = DetectPackingInputSchema.parse({ binaryPath, options });
      const result = await detectPacking(input);
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    // Phase 3: Advanced Ghidra Analysis Tools (HTTP mode)
    case 'extract_cfg': {
      const result = await executeGhidraScript({
        binaryPath: binaryPath ?? '',
        script: 'extract-cfg',
        args: (options as { maxFunctions?: number })?.maxFunctions
          ? [`--maxFunctions=${(options as { maxFunctions?: number }).maxFunctions}`]
          : undefined,
      });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'detect_crypto': {
      const result = await executeGhidraScript({
        binaryPath: binaryPath ?? '',
        script: 'detect-crypto',
        args: (options as { minConfidence?: number })?.minConfidence
          ? [`--minConfidence=${(options as { minConfidence?: number }).minConfidence}`]
          : undefined,
      });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    case 'extract_api_calls': {
      const result = await executeGhidraScript({
        binaryPath: binaryPath ?? '',
        script: 'extract-api-calls',
        args:
          (options as { groupByLib?: boolean })?.groupByLib === false ? ['--noGroup'] : undefined,
      });
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
    default:
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: `Unknown tool: ${toolName}` }) }],
        isError: true,
      };
  }
}

// Start the server with appropriate transport
async function main() {
  logger.info`Starting SENTINEL MCP Server v0.1.0`;
  logger.info`Available tools: ${TOOLS.map((t) => t.name).join(', ')}`;

  const mode = process.env.MCP_MODE ?? 'stdio';

  if (mode === 'http') {
    // HTTP server mode for Docker/network access
    const port = Number.parseInt(process.env.PORT ?? '3000', 10);

    const _httpServer = Bun.serve({
      port,
      hostname: '0.0.0.0',

      // biome-ignore lint/complexity/noExcessiveCognitiveComplexity: HTTP router requires multiple route handlers
      async fetch(req: Request): Promise<Response> {
        const url = new URL(req.url);

        // Health check
        if (url.pathname === '/health') {
          return Response.json({ status: 'healthy', tools: TOOLS.map((t) => t.name) });
        }

        // List tools
        if (url.pathname === '/tools' && req.method === 'GET') {
          return Response.json({ tools: TOOLS });
        }

        // MCP-style tools/call endpoint (check before /tools/:name)
        if (url.pathname === '/tools/call' && req.method === 'POST') {
          try {
            const body = (await req.json()) as { name: string; arguments: Record<string, unknown> };
            const result = await executeToolByName(body.name, body.arguments);
            return Response.json(result);
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return Response.json({ error: errorMessage }, { status: 500 });
          }
        }

        // Call tool by name: /tools/:toolName
        if (url.pathname.startsWith('/tools/') && req.method === 'POST') {
          const toolName = url.pathname.replace('/tools/', '');
          try {
            const args = (await req.json()) as Record<string, unknown>;
            const result = await executeToolByName(toolName, args);
            return Response.json(result);
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return Response.json({ error: errorMessage }, { status: 500 });
          }
        }

        // =======================================================================
        // Phase 3: Visualization Endpoints
        // =======================================================================

        // Render CFG as Mermaid diagram (returns HTML with embedded Mermaid)
        if (url.pathname === '/viz/cfg' && req.method === 'POST') {
          try {
            const body = (await req.json()) as { binaryPath: string; functionAddress?: string };
            const result = await executeGhidraScript({
              binaryPath: body.binaryPath,
              script: 'extract-cfg',
            });

            if (!result.success || !result.data) {
              return Response.json(
                { error: result.error ?? 'CFG extraction failed' },
                { status: 500 },
              );
            }

            // Return Mermaid diagrams for all functions
            const mermaidDiagrams =
              (
                result.data as {
                  functionCFGs?: Array<{ functionName: string; mermaidDiagram?: string }>;
                }
              ).functionCFGs
                ?.map((cfg) => ({
                  functionName: cfg.functionName,
                  diagram: cfg.mermaidDiagram,
                }))
                .filter((d) => d.diagram) ?? [];

            return Response.json({
              format: 'mermaid',
              diagrams: mermaidDiagrams,
              renderHtml: generateMermaidHtml(mermaidDiagrams),
            });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return Response.json({ error: errorMessage }, { status: 500 });
          }
        }

        // Get analysis summary as structured data for dashboard
        if (url.pathname === '/viz/summary' && req.method === 'POST') {
          try {
            const body = (await req.json()) as { binaryPath: string };

            // Run multiple analyses in parallel
            const [hashResult, typeResult, stringsResult] = await Promise.all([
              executeToolByName(TOOL_NAMES.CALCULATE_HASHES, { binaryPath: body.binaryPath }),
              executeToolByName(TOOL_NAMES.DETECT_FILE_TYPE, { binaryPath: body.binaryPath }),
              executeToolByName(TOOL_NAMES.EXTRACT_STRINGS, {
                binaryPath: body.binaryPath,
                options: { limit: 100 },
              }),
            ]);

            return Response.json({
              hashes: JSON.parse(hashResult.content[0]?.text ?? '{}'),
              fileType: JSON.parse(typeResult.content[0]?.text ?? '{}'),
              strings: JSON.parse(stringsResult.content[0]?.text ?? '{}'),
            });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            return Response.json({ error: errorMessage }, { status: 500 });
          }
        }

        return Response.json({ error: 'Not found' }, { status: 404 });
      },
    });

    logger.info`MCP HTTP Server listening on port ${port}`;

    // Keep the server running
    await new Promise(() => {});
  } else {
    // Standard stdio mode for MCP clients
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info`MCP Server connected and ready`;
  }
}

main().catch((error) => {
  logger.fatal`Failed to start MCP server: ${error}`;
  process.exit(1);
});
