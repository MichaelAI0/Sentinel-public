/**
 * MCP Client Bridge
 * Communicates with the MCP server to invoke binary analysis tools
 *
 * Uses the MCP SDK for proper protocol compliance.
 * Falls back to HTTP transport in Docker environments.
 */

import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { ToolResult } from '../types.js';
import { logger } from './logger.js';

// Resolve project root - works in development and Docker
const PROJECT_ROOT = process.cwd();

// Path mappings for Docker environment
// Maps local paths to container paths when MCP server runs in Docker
const PATH_MAPPINGS: Array<{ local: string; container: string }> = [
  {
    local: process.env.BINARIES_DIR ?? join(PROJECT_ROOT, 'binaries'),
    container: '/binaries',
  },
  {
    local: process.env.OUTPUT_DIR ?? join(PROJECT_ROOT, 'outputs'),
    container: '/outputs',
  },
];

/**
 * Translate local path to container path for Docker MCP server
 */
function translatePathForDocker(localPath: string): string {
  for (const mapping of PATH_MAPPINGS) {
    if (localPath.startsWith(mapping.local)) {
      return localPath.replace(mapping.local, mapping.container);
    }
  }
  return localPath;
}

/**
 * Translate container path back to local path
 */
function _translatePathFromDocker(containerPath: string): string {
  for (const mapping of PATH_MAPPINGS) {
    if (containerPath.startsWith(mapping.container)) {
      return containerPath.replace(mapping.container, mapping.local);
    }
  }
  return containerPath;
}

/**
 * MCP Client for communicating with the binary analysis tools
 */
export class McpBridge {
  private client: Client | null = null;
  private serverUrl: string;
  private connected = false;
  private useFallback = false;
  private translatePaths: boolean;
  private connectInFlight: Promise<void> | null = null;

  constructor(serverUrl?: string) {
    this.serverUrl = serverUrl ?? process.env.MCP_SERVER_URL ?? 'http://mcp-server:3000';
    // Enable path translation when MCP server is in Docker (HTTP mode)
    this.translatePaths = process.env.MCP_TRANSLATE_PATHS !== 'false';
  }

  /**
   * Initialize MCP connection
   */
  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    if (this.connectInFlight) {
      await this.connectInFlight;
      return;
    }

    this.connectInFlight = (async () => {
      logger.info`Connecting to MCP server at ${this.serverUrl}`;

      try {
        // Try MCP SDK connection first
        this.client = new Client({
          name: 'sentinel-orchestrator',
          version: '0.1.0',
        });

        const transport = new StreamableHTTPClientTransport(new URL(this.serverUrl));
        await this.client.connect(transport);
        this.connected = true;
        this.useFallback = false;
        logger.info`MCP client connected via SDK`;
      } catch (error) {
        // Fall back to HTTP transport for Docker environment
        logger.warn`MCP SDK connection failed, using HTTP fallback: ${error}`;
        this.connected = true;
        this.useFallback = true;
        logger.info`MCP client connected via HTTP fallback`;
      }
    })().finally(() => {
      this.connectInFlight = null;
    });

    await this.connectInFlight;
  }

  /**
   * Disconnect from MCP server
   */
  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
    }
    this.connected = false;
    logger.info`MCP client disconnected`;
  }

  /**
   * Call an MCP tool
   */
  async callTool<T = unknown>(
    toolName: string,
    args: Record<string, unknown>,
  ): Promise<ToolResult<T>> {
    if (!this.connected) {
      await this.connect();
    }

    // Translate paths for Docker environment
    const translatedArgs = this.translatePaths ? this.translateArgsForDocker(args) : args;

    logger.debug`Calling tool: ${toolName} with args: ${JSON.stringify(translatedArgs)}`;

    try {
      // Use MCP SDK if available
      if (this.client && !this.useFallback) {
        const result = await this.client.callTool({
          name: toolName,
          arguments: translatedArgs,
        });

        // Parse the result content
        const content = result.content;
        if (Array.isArray(content) && content.length > 0) {
          const firstContent = content[0];
          if (firstContent && 'text' in firstContent) {
            const data = JSON.parse(firstContent.text) as T;
            return { success: true, data };
          }
        }

        return { success: true, data: result as unknown as T };
      }

      // HTTP fallback for Docker environment
      const response = await fetch(`${this.serverUrl}/tools/${toolName}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(translatedArgs),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Tool call failed: ${response.status} - ${errorText}`);
      }

      const rawData = (await response.json()) as {
        content?: Array<{ type: string; text: string }>;
      };

      // Parse MCP content format
      let data: T;
      if (rawData.content && Array.isArray(rawData.content) && rawData.content.length > 0) {
        const firstContent = rawData.content[0];
        if (firstContent && firstContent.type === 'text' && firstContent.text) {
          data = JSON.parse(firstContent.text) as T;
        } else {
          data = rawData as unknown as T;
        }
      } else {
        data = rawData as unknown as T;
      }

      logger.debug`Tool ${toolName} returned successfully`;

      return {
        success: true,
        data,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error`Tool ${toolName} failed: ${errorMessage}`;

      return {
        success: false,
        error: errorMessage,
      };
    }
  }

  /**
   * Translate path arguments for Docker environment
   */
  private translateArgsForDocker(args: Record<string, unknown>): Record<string, unknown> {
    const translated = { ...args };

    // Translate common path fields
    const pathFields = ['filePath', 'binaryPath', 'path', 'outputPath'];
    for (const field of pathFields) {
      if (typeof translated[field] === 'string') {
        translated[field] = translatePathForDocker(translated[field] as string);
      }
    }

    return translated;
  }

  // === Convenience Methods for Common Tools ===

  /**
   * Calculate file hashes
   */
  async calculateHashes(
    filePath: string,
  ): Promise<ToolResult<{ md5: string; sha256: string; sha1: string; ssdeep?: string }>> {
    return this.callTool('calculate_hashes', { binaryPath: filePath });
  }

  /**
   * Detect file type
   */
  async detectFileType(
    filePath: string,
  ): Promise<ToolResult<{ type: string; mime: string; architecture?: string }>> {
    return this.callTool('detect_file_type', { binaryPath: filePath });
  }

  /**
   * Extract strings from binary
   */
  async extractStrings(
    filePath: string,
    options?: { minLength?: number; encoding?: string },
  ): Promise<ToolResult<{ strings: string[]; count: number }>> {
    return this.callTool('extract_strings', { filePath, ...options });
  }

  /**
   * Extract PE headers
   */
  async extractPeHeaders(filePath: string): Promise<
    ToolResult<{
      machine: string;
      sections: Array<{ name: string; entropy: number }>;
      imports: Array<{ dll: string; functions: string[] }>;
      exports: string[];
      optionalHeader?: {
        entryPoint?: string;
        imageBase?: string;
        magic?: string;
      };
    }>
  > {
    return this.callTool('extract_pe_headers', { filePath });
  }

  /**
   * Extract ELF headers
   */
  async extractElfHeaders(filePath: string): Promise<
    ToolResult<{
      class: string;
      machine: string;
      sections: Array<{ name: string; size: number }>;
      symbols: string[];
      header?: {
        entryPoint?: string;
      };
    }>
  > {
    return this.callTool('extract_elf_headers', { filePath });
  }

  /**
   * Detect packing
   */
  async detectPacking(
    filePath: string,
  ): Promise<ToolResult<{ isPacked: boolean; packerName?: string; confidence: number }>> {
    return this.callTool('detect_packing', { filePath });
  }

  /**
   * Full Ghidra binary analysis
   */
  async analyzeBinary(
    filePath: string,
    options?: { scriptName?: string; timeout?: number },
  ): Promise<
    ToolResult<{
      binaryPath: string;
      fileInfo: {
        format: string;
        architecture: string;
        size: number;
        entropy: number;
      };
      functions: Array<{
        name: string;
        address: string;
        size: number;
        callers: string[];
        callees: string[];
        decompiled?: string;
      }>;
      imports: Array<{
        library: string;
        function: string;
        address?: string;
      }>;
      exports: Array<{
        name: string;
        address: string;
      }>;
      sections: Array<{
        name: string;
        virtualAddress: string;
        virtualSize: number;
        rawSize: number;
        entropy: number;
        permissions: string;
      }>;
      strings: Array<{
        value: string;
        address: string;
        type: string;
      }>;
      analysisMetadata: {
        ghidraVersion: string;
        analysisTime: number;
        analyzedAt: string;
        functionCount: number;
      };
    }>
  > {
    return this.callTool('analyze_binary', { filePath, ...options });
  }

  /**
   * Extract control flow graphs from binary
   */
  async extractCFG(
    filePath: string,
    options?: { addresses?: string[]; maxFunctions?: number },
  ): Promise<
    ToolResult<{
      success: boolean;
      data?: {
        binaryName: string;
        functionCFGs: Array<{
          functionName: string;
          functionAddress: string;
          basicBlocks: Array<{
            id: string;
            startAddress: string;
            endAddress: string;
            instructionCount: number;
            isEntryBlock: boolean;
            isExitBlock: boolean;
          }>;
          edges: Array<{
            fromBlock: string;
            toBlock: string;
            edgeType: string;
          }>;
          mermaidDiagram?: string;
          graphvizDot?: string;
        }>;
        metadata: {
          functionCount: number;
          totalBlocks: number;
          totalEdges: number;
        };
      };
      error?: string;
    }>
  > {
    return this.callTool('ghidra_extract_cfg', { filePath, ...options });
  }

  /**
   * Detect cryptographic constants in binary
   */
  async detectCrypto(
    filePath: string,
    options?: { minConfidence?: number },
  ): Promise<
    ToolResult<{
      success: boolean;
      data?: {
        binaryName: string;
        findings: Array<{
          algorithm: string;
          type: string;
          address: string;
          size: number;
          confidence: number;
          description: string;
          nearbyFunctions: string[];
        }>;
        metadata: {
          findingCount: number;
          scannedBytes: number;
        };
      };
      error?: string;
    }>
  > {
    return this.callTool('ghidra_detect_crypto', { filePath, ...options });
  }

  /**
   * Extract API calls and imports from binary
   */
  async extractAPICalls(
    filePath: string,
    options?: { groupByLib?: boolean },
  ): Promise<
    ToolResult<{
      success: boolean;
      data?: {
        binaryName: string;
        imports: Array<{
          library: string;
          functionName: string;
          address: string;
          calledBy: string[];
        }>;
        exports: Array<{
          functionName: string;
          address: string;
        }>;
        apiCalls: Array<{
          callerFunction: string;
          callerAddress: string;
          targetAPI: string;
          targetLibrary: string;
        }>;
        libraryGroups?: Array<{
          libraryName: string;
          functionCount: number;
          functions: string[];
          callerCount: number;
        }>;
        metadata: {
          importCount: number;
          exportCount: number;
          callCount: number;
          libraryCount: number;
        };
      };
      error?: string;
    }>
  > {
    return this.callTool('ghidra_extract_api_calls', { filePath, ...options });
  }
}

// Singleton instance
let mcpBridgeInstance: McpBridge | null = null;

/**
 * Get or create the MCP bridge singleton
 */
export function getMcpBridge(): McpBridge {
  if (!mcpBridgeInstance) {
    mcpBridgeInstance = new McpBridge();
  }
  return mcpBridgeInstance;
}
