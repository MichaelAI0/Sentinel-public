/**
 * MCP Tool Base Class
 *
 * Provides common functionality for all MCP tools:
 * - Standardized logging
 * - Error handling
 * - Input validation
 * - Caching support
 * - Performance metrics
 */

import type { z } from 'zod';
import { logToolExecution } from './logger.js';

// ============================================================================
// Types
// ============================================================================

export type ToolExecutionContext = {
  /** Unique ID for this execution */
  executionId: string;
  /** Start time for performance tracking */
  startTime: number;
  /** Optional file hash for caching */
  fileHash?: string;
};

export type ToolResult<T> =
  | {
      success: true;
      data: T;
      executionTimeMs: number;
      cached?: boolean;
    }
  | {
      success: false;
      error: string;
      executionTimeMs: number;
    };

export type ToolMetadata = {
  name: string;
  description: string;
  version: string;
  category: 'analysis' | 'extraction' | 'detection' | 'utility';
};

// ============================================================================
// Base Tool Class
// ============================================================================

/**
 * Abstract base class for MCP tools.
 * Provides standardized error handling, logging, and optional caching.
 *
 * @example
 * ```typescript
 * class CalculateHashesTool extends BaseTool<HashInput, HashOutput> {
 *   metadata = {
 *     name: 'calculate_hashes',
 *     description: 'Calculate file hashes',
 *     version: '1.0.0',
 *     category: 'utility' as const,
 *   };
 *
 *   protected async executeImpl(input: HashInput): Promise<HashOutput> {
 *     // Implementation here
 *   }
 * }
 * ```
 */
export abstract class BaseTool<TInput extends Record<string, unknown>, TOutput> {
  abstract readonly metadata: ToolMetadata;

  /**
   * Whether this tool's results can be cached.
   * Override to enable caching for the tool.
   */
  protected readonly cacheable: boolean = false;

  /**
   * Input validation schema. Override to add validation.
   */
  protected readonly inputSchema?: z.ZodType<TInput>;

  /**
   * Execute the tool with standardized error handling and logging.
   */
  async execute(input: TInput): Promise<ToolResult<TOutput>> {
    const context = this.createContext();

    logToolExecution(this.metadata.name, input, 'start');

    try {
      // Validate input if schema provided
      if (this.inputSchema) {
        const parseResult = this.inputSchema.safeParse(input);
        if (!parseResult.success) {
          const error = parseResult.error.issues.map((e) => e.message).join(', ');
          return this.createErrorResult(context, `Invalid input: ${error}`);
        }
      }

      // Execute the implementation
      const data = await this.executeImpl(input, context);
      const executionTimeMs = Date.now() - context.startTime;

      logToolExecution(this.metadata.name, input, 'success', {
        executionTimeMs,
      });

      return {
        success: true,
        data,
        executionTimeMs,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logToolExecution(this.metadata.name, input, 'error', { error: errorMessage });
      return this.createErrorResult(context, errorMessage);
    }
  }

  /**
   * Create execution context with unique ID and timing.
   */
  private createContext(): ToolExecutionContext {
    return {
      executionId: crypto.randomUUID(),
      startTime: Date.now(),
    };
  }

  /**
   * Create a standardized error result.
   */
  private createErrorResult(context: ToolExecutionContext, error: string): ToolResult<TOutput> {
    return {
      success: false,
      error,
      executionTimeMs: Date.now() - context.startTime,
    };
  }

  /**
   * Implementation method to be overridden by subclasses.
   */
  protected abstract executeImpl(input: TInput, context: ToolExecutionContext): Promise<TOutput>;
}

// ============================================================================
// Tool Registry
// ============================================================================

type AnyTool = BaseTool<Record<string, unknown>, unknown>;

/**
 * Registry for managing and discovering available tools.
 */
export class ToolRegistry {
  private tools = new Map<string, AnyTool>();

  /**
   * Register a tool in the registry.
   */
  register(tool: AnyTool): void {
    this.tools.set(tool.metadata.name, tool);
  }

  /**
   * Get a tool by name.
   */
  get(name: string): AnyTool | undefined {
    return this.tools.get(name);
  }

  /**
   * List all registered tools.
   */
  list(): ToolMetadata[] {
    return Array.from(this.tools.values()).map((t) => t.metadata);
  }

  /**
   * Get tools by category.
   */
  byCategory(category: ToolMetadata['category']): AnyTool[] {
    return Array.from(this.tools.values()).filter((t) => t.metadata.category === category);
  }

  /**
   * Check if a tool exists.
   */
  has(name: string): boolean {
    return this.tools.has(name);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Wrap an existing function-based tool with BaseTool functionality.
 * Useful for gradual migration without rewriting existing tools.
 */
export function wrapTool<TInput extends Record<string, unknown>, TOutput>(
  metadata: ToolMetadata,
  fn: (input: TInput) => Promise<TOutput>,
): BaseTool<TInput, TOutput> {
  return new (class extends BaseTool<TInput, TOutput> {
    metadata = metadata;

    protected async executeImpl(input: TInput): Promise<TOutput> {
      return fn(input);
    }
  })();
}

/**
 * Execute multiple tools in parallel.
 * Returns results keyed by tool name.
 */
export async function executeToolsParallel<T extends Record<string, unknown>>(
  toolCalls: Array<{
    tool: BaseTool<Record<string, unknown>, unknown>;
    input: Record<string, unknown>;
    key: keyof T;
  }>,
): Promise<Record<keyof T, ToolResult<unknown>>> {
  const results = await Promise.all(
    toolCalls.map(async ({ tool, input, key }) => ({
      key,
      result: await tool.execute(input),
    })),
  );

  return Object.fromEntries(results.map(({ key, result }) => [key, result])) as Record<
    keyof T,
    ToolResult<unknown>
  >;
}

// ============================================================================
// Singleton Registry
// ============================================================================

let registryInstance: ToolRegistry | null = null;

/**
 * Get the global tool registry.
 */
export function getToolRegistry(): ToolRegistry {
  if (!registryInstance) {
    registryInstance = new ToolRegistry();
  }
  return registryInstance;
}
