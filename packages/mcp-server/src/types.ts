/**
 * Tool type definitions for MCP server
 *
 * @module types
 */

import type { z } from 'zod';

/**
 * Type-safe tool definition for MCP server
 *
 * @template TInput - Input type validated by inputSchema
 * @template TOutput - Output type validated by outputSchema
 */
export type ToolDefinition<TInput, TOutput> = {
  name: string;
  description: string;
  inputSchema: z.ZodType<TInput>;
  outputSchema: z.ZodType<TOutput>;
  execute: (input: TInput) => Promise<TOutput>;
};
