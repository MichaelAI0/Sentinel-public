/**
 * Input Validation Schemas
 *
 * Provides comprehensive validation for all user inputs including:
 * - File paths (with path traversal protection)
 * - Binary names (safe filename patterns)
 * - CLI command arguments
 * - API request payloads
 *
 * @module schemas/input
 */

import { z } from 'zod';

// ============================================
// PATH & FILE VALIDATION
// ============================================

/**
 * Dangerous path patterns that could indicate path traversal attacks
 */
const DANGEROUS_PATH_PATTERNS = [
  /\.\./, // Parent directory traversal
  // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional null byte detection
  /\x00/, // Null byte injection
  /^~/, // Home directory expansion (can leak info)
  /%2e%2e/i, // URL-encoded ..
  /%252e%252e/i, // Double URL-encoded ..
  /\\/, // Backslash (Windows paths on Linux)
];

/**
 * Maximum allowed path length (Linux PATH_MAX is 4096)
 */
const MAX_PATH_LENGTH = 4096;

/**
 * Maximum allowed filename length
 */
const MAX_FILENAME_LENGTH = 255;

/**
 * Validates and sanitizes file paths
 * - Prevents path traversal attacks
 * - Blocks null bytes and dangerous patterns
 * - Enforces maximum length
 */
export const FilePathSchema = z
  .string()
  .min(1, 'File path cannot be empty')
  .max(MAX_PATH_LENGTH, `Path exceeds maximum length of ${MAX_PATH_LENGTH}`)
  .transform((p) => p.trim())
  .refine(
    (p) => !DANGEROUS_PATH_PATTERNS.some((pattern) => pattern.test(p)),
    'Path contains dangerous patterns (path traversal, null bytes, or encoding attacks)',
  )
  .refine((p) => !p.includes('\n') && !p.includes('\r'), 'Path cannot contain newline characters')
  .describe('Validated file path (absolute or relative)');

/**
 * Validates absolute file paths only
 */
export const AbsolutePathSchema = FilePathSchema.refine(
  (p) => p.startsWith('/'),
  'Path must be absolute (start with /)',
).describe('Validated absolute file path');

/**
 * Validates binary/file names (no path components)
 * - Only alphanumeric, underscore, dash, and dot
 * - No path separators
 * - Reasonable length limit
 */
export const BinaryNameSchema = z
  .string()
  .min(1, 'Binary name cannot be empty')
  .max(MAX_FILENAME_LENGTH, `Filename exceeds maximum length of ${MAX_FILENAME_LENGTH}`)
  .regex(
    /^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$/,
    'Binary name must start with alphanumeric and contain only letters, numbers, underscores, dashes, and dots',
  )
  .refine(
    (name) => !name.includes('/') && !name.includes('\\'),
    'Binary name cannot contain path separators',
  )
  .refine((name) => name !== '.' && name !== '..', 'Binary name cannot be . or ..')
  .describe('Safe binary filename');

// ============================================
// CLI COMMAND VALIDATION
// ============================================

/**
 * Valid CLI commands
 */
export const CommandEnum = z.enum(['analyze', 'triage', 'server', 'batch']);
export type Command = z.infer<typeof CommandEnum>;

/**
 * Output format options
 */
export const OutputFormatEnum = z.enum(['json', 'markdown', 'stix', 'all']);
export type OutputFormat = z.infer<typeof OutputFormatEnum>;

/**
 * Log level options
 */
export const InputLogLevelEnum = z.enum(['debug', 'info', 'warn', 'error', 'silent']);
export type InputLogLevel = z.infer<typeof InputLogLevelEnum>;

/**
 * Common CLI options shared across commands
 */
export const CommonOptionsSchema = z.object({
  verbose: z.boolean().default(false).describe('Enable verbose output'),
  quiet: z.boolean().default(false).describe('Suppress non-essential output'),
  json: z.boolean().default(false).describe('Output in JSON format'),
  config: FilePathSchema.optional().describe('Path to config file'),
  logLevel: InputLogLevelEnum.optional().default('info').describe('Log level'),
});

/**
 * Analyze command arguments
 */
export const AnalyzeArgsSchema = CommonOptionsSchema.extend({
  command: z.literal('analyze'),
  filePath: FilePathSchema.describe('Path to binary file to analyze'),
  output: FilePathSchema.optional().describe('Output directory for reports'),
  format: OutputFormatEnum.optional().default('all').describe('Output format'),
  timeout: z
    .number()
    .int()
    .positive()
    .max(3600)
    .default(300)
    .describe('Analysis timeout in seconds'),
  skipGhidra: z.boolean().default(false).describe('Skip Ghidra decompilation'),
  model: z.string().optional().describe('Override default LLM model'),
});

/**
 * Triage command arguments
 */
export const TriageArgsSchema = CommonOptionsSchema.extend({
  command: z.literal('triage'),
  filePath: FilePathSchema.describe('Path to binary file to triage'),
});

/**
 * Server command arguments
 */
export const ServerArgsSchema = CommonOptionsSchema.extend({
  command: z.literal('server'),
  port: z.number().int().min(1).max(65535).default(8080).describe('Port to listen on'),
  host: z.string().default('localhost').describe('Host to bind to'),
});

/**
 * Batch command arguments
 */
export const BatchArgsSchema = CommonOptionsSchema.extend({
  command: z.literal('batch'),
  directory: FilePathSchema.describe('Directory containing binaries to analyze'),
  output: FilePathSchema.optional().describe('Output directory for reports'),
  parallel: z.number().int().min(1).max(16).default(4).describe('Number of parallel analyses'),
  pattern: z.string().default('*').describe('Glob pattern to match files'),
});

/**
 * Union of all command argument schemas
 */
export const CommandArgsSchema = z.discriminatedUnion('command', [
  AnalyzeArgsSchema,
  TriageArgsSchema,
  ServerArgsSchema,
  BatchArgsSchema,
]);

export type AnalyzeArgs = z.infer<typeof AnalyzeArgsSchema>;
export type TriageArgs = z.infer<typeof TriageArgsSchema>;
export type ServerArgs = z.infer<typeof ServerArgsSchema>;
export type BatchArgs = z.infer<typeof BatchArgsSchema>;
export type CommandArgs = z.infer<typeof CommandArgsSchema>;

// ============================================
// API REQUEST VALIDATION
// ============================================

/**
 * Analyze API request body
 */
export const AnalyzeRequestSchema = z.object({
  filePath: FilePathSchema.describe('Path to binary file'),
  options: z
    .object({
      timeout: z.number().int().positive().max(3600).optional(),
      format: OutputFormatEnum.optional(),
      skipGhidra: z.boolean().optional(),
      model: z.string().optional(),
    })
    .optional(),
});

export type AnalyzeRequest = z.infer<typeof AnalyzeRequestSchema>;

/**
 * Batch analyze API request body
 */
export const BatchAnalyzeRequestSchema = z.object({
  files: z
    .array(FilePathSchema)
    .min(1, 'At least one file is required')
    .max(100, 'Maximum 100 files per batch'),
  options: z
    .object({
      parallel: z.number().int().min(1).max(16).optional(),
      timeout: z.number().int().positive().max(3600).optional(),
    })
    .optional(),
});

export type BatchAnalyzeRequest = z.infer<typeof BatchAnalyzeRequestSchema>;

// ============================================
// VALIDATION UTILITIES
// ============================================

/**
 * Validate input and return typed result or throw
 */
export function validateInput<T>(schema: z.ZodSchema<T>, input: unknown, context?: string): T {
  const result = schema.safeParse(input);

  if (!result.success) {
    const errors = result.error.issues
      .map((e: z.ZodIssue) => `${e.path.join('.')}: ${e.message}`)
      .join('; ');

    throw new Error(context ? `${context}: ${errors}` : `Validation failed: ${errors}`);
  }

  return result.data;
}

/**
 * Validate input and return Result type (no throw)
 */
export function safeValidateInput<T>(
  schema: z.ZodSchema<T>,
  input: unknown,
): { ok: true; data: T } | { ok: false; errors: z.ZodIssue[] } {
  const result = schema.safeParse(input);

  if (result.success) {
    return { ok: true, data: result.data };
  }

  return { ok: false, errors: result.error.issues };
}

/**
 * Parse and validate CLI arguments into typed command args
 */
export function parseCommandArgs(command: string, rawArgs: Record<string, unknown>): CommandArgs {
  const argsWithCommand = { ...rawArgs, command };
  return validateInput(CommandArgsSchema, argsWithCommand, 'CLI arguments');
}
