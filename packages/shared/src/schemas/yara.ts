/**
 * YARA Signature Matching Schemas
 *
 * Zod schemas for YARA scan results and signature matching
 *
 * @module schemas/yara
 */

import { z } from 'zod';

// ============================================
// YARA MATCH TYPES
// ============================================

/**
 * String match instance within a YARA rule
 */
export const YARAStringInstanceSchema = z.object({
  /** File offset where string was found */
  offset: z.number(),
  /** Length of matched data */
  length: z.number(),
  /** XOR key if string was XOR-encoded */
  xorKey: z.number().optional(),
  /** Matched bytes as hex string */
  matchedBytes: z.string().optional(),
});

/**
 * String pattern that matched within a YARA rule
 */
export const YARAStringMatchSchema = z.object({
  /** String identifier from rule (e.g., $s1) */
  identifier: z.string(),
  /** All instances where this string was found */
  instances: z.array(YARAStringInstanceSchema),
});

/**
 * Individual YARA rule match
 */
export const YARAMatchSchema = z.object({
  /** Rule name that matched */
  rule: z.string(),
  /** Namespace/category of rule */
  namespace: z.string().optional(),
  /** Tags associated with rule */
  tags: z.array(z.string()).default([]),
  /** Metadata from rule definition */
  metas: z.record(z.string(), z.unknown()).default({}),
  /** String patterns that matched */
  strings: z.array(YARAStringMatchSchema).default([]),
});

/**
 * Severity level based on YARA matches
 */
export const YARASeverityEnum = z.enum(['critical', 'high', 'medium', 'low', 'unknown']);

/**
 * Complete YARA scan result
 */
export const YARAScanResultSchema = z.object({
  /** Whether scan was performed */
  scanned: z.literal(true),
  /** All matching rules */
  matches: z.array(YARAMatchSchema),
  /** Detected malware families */
  malwareFamilies: z.array(z.string()).default([]),
  /** Assessed severity based on matches */
  severity: YARASeverityEnum,
  /** Scan timestamp */
  timestamp: z.coerce.date(),
  /** Scan duration in milliseconds */
  durationMs: z.number().optional(),
  /** Number of rules scanned */
  rulesScanned: z.number().optional(),
  /** Errors during scanning */
  errors: z.array(z.string()).default([]),
});

/**
 * YARA scan result when no rules are loaded
 */
export const YARANoRulesResultSchema = z.object({
  scanned: z.literal(false),
  reason: z.string(),
  timestamp: z.coerce.date(),
});

/**
 * YARA scan input parameters
 */
export const YARAScanInputSchema = z.object({
  /** Path to file to scan */
  filePath: z.string(),
  /** Timeout in seconds */
  timeout: z.number().positive().default(60),
  /** Specific rule files to use (empty = all) */
  ruleFiles: z.array(z.string()).optional(),
  /** Maximum matches per rule */
  maxMatchesPerRule: z.number().positive().default(100),
});

/**
 * YARA rule metadata
 */
export const YARARuleInfoSchema = z.object({
  /** Rule name */
  name: z.string(),
  /** Namespace/category */
  namespace: z.string().optional(),
  /** Rule description */
  description: z.string().optional(),
  /** Author information */
  author: z.string().optional(),
  /** Reference URLs */
  references: z.array(z.string()).default([]),
  /** Rule version */
  version: z.string().optional(),
  /** Creation/update date */
  date: z.string().optional(),
  /** Associated malware families */
  malwareFamilies: z.array(z.string()).default([]),
  /** Severity level if specified */
  severity: YARASeverityEnum.optional(),
  /** Tags from rule */
  tags: z.array(z.string()).default([]),
});

// ============================================
// TYPE EXPORTS
// ============================================

export type YARAStringInstance = z.infer<typeof YARAStringInstanceSchema>;
export type YARAStringMatch = z.infer<typeof YARAStringMatchSchema>;
export type YARAMatch = z.infer<typeof YARAMatchSchema>;
export type YARASeverity = z.infer<typeof YARASeverityEnum>;
export type YARAScanResult = z.infer<typeof YARAScanResultSchema>;
export type YARANoRulesResult = z.infer<typeof YARANoRulesResultSchema>;
export type YARAScanInput = z.infer<typeof YARAScanInputSchema>;
export type YARARuleInfo = z.infer<typeof YARARuleInfoSchema>;
