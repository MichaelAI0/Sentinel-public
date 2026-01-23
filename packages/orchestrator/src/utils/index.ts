/**
 * Orchestrator Utilities
 *
 * Re-exports all utility modules for convenient imports
 *
 * @module utils
 */

// Assembly extraction and analysis (exclude AssemblyPattern to avoid conflict with types.ts)
export {
  type AssemblyAnalysisSummary,
  AssemblyExtractor,
  type AssemblyExtractorConfig,
  type AssemblyFunction,
  type AssemblyInstruction,
  type AssemblyPatternType,
} from './assembly-extractor.js';
// LLM context window management
export * from './context-manager.js';
// Cryptographic detection
export * from './crypto-detector.js';
// Error handling utilities (withRetry excluded - use from llm/retry.js instead)
export {
  assert,
  categorizeError,
  collectErrors,
  createErrorAggregator,
  type ErrorCategory,
  type ErrorContext,
  handleAsyncOperation,
  isErrorOfType,
  logError,
  normalizeError,
  type RetryOptions,
  wrapAsync,
  wrapSync,
} from './error-handler.js';
// File size limits and streaming
export * from './file-limits.js';
// HTTP error responses
export * from './http-errors.js';
// Path security and sandboxing
export * from './path-sandbox.js';
// String analysis with entropy and categorization
export * from './string-analyzer.js';
// Binary unpacking (UPX, etc.)
export * from './unpacker.js';
// YARA signature scanning
export * from './yara-manager.js';
