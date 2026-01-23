/**
 * Error Handling Utilities
 *
 * Provides consistent error handling patterns:
 * - Error normalization (unknown → Error)
 * - Async operation wrapping with retry
 * - Structured error logging
 * - Error categorization
 *
 * @module utils/error-handler
 */

import { getLogger } from '@logtape/logtape';
import {
  AgentError,
  AnalysisError,
  ConfigError,
  FileAccessError,
  SentinelError,
  ServiceError,
  TimeoutError,
  ToolError,
  ValidationError,
} from '@sentinel/shared';

const logger = getLogger(['sentinel', 'error-handler']);

// ============================================
// TYPES
// ============================================

/**
 * Context for error handling operations
 */
export type ErrorContext = {
  /** Name of the operation being performed */
  operation: string;
  /** File path if file-related operation */
  filePath?: string;
  /** Additional metadata for logging */
  metadata?: Record<string, unknown>;
};

/**
 * Retry options for async operations
 */
export type RetryOptions = {
  /** Maximum number of attempts (default: 3) */
  maxAttempts?: number;
  /** Initial delay in ms (default: 1000) */
  initialDelayMs?: number;
  /** Multiplier for exponential backoff (default: 2) */
  backoffMultiplier?: number;
  /** Maximum delay in ms (default: 30000) */
  maxDelayMs?: number;
  /** Errors that should trigger retry (default: all except ValidationError) */
  retryableErrors?: Array<new (...args: unknown[]) => Error>;
  /** Callback on each retry */
  onRetry?: (attempt: number, error: Error, nextDelayMs: number) => void;
};

/**
 * Result of categorizing an error
 */
export type ErrorCategory = {
  /** HTTP-appropriate status code */
  httpStatus: number;
  /** Error category for grouping */
  category:
    | 'validation'
    | 'file'
    | 'network'
    | 'timeout'
    | 'analysis'
    | 'configuration'
    | 'internal';
  /** Whether operation should be retried */
  retryable: boolean;
  /** User-friendly error message */
  userMessage: string;
};

// ============================================
// ERROR NORMALIZATION
// ============================================

/**
 * Convert any thrown value to a proper Error instance
 *
 * @param error - Unknown thrown value
 * @returns Normalized Error instance
 *
 * @example
 * ```ts
 * try {
 *   throw 'oops';
 * } catch (e) {
 *   const error = normalizeError(e);
 *   // error instanceof Error === true
 * }
 * ```
 */
export function normalizeError(error: unknown): Error {
  // Already an Error
  if (error instanceof Error) {
    return error;
  }

  // String error
  if (typeof error === 'string') {
    return new Error(error);
  }

  // Object with message property
  if (
    error !== null &&
    typeof error === 'object' &&
    'message' in error &&
    typeof error.message === 'string'
  ) {
    const err = new Error(error.message);
    if ('name' in error && typeof error.name === 'string') {
      err.name = error.name;
    }
    return err;
  }

  // Unknown type - serialize as JSON
  try {
    return new Error(`Unknown error: ${JSON.stringify(error)}`);
  } catch {
    return new Error(`Unknown error (not serializable): ${typeof error}`);
  }
}

// ============================================
// ERROR CATEGORIZATION
// ============================================

/**
 * Categorize an error for appropriate handling
 *
 * @param error - Error to categorize
 * @returns Category information for the error
 *
 * @example
 * ```ts
 * const category = categorizeError(new ValidationError('bad input'));
 * // { httpStatus: 400, category: 'validation', retryable: false, ... }
 * ```
 */
export function categorizeError(error: Error): ErrorCategory {
  if (error instanceof ValidationError) {
    return {
      httpStatus: 400,
      category: 'validation',
      retryable: false,
      userMessage: error.message,
    };
  }

  if (error instanceof FileAccessError) {
    return {
      httpStatus: 404,
      category: 'file',
      retryable: false,
      userMessage: `File not accessible: ${error.filePath}`,
    };
  }

  if (error instanceof TimeoutError) {
    return {
      httpStatus: 408,
      category: 'timeout',
      retryable: true,
      userMessage: `Operation timed out: ${error.operation}`,
    };
  }

  if (error instanceof ServiceError) {
    return {
      httpStatus: 502,
      category: 'network',
      retryable: true,
      userMessage: 'Service error occurred. Please try again.',
    };
  }

  if (error instanceof ToolError || error instanceof AgentError) {
    return {
      httpStatus: 503,
      category: 'analysis',
      retryable: true,
      userMessage: 'Analysis service temporarily unavailable.',
    };
  }

  if (error instanceof ConfigError) {
    return {
      httpStatus: 500,
      category: 'configuration',
      retryable: false,
      userMessage: 'Server configuration error. Please contact support.',
    };
  }

  if (error instanceof AnalysisError) {
    return {
      httpStatus: 422,
      category: 'analysis',
      retryable: false,
      userMessage: error.message,
    };
  }

  // Default: internal error
  return {
    httpStatus: 500,
    category: 'internal',
    retryable: false,
    userMessage: 'An unexpected error occurred.',
  };
}

// ============================================
// ERROR LOGGING
// ============================================

/**
 * Log an error with structured context
 *
 * @param error - Error to log
 * @param context - Additional context for the error
 */
export function logError(error: Error, context: ErrorContext): void {
  const category = categorizeError(error);

  const logData: Record<string, unknown> = {
    operation: context.operation,
    errorName: error.name,
    category: category.category,
    httpStatus: category.httpStatus,
    retryable: category.retryable,
    ...context.metadata,
  };

  if (context.filePath) {
    logData.filePath = context.filePath;
  }

  // Add SentinelError-specific data
  if (error instanceof SentinelError) {
    logData.errorCode = error.code;
    logData.errorMetadata = error.metadata;
  }

  // Add cause chain if present
  if (error.cause instanceof Error) {
    logData.causeName = error.cause.name;
    logData.causeMessage = error.cause.message;
  }

  // Log at appropriate level based on category
  if (category.category === 'validation') {
    logger.warn`${error.message} ${logData}`;
  } else if (category.retryable) {
    logger.warn`${error.message} ${logData}`;
  } else {
    logger.error`${error.message} ${logData}`;
  }
}

// ============================================
// ASYNC OPERATION HANDLING
// ============================================

/**
 * Wrap an async operation with consistent error handling
 *
 * @param operation - Async function to execute
 * @param context - Context for error logging
 * @returns Promise resolving to operation result
 * @throws Normalized and logged error
 *
 * @example
 * ```ts
 * const result = await handleAsyncOperation(
 *   () => readFile(path),
 *   { operation: 'readFile', filePath: path }
 * );
 * ```
 */
export async function handleAsyncOperation<T>(
  operation: () => Promise<T>,
  context: ErrorContext,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const normalizedError = normalizeError(error);
    logError(normalizedError, context);
    throw normalizedError;
  }
}

/**
 * Execute an async operation with automatic retry on failure
 *
 * @param operation - Async function to execute
 * @param context - Context for error logging
 * @param options - Retry configuration
 * @returns Promise resolving to operation result
 * @throws Error after all retry attempts exhausted
 *
 * @example
 * ```ts
 * const result = await withRetry(
 *   () => fetchFromAPI(url),
 *   { operation: 'fetchAPI', metadata: { url } },
 *   { maxAttempts: 3, initialDelayMs: 1000 }
 * );
 * ```
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  context: ErrorContext,
  options: RetryOptions = {},
): Promise<T> {
  const {
    maxAttempts = 3,
    initialDelayMs = 1000,
    backoffMultiplier = 2,
    maxDelayMs = 30000,
    retryableErrors,
    onRetry,
  } = options;

  let lastError: Error | undefined;
  let delayMs = initialDelayMs;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = normalizeError(error);

      // Check if error is retryable
      const category = categorizeError(lastError);
      const isRetryable = retryableErrors
        ? retryableErrors.some((ErrorClass) => lastError instanceof ErrorClass)
        : category.retryable;

      // Don't retry on last attempt or non-retryable errors
      if (attempt === maxAttempts || !isRetryable) {
        logError(lastError, {
          ...context,
          metadata: {
            ...context.metadata,
            attempt,
            maxAttempts,
            retriesExhausted: true,
          },
        });
        throw lastError;
      }

      // Log retry attempt
      logger.warn`Retry attempt ${attempt}/${maxAttempts} for ${context.operation}: ${lastError.message}`;

      if (onRetry) {
        onRetry(attempt, lastError, delayMs);
      }

      // Wait before retry
      await sleep(delayMs);

      // Increase delay for next attempt (exponential backoff)
      delayMs = Math.min(delayMs * backoffMultiplier, maxDelayMs);
    }
  }

  // Should never reach here, but TypeScript doesn't know that
  throw lastError ?? new Error('Retry failed unexpectedly');
}

/**
 * Execute multiple operations, collecting all errors
 *
 * @param operations - Array of async operations
 * @param context - Shared context for all operations
 * @returns Object with successful results and collected errors
 *
 * @example
 * ```ts
 * const { results, errors } = await collectErrors(
 *   [readFile(path1), readFile(path2), readFile(path3)],
 *   { operation: 'batchRead' }
 * );
 * ```
 */
export async function collectErrors<T>(
  operations: Array<Promise<T>>,
  context: ErrorContext,
): Promise<{ results: T[]; errors: Error[] }> {
  const results: T[] = [];
  const errors: Error[] = [];

  const settled = await Promise.allSettled(operations);

  for (const result of settled) {
    if (result.status === 'fulfilled') {
      results.push(result.value);
    } else {
      const error = normalizeError(result.reason);
      logError(error, context);
      errors.push(error);
    }
  }

  return { results, errors };
}

// ============================================
// ERROR WRAPPING UTILITIES
// ============================================

/**
 * Wrap a synchronous function to catch and normalize errors
 *
 * @param fn - Function to wrap
 * @param context - Error context
 * @returns Wrapped function
 */
export function wrapSync<Args extends unknown[], R>(
  fn: (...args: Args) => R,
  context: ErrorContext,
): (...args: Args) => R {
  return (...args: Args): R => {
    try {
      return fn(...args);
    } catch (error) {
      const normalizedError = normalizeError(error);
      logError(normalizedError, context);
      throw normalizedError;
    }
  };
}

/**
 * Wrap an async function to catch and normalize errors
 *
 * @param fn - Async function to wrap
 * @param context - Error context
 * @returns Wrapped async function
 */
export function wrapAsync<Args extends unknown[], R>(
  fn: (...args: Args) => Promise<R>,
  context: ErrorContext,
): (...args: Args) => Promise<R> {
  return async (...args: Args): Promise<R> => {
    try {
      return await fn(...args);
    } catch (error) {
      const normalizedError = normalizeError(error);
      logError(normalizedError, context);
      throw normalizedError;
    }
  };
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Sleep for specified duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Check if an error is of a specific type
 *
 * @param error - Error to check
 * @param ErrorClass - Error class to check against
 * @returns Type predicate
 */
export function isErrorOfType<T extends Error>(
  error: unknown,
  // biome-ignore lint/suspicious/noExplicitAny: Need to accept any constructor signature
  ErrorClass: abstract new (...args: any[]) => T,
): error is T {
  return error instanceof ErrorClass;
}

/**
 * Assert a condition, throwing if false
 *
 * @param condition - Condition to assert
 * @param message - Error message if assertion fails
 * @param ErrorClass - Error class to throw (default: SentinelError)
 * @throws If condition is false
 */
export function assert(
  condition: unknown,
  message: string,
  ErrorClass: new (message: string, code: string) => SentinelError = SentinelError,
): asserts condition {
  if (!condition) {
    throw new ErrorClass(message, 'ASSERTION_FAILED');
  }
}

/**
 * Create an error aggregator for collecting multiple errors
 *
 * @returns Error aggregator object
 *
 * @example
 * ```ts
 * const errors = createErrorAggregator();
 * errors.add(new ValidationError('field1 invalid'));
 * errors.add(new ValidationError('field2 invalid'));
 * if (errors.hasErrors()) {
 *   throw errors.toAggregateError('Multiple validation errors');
 * }
 * ```
 */
export function createErrorAggregator() {
  const collected: Error[] = [];

  return {
    add(error: Error): void {
      collected.push(error);
    },

    addMany(errors: Error[]): void {
      collected.push(...errors);
    },

    hasErrors(): boolean {
      return collected.length > 0;
    },

    count(): number {
      return collected.length;
    },

    getErrors(): Error[] {
      return [...collected];
    },

    clear(): void {
      collected.length = 0;
    },

    toAggregateError(message: string): AggregateError {
      return new AggregateError(collected, message);
    },

    throwIfErrors(message: string): void {
      if (collected.length > 0) {
        throw new AggregateError(collected, message);
      }
    },
  };
}
