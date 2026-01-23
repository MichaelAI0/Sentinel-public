/**
 * LLM Provider Retry Policy
 * Handles transient failures with exponential backoff
 */

import { logger } from '../utils/logger.js';

/** Retry configuration */
export type RetryConfig = {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Initial delay in ms before first retry */
  initialDelayMs: number;
  /** Maximum delay between retries in ms */
  maxDelayMs: number;
  /** Multiplier for exponential backoff */
  backoffMultiplier: number;
  /** Whether to add jitter to delays */
  jitter: boolean;
};

/** Default retry configuration */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  jitter: true,
} as const;

/** Errors that should trigger a retry */
const RETRYABLE_ERROR_PATTERNS = [
  /timeout/i,
  /ECONNRESET/i,
  /ECONNREFUSED/i,
  /ETIMEDOUT/i,
  /socket hang up/i,
  /network/i,
  /rate limit/i,
  /429/,
  /503/,
  /502/,
  /504/,
] as const;

/** Result of a retry operation */
export type RetryResult<T> =
  | { ok: true; value: T; attempts: number }
  | { ok: false; error: Error; attempts: number };

/**
 * Check if an error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;

  const message = error.message;
  return RETRYABLE_ERROR_PATTERNS.some((pattern) => pattern.test(message));
}

/**
 * Calculate delay for a retry attempt with optional jitter
 */
export function calculateDelay(attempt: number, config: RetryConfig): number {
  const exponentialDelay = config.initialDelayMs * config.backoffMultiplier ** attempt;
  const clampedDelay = Math.min(exponentialDelay, config.maxDelayMs);

  if (!config.jitter) return clampedDelay;

  // Add +/- 25% jitter
  const jitterRange = clampedDelay * 0.25;
  const jitter = Math.random() * jitterRange * 2 - jitterRange;
  return Math.max(0, clampedDelay + jitter);
}

/**
 * Sleep for a specified duration
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Execute a function with retry logic
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {},
): Promise<RetryResult<T>> {
  const fullConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
  let lastError: Error = new Error('No attempts made');
  let attempts = 0;

  for (let attempt = 0; attempt <= fullConfig.maxRetries; attempt++) {
    attempts = attempt + 1;

    try {
      const result = await fn();
      return { ok: true, value: result, attempts };
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Don't retry if this is the last attempt or error is not retryable
      if (attempt === fullConfig.maxRetries) {
        logger.warn`All ${attempts} attempts failed: ${lastError.message}`;
        break;
      }

      if (!isRetryableError(error)) {
        logger.debug`Non-retryable error: ${lastError.message}`;
        break;
      }

      const delay = calculateDelay(attempt, fullConfig);
      logger.debug`Retry attempt ${attempt + 1}/${fullConfig.maxRetries} after ${delay.toFixed(0)}ms: ${lastError.message}`;
      await sleep(delay);
    }
  }

  return { ok: false, error: lastError, attempts };
}

/**
 * Wrap a provider method with retry logic
 */
export function withRetryWrapper<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
  config: Partial<RetryConfig> = {},
): (...args: TArgs) => Promise<TResult> {
  return async (...args: TArgs): Promise<TResult> => {
    const result = await withRetry(() => fn(...args), config);

    if (result.ok) {
      return result.value;
    }

    throw result.error;
  };
}
