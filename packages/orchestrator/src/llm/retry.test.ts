/**
 * Retry Logic Tests
 */

import { describe, expect, test } from 'bun:test';
import {
  calculateDelay,
  DEFAULT_RETRY_CONFIG,
  isRetryableError,
  type RetryConfig,
  withRetry,
} from './retry.js';

describe('retry', () => {
  describe('isRetryableError', () => {
    test('returns true for timeout errors', () => {
      expect(isRetryableError(new Error('Request timeout'))).toBe(true);
      expect(isRetryableError(new Error('ETIMEDOUT'))).toBe(true);
    });

    test('returns true for connection errors', () => {
      expect(isRetryableError(new Error('ECONNRESET'))).toBe(true);
      expect(isRetryableError(new Error('ECONNREFUSED'))).toBe(true);
      expect(isRetryableError(new Error('socket hang up'))).toBe(true);
    });

    test('returns true for rate limit errors', () => {
      expect(isRetryableError(new Error('rate limit exceeded'))).toBe(true);
      expect(isRetryableError(new Error('HTTP 429'))).toBe(true);
    });

    test('returns true for server errors', () => {
      expect(isRetryableError(new Error('HTTP 502'))).toBe(true);
      expect(isRetryableError(new Error('HTTP 503'))).toBe(true);
      expect(isRetryableError(new Error('HTTP 504'))).toBe(true);
    });

    test('returns false for non-retryable errors', () => {
      expect(isRetryableError(new Error('Invalid API key'))).toBe(false);
      expect(isRetryableError(new Error('Bad request'))).toBe(false);
      expect(isRetryableError(new Error('HTTP 400'))).toBe(false);
      expect(isRetryableError(new Error('HTTP 401'))).toBe(false);
    });

    test('returns false for non-Error values', () => {
      expect(isRetryableError('timeout')).toBe(false);
      expect(isRetryableError(null)).toBe(false);
      expect(isRetryableError(undefined)).toBe(false);
    });
  });

  describe('calculateDelay', () => {
    const config: RetryConfig = {
      maxRetries: 3,
      initialDelayMs: 1000,
      maxDelayMs: 10000,
      backoffMultiplier: 2,
      jitter: false,
    };

    test('calculates exponential delay without jitter', () => {
      expect(calculateDelay(0, config)).toBe(1000);
      expect(calculateDelay(1, config)).toBe(2000);
      expect(calculateDelay(2, config)).toBe(4000);
      expect(calculateDelay(3, config)).toBe(8000);
    });

    test('caps delay at maxDelayMs', () => {
      expect(calculateDelay(4, config)).toBe(10000); // Would be 16000
      expect(calculateDelay(5, config)).toBe(10000); // Would be 32000
    });

    test('adds jitter when enabled', () => {
      const jitterConfig = { ...config, jitter: true };
      const delays = new Set<number>();

      // Run multiple times to verify jitter varies
      for (let i = 0; i < 10; i++) {
        delays.add(calculateDelay(1, jitterConfig));
      }

      // With jitter, we should get different values
      // Base delay is 2000, jitter adds +/- 25% (500)
      // So range is 1500-2500
      expect(delays.size).toBeGreaterThan(1);

      for (const delay of delays) {
        expect(delay).toBeGreaterThanOrEqual(1500);
        expect(delay).toBeLessThanOrEqual(2500);
      }
    });
  });

  describe('withRetry', () => {
    test('returns success on first attempt', async () => {
      const fn = async () => 'success';
      const result = await withRetry(fn);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toBe('success');
        expect(result.attempts).toBe(1);
      }
    });

    test('retries on retryable errors', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error('ECONNRESET');
        }
        return 'success';
      };

      const result = await withRetry(fn, { initialDelayMs: 10 });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value).toBe('success');
        expect(result.attempts).toBe(3);
      }
    });

    test('does not retry on non-retryable errors', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        throw new Error('Invalid API key');
      };

      const result = await withRetry(fn);

      expect(result.ok).toBe(false);
      expect(attempts).toBe(1);
      if (!result.ok) {
        expect(result.error.message).toBe('Invalid API key');
      }
    });

    test('returns error after max retries', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        throw new Error('ECONNREFUSED');
      };

      const result = await withRetry(fn, { maxRetries: 2, initialDelayMs: 10 });

      expect(result.ok).toBe(false);
      expect(attempts).toBe(3); // Initial + 2 retries
      if (!result.ok) {
        expect(result.error.message).toBe('ECONNREFUSED');
        expect(result.attempts).toBe(3);
      }
    });

    test('uses custom retry config', async () => {
      let attempts = 0;
      const fn = async () => {
        attempts++;
        if (attempts < 5) {
          throw new Error('timeout');
        }
        return 'success';
      };

      const result = await withRetry(fn, { maxRetries: 5, initialDelayMs: 5 });

      expect(result.ok).toBe(true);
      expect(attempts).toBe(5);
    });
  });

  describe('DEFAULT_RETRY_CONFIG', () => {
    test('has sensible defaults', () => {
      expect(DEFAULT_RETRY_CONFIG.maxRetries).toBe(3);
      expect(DEFAULT_RETRY_CONFIG.initialDelayMs).toBe(1000);
      expect(DEFAULT_RETRY_CONFIG.maxDelayMs).toBe(30000);
      expect(DEFAULT_RETRY_CONFIG.backoffMultiplier).toBe(2);
      expect(DEFAULT_RETRY_CONFIG.jitter).toBe(true);
    });
  });
});
