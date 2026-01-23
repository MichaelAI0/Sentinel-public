/**
 * Rate Limiter Tests
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import {
  createRateLimitHeaders,
  createRateLimitResponse,
  RateLimiter,
} from '../utils/rate-limiter.js';

describe('RateLimiter', () => {
  let limiter: RateLimiter;

  afterEach(() => {
    limiter?.stop();
  });

  describe('Fixed Window', () => {
    beforeEach(() => {
      limiter = new RateLimiter({
        maxRequests: 5,
        windowMs: 1000,
        slidingWindow: false,
      });
    });

    test('allows requests within limit', () => {
      for (let i = 0; i < 5; i++) {
        const result = limiter.consume('client1');
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(4 - i);
      }
    });

    test('blocks requests over limit', () => {
      // Consume all allowed requests
      for (let i = 0; i < 5; i++) {
        limiter.consume('client1');
      }

      // Next request should be blocked
      const result = limiter.consume('client1');
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    test('tracks clients independently', () => {
      // Client 1 uses all requests
      for (let i = 0; i < 5; i++) {
        limiter.consume('client1');
      }

      // Client 2 should still be allowed
      const result = limiter.consume('client2');
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    test('check does not consume requests', () => {
      const check1 = limiter.check('client1');
      expect(check1.remaining).toBe(5);

      const check2 = limiter.check('client1');
      expect(check2.remaining).toBe(5);

      // Consume should decrement
      limiter.consume('client1');
      const check3 = limiter.check('client1');
      expect(check3.remaining).toBe(4);
    });

    test('resets after window expires', async () => {
      // Use all requests
      for (let i = 0; i < 5; i++) {
        limiter.consume('client1');
      }

      expect(limiter.consume('client1').allowed).toBe(false);

      // Wait for window to expire
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Should be allowed again
      const result = limiter.consume('client1');
      expect(result.allowed).toBe(true);
    });
  });

  describe('Sliding Window', () => {
    beforeEach(() => {
      limiter = new RateLimiter({
        maxRequests: 5,
        windowMs: 1000,
        slidingWindow: true,
      });
    });

    test('allows requests within limit', () => {
      for (let i = 0; i < 5; i++) {
        const result = limiter.consume('client1');
        expect(result.allowed).toBe(true);
      }
    });

    test('blocks requests over limit', () => {
      for (let i = 0; i < 5; i++) {
        limiter.consume('client1');
      }

      const result = limiter.consume('client1');
      expect(result.allowed).toBe(false);
    });
  });

  describe('Stats', () => {
    test('returns correct stats', () => {
      limiter = new RateLimiter({
        maxRequests: 10,
        windowMs: 60000,
      });

      limiter.consume('client1');
      limiter.consume('client1');
      limiter.consume('client2');

      const stats = limiter.getStats();
      expect(stats.activeClients).toBe(2);
      expect(stats.totalRequests).toBe(3);
    });
  });
});

describe('Rate Limit Response Helpers', () => {
  test('createRateLimitHeaders returns correct headers', () => {
    const result = {
      allowed: true,
      remaining: 5,
      resetIn: 30000,
      limit: 10,
    };

    const headers = createRateLimitHeaders(result);
    expect(headers['X-RateLimit-Limit']).toBe('10');
    expect(headers['X-RateLimit-Remaining']).toBe('5');
    expect(headers['X-RateLimit-Reset']).toBe('30');
  });

  test('createRateLimitResponse returns 429 response', async () => {
    const result = {
      allowed: false,
      remaining: 0,
      resetIn: 30000,
      limit: 10,
    };

    const response = createRateLimitResponse(result);
    expect(response.status).toBe(429);

    const body = (await response.json()) as { error: string; retryAfter: number };
    expect(body.error).toBe('Too many requests');
    expect(body.retryAfter).toBe(30);
  });
});
