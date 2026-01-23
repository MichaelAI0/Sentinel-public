/**
 * Rate Limiter
 * Token bucket rate limiting for API endpoints
 *
 * @module utils/rate-limiter
 */

import { logger } from './logger.js';

/**
 * Rate limiter configuration
 */
export type RateLimiterConfig = {
  /** Maximum requests per window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
  /** Enable sliding window (more accurate but uses more memory) */
  slidingWindow?: boolean;
};

/**
 * Rate limit result
 */
export type RateLimitResult = {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Remaining requests in current window */
  remaining: number;
  /** Time until limit resets (ms) */
  resetIn: number;
  /** Total limit */
  limit: number;
};

type ClientEntry = {
  count: number;
  windowStart: number;
  requests: number[]; // Timestamps for sliding window
};

/**
 * In-memory rate limiter using token bucket algorithm
 */
export class RateLimiter {
  private clients: Map<string, ClientEntry> = new Map();
  private config: Required<RateLimiterConfig>;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: RateLimiterConfig) {
    this.config = {
      maxRequests: config.maxRequests,
      windowMs: config.windowMs,
      slidingWindow: config.slidingWindow ?? false,
    };

    // Cleanup old entries periodically
    this.cleanupInterval = setInterval(() => this.cleanup(), this.config.windowMs * 2);
  }

  /**
   * Check if a request is allowed for a given client
   */
  check(clientId: string): RateLimitResult {
    const now = Date.now();
    let entry = this.clients.get(clientId);

    if (!entry) {
      entry = { count: 0, windowStart: now, requests: [] };
      this.clients.set(clientId, entry);
    }

    if (this.config.slidingWindow) {
      return this.checkSlidingWindow(entry, now);
    }

    return this.checkFixedWindow(entry, now);
  }

  /**
   * Consume a request from the rate limit
   */
  consume(clientId: string): RateLimitResult {
    const result = this.check(clientId);

    if (result.allowed) {
      const entry = this.clients.get(clientId);
      if (entry) {
        entry.count++;
        if (this.config.slidingWindow) {
          entry.requests.push(Date.now());
        }
        // Return updated remaining count after consumption
        return {
          ...result,
          remaining: Math.max(0, result.remaining - 1),
        };
      }
    }

    return result;
  }

  /**
   * Fixed window rate limiting
   */
  private checkFixedWindow(entry: ClientEntry, now: number): RateLimitResult {
    const windowEnd = entry.windowStart + this.config.windowMs;

    // Reset window if expired
    if (now >= windowEnd) {
      entry.count = 0;
      entry.windowStart = now;
    }

    const remaining = Math.max(0, this.config.maxRequests - entry.count);
    const resetIn = Math.max(0, windowEnd - now);

    return {
      allowed: entry.count < this.config.maxRequests,
      remaining,
      resetIn,
      limit: this.config.maxRequests,
    };
  }

  /**
   * Sliding window rate limiting
   */
  private checkSlidingWindow(entry: ClientEntry, now: number): RateLimitResult {
    const windowStart = now - this.config.windowMs;

    // Remove old requests outside the window
    entry.requests = entry.requests.filter((t) => t > windowStart);

    const remaining = Math.max(0, this.config.maxRequests - entry.requests.length);
    const oldestRequest = entry.requests[0] ?? now;
    const resetIn = Math.max(0, oldestRequest + this.config.windowMs - now);

    return {
      allowed: entry.requests.length < this.config.maxRequests,
      remaining,
      resetIn,
      limit: this.config.maxRequests,
    };
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    const expiredBefore = now - this.config.windowMs * 2;

    let cleaned = 0;
    for (const [clientId, entry] of this.clients) {
      if (entry.windowStart < expiredBefore) {
        this.clients.delete(clientId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug`Rate limiter cleanup: removed ${cleaned} expired entries`;
    }
  }

  /**
   * Get current stats
   */
  getStats(): { activeClients: number; totalRequests: number } {
    let totalRequests = 0;
    for (const entry of this.clients.values()) {
      totalRequests += this.config.slidingWindow ? entry.requests.length : entry.count;
    }
    return {
      activeClients: this.clients.size,
      totalRequests,
    };
  }

  /**
   * Stop the cleanup interval
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

/**
 * Default rate limiter instances
 */
const rateLimiters: Map<string, RateLimiter> = new Map();

/**
 * Get or create a rate limiter for an endpoint
 */
export function getRateLimiter(
  name: string,
  config: RateLimiterConfig = { maxRequests: 60, windowMs: 60_000 },
): RateLimiter {
  let limiter = rateLimiters.get(name);
  if (!limiter) {
    limiter = new RateLimiter(config);
    rateLimiters.set(name, limiter);
  }
  return limiter;
}

/**
 * Create rate limit headers for HTTP response
 */
export function createRateLimitHeaders(result: RateLimitResult): Record<string, string> {
  return {
    'X-RateLimit-Limit': String(result.limit),
    'X-RateLimit-Remaining': String(result.remaining),
    'X-RateLimit-Reset': String(Math.ceil(result.resetIn / 1000)),
  };
}

/**
 * Create a 429 Too Many Requests response
 */
export function createRateLimitResponse(result: RateLimitResult): Response {
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      retryAfter: Math.ceil(result.resetIn / 1000),
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(Math.ceil(result.resetIn / 1000)),
        ...createRateLimitHeaders(result),
      },
    },
  );
}
