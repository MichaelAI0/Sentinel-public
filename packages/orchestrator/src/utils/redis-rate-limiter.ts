/**
 * Redis-backed Rate Limiter
 * Distributed rate limiting for multi-instance deployments
 * Falls back to in-memory rate limiting when Redis is unavailable
 *
 * @module utils/redis-rate-limiter
 */

import { logger } from './logger.js';
import {
  createRateLimitHeaders,
  createRateLimitResponse,
  RateLimiter,
  type RateLimiterConfig,
  type RateLimitResult,
} from './rate-limiter.js';

/**
 * Redis client interface (compatible with ioredis and node-redis)
 * Using `type` per style guide
 */
export type RedisClient = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number): Promise<unknown>;
  setex(key: string, seconds: number, value: string): Promise<unknown>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  ttl(key: string): Promise<number>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  ping(): Promise<string>;
  quit(): Promise<unknown>;
};

/**
 * Redis rate limiter configuration
 */
export type RedisRateLimiterConfig = RateLimiterConfig & {
  /** Redis key prefix */
  keyPrefix?: string;
  /** Fallback to in-memory if Redis fails */
  fallbackToMemory?: boolean;
};

/**
 * Lua script for atomic rate limit check and increment
 * Returns: [allowed (0/1), remaining, resetIn (ms)]
 */
const RATE_LIMIT_SCRIPT = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local current = redis.call('GET', key)
local count = 0

if current then
  count = tonumber(current)
end

local remaining = limit - count
local allowed = 0

if count < limit then
  redis.call('INCR', key)
  if count == 0 then
    redis.call('PEXPIRE', key, window)
  end
  allowed = 1
  remaining = remaining - 1
end

local ttl = redis.call('PTTL', key)
if ttl < 0 then
  ttl = window
end

return {allowed, math.max(0, remaining), ttl}
`;

/**
 * Sliding window Lua script for more accurate rate limiting
 * Uses a sorted set to track request timestamps
 */
const SLIDING_WINDOW_SCRIPT = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local window_start = now - window

-- Remove old entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current entries
local count = redis.call('ZCARD', key)
local remaining = limit - count
local allowed = 0

if count < limit then
  -- Add new entry with current timestamp as score
  redis.call('ZADD', key, now, now .. '-' .. math.random(1000000))
  redis.call('PEXPIRE', key, window)
  allowed = 1
  remaining = remaining - 1
end

-- Get oldest entry for reset time
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset_in = window

if oldest and #oldest > 0 then
  reset_in = math.max(0, (tonumber(oldest[2]) + window) - now)
end

return {allowed, math.max(0, remaining), reset_in}
`;

/**
 * Redis-backed rate limiter with in-memory fallback
 */
export class RedisRateLimiter {
  private redis: RedisClient | null = null;
  private fallback: RateLimiter;
  private config: Required<RedisRateLimiterConfig>;
  private connected = false;
  private useMemory = false;

  constructor(redis: RedisClient | null, config: RedisRateLimiterConfig) {
    this.redis = redis;
    this.config = {
      maxRequests: config.maxRequests,
      windowMs: config.windowMs,
      slidingWindow: config.slidingWindow ?? false,
      keyPrefix: config.keyPrefix ?? 'sentinel:ratelimit:',
      fallbackToMemory: config.fallbackToMemory ?? true,
    };

    // Create fallback in-memory limiter
    this.fallback = new RateLimiter({
      maxRequests: config.maxRequests,
      windowMs: config.windowMs,
      slidingWindow: config.slidingWindow,
    });

    // Check Redis connection
    this.checkConnection();
  }

  /**
   * Check if Redis is available
   */
  private async checkConnection(): Promise<void> {
    if (!this.redis) {
      this.useMemory = true;
      logger.info`Redis rate limiter: no client provided, using in-memory fallback`;
      return;
    }

    try {
      await this.redis.ping();
      this.connected = true;
      this.useMemory = false;
      logger.info`Redis rate limiter: connected successfully`;
    } catch {
      this.connected = false;
      this.useMemory = this.config.fallbackToMemory;
      logger.warn`Redis rate limiter: connection failed, ${this.useMemory ? 'using in-memory fallback' : 'rate limiting disabled'}`;
    }
  }

  /**
   * Get Redis key for a client
   */
  private getKey(clientId: string): string {
    return `${this.config.keyPrefix}${clientId}`;
  }

  /**
   * Check if a request is allowed
   */
  async check(clientId: string): Promise<RateLimitResult> {
    if (this.useMemory || !this.redis) {
      return this.fallback.check(clientId);
    }

    try {
      const key = this.getKey(clientId);
      const now = Date.now();
      const script = this.config.slidingWindow ? SLIDING_WINDOW_SCRIPT : RATE_LIMIT_SCRIPT;

      const result = (await this.redis.eval(
        script,
        1,
        key,
        this.config.maxRequests,
        this.config.windowMs,
        now,
      )) as [number, number, number];

      return {
        allowed: result[0] === 1,
        remaining: result[1],
        resetIn: result[2],
        limit: this.config.maxRequests,
      };
    } catch (error) {
      logger.warn`Redis rate limit check failed: ${error}`;

      if (this.config.fallbackToMemory) {
        this.useMemory = true;
        return this.fallback.check(clientId);
      }

      // If fallback disabled, allow the request
      return {
        allowed: true,
        remaining: this.config.maxRequests,
        resetIn: this.config.windowMs,
        limit: this.config.maxRequests,
      };
    }
  }

  /**
   * Consume a request (alias for check in Redis implementation)
   * Redis script atomically checks and increments
   */
  async consume(clientId: string): Promise<RateLimitResult> {
    if (this.useMemory || !this.redis) {
      return this.fallback.consume(clientId);
    }
    return this.check(clientId);
  }

  /**
   * Get stats about rate limiting
   */
  getStats(): {
    connected: boolean;
    usingMemory: boolean;
    fallbackStats: ReturnType<RateLimiter['getStats']>;
  } {
    return {
      connected: this.connected,
      usingMemory: this.useMemory,
      fallbackStats: this.fallback.getStats(),
    };
  }

  /**
   * Stop the rate limiter
   */
  stop(): void {
    this.fallback.stop();
  }

  /**
   * Reconnect to Redis
   */
  async reconnect(): Promise<boolean> {
    await this.checkConnection();
    return this.connected;
  }
}

/**
 * Redis rate limiter instances
 */
const redisRateLimiters: Map<string, RedisRateLimiter> = new Map();
let globalRedisClient: RedisClient | null = null;

/**
 * Set global Redis client for rate limiting
 */
export function setRedisClient(client: RedisClient | null): void {
  globalRedisClient = client;
  // Reconnect existing limiters
  for (const limiter of redisRateLimiters.values()) {
    limiter.reconnect();
  }
}

/**
 * Get or create a Redis-backed rate limiter
 */
export function getRedisRateLimiter(
  name: string,
  config: RedisRateLimiterConfig = { maxRequests: 60, windowMs: 60_000 },
): RedisRateLimiter {
  let limiter = redisRateLimiters.get(name);
  if (!limiter) {
    limiter = new RedisRateLimiter(globalRedisClient, {
      ...config,
      keyPrefix: `sentinel:ratelimit:${name}:`,
    });
    redisRateLimiters.set(name, limiter);
  }
  return limiter;
}

// Re-export helper functions
export { createRateLimitHeaders, createRateLimitResponse };
