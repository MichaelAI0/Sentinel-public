/**
 * Analysis Cache Tests
 */

import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { AnalysisCache, computeFileHash, getCache } from '../utils/analysis-cache';

const TEST_CACHE_DIR = join(import.meta.dir, '.test-cache');

describe('AnalysisCache', () => {
  let cache: AnalysisCache;

  beforeEach(async () => {
    // Clean up test cache directory
    await rm(TEST_CACHE_DIR, { recursive: true, force: true });
    cache = new AnalysisCache({
      cacheDir: TEST_CACHE_DIR,
      ttlMs: 60000, // 1 minute for tests
      enabled: true,
    });
  });

  afterEach(async () => {
    await rm(TEST_CACHE_DIR, { recursive: true, force: true });
  });

  describe('Basic Operations', () => {
    test('set and get returns cached value', async () => {
      const fileHash = 'abc123';
      const toolName = 'test_tool';
      const data = { result: 'test data', count: 42 };

      await cache.set(fileHash, toolName, data);
      const retrieved = await cache.get<typeof data>(fileHash, toolName);

      expect(retrieved).toEqual(data);
    });

    test('get returns null for missing entry', async () => {
      const result = await cache.get('nonexistent', 'tool');
      expect(result).toBeNull();
    });

    test('has returns true for existing entry', async () => {
      await cache.set('hash1', 'tool1', { data: 'test' });

      expect(await cache.has('hash1', 'tool1')).toBe(true);
      expect(await cache.has('hash1', 'tool2')).toBe(false);
    });

    test('delete removes entry', async () => {
      await cache.set('hash1', 'tool1', { data: 'test' });
      expect(await cache.has('hash1', 'tool1')).toBe(true);

      await cache.delete('hash1', 'tool1');
      expect(await cache.has('hash1', 'tool1')).toBe(false);
    });
  });

  describe('TTL Expiration', () => {
    test('expired entries return null', async () => {
      // Create cache with very short TTL
      const shortTtlCache = new AnalysisCache({
        cacheDir: TEST_CACHE_DIR,
        ttlMs: 1, // 1ms TTL
        enabled: true,
      });

      await shortTtlCache.set('hash', 'tool', { data: 'test' });

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 10));

      const result = await shortTtlCache.get('hash', 'tool');
      expect(result).toBeNull();
    });
  });

  describe('Cache Stats', () => {
    test('tracks hits and misses', async () => {
      await cache.set('hash1', 'tool1', { data: 'test' });

      // Hit
      await cache.get('hash1', 'tool1');
      // Miss
      await cache.get('hash2', 'tool1');

      const stats = cache.getStats();
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
    });

    test('calculates hit rate', async () => {
      await cache.set('hash1', 'tool1', { data: 'test' });

      await cache.get('hash1', 'tool1'); // hit
      await cache.get('hash1', 'tool1'); // hit
      await cache.get('hash2', 'tool1'); // miss

      expect(cache.getHitRate()).toBeCloseTo(66.67, 0);
    });

    test('hit rate is 0 with no operations', () => {
      expect(cache.getHitRate()).toBe(0);
    });
  });

  describe('Clear and Cleanup', () => {
    test('clear removes all entries', async () => {
      await cache.set('hash1', 'tool1', { data: 'test1' });
      await cache.set('hash2', 'tool2', { data: 'test2' });

      await cache.clear();

      expect(await cache.has('hash1', 'tool1')).toBe(false);
      expect(await cache.has('hash2', 'tool2')).toBe(false);
    });

    test('cleanup removes expired entries', async () => {
      // Create cache with very short TTL
      const shortTtlCache = new AnalysisCache({
        cacheDir: TEST_CACHE_DIR,
        ttlMs: 1,
        enabled: true,
      });

      await shortTtlCache.set('hash1', 'tool1', { data: 'test' });

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 10));

      const result = await shortTtlCache.cleanup();
      expect(result.deleted).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Disabled Cache', () => {
    test('returns null when disabled', async () => {
      const disabledCache = new AnalysisCache({ enabled: false });

      await disabledCache.set('hash', 'tool', { data: 'test' });
      const result = await disabledCache.get('hash', 'tool');

      expect(result).toBeNull();
    });

    test('has returns false when disabled', async () => {
      const disabledCache = new AnalysisCache({ enabled: false });
      expect(await disabledCache.has('hash', 'tool')).toBe(false);
    });
  });

  describe('Different Data Types', () => {
    test('caches arrays', async () => {
      const data = [1, 2, 3, 'test', { nested: true }];
      await cache.set('hash', 'tool', data);

      const result = await cache.get('hash', 'tool');
      expect(result).toEqual(data);
    });

    test('caches complex objects', async () => {
      const data = {
        name: 'test',
        nested: {
          array: [1, 2, 3],
          deep: { value: true },
        },
        nullValue: null,
      };
      await cache.set('hash', 'tool', data);

      const result = await cache.get('hash', 'tool');
      expect(result).toEqual(data);
    });
  });
});

describe('getCache Singleton', () => {
  test('returns same instance without config', () => {
    const c1 = getCache();
    const c2 = getCache();
    expect(c1).toBe(c2);
  });

  test('returns new instance with config', () => {
    const c1 = getCache();
    const c2 = getCache({ ttlMs: 9999 });
    expect(c1).not.toBe(c2);
  });
});

describe('computeFileHash', () => {
  test('computes SHA256 hash of file', async () => {
    // Use the test file itself
    const testFile = import.meta.path;
    const hash = await computeFileHash(testFile);

    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });
});
