/**
 * Analysis Cache
 *
 * Caches analysis results by file hash to avoid redundant re-analysis.
 * Supports configurable TTL and automatic cleanup of expired entries.
 */

import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { logger } from './logger.js';

// ============================================================================
// Types
// ============================================================================

export type CacheConfig = {
  /** Directory to store cache files */
  cacheDir: string;
  /** Time-to-live in milliseconds (default: 24 hours) */
  ttlMs: number;
  /** Maximum cache size in bytes (default: 100MB) */
  maxSizeBytes: number;
  /** Whether caching is enabled (default: true) */
  enabled: boolean;
};

type CacheEntry<T> = {
  /** The cached data */
  data: T;
  /** Timestamp when the entry was created */
  createdAt: number;
  /** The tool/operation that produced this result */
  toolName: string;
  /** File hash this result is for */
  fileHash: string;
};

type CacheStats = {
  hits: number;
  misses: number;
  size: number;
  entries: number;
};

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_CONFIG: CacheConfig = {
  cacheDir: join(process.cwd(), '.cache', 'sentinel'),
  ttlMs: 24 * 60 * 60 * 1000, // 24 hours
  maxSizeBytes: 100 * 1024 * 1024, // 100MB
  enabled: true,
};

// ============================================================================
// Analysis Cache Class
// ============================================================================

export class AnalysisCache {
  private readonly config: CacheConfig;
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    size: 0,
    entries: 0,
  };
  private initialized = false;

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Initialize the cache directory
   */
  async init(): Promise<void> {
    if (this.initialized || !this.config.enabled) {
      return;
    }

    try {
      await mkdir(this.config.cacheDir, { recursive: true });
      this.initialized = true;
      logger.debug('Cache initialized', { cacheDir: this.config.cacheDir });
    } catch (error) {
      logger.warn('Failed to initialize cache directory', { error });
      // Continue without caching
    }
  }

  /**
   * Generate a cache key from file hash and tool name
   */
  private getCacheKey(fileHash: string, toolName: string): string {
    const combined = `${fileHash}:${toolName}`;
    return createHash('sha256').update(combined).digest('hex').slice(0, 32);
  }

  /**
   * Get the file path for a cache entry
   */
  private getCachePath(cacheKey: string): string {
    // Use first 2 chars as subdirectory for better file distribution
    const subDir = cacheKey.slice(0, 2);
    return join(this.config.cacheDir, subDir, `${cacheKey}.json`);
  }

  /**
   * Get a cached result if it exists and is not expired
   */
  async get<T>(fileHash: string, toolName: string): Promise<T | null> {
    if (!this.config.enabled) {
      return null;
    }

    await this.init();

    const cacheKey = this.getCacheKey(fileHash, toolName);
    const cachePath = this.getCachePath(cacheKey);

    try {
      const content = await readFile(cachePath, 'utf-8');
      const entry = JSON.parse(content) as CacheEntry<T>;

      // Check if expired
      const age = Date.now() - entry.createdAt;
      if (age > this.config.ttlMs) {
        logger.debug('Cache entry expired', { fileHash, toolName, ageMs: age });
        await this.delete(fileHash, toolName);
        this.stats.misses += 1;
        return null;
      }

      this.stats.hits += 1;
      logger.debug('Cache hit', { fileHash, toolName });
      return entry.data;
    } catch {
      this.stats.misses += 1;
      return null;
    }
  }

  /**
   * Store a result in the cache
   */
  async set<T>(fileHash: string, toolName: string, data: T): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    await this.init();

    const cacheKey = this.getCacheKey(fileHash, toolName);
    const cachePath = this.getCachePath(cacheKey);
    const cacheDir = cachePath.replace(/\/[^/]+$/, '');

    const entry: CacheEntry<T> = {
      data,
      createdAt: Date.now(),
      toolName,
      fileHash,
    };

    try {
      await mkdir(cacheDir, { recursive: true });
      const content = JSON.stringify(entry, null, 2);
      await writeFile(cachePath, content, 'utf-8');
      this.stats.entries += 1;
      logger.debug('Cached result', { fileHash, toolName, size: content.length });
    } catch (error) {
      logger.warn('Failed to cache result', { error, fileHash, toolName });
    }
  }

  /**
   * Delete a specific cache entry
   */
  async delete(fileHash: string, toolName: string): Promise<boolean> {
    const cacheKey = this.getCacheKey(fileHash, toolName);
    const cachePath = this.getCachePath(cacheKey);

    try {
      await rm(cachePath);
      this.stats.entries = Math.max(0, this.stats.entries - 1);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if a cache entry exists (without loading it)
   */
  async has(fileHash: string, toolName: string): Promise<boolean> {
    if (!this.config.enabled) {
      return false;
    }

    const cacheKey = this.getCacheKey(fileHash, toolName);
    const cachePath = this.getCachePath(cacheKey);

    try {
      await stat(cachePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Clean up expired cache entries
   */
  async cleanup(): Promise<{ deleted: number; freedBytes: number }> {
    if (!this.config.enabled) {
      return { deleted: 0, freedBytes: 0 };
    }

    await this.init();

    let deleted = 0;
    let freedBytes = 0;
    const now = Date.now();

    try {
      const subDirs = await readdir(this.config.cacheDir);

      for (const subDir of subDirs) {
        const subDirPath = join(this.config.cacheDir, subDir);
        const subDirStat = await stat(subDirPath);

        if (!subDirStat.isDirectory()) {
          continue;
        }

        const files = await readdir(subDirPath);

        for (const file of files) {
          if (!file.endsWith('.json')) {
            continue;
          }

          const filePath = join(subDirPath, file);

          try {
            const content = await readFile(filePath, 'utf-8');
            const entry = JSON.parse(content) as CacheEntry<unknown>;
            const age = now - entry.createdAt;

            if (age > this.config.ttlMs) {
              const fileStat = await stat(filePath);
              freedBytes += fileStat.size;
              await rm(filePath);
              deleted += 1;
            }
          } catch {
            // Skip invalid entries
          }
        }
      }

      logger.info('Cache cleanup complete', { deleted, freedBytes });
    } catch (error) {
      logger.warn('Cache cleanup failed', { error });
    }

    return { deleted, freedBytes };
  }

  /**
   * Clear all cache entries
   */
  async clear(): Promise<void> {
    try {
      await rm(this.config.cacheDir, { recursive: true, force: true });
      this.stats = { hits: 0, misses: 0, size: 0, entries: 0 };
      this.initialized = false;
      logger.info('Cache cleared');
    } catch (error) {
      logger.warn('Failed to clear cache', { error });
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    return { ...this.stats };
  }

  /**
   * Get hit rate as a percentage
   */
  getHitRate(): number {
    const total = this.stats.hits + this.stats.misses;
    if (total === 0) {
      return 0;
    }
    return (this.stats.hits / total) * 100;
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let cacheInstance: AnalysisCache | null = null;

/**
 * Get the global cache instance
 */
export function getCache(config?: Partial<CacheConfig>): AnalysisCache {
  if (!cacheInstance || config) {
    cacheInstance = new AnalysisCache(config);
  }
  return cacheInstance;
}

/**
 * Helper to compute file hash for cache lookups
 */
export async function computeFileHash(filePath: string): Promise<string> {
  const content = await readFile(filePath);
  return createHash('sha256').update(content).digest('hex');
}
