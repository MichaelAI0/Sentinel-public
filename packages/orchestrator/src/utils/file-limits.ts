/**
 * File Size Limits and Streaming Utilities
 *
 * Handles large files safely with streaming, chunking, and
 * memory-aware processing to prevent OOM conditions.
 *
 * @module utils/file-limits
 */

import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { Transform, type TransformCallback } from 'node:stream';
import {
  err,
  FileAccessError,
  FileSizeError,
  fromPromise,
  ok,
  type Result,
  TimeoutError,
} from '@sentinel/shared';

// ============================================
// CONSTANTS
// ============================================

/** Default maximum file size: 100MB */
export const DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024;

/** Default chunk size for streaming: 64KB */
export const DEFAULT_CHUNK_SIZE = 64 * 1024;

/** Memory threshold percentage to trigger cleanup */
export const MEMORY_THRESHOLD_PERCENT = 0.8;

/** Size thresholds for different processing strategies */
export const SIZE_THRESHOLDS = {
  /** Files small enough to load entirely in memory */
  SMALL: 1 * 1024 * 1024, // 1MB
  /** Files that should use chunked processing */
  MEDIUM: 10 * 1024 * 1024, // 10MB
  /** Files that require streaming */
  LARGE: 50 * 1024 * 1024, // 50MB
  /** Maximum supported size */
  MAX: 100 * 1024 * 1024, // 100MB
} as const;

// ============================================
// TYPES & INTERFACES
// ============================================

/**
 * Processing strategy based on file size
 */
export type ProcessingStrategy = 'memory' | 'chunked' | 'streaming';

/**
 * File size analysis result
 */
export type FileSizeAnalysis = {
  size: number;
  sizeFormatted: string;
  strategy: ProcessingStrategy;
  estimatedChunks: number;
  estimatedMemoryMb: number;
  withinLimits: boolean;
};

/**
 * Chunk processing callback
 */
export type ChunkProcessor<T> = (chunk: Buffer, index: number, totalChunks: number) => Promise<T>;

/**
 * Stream processing options
 */
export type StreamOptions = {
  chunkSize: number;
  highWaterMark: number;
  timeout: number;
  onProgress?: (bytesRead: number, totalBytes: number) => void;
};

/**
 * Accumulated results from chunk processing
 */
export type ChunkResults<T> = {
  results: T[];
  chunksProcessed: number;
  bytesProcessed: number;
  errors: Error[];
};

// ============================================
// FILE SIZE UTILITIES
// ============================================

/**
 * Format bytes into human-readable string
 */
export function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }

  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

/**
 * Analyze file size and recommend processing strategy
 */
export async function analyzeFileSize(
  filePath: string,
  maxSize: number = DEFAULT_MAX_FILE_SIZE,
): Promise<Result<FileSizeAnalysis, FileAccessError | FileSizeError>> {
  const statResult = await fromPromise(stat(filePath));

  if (!statResult.ok) {
    return err(new FileAccessError(filePath, 'stat'));
  }

  const { size } = statResult.value;

  if (size > maxSize) {
    return err(new FileSizeError(size, maxSize, { filePath }));
  }

  let strategy: ProcessingStrategy;
  if (size <= SIZE_THRESHOLDS.SMALL) {
    strategy = 'memory';
  } else if (size <= SIZE_THRESHOLDS.MEDIUM) {
    strategy = 'chunked';
  } else {
    strategy = 'streaming';
  }

  return ok({
    size,
    sizeFormatted: formatBytes(size),
    strategy,
    estimatedChunks: Math.ceil(size / DEFAULT_CHUNK_SIZE),
    estimatedMemoryMb: Math.ceil(size / (1024 * 1024)),
    withinLimits: true,
  });
}

/**
 * Get current memory usage
 */
export function getMemoryUsage(): {
  heapUsed: number;
  heapTotal: number;
  rss: number;
  percentUsed: number;
} {
  const usage = process.memoryUsage();
  return {
    heapUsed: usage.heapUsed,
    heapTotal: usage.heapTotal,
    rss: usage.rss,
    percentUsed: usage.heapUsed / usage.heapTotal,
  };
}

/**
 * Check if memory is available for an operation
 */
export function checkMemoryAvailable(requiredBytes: number): boolean {
  const usage = getMemoryUsage();
  const available = usage.heapTotal - usage.heapUsed;
  return available > requiredBytes * 1.5; // 50% buffer
}

// ============================================
// STREAMING FILE READER
// ============================================

/**
 * Read a file in chunks with progress tracking
 *
 * @example
 * ```typescript
 * const reader = new ChunkedFileReader(filePath, {
 *   chunkSize: 128 * 1024,
 *   onProgress: (read, total) => console.log(`${read}/${total}`)
 * });
 *
 * for await (const chunk of reader) {
 *   processChunk(chunk);
 * }
 * ```
 */
export class ChunkedFileReader implements AsyncIterable<Buffer> {
  private readonly filePath: string;
  private readonly options: StreamOptions;
  private bytesRead = 0;
  private totalBytes = 0;

  constructor(filePath: string, options: Partial<StreamOptions> = {}) {
    this.filePath = filePath;
    this.options = {
      chunkSize: options.chunkSize ?? DEFAULT_CHUNK_SIZE,
      highWaterMark: options.highWaterMark ?? DEFAULT_CHUNK_SIZE,
      timeout: options.timeout ?? 60000,
      onProgress: options.onProgress,
    };
  }

  async *[Symbol.asyncIterator](): AsyncIterator<Buffer> {
    // Get file size first
    const stats = await stat(this.filePath);
    this.totalBytes = stats.size;
    this.bytesRead = 0;

    const stream = createReadStream(this.filePath, {
      highWaterMark: this.options.highWaterMark,
    });

    const timeout = this.options.timeout;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

    // Promise used to setup timeout that will destroy stream if exceeded
    const _timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => {
        stream.destroy();
        reject(new TimeoutError('file_read', timeout));
      }, timeout);
    });

    try {
      for await (const chunk of stream) {
        const buffer = chunk as Buffer;
        this.bytesRead += buffer.length;

        if (this.options.onProgress) {
          this.options.onProgress(this.bytesRead, this.totalBytes);
        }

        // Reset timeout on each chunk
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
          timeoutHandle = setTimeout(() => {
            stream.destroy();
          }, timeout);
        }

        yield buffer;
      }
    } finally {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
    }
  }

  /**
   * Get bytes read so far
   */
  getBytesRead(): number {
    return this.bytesRead;
  }

  /**
   * Get total bytes to read
   */
  getTotalBytes(): number {
    return this.totalBytes;
  }

  /**
   * Get progress percentage
   */
  getProgress(): number {
    if (this.totalBytes === 0) return 0;
    return (this.bytesRead / this.totalBytes) * 100;
  }
}

// ============================================
// CHUNK PROCESSING
// ============================================

/**
 * Process a file in chunks with a custom processor
 */
export async function processFileChunks<T>(
  filePath: string,
  processor: ChunkProcessor<T>,
  options: Partial<StreamOptions> = {},
): Promise<Result<ChunkResults<T>, FileAccessError | TimeoutError>> {
  const analysis = await analyzeFileSize(filePath);
  if (!analysis.ok) {
    return err(new FileAccessError(filePath, 'read'));
  }

  const reader = new ChunkedFileReader(filePath, options);
  const results: T[] = [];
  const errors: Error[] = [];
  let chunksProcessed = 0;
  let bytesProcessed = 0;

  try {
    const totalChunks = analysis.value.estimatedChunks;

    for await (const chunk of reader) {
      try {
        const result = await processor(chunk, chunksProcessed, totalChunks);
        results.push(result);
      } catch (e) {
        errors.push(e instanceof Error ? e : new Error(String(e)));
      }

      chunksProcessed++;
      bytesProcessed += chunk.length;
    }

    return ok({
      results,
      chunksProcessed,
      bytesProcessed,
      errors,
    });
  } catch (e) {
    if (e instanceof TimeoutError) {
      return err(e);
    }
    return err(
      new FileAccessError(filePath, 'read', { cause: e instanceof Error ? e : undefined }),
    );
  }
}

/**
 * Read entire file safely with size limits
 */
export async function safeReadFile(
  filePath: string,
  maxSize: number = SIZE_THRESHOLDS.SMALL,
): Promise<Result<Buffer, FileAccessError | FileSizeError>> {
  // Check size first
  const analysis = await analyzeFileSize(filePath, maxSize);
  if (!analysis.ok) {
    return analysis;
  }

  // Check memory
  if (!checkMemoryAvailable(analysis.value.size)) {
    return err(
      new FileSizeError(analysis.value.size, analysis.value.size, {
        filePath,
        metadata: { reason: 'Insufficient memory to load file' },
      }),
    );
  }

  const result = await fromPromise(readFile(filePath));
  if (!result.ok) {
    return err(new FileAccessError(filePath, 'read'));
  }

  return ok(result.value);
}

// ============================================
// STREAM TRANSFORMS
// ============================================

/**
 * Transform stream that limits total bytes processed
 */
export class LimitedStream extends Transform {
  private bytesProcessed = 0;
  private readonly maxBytes: number;

  constructor(maxBytes: number) {
    super();
    this.maxBytes = maxBytes;
  }

  override _transform(chunk: Buffer, _encoding: string, callback: TransformCallback): void {
    this.bytesProcessed += chunk.length;

    if (this.bytesProcessed > this.maxBytes) {
      callback(new FileSizeError(this.bytesProcessed, this.maxBytes));
      return;
    }

    callback(null, chunk);
  }

  getBytesProcessed(): number {
    return this.bytesProcessed;
  }
}

/**
 * Transform stream that accumulates chunks up to a limit
 */
export class AccumulatorStream extends Transform {
  private chunks: Buffer[] = [];
  private totalSize = 0;
  private readonly maxSize: number;

  constructor(maxSize: number = SIZE_THRESHOLDS.MEDIUM) {
    super({ objectMode: true });
    this.maxSize = maxSize;
  }

  override _transform(chunk: Buffer, _encoding: string, callback: TransformCallback): void {
    this.totalSize += chunk.length;

    if (this.totalSize > this.maxSize) {
      callback(new FileSizeError(this.totalSize, this.maxSize));
      return;
    }

    this.chunks.push(chunk);
    callback();
  }

  override _flush(callback: TransformCallback): void {
    const combined = Buffer.concat(this.chunks);
    this.chunks = []; // Free memory
    callback(null, combined);
  }

  getAccumulatedSize(): number {
    return this.totalSize;
  }
}

// ============================================
// BINARY-SPECIFIC UTILITIES
// ============================================

/**
 * Extract head of binary for quick analysis
 */
export async function extractBinaryHead(
  filePath: string,
  bytes: number = 8192,
): Promise<Result<Buffer, FileAccessError>> {
  const chunks: Buffer[] = [];
  let bytesRead = 0;

  const reader = new ChunkedFileReader(filePath, {
    chunkSize: Math.min(bytes, DEFAULT_CHUNK_SIZE),
  });

  try {
    for await (const chunk of reader) {
      const remaining = bytes - bytesRead;
      if (remaining <= 0) break;

      if (chunk.length <= remaining) {
        chunks.push(chunk);
        bytesRead += chunk.length;
      } else {
        chunks.push(chunk.subarray(0, remaining));
        bytesRead += remaining;
        break;
      }
    }

    return ok(Buffer.concat(chunks));
  } catch (e) {
    return err(
      new FileAccessError(filePath, 'read', { cause: e instanceof Error ? e : undefined }),
    );
  }
}

/**
 * Stream sections of a binary file
 * Useful for extracting specific sections (e.g., .text, .data)
 */
export async function extractBinarySection(
  filePath: string,
  offset: number,
  length: number,
): Promise<Result<Buffer, FileAccessError | FileSizeError>> {
  // Validate length
  if (length > SIZE_THRESHOLDS.MEDIUM) {
    return err(new FileSizeError(length, SIZE_THRESHOLDS.MEDIUM, { filePath }));
  }

  const stream = createReadStream(filePath, {
    start: offset,
    end: offset + length - 1,
    highWaterMark: DEFAULT_CHUNK_SIZE,
  });

  const chunks: Buffer[] = [];

  try {
    for await (const chunk of stream) {
      chunks.push(chunk as Buffer);
    }
    return ok(Buffer.concat(chunks));
  } catch (e) {
    return err(
      new FileAccessError(filePath, 'read', { cause: e instanceof Error ? e : undefined }),
    );
  }
}
