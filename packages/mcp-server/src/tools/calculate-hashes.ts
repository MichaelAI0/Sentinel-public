import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import type { CalculateHashesInputSchema, CalculateHashesOutputSchema } from '@sentinel/shared';
import ssdeep from 'ssdeep.js';
import type { z } from 'zod';
import { logToolExecution } from '../utils/logger.js';

type CalculateHashesInput = z.infer<typeof CalculateHashesInputSchema>;
type CalculateHashesOutput = z.infer<typeof CalculateHashesOutputSchema>;

/**
 * Calculate cryptographic hashes for a binary file.
 * Supports MD5, SHA1, SHA256, and SSDEEP (fuzzy hashing).
 */
export async function calculateHashes(input: CalculateHashesInput): Promise<CalculateHashesOutput> {
  const { binaryPath, algorithms = ['MD5', 'SHA256'] } = input;

  logToolExecution('calculate_hashes', { binaryPath, algorithms }, 'start');

  try {
    // Read file and get stats in parallel
    const [fileBuffer, fileStats] = await Promise.all([readFile(binaryPath), stat(binaryPath)]);

    const result: CalculateHashesOutput = {
      fileSize: fileStats.size,
    };

    // Calculate requested hashes
    for (const algo of algorithms) {
      switch (algo) {
        case 'MD5':
          result.md5 = createHash('md5').update(fileBuffer).digest('hex');
          break;
        case 'SHA1':
          result.sha1 = createHash('sha1').update(fileBuffer).digest('hex');
          break;
        case 'SHA256':
          result.sha256 = createHash('sha256').update(fileBuffer).digest('hex');
          break;
        case 'SSDEEP':
          result.ssdeep = computeSSDeep(fileBuffer);
          break;
      }
    }

    logToolExecution('calculate_hashes', { binaryPath }, 'success', {
      fileSize: result.fileSize,
      hashesComputed: algorithms,
    });

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('calculate_hashes', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to calculate hashes: ${errorMessage}`);
  }
}

/**
 * Compute SSDEEP fuzzy hash using ssdeep.js library.
 *
 * SSDEEP (context-triggered piecewise hashing) produces fuzzy hashes
 * that can be compared to find similar files, even after modification.
 * Format: blocksize:hash1:hash2
 *
 * @param buffer - File contents as a Buffer
 * @returns SSDEEP hash string
 */
function computeSSDeep(buffer: Buffer): string {
  // ssdeep.js uses .digest() method - it accepts string or array-like data
  // Convert Buffer to string for the library
  return ssdeep.digest(buffer.toString('binary')) as string;
}

/**
 * Compare two SSDEEP hashes and return similarity score (0-100).
 *
 * @param hash1 - First SSDEEP hash
 * @param hash2 - Second SSDEEP hash
 * @returns Similarity percentage (0 = no match, 100 = identical)
 */
export function compareSsdeep(hash1: string, hash2: string): number {
  return ssdeep.similarity(hash1, hash2) as number;
}

export default calculateHashes;
