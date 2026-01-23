/**
 * Type declarations for ssdeep.js
 * @see https://www.npmjs.com/package/ssdeep.js
 * @see https://github.com/cloudtracer/ssdeep.js
 *
 * Note: The actual API methods are `digest` and `similarity`,
 * not `hash` and `compare` as some docs suggest.
 */

declare module 'ssdeep.js' {
  /**
   * Calculate the fuzzy hash (SSDEEP) of data
   * @param data - The data to hash (string or array-like)
   * @returns The SSDEEP fuzzy hash string (format: blocksize:hash1:hash2)
   */
  export function digest(data: string | number[]): string;

  /**
   * Compare two SSDEEP hashes and return a similarity score
   * @param hash1 - First SSDEEP hash
   * @param hash2 - Second SSDEEP hash
   * @returns Similarity score from 0 to 100
   */
  export function similarity(hash1: string, hash2: string): number;

  const ssdeep: {
    digest: typeof digest;
    similarity: typeof similarity;
  };

  export default ssdeep;
}
