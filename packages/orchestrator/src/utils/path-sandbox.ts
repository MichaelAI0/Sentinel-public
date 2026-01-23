/**
 * Path Sandbox Utilities
 *
 * Provides secure file path handling with sandboxing to prevent
 * directory traversal attacks and unauthorized file access.
 *
 * @module utils/path-sandbox
 */

import { access, constants, realpath, stat } from 'node:fs/promises';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import type { Result } from '@sentinel/shared';
import {
  err,
  FileAccessError,
  FileSizeError,
  fromPromise,
  ok,
  PathSecurityError,
  ValidationError,
} from '@sentinel/shared';

// ============================================
// TYPES
// ============================================

/**
 * Configuration for sandbox behavior
 */
export type SandboxConfig = {
  /** Allowed base directories for file access */
  allowedDirs: string[];
  /** Maximum file size in bytes */
  maxFileSize: number;
  /** Whether to follow symbolic links */
  followSymlinks: boolean;
  /** File extensions to allow (empty = all) */
  allowedExtensions: string[];
  /** Whether to allow reading from /tmp */
  allowTmp: boolean;
  /** Maximum path depth to prevent deep nesting attacks */
  maxPathDepth: number;
};

/**
 * Default sandbox configuration
 */
export const DEFAULT_SANDBOX_CONFIG: SandboxConfig = {
  allowedDirs: [process.cwd()],
  maxFileSize: 100 * 1024 * 1024, // 100MB
  followSymlinks: false,
  allowedExtensions: [],
  allowTmp: true,
  maxPathDepth: 20,
};

/**
 * Result of path validation
 */
export type ValidatedPath = {
  /** The original input path */
  original: string;
  /** The resolved absolute path */
  resolved: string;
  /** Whether the path is within sandbox */
  isSandboxed: boolean;
  /** The sandbox directory it's within */
  sandboxDir: string;
  /** Path relative to sandbox */
  relativePath: string;
};

/**
 * File metadata after validation
 */
export type FileMetadata = {
  path: ValidatedPath;
  size: number;
  isFile: boolean;
  isDirectory: boolean;
  isSymlink: boolean;
  extension: string;
  name: string;
};

// ============================================
// SANDBOX CLASS
// ============================================

/**
 * Path Sandbox for secure file operations
 *
 * @example
 * ```typescript
 * const sandbox = new PathSandbox({
 *   allowedDirs: ['/home/user/binaries', '/tmp'],
 *   maxFileSize: 50 * 1024 * 1024, // 50MB
 * });
 *
 * // Validate a path
 * const result = await sandbox.validatePath('./malware.exe');
 * if (result.ok) {
 *   console.log(`Safe path: ${result.value.resolved}`);
 * }
 * ```
 */
export class PathSandbox {
  private readonly config: SandboxConfig;
  private readonly normalizedDirs: string[];

  constructor(config: Partial<SandboxConfig> = {}) {
    this.config = { ...DEFAULT_SANDBOX_CONFIG, ...config };

    // Add /tmp if allowed
    if (this.config.allowTmp && !this.config.allowedDirs.includes('/tmp')) {
      this.config.allowedDirs.push('/tmp');
    }

    // Normalize all allowed directories
    this.normalizedDirs = this.config.allowedDirs.map((dir) => resolve(dir));
  }

  /**
   * Validate a path is safe and within sandbox
   */
  async validatePath(
    input: string,
  ): Promise<Result<ValidatedPath, PathSecurityError | ValidationError>> {
    // Check for null bytes
    if (input.includes('\0')) {
      return err(new PathSecurityError(input, 'Path contains null bytes'));
    }

    // Check for dangerous patterns
    const dangerousPatterns = [
      /\.\.\//, // Parent traversal
      /\/\.\./, // Parent traversal
      /^\.\.$/, // Just ..
      /%2e%2e/i, // URL encoded
      /%252e/i, // Double encoded
      // biome-ignore lint/suspicious/noControlCharactersInRegex: Intentional null byte detection for security
      /\x00/, // Null byte (backup check)
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(input)) {
        return err(new PathSecurityError(input, 'Path contains dangerous patterns'));
      }
    }

    // Resolve to absolute path
    const resolved = resolve(input);

    // Check path depth
    const depth = resolved.split('/').filter(Boolean).length;
    if (depth > this.config.maxPathDepth) {
      return err(
        new PathSecurityError(
          input,
          `Path depth (${depth}) exceeds maximum (${this.config.maxPathDepth})`,
        ),
      );
    }

    // Find which sandbox directory this path is in
    const sandboxDir = this.normalizedDirs.find((dir) => {
      const rel = relative(dir, resolved);
      // Must not start with .. and must not be absolute
      return !rel.startsWith('..') && !isAbsolute(rel);
    });

    if (!sandboxDir) {
      return err(
        new PathSecurityError(
          input,
          `Path is not within allowed directories: ${this.normalizedDirs.join(', ')}`,
        ),
      );
    }

    return ok({
      original: input,
      resolved,
      isSandboxed: true,
      sandboxDir,
      relativePath: relative(sandboxDir, resolved),
    });
  }

  /**
   * Validate path and get file metadata
   */
  async validateFile(
    input: string,
  ): Promise<
    Result<FileMetadata, PathSecurityError | FileAccessError | FileSizeError | ValidationError>
  > {
    // First validate the path
    const pathResult = await this.validatePath(input);
    if (!pathResult.ok) {
      return pathResult;
    }

    const validatedPath = pathResult.value;

    // Check if file exists and is accessible
    const accessResult = await fromPromise(access(validatedPath.resolved, constants.R_OK));

    if (!accessResult.ok) {
      return err(new FileAccessError(validatedPath.resolved, 'read'));
    }

    // Get file stats
    const statResult = await fromPromise(stat(validatedPath.resolved));
    if (!statResult.ok) {
      return err(new FileAccessError(validatedPath.resolved, 'stat'));
    }

    const stats = statResult.value;

    // Check if it's a symlink and whether we allow following
    if (stats.isSymbolicLink() && !this.config.followSymlinks) {
      return err(new PathSecurityError(validatedPath.resolved, 'Symbolic links are not allowed'));
    }

    // If we follow symlinks, resolve and re-validate
    if (stats.isSymbolicLink() && this.config.followSymlinks) {
      const realResult = await fromPromise(realpath(validatedPath.resolved));
      if (!realResult.ok) {
        return err(new FileAccessError(validatedPath.resolved, 'read'));
      }

      // Re-validate the real path
      const realPathResult = await this.validatePath(realResult.value);
      if (!realPathResult.ok) {
        return err(
          new PathSecurityError(
            validatedPath.resolved,
            `Symlink target escapes sandbox: ${realResult.value}`,
          ),
        );
      }
    }

    // Check file size
    if (stats.isFile() && stats.size > this.config.maxFileSize) {
      return err(
        new FileSizeError(stats.size, this.config.maxFileSize, {
          filePath: validatedPath.resolved,
        }),
      );
    }

    // Check extension if restricted
    const ext = basename(validatedPath.resolved).split('.').pop() || '';
    if (this.config.allowedExtensions.length > 0 && !this.config.allowedExtensions.includes(ext)) {
      return err(
        new PathSecurityError(
          validatedPath.resolved,
          `Extension .${ext} is not allowed. Allowed: ${this.config.allowedExtensions.join(', ')}`,
        ),
      );
    }

    return ok({
      path: validatedPath,
      size: stats.size,
      isFile: stats.isFile(),
      isDirectory: stats.isDirectory(),
      isSymlink: stats.isSymbolicLink(),
      extension: ext,
      name: basename(validatedPath.resolved),
    });
  }

  /**
   * Create a safe path within the sandbox for output
   */
  createOutputPath(
    baseDir: string,
    filename: string,
  ): Result<string, PathSecurityError | ValidationError> {
    // Validate filename (no path components)
    if (filename.includes('/') || filename.includes('\\')) {
      return err(
        new ValidationError('Filename cannot contain path separators', {
          field: 'filename',
        }),
      );
    }

    if (filename.includes('..')) {
      return err(new PathSecurityError(filename, 'Filename contains traversal pattern'));
    }

    // Sanitize filename
    const sanitized = filename.replace(/[^a-zA-Z0-9_\-.]/g, '_');

    // Build and validate the full path
    const fullPath = join(baseDir, sanitized);
    const resolved = resolve(fullPath);

    // Ensure it's still in the base directory
    const rel = relative(resolve(baseDir), resolved);
    if (rel.startsWith('..') || isAbsolute(rel)) {
      return err(new PathSecurityError(fullPath, 'Output path escapes base directory'));
    }

    return ok(resolved);
  }

  /**
   * Get the sandbox directories
   */
  getAllowedDirs(): readonly string[] {
    return this.normalizedDirs;
  }

  /**
   * Check if a path is within the sandbox (synchronous check)
   */
  isPathAllowed(input: string): boolean {
    try {
      const resolved = resolve(input);
      return this.normalizedDirs.some((dir) => {
        const rel = relative(dir, resolved);
        return !rel.startsWith('..') && !isAbsolute(rel);
      });
    } catch {
      return false;
    }
  }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Create a sandbox for binary analysis
 * Pre-configured for typical binary analysis use case
 */
export function createBinarySandbox(additionalDirs: string[] = []): PathSandbox {
  return new PathSandbox({
    allowedDirs: [process.cwd(), './binaries', './outputs', ...additionalDirs],
    maxFileSize: 100 * 1024 * 1024, // 100MB max binary size
    followSymlinks: false, // Security: don't follow symlinks
    allowedExtensions: [], // Allow any extension for binaries
    allowTmp: true,
    maxPathDepth: 10,
  });
}

/**
 * Create a sandbox for output files
 */
export function createOutputSandbox(outputDir: string): PathSandbox {
  return new PathSandbox({
    allowedDirs: [outputDir],
    maxFileSize: 10 * 1024 * 1024, // 10MB max output
    followSymlinks: false,
    allowedExtensions: ['json', 'md', 'txt', 'log'],
    allowTmp: false,
    maxPathDepth: 5,
  });
}

/**
 * Quick validation of a binary path
 */
export async function validateBinaryPath(
  input: string,
  sandbox?: PathSandbox,
): Promise<
  Result<FileMetadata, PathSecurityError | FileAccessError | FileSizeError | ValidationError>
> {
  const s = sandbox ?? createBinarySandbox();
  return s.validateFile(input);
}
