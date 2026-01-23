/**
 * Branded Types for Type-Safe Validation
 *
 * Uses TypeScript's branded types pattern to ensure
 * validated data is distinguishable from unvalidated data.
 *
 * @example
 * ```typescript
 * // This won't compile - you can't pass a raw string
 * analyzeFile("../../../etc/passwd");
 *
 * // This will work - validated and branded
 * const path = validateFilePath("./sample.exe");
 * analyzeFile(path); // path is FilePath type
 * ```
 *
 * @module types/branded
 */

import { isAbsolute, relative, resolve } from 'node:path';
import { PathSecurityError, ValidationError } from './errors.js';

// ============================================
// BRAND SYMBOLS
// ============================================

declare const __filePath: unique symbol;
declare const __absolutePath: unique symbol;
declare const __binaryName: unique symbol;
declare const __sanitizedString: unique symbol;
declare const __positiveInt: unique symbol;
declare const __hash: unique symbol;

// ============================================
// BRANDED TYPES
// ============================================

/**
 * A validated file path (relative or absolute)
 * Guaranteed to be free of path traversal attacks
 */
export type FilePath = string & { readonly [__filePath]: true };

/**
 * A validated absolute file path
 * Guaranteed to be absolute and safe
 */
export type AbsolutePath = string & { readonly [__absolutePath]: true };

/**
 * A validated binary/file name (no path components)
 */
export type BinaryName = string & { readonly [__binaryName]: true };

/**
 * A sanitized string (no control characters, trimmed)
 */
export type SanitizedString = string & { readonly [__sanitizedString]: true };

/**
 * A positive integer (> 0)
 */
export type PositiveInt = number & { readonly [__positiveInt]: true };

/**
 * A validated hash string (hex, appropriate length)
 */
export type Hash = string & { readonly [__hash]: true };

// ============================================
// VALIDATION FUNCTIONS
// ============================================

/**
 * Dangerous patterns that indicate path traversal or injection
 */
const DANGEROUS_PATTERNS = [
  /\.\./, // Parent directory
  // biome-ignore lint/suspicious/noControlCharactersInRegex: Intentional null byte detection for security
  /\x00/, // Null byte
  /%2e%2e/i, // URL encoded ..
  /%252e/i, // Double encoded
];

/**
 * Validate and brand a file path
 * @throws PathSecurityError if path contains dangerous patterns
 * @throws ValidationError if path is empty or too long
 */
export function filePath(input: string): FilePath {
  if (!input || input.trim().length === 0) {
    throw new ValidationError('File path cannot be empty', { field: 'filePath' });
  }

  const trimmed = input.trim();

  if (trimmed.length > 4096) {
    throw new ValidationError('File path exceeds maximum length', {
      field: 'filePath',
      metadata: { length: trimmed.length, maxLength: 4096 },
    });
  }

  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(trimmed)) {
      throw new PathSecurityError(trimmed, 'Path contains dangerous patterns');
    }
  }

  if (trimmed.includes('\n') || trimmed.includes('\r')) {
    throw new PathSecurityError(trimmed, 'Path contains newline characters');
  }

  return trimmed as FilePath;
}

/**
 * Validate and brand an absolute file path
 * @throws PathSecurityError if path is not absolute or contains dangerous patterns
 */
export function absolutePath(input: string): AbsolutePath {
  const validated = filePath(input);

  if (!isAbsolute(validated)) {
    throw new ValidationError('Path must be absolute', {
      field: 'filePath',
      metadata: { path: validated },
    });
  }

  return validated as unknown as AbsolutePath;
}

/**
 * Validate and brand a binary name (filename only, no path)
 * @throws ValidationError if name contains invalid characters
 */
export function binaryName(input: string): BinaryName {
  if (!input || input.trim().length === 0) {
    throw new ValidationError('Binary name cannot be empty', { field: 'binaryName' });
  }

  const trimmed = input.trim();

  if (trimmed.length > 255) {
    throw new ValidationError('Binary name exceeds maximum length', {
      field: 'binaryName',
      metadata: { length: trimmed.length, maxLength: 255 },
    });
  }

  if (!/^[a-zA-Z0-9][a-zA-Z0-9_\-.]*$/.test(trimmed)) {
    throw new ValidationError(
      'Binary name must start with alphanumeric and contain only letters, numbers, underscores, dashes, and dots',
      { field: 'binaryName', metadata: { value: trimmed } },
    );
  }

  if (trimmed.includes('/') || trimmed.includes('\\')) {
    throw new ValidationError('Binary name cannot contain path separators', {
      field: 'binaryName',
    });
  }

  if (trimmed === '.' || trimmed === '..') {
    throw new ValidationError('Binary name cannot be . or ..', { field: 'binaryName' });
  }

  return trimmed as BinaryName;
}

/**
 * Sanitize and brand a string (remove control characters, trim)
 */
export function sanitizedString(input: string): SanitizedString {
  // Remove control characters except space, tab, newline
  const sanitized = input
    .trim()
    // biome-ignore lint/suspicious/noControlCharactersInRegex: intentional
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');

  return sanitized as SanitizedString;
}

/**
 * Validate and brand a positive integer
 * @throws ValidationError if not a positive integer
 */
export function positiveInt(input: number): PositiveInt {
  if (!Number.isInteger(input)) {
    throw new ValidationError('Value must be an integer', {
      field: 'number',
      metadata: { value: input },
    });
  }

  if (input <= 0) {
    throw new ValidationError('Value must be positive', {
      field: 'number',
      metadata: { value: input },
    });
  }

  return input as PositiveInt;
}

/**
 * Validate and brand a hash string
 * @throws ValidationError if not a valid hash format
 */
export function hash(input: string, expectedLength?: number): Hash {
  const trimmed = input.trim().toLowerCase();

  if (!/^[a-f0-9]+$/.test(trimmed)) {
    throw new ValidationError('Hash must be hexadecimal', {
      field: 'hash',
      metadata: { value: input },
    });
  }

  if (expectedLength !== undefined && trimmed.length !== expectedLength) {
    throw new ValidationError(`Hash must be ${expectedLength} characters`, {
      field: 'hash',
      metadata: { actualLength: trimmed.length, expectedLength },
    });
  }

  return trimmed as Hash;
}

// ============================================
// PATH SANDBOX UTILITIES
// ============================================

/**
 * Default allowed directories for file operations
 */
const DEFAULT_ALLOWED_DIRS = [process.cwd(), '/tmp'];

/**
 * Resolve a path within a sandbox
 * Ensures the resolved path doesn't escape allowed directories
 *
 * @throws PathSecurityError if path escapes sandbox
 */
export function sandboxPath(
  input: string,
  allowedDirs: string[] = DEFAULT_ALLOWED_DIRS,
): AbsolutePath {
  // First validate as file path
  const validated = filePath(input);

  // Resolve to absolute
  const resolved = resolve(validated);

  // Check if resolved path is within any allowed directory
  const isAllowed = allowedDirs.some((dir) => {
    const rel = relative(dir, resolved);
    // If relative path starts with '..' or is absolute, it escapes
    return !rel.startsWith('..') && !isAbsolute(rel);
  });

  if (!isAllowed) {
    throw new PathSecurityError(
      input,
      `Path escapes sandbox. Allowed directories: ${allowedDirs.join(', ')}`,
    );
  }

  return resolved as AbsolutePath;
}

// ============================================
// TYPE GUARDS
// ============================================

/**
 * Check if a value is a branded FilePath
 * Note: At runtime, branded types are just strings
 * This checks the value pattern, not the brand
 */
export function isValidFilePath(value: unknown): value is FilePath {
  if (typeof value !== 'string') return false;

  try {
    filePath(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a value is a valid binary name
 */
export function isValidBinaryName(value: unknown): value is BinaryName {
  if (typeof value !== 'string') return false;

  try {
    binaryName(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a value is a valid hash
 */
export function isValidHash(value: unknown, length?: number): value is Hash {
  if (typeof value !== 'string') return false;

  try {
    hash(value, length);
    return true;
  } catch {
    return false;
  }
}
