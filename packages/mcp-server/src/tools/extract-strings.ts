/**
 * extract_strings - Fast string extraction from binary
 *
 * This tool extracts ASCII and Unicode strings from a binary file
 * without using Ghidra (fast, native implementation).
 */

import { readFile } from 'node:fs/promises';
import type { ExtractStringsInput, ExtractStringsOutput } from '@sentinel/shared';
import { logToolExecution } from '../utils/logger.js';

// Suspicious string patterns
const SUSPICIOUS_PATTERNS = [
  { pattern: /^https?:\/\/.+/i, category: 'URL' as const, reason: 'Contains URL' },
  { pattern: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, category: 'IP' as const, reason: 'IP address' },
  { pattern: /@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, category: 'EMAIL' as const, reason: 'Email address' },
  {
    pattern: /^[A-Z]:\\.*\.(exe|dll|bat|cmd|ps1|vbs)/i,
    category: 'FILE_PATH' as const,
    reason: 'Executable file path',
  },
  {
    pattern: /^HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)/,
    category: 'REGISTRY' as const,
    reason: 'Registry key',
  },
  {
    pattern:
      /^(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtCreateThreadEx|RtlCreateUserThread)/,
    category: 'API' as const,
    reason: 'Process injection API',
  },
  {
    pattern: /^(RegSetValue|RegCreateKey|RegOpenKey)/,
    category: 'API' as const,
    reason: 'Registry manipulation API',
  },
  {
    pattern: /^(WSASocket|connect|send|recv|InternetOpen)/,
    category: 'API' as const,
    reason: 'Network API',
  },
];

/**
 * Extract ASCII strings from buffer
 */
function extractAsciiStrings(
  buffer: Buffer,
  minLength: number,
): Array<{ value: string; offset: number }> {
  const strings: Array<{ value: string; offset: number }> = [];
  let current = '';
  let startOffset = 0;

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];

    // Printable ASCII range (32-126)
    if (byte !== undefined && byte >= 32 && byte <= 126) {
      if (current === '') {
        startOffset = i;
      }
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        strings.push({ value: current, offset: startOffset });
      }
      current = '';
    }
  }

  // Don't forget the last string
  if (current.length >= minLength) {
    strings.push({ value: current, offset: startOffset });
  }

  return strings;
}

/**
 * Extract Unicode (UTF-16LE) strings from buffer
 */
function extractUnicodeStrings(
  buffer: Buffer,
  minLength: number,
): Array<{ value: string; offset: number }> {
  const strings: Array<{ value: string; offset: number }> = [];
  let current = '';
  let startOffset = 0;

  // UTF-16LE: 2 bytes per character, null byte follows ASCII byte
  for (let i = 0; i < buffer.length - 1; i += 2) {
    const lowByte = buffer[i];
    const highByte = buffer[i + 1];

    // Check for ASCII character in UTF-16LE (high byte is 0)
    if (lowByte !== undefined && highByte === 0 && lowByte >= 32 && lowByte <= 126) {
      if (current === '') {
        startOffset = i;
      }
      current += String.fromCharCode(lowByte);
    } else {
      if (current.length >= minLength) {
        strings.push({ value: current, offset: startOffset });
      }
      current = '';
    }
  }

  if (current.length >= minLength) {
    strings.push({ value: current, offset: startOffset });
  }

  return strings;
}

/**
 * Detect suspicious strings
 */
function detectSuspiciousStrings(
  strings: Array<{ value: string; offset: number; type: 'ASCII' | 'UNICODE' }>,
): ExtractStringsOutput['suspiciousStrings'] {
  const suspicious: ExtractStringsOutput['suspiciousStrings'] = [];

  for (const str of strings) {
    for (const { pattern, category, reason } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(str.value)) {
        suspicious.push({
          value: str.value,
          category,
          reason,
        });
        break; // Only add once per string
      }
    }
  }

  return suspicious;
}

/**
 * Extract ASCII and Unicode strings from a binary file.
 * Identifies potentially suspicious strings like URLs, IPs, and API names.
 */
export async function extractStrings(input: ExtractStringsInput): Promise<ExtractStringsOutput> {
  const { binaryPath, options } = input;
  const minLength = options?.minLength ?? 4;
  const includeUnicode = options?.includeUnicode ?? true;
  const limit = options?.limit ?? 10000;

  logToolExecution('extract_strings', { binaryPath, minLength, includeUnicode }, 'start');

  try {
    // Read binary file
    const buffer = await readFile(binaryPath);

    // Extract ASCII strings
    const asciiStrings = extractAsciiStrings(buffer, minLength).map((s) => ({
      ...s,
      type: 'ASCII' as const,
    }));

    // Extract Unicode strings if enabled
    const unicodeStrings = includeUnicode
      ? extractUnicodeStrings(buffer, minLength).map((s) => ({
          ...s,
          type: 'UNICODE' as const,
        }))
      : [];

    // Combine and deduplicate
    const allStrings = [...asciiStrings, ...unicodeStrings];

    // Remove duplicates (same value)
    const seen = new Set<string>();
    const uniqueStrings = allStrings.filter((s) => {
      if (seen.has(s.value)) return false;
      seen.add(s.value);
      return true;
    });

    // Apply limit
    const limitedStrings = uniqueStrings.slice(0, limit);

    // Detect suspicious strings
    const suspiciousStrings = detectSuspiciousStrings(limitedStrings);

    const result: ExtractStringsOutput = {
      strings: limitedStrings,
      statistics: {
        totalStrings: limitedStrings.length,
        asciiCount: limitedStrings.filter((s) => s.type === 'ASCII').length,
        unicodeCount: limitedStrings.filter((s) => s.type === 'UNICODE').length,
        suspiciousCount: suspiciousStrings.length,
      },
      suspiciousStrings,
    };

    logToolExecution('extract_strings', { binaryPath }, 'success', {
      totalStrings: result.statistics.totalStrings,
      suspiciousCount: result.statistics.suspiciousCount,
    });

    return result;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logToolExecution('extract_strings', { binaryPath }, 'error', { error: errorMessage });
    throw new Error(`Failed to extract strings: ${errorMessage}`);
  }
}
