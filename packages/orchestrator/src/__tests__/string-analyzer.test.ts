/**
 * String Analyzer Tests
 *
 * Tests for enhanced string analysis including categorization,
 * entropy calculation, encoding detection, and pattern matching.
 */

import { describe, expect, test } from 'bun:test';
import { getStringAnalyzer } from '../utils/string-analyzer';

describe('StringAnalyzer', () => {
  const analyzer = getStringAnalyzer();

  describe('analyzeString', () => {
    test('calculates entropy correctly for low entropy strings', () => {
      const result = analyzer.analyzeString('aaaaaaaaaa');
      expect(result.entropy).toBe(0); // Single character repeated = 0 entropy
    });

    test('calculates entropy correctly for high entropy strings', () => {
      const result = analyzer.analyzeString('abcdefghijklmnop');
      expect(result.entropy).toBeGreaterThan(3); // High variety = higher entropy
    });

    test('detects URL category', () => {
      const result = analyzer.analyzeString('https://malicious-site.com/payload');
      expect(result.category).toBe('url');
    });

    test('detects filepath category for Windows paths', () => {
      const result = analyzer.analyzeString('C:\\Windows\\System32\\cmd.exe');
      expect(result.category).toBe('filepath');
    });

    test('detects filepath category for Unix paths', () => {
      const result = analyzer.analyzeString('/etc/passwd');
      expect(result.category).toBe('filepath');
    });

    test('detects registry category', () => {
      const result = analyzer.analyzeString('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft');
      expect(result.category).toBe('registry');
    });

    test('detects IP address category', () => {
      const result = analyzer.analyzeString('192.168.1.100');
      expect(result.category).toBe('ip');
    });

    test('detects email category', () => {
      const result = analyzer.analyzeString('malware@evil.com');
      expect(result.category).toBe('email');
    });

    test('detects GUID category', () => {
      const result = analyzer.analyzeString('12345678-1234-1234-1234-123456789abc');
      expect(result.category).toBe('guid');
    });

    test('detects base64 encoding', () => {
      const result = analyzer.analyzeString('SGVsbG8gV29ybGQ=');
      expect(result.encoding).toBe('base64');
      expect(result.decodedValue).toBe('Hello World');
    });

    test('detects hex encoding', () => {
      const result = analyzer.analyzeString('48656c6c6f');
      expect(result.encoding).toBe('hex');
      expect(result.decodedValue).toBe('Hello');
    });
  });

  describe('suspicious pattern detection', () => {
    test('flags cmd.exe as suspicious', () => {
      const result = analyzer.analyzeString('cmd.exe /c del *.*');
      expect(result.suspicious).toBe(true);
      expect(result.suspicionReasons.some((r) => r.includes('Command shell'))).toBe(true);
    });

    test('flags PowerShell as suspicious', () => {
      const result = analyzer.analyzeString('powershell -encodedcommand');
      expect(result.suspicious).toBe(true);
      expect(result.suspicionReasons.some((r) => r.includes('PowerShell'))).toBe(true);
    });

    test('flags CreateRemoteThread as suspicious', () => {
      const result = analyzer.analyzeString('CreateRemoteThread');
      expect(result.suspicious).toBe(true);
      expect(result.suspicionReasons.some((r) => r.includes('Remote thread'))).toBe(true);
    });

    test('flags VirtualAllocEx as suspicious', () => {
      const result = analyzer.analyzeString('VirtualAllocEx');
      expect(result.suspicious).toBe(true);
    });

    test('flags debugger detection as suspicious', () => {
      const result = analyzer.analyzeString('IsDebuggerPresent');
      expect(result.suspicious).toBe(true);
      expect(result.suspicionReasons.some((r) => r.includes('Debugger'))).toBe(true);
    });

    test('flags startup registry as suspicious', () => {
      const result = analyzer.analyzeString(
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      );
      expect(result.suspicious).toBe(true);
      expect(result.suspicionReasons.some((r) => r.includes('Startup registry'))).toBe(true);
    });

    test('does not flag benign strings as suspicious', () => {
      const result = analyzer.analyzeString('Hello World');
      expect(result.suspicious).toBe(false);
      expect(result.suspicionReasons).toHaveLength(0);
    });
  });

  describe('analyze (batch)', () => {
    test('deduplicates strings', () => {
      const strings = ['hello', 'world', 'hello', 'test', 'hello'];
      const summary = analyzer.analyze(strings);
      expect(summary.totalStrings).toBe(5);
      expect(summary.uniqueStrings).toBe(3);
    });

    test('categorizes strings by type', () => {
      const strings = ['https://example.com', '/etc/passwd', '192.168.1.1', 'generic text'];
      const summary = analyzer.analyze(strings);
      expect(summary.categoryBreakdown.url).toBe(1);
      expect(summary.categoryBreakdown.filepath).toBe(1);
      expect(summary.categoryBreakdown.ip).toBe(1);
      expect(summary.categoryBreakdown.generic).toBe(1);
    });

    test('counts suspicious strings', () => {
      const strings = ['cmd.exe', 'powershell', 'hello', 'world'];
      const summary = analyzer.analyze(strings);
      expect(summary.suspiciousCount).toBe(2);
    });

    test('extracts high-value strings', () => {
      const strings = ['hello', 'CreateRemoteThread', 'world'];
      const summary = analyzer.analyze(strings);
      expect(summary.highValueStrings.length).toBeGreaterThanOrEqual(1);
      expect(summary.highValueStrings.some((s) => s.value === 'CreateRemoteThread')).toBe(true);
    });

    test('respects minLength config', () => {
      const customAnalyzer = getStringAnalyzer({ minLength: 6 });
      const strings = ['abc', 'short', 'longenough'];
      const summary = customAnalyzer.analyze(strings);
      expect(summary.strings.every((s) => s.value.length >= 6)).toBe(true);
    });

    test('respects maxStrings config', () => {
      const customAnalyzer = getStringAnalyzer({ maxStrings: 5 });
      const strings = Array(100)
        .fill(0)
        .map((_, i) => `string_${i}`);
      const summary = customAnalyzer.analyze(strings);
      expect(summary.strings.length).toBeLessThanOrEqual(5);
    });
  });

  describe('encoding detection', () => {
    test('detects ASCII encoding', () => {
      const result = analyzer.analyzeString('Hello World 123');
      expect(result.encoding).toBe('ascii');
    });

    test('handles non-ASCII characters', () => {
      const result = analyzer.analyzeString('Hëllo Wörld');
      // The analyzer returns 'unknown' for extended characters
      expect(['utf8', 'unknown']).toContain(result.encoding);
    });

    test('validates base64 decoding', () => {
      // Valid base64: "Test String"
      const result = analyzer.analyzeString('VGVzdCBTdHJpbmc=');
      expect(result.encoding).toBe('base64');
      expect(result.decodedValue).toBe('Test String');
    });

    test('does not decode invalid base64', () => {
      // Not valid base64 length
      const result = analyzer.analyzeString('NotBase64!!');
      expect(result.encoding).not.toBe('base64');
    });
  });

  describe('getStringAnalyzer singleton', () => {
    test('returns same instance with same config', () => {
      const a1 = getStringAnalyzer();
      const a2 = getStringAnalyzer();
      expect(a1).toBe(a2);
    });

    test('returns new instance with different config', () => {
      const a1 = getStringAnalyzer();
      const a2 = getStringAnalyzer({ minLength: 10 });
      expect(a1).not.toBe(a2);
    });
  });
});
