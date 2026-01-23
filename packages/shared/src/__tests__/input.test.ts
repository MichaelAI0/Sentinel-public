/**
 * Input Validation Schema Tests
 *
 * Tests for Zod schemas that validate user inputs
 *
 * @module __tests__/input.test
 */

import { describe, expect, it } from 'bun:test';
import {
  AnalyzeArgsSchema,
  BinaryNameSchema,
  CommonOptionsSchema,
  FilePathSchema,
  InputLogLevelEnum,
  OutputFormatEnum,
} from '../schemas/input';

describe('FilePathSchema', () => {
  describe('valid paths', () => {
    it('accepts absolute paths', () => {
      expect(FilePathSchema.parse('/home/user/file.bin')).toBe('/home/user/file.bin');
    });

    it('accepts relative paths', () => {
      expect(FilePathSchema.parse('./binaries/sample.exe')).toBe('./binaries/sample.exe');
    });

    it('trims whitespace', () => {
      expect(FilePathSchema.parse('  /path/to/file.bin  ')).toBe('/path/to/file.bin');
    });

    it('accepts paths with dashes and underscores', () => {
      expect(FilePathSchema.parse('/path/to/my-file_v2.bin')).toBe('/path/to/my-file_v2.bin');
    });
  });

  describe('invalid paths', () => {
    it('rejects empty strings', () => {
      expect(() => FilePathSchema.parse('')).toThrow();
    });

    it('rejects paths with null bytes', () => {
      expect(() => FilePathSchema.parse('/path/to\x00/file.bin')).toThrow();
    });

    it('rejects path traversal with ../', () => {
      expect(() => FilePathSchema.parse('../../../etc/passwd')).toThrow();
    });

    it('rejects path traversal with /..', () => {
      expect(() => FilePathSchema.parse('/home/user/../../../etc/passwd')).toThrow();
    });

    it('rejects very long paths', () => {
      const longPath = '/a'.repeat(2050);
      expect(() => FilePathSchema.parse(longPath)).toThrow();
    });
  });
});

describe('BinaryNameSchema', () => {
  describe('valid names', () => {
    it('accepts alphanumeric names', () => {
      expect(BinaryNameSchema.parse('malware123')).toBe('malware123');
    });

    it('accepts names with underscores', () => {
      expect(BinaryNameSchema.parse('suspicious_binary')).toBe('suspicious_binary');
    });

    it('accepts names with dashes', () => {
      expect(BinaryNameSchema.parse('sample-v2')).toBe('sample-v2');
    });

    it('accepts names with dots', () => {
      expect(BinaryNameSchema.parse('sample.exe')).toBe('sample.exe');
    });

    it('accepts uppercase letters', () => {
      expect(BinaryNameSchema.parse('MalwareSample.EXE')).toBe('MalwareSample.EXE');
    });
  });

  describe('invalid names', () => {
    it('rejects empty strings', () => {
      expect(() => BinaryNameSchema.parse('')).toThrow();
    });

    it('rejects names with spaces', () => {
      expect(() => BinaryNameSchema.parse('my sample')).toThrow();
    });

    it('rejects names with slashes', () => {
      expect(() => BinaryNameSchema.parse('path/to/file')).toThrow();
    });

    it('rejects names with special characters', () => {
      expect(() => BinaryNameSchema.parse('file<script>')).toThrow();
      expect(() => BinaryNameSchema.parse('file;rm -rf')).toThrow();
      expect(() => BinaryNameSchema.parse('file`whoami`')).toThrow();
    });

    it('rejects very long names', () => {
      const longName = 'a'.repeat(300);
      expect(() => BinaryNameSchema.parse(longName)).toThrow();
    });
  });
});

describe('AnalyzeArgsSchema', () => {
  describe('valid inputs', () => {
    it('accepts analyze args with required fields', () => {
      const result = AnalyzeArgsSchema.parse({
        command: 'analyze',
        filePath: '/home/user/sample.bin',
      });
      expect(result.command).toBe('analyze');
      expect(result.filePath).toBe('/home/user/sample.bin');
      expect(result.verbose).toBe(false); // default
      expect(result.quiet).toBe(false); // default
    });

    it('applies default timeout', () => {
      const result = AnalyzeArgsSchema.parse({
        command: 'analyze',
        filePath: '/sample.bin',
      });
      expect(result.timeout).toBe(300);
    });

    it('accepts custom timeout', () => {
      const result = AnalyzeArgsSchema.parse({
        command: 'analyze',
        filePath: '/sample.bin',
        timeout: 600,
      });
      expect(result.timeout).toBe(600);
    });

    it('accepts skipGhidra option', () => {
      const result = AnalyzeArgsSchema.parse({
        command: 'analyze',
        filePath: '/sample.bin',
        skipGhidra: true,
      });
      expect(result.skipGhidra).toBe(true);
    });
  });

  describe('invalid inputs', () => {
    it('rejects missing filePath', () => {
      expect(() =>
        AnalyzeArgsSchema.parse({
          command: 'analyze',
        }),
      ).toThrow();
    });

    it('rejects negative timeout', () => {
      expect(() =>
        AnalyzeArgsSchema.parse({
          command: 'analyze',
          filePath: '/sample.bin',
          timeout: -1,
        }),
      ).toThrow();
    });

    it('rejects zero timeout', () => {
      expect(() =>
        AnalyzeArgsSchema.parse({
          command: 'analyze',
          filePath: '/sample.bin',
          timeout: 0,
        }),
      ).toThrow();
    });
  });
});

describe('InputLogLevelEnum', () => {
  it('accepts valid log levels', () => {
    expect(InputLogLevelEnum.parse('debug')).toBe('debug');
    expect(InputLogLevelEnum.parse('info')).toBe('info');
    expect(InputLogLevelEnum.parse('warn')).toBe('warn');
    expect(InputLogLevelEnum.parse('error')).toBe('error');
    expect(InputLogLevelEnum.parse('silent')).toBe('silent');
  });

  it('rejects invalid log levels', () => {
    expect(() => InputLogLevelEnum.parse('trace')).toThrow();
    expect(() => InputLogLevelEnum.parse('verbose')).toThrow();
    expect(() => InputLogLevelEnum.parse('')).toThrow();
  });
});

describe('CommonOptionsSchema', () => {
  it('applies default values', () => {
    const result = CommonOptionsSchema.parse({});
    expect(result.verbose).toBe(false);
    expect(result.quiet).toBe(false);
    expect(result.json).toBe(false);
    expect(result.logLevel).toBe('info');
  });

  it('accepts custom values', () => {
    const result = CommonOptionsSchema.parse({
      verbose: true,
      quiet: true,
      json: true,
      logLevel: 'debug',
    });
    expect(result.verbose).toBe(true);
    expect(result.quiet).toBe(true);
    expect(result.json).toBe(true);
    expect(result.logLevel).toBe('debug');
  });

  it('accepts optional config path', () => {
    const result = CommonOptionsSchema.parse({
      config: '/etc/sentinel/config.json',
    });
    expect(result.config).toBe('/etc/sentinel/config.json');
  });
});

describe('OutputFormatEnum', () => {
  it('accepts valid output formats', () => {
    expect(OutputFormatEnum.parse('json')).toBe('json');
    expect(OutputFormatEnum.parse('markdown')).toBe('markdown');
    expect(OutputFormatEnum.parse('stix')).toBe('stix');
    expect(OutputFormatEnum.parse('all')).toBe('all');
  });

  it('rejects invalid output formats', () => {
    expect(() => OutputFormatEnum.parse('xml')).toThrow();
    expect(() => OutputFormatEnum.parse('html')).toThrow();
    expect(() => OutputFormatEnum.parse('')).toThrow();
  });
});
