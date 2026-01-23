/**
 * Integration Tests
 *
 * Tests that verify components work together correctly.
 * Uses real binaries from the binaries/ directory when available.
 */

import { beforeAll, describe, expect, test } from 'bun:test';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';

// Test fixtures
const BINARIES_DIR = join(import.meta.dir, '..', '..', '..', '..', 'binaries');
const TEST_BINARY = join(BINARIES_DIR, 'test_binary');

// Check if binaries exist
async function binaryExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

describe('Integration Tests', () => {
  let hasTestBinary = false;

  beforeAll(async () => {
    hasTestBinary = await binaryExists(TEST_BINARY);
  });

  describe('Path Sandbox + File Operations', () => {
    test('PathSandbox validates real binary paths', async () => {
      const { PathSandbox } = await import('../utils/path-sandbox.js');

      // Create sandbox with binaries directory
      const sandbox = new PathSandbox({ allowedDirs: [BINARIES_DIR] });

      if (hasTestBinary) {
        // Should allow access to test binary - use validatePath which is the actual API
        const result = await sandbox.validatePath(TEST_BINARY);
        expect(result.ok).toBe(true);
      }

      // Should reject paths outside sandbox
      const badResult = await sandbox.validatePath('/etc/passwd');
      expect(badResult.ok).toBe(false);
    });

    test('PathSandbox blocks path traversal attacks', async () => {
      const { PathSandbox } = await import('../utils/path-sandbox.js');

      const sandbox = new PathSandbox({ allowedDirs: [BINARIES_DIR] });

      // Various traversal attempts
      const attacks = [
        join(BINARIES_DIR, '..', 'etc', 'passwd'),
        `${BINARIES_DIR}/../../../etc/passwd`,
      ];

      for (const attack of attacks) {
        const result = await sandbox.validatePath(attack);
        expect(result.ok).toBe(false);
      }
    });
  });

  describe('String Analyzer Integration', () => {
    test('analyzes strings array', async () => {
      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();

      // StringAnalyzer.analyze expects an array of strings
      const testStrings = ['test', 'hello', 'http://example.com'];
      const result = analyzer.analyze(testStrings);

      expect(result.totalStrings).toBeGreaterThan(0);
      expect(Array.isArray(result.strings)).toBe(true);
    });

    test('detects suspicious patterns', async () => {
      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();

      // Test with suspicious strings
      const suspiciousStrings = [
        'CreateRemoteThread',
        'http://malware.com/payload',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Run',
      ];
      const result = analyzer.analyze(suspiciousStrings);

      expect(result.suspiciousCount).toBeGreaterThan(0);
    });
  });

  describe('Crypto Detector Integration', () => {
    test('scans data for crypto constants', async () => {
      const { getCryptoDetector } = await import('../utils/crypto-detector.js');
      const detector = getCryptoDetector();

      // Create test data with AES S-box bytes
      const aesBytes = new Uint8Array([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]);
      const result = detector.analyze(aesBytes);

      expect(result.detections).toBeDefined();
      expect(Array.isArray(result.detections)).toBe(true);
    });

    test('analyzes entropy', async () => {
      const { CryptoDetector } = await import('../utils/crypto-detector.js');
      const detector = new CryptoDetector();

      // Low entropy data
      const lowEntropy = new Uint8Array(100).fill(0);
      expect(detector.calculateEntropy(lowEntropy)).toBeLessThan(1);

      // High entropy data
      const highEntropy = new Uint8Array(256);
      for (let i = 0; i < 256; i++) highEntropy[i] = i;
      expect(detector.calculateEntropy(highEntropy)).toBeGreaterThan(7);
    });
  });

  describe('Unpacker Integration', () => {
    test('unpacker methods exist', async () => {
      const { getUnpacker } = await import('../utils/unpacker.js');
      const unpacker = getUnpacker();

      expect(typeof unpacker.detect).toBe('function');
      expect(typeof unpacker.unpack).toBe('function');
    });
  });

  describe('MITRE Mapper Integration', () => {
    test('MitreMapper class exists with map method', async () => {
      const { MitreMapper } = await import('../utils/mitre-mapper.js');
      const mapper = new MitreMapper();

      // MitreMapper.map takes AnalysisResults, verify it exists
      expect(typeof mapper.map).toBe('function');
      expect(typeof mapper.toNavigatorLayer).toBe('function');
    });

    test('generates ATT&CK Navigator layer', async () => {
      const { MitreMapper } = await import('../utils/mitre-mapper.js');
      const mapper = new MitreMapper();

      // MitreTechnique requires evidence array
      const techniques = [
        {
          id: 'T1055',
          name: 'Process Injection',
          tactic: 'defense-evasion',
          evidence: ['Test evidence'],
          confidence: 0.8,
        },
      ];
      const layer = mapper.toNavigatorLayer(techniques, 'Test Sample');

      expect(layer.name).toContain('Test Sample');
      expect(layer.techniques).toBeDefined();
    });
  });

  describe('Assembly Extractor Integration', () => {
    test('parses assembly text', async () => {
      const { getAssemblyExtractor } = await import('../utils/assembly-extractor.js');
      const extractor = getAssemblyExtractor();

      // Use objdump format which the parser expects
      const asmText = '  401000:\t55\t\t\tpush   rbp\n  401001:\t48 89 e5\t\tmov    rbp,rsp';
      const instructions = extractor.parseAssemblyText(asmText);

      expect(Array.isArray(instructions)).toBe(true);
      expect(instructions.length).toBe(2);
    });

    test('detects suspicious patterns', async () => {
      const { getAssemblyExtractor } = await import('../utils/assembly-extractor.js');
      const extractor = getAssemblyExtractor();

      const instructions = [
        { address: '0x401000', mnemonic: 'syscall', operands: '', bytes: '' },
        { address: '0x401002', mnemonic: 'int', operands: '0x80', bytes: '' },
      ];
      const patterns = extractor.analyzeInstructions(instructions);

      expect(patterns.length).toBeGreaterThan(0);
    });
  });

  describe('Behavior Predictor Integration', () => {
    test('BehaviorPredictor class exists', async () => {
      const { BehaviorPredictor } = await import('../utils/behavior-predictor.js');
      const predictor = new BehaviorPredictor();
      expect(typeof predictor.predict).toBe('function');
      expect(typeof predictor.augmentTechniques).toBe('function');
    });
  });

  describe('Error Handler Integration', () => {
    test('normalizeError function works', async () => {
      const { normalizeError } = await import('../utils/error-handler.js');

      const error = normalizeError('string error');
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('string error');
    });

    test('categorizeError function works', async () => {
      const { categorizeError } = await import('../utils/error-handler.js');

      const error = new Error('test error');
      const category = categorizeError(error);

      // categorizeError returns { httpStatus, category, retryable, userMessage }
      expect(typeof category.category).toBe('string');
      expect(typeof category.retryable).toBe('boolean');
    });
  });

  describe('Config Integration', () => {
    test('loadConfig function exists', async () => {
      const { loadConfig } = await import('../utils/config.js');
      expect(typeof loadConfig).toBe('function');
    });
  });

  describe('Context Manager Integration', () => {
    test('ContextWindowManager manages context', async () => {
      const { ContextWindowManager, estimateTokens } = await import('../utils/context-manager.js');

      const manager = new ContextWindowManager(8192);

      expect(typeof manager.allocate).toBe('function');

      // Test token estimation
      const tokens = estimateTokens('This is a test string');
      expect(tokens).toBeGreaterThan(0);
    });
  });
});

describe('End-to-End Workflow', () => {
  test('complete analysis workflow components exist', async () => {
    // Verify all workflow components can be imported
    const imports = await Promise.all([
      import('../utils/path-sandbox.js'),
      import('../utils/string-analyzer.js'),
      import('../utils/crypto-detector.js'),
      import('../utils/unpacker.js'),
      import('../utils/mitre-mapper.js'),
      import('../utils/behavior-predictor.js'),
      import('../utils/error-handler.js'),
      import('../utils/config.js'),
    ]);

    expect(imports.length).toBe(8);
    for (const mod of imports) {
      expect(mod).toBeDefined();
    }
  });
});
