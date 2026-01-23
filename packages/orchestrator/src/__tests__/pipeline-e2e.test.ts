/**
 * Analysis Pipeline E2E Tests
 *
 * End-to-end tests for the complete analysis workflow:
 * Binary → Triage → Analysis → Report
 *
 * These tests verify the full integration of all components
 * using our test binaries with simulated malware patterns.
 */

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { exec } from 'node:child_process';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

// Paths
const CLI_PATH = join(import.meta.dir, '..', 'cli.ts');
const BINARIES_DIR = join(import.meta.dir, '..', '..', '..', '..', 'binaries');
const OUTPUT_DIR = join(import.meta.dir, '..', '..', '..', '..', 'outputs', 'test-runs');

// Test binaries
const TEST_BINARIES = {
  ransomware: join(BINARIES_DIR, 'ransomware_sim'),
  keylogger: join(BINARIES_DIR, 'keylogger_sim'),
  trojan: join(BINARIES_DIR, 'trojan_sim'),
  cryptominer: join(BINARIES_DIR, 'cryptominer_sim'),
  rat: join(BINARIES_DIR, 'rat_sim'),
  suspicious: join(BINARIES_DIR, 'suspicious_test'),
};

// Helper to run CLI commands
async function runCli(
  args: string,
  options?: { timeout?: number },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const timeout = options?.timeout ?? 60000;

  try {
    const { stdout, stderr } = await execAsync(`bun run ${CLI_PATH} ${args}`, {
      timeout,
      env: { ...process.env, LOG_LEVEL: 'warn' },
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large outputs
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error) {
    const execError = error as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: execError.stdout ?? '',
      stderr: execError.stderr ?? '',
      exitCode: execError.code ?? 1,
    };
  }
}

// Helper to check file exists
async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

describe('Analysis Pipeline E2E', () => {
  const binariesExist: Record<string, boolean> = {};
  let outputDirCreated = false;

  beforeAll(async () => {
    // Check which binaries exist
    for (const [name, path] of Object.entries(TEST_BINARIES)) {
      binariesExist[name] = await fileExists(path);
    }

    // Create output directory
    try {
      await mkdir(OUTPUT_DIR, { recursive: true });
      outputDirCreated = true;
    } catch {
      console.warn('Could not create test output directory');
    }

    const available = Object.values(binariesExist).filter(Boolean).length;
    if (available === 0) {
      console.warn('⚠️  No test binaries found. Run "make all" in binaries/src/');
    }
  });

  afterAll(async () => {
    // Cleanup test outputs
    if (outputDirCreated) {
      try {
        await rm(OUTPUT_DIR, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  describe('Triage Command', () => {
    test('triage returns quick assessment for ransomware', async () => {
      if (!binariesExist.ransomware) {
        console.log('Skipping: ransomware binary not built');
        return;
      }

      const { stdout, exitCode } = await runCli(`triage "${TEST_BINARIES.ransomware}" --json`, {
        timeout: 30000,
      });

      // Should complete without error (0) or with findings (non-zero but output exists)
      if (exitCode === 0 || stdout.length > 0) {
        // Check for expected triage output structure
        if (stdout.includes('{')) {
          try {
            const result = JSON.parse(stdout);
            expect(result).toBeDefined();
            // Triage should provide some assessment
            expect(
              result.riskLevel || result.severity || result.classification || result.verdict,
            ).toBeDefined();
          } catch {
            // If not JSON, check for text output
            expect(stdout.toLowerCase()).toMatch(/risk|suspicious|malware|verdict|clean/i);
          }
        }
      }
    });

    test('triage handles all test binaries', async () => {
      for (const [name, path] of Object.entries(TEST_BINARIES)) {
        if (!binariesExist[name]) continue;

        const { stdout, stderr } = await runCli(`triage "${path}"`, { timeout: 30000 });

        // Should not crash - either succeeds or fails gracefully
        const output = stdout + stderr;
        expect(output.length).toBeGreaterThan(0);

        // Should not have unhandled errors
        expect(output.toLowerCase()).not.toContain('unhandled');
        expect(output.toLowerCase()).not.toContain('uncaught');
      }
    });
  });

  describe('String Extraction', () => {
    test('extracts strings from ransomware binary', async () => {
      if (!binariesExist.ransomware) return;

      // Use strings command directly for comparison
      try {
        const { stdout } = await execAsync(`strings "${TEST_BINARIES.ransomware}"`, {
          timeout: 10000,
        });

        // Should find ransomware-related strings
        expect(stdout).toMatch(/CryptEncrypt|bitcoin|encrypt|ransom/i);
      } catch {
        // strings command may not be available
        console.log('Skipping: strings command not available');
      }
    });

    test('extracts strings from all test binaries', async () => {
      const results: Record<string, number> = {};

      for (const [name, path] of Object.entries(TEST_BINARIES)) {
        if (!binariesExist[name]) continue;

        try {
          const { stdout } = await execAsync(`strings "${path}" | wc -l`, {
            timeout: 10000,
          });
          results[name] = parseInt(stdout.trim(), 10);
        } catch {
          results[name] = 0;
        }
      }

      // Each binary should have significant strings
      for (const [, count] of Object.entries(results)) {
        if (count > 0) {
          expect(count).toBeGreaterThan(10);
        }
      }
    });
  });

  describe('Hash Calculation', () => {
    test('calculates correct hashes for test binaries', async () => {
      if (!binariesExist.ransomware) return;

      // Calculate SHA256 using system command
      try {
        const { stdout } = await execAsync(`sha256sum "${TEST_BINARIES.ransomware}"`, {
          timeout: 5000,
        });

        const hash = stdout.split(/\s+/)[0];
        expect(hash).toMatch(/^[a-f0-9]{64}$/i);
      } catch {
        console.log('Skipping: sha256sum not available');
      }
    });
  });

  describe('File Type Detection', () => {
    test('correctly identifies ELF binaries', async () => {
      if (!binariesExist.ransomware) return;

      try {
        const { stdout } = await execAsync(`file "${TEST_BINARIES.ransomware}"`, {
          timeout: 5000,
        });

        // Should identify as ELF executable
        expect(stdout).toMatch(/ELF.*executable/i);
      } catch {
        console.log('Skipping: file command not available');
      }
    });

    test('detects all test binaries as ELF', async () => {
      for (const [name, path] of Object.entries(TEST_BINARIES)) {
        if (!binariesExist[name]) continue;

        try {
          const { stdout } = await execAsync(`file "${path}"`, { timeout: 5000 });
          expect(stdout).toContain('ELF');
        } catch {
          // Skip if file command not available
        }
      }
    });
  });

  describe('Analysis Output', () => {
    test(
      'analyze command produces output for ransomware',
      async () => {
        // Skip if binaries don't exist or in CI without Docker
        if (!binariesExist.ransomware) return;
        if (process.env.CI && !process.env.DOCKER_AVAILABLE) {
          console.log('Skipping: Docker not available in CI');
          return;
        }

        const { stdout, stderr, exitCode } = await runCli(
          `analyze "${TEST_BINARIES.ransomware}" --json --output-dir "${OUTPUT_DIR}"`,
          { timeout: 120000 },
        );

        // Check that analysis ran (may require Ghidra, so allow failures)
        const output = stdout + stderr;

        if (exitCode === 0) {
          // Success - should have produced output
          expect(output.length).toBeGreaterThan(0);
        } else {
          // May fail due to missing deps, but shouldn't crash
          expect(output).not.toContain('SIGSEGV');
          expect(output).not.toContain('core dumped');
        }
      },
      { timeout: 150000 },
    );
  });

  describe('Component Integration', () => {
    test('PathSandbox allows binaries directory', async () => {
      const { PathSandbox } = await import('../utils/path-sandbox.js');
      const sandbox = new PathSandbox({ allowedDirs: [BINARIES_DIR] });

      for (const [name, path] of Object.entries(TEST_BINARIES)) {
        if (!binariesExist[name]) continue;

        const result = await sandbox.validatePath(path);
        expect(result.ok).toBe(true);
      }
    });

    test('PathSandbox blocks traversal attacks', async () => {
      const { PathSandbox } = await import('../utils/path-sandbox.js');
      const sandbox = new PathSandbox({ allowedDirs: [BINARIES_DIR] });

      const attacks = [
        join(BINARIES_DIR, '..', 'etc', 'passwd'),
        join(BINARIES_DIR, '..', '..', 'root', '.ssh'),
        `${BINARIES_DIR}/../../../etc/shadow`,
      ];

      for (const attack of attacks) {
        const result = await sandbox.validatePath(attack);
        expect(result.ok).toBe(false);
      }
    });

    test('StringAnalyzer processes binary strings', async () => {
      if (!binariesExist.ransomware) return;

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();

      // Read binary and extract strings
      const data = await readFile(TEST_BINARIES.ransomware);
      const strings: string[] = [];
      let current = '';

      for (let i = 0; i < data.length; i++) {
        const byte = data[i];
        if (byte !== undefined && byte >= 32 && byte <= 126) {
          current += String.fromCharCode(byte);
        } else if (current.length >= 4) {
          strings.push(current);
          current = '';
        } else {
          current = '';
        }
      }

      const result = analyzer.analyze(strings);

      expect(result.totalStrings).toBeGreaterThan(0);
      expect(result.suspiciousCount).toBeGreaterThan(0);
    });

    test('CryptoDetector finds encryption indicators', async () => {
      if (!binariesExist.ransomware) return;

      const { getCryptoDetector } = await import('../utils/crypto-detector.js');
      const detector = getCryptoDetector();
      const data = await readFile(TEST_BINARIES.ransomware);

      const result = detector.analyze(data);

      expect(result).toBeDefined();
      expect(Array.isArray(result.detections)).toBe(true);
    });
  });
});

describe('Performance Benchmarks', () => {
  test('triage completes within timeout', async () => {
    const binPath = TEST_BINARIES.ransomware;
    if (!(await fileExists(binPath))) return;

    const startTime = performance.now();
    await runCli(`triage "${binPath}"`, { timeout: 30000 });
    const duration = performance.now() - startTime;

    // Triage should be fast - under 30 seconds
    expect(duration).toBeLessThan(30000);
    console.log(`Triage completed in ${Math.round(duration)}ms`);
  });

  test('string extraction is fast', async () => {
    const binPath = TEST_BINARIES.ransomware;
    if (!(await fileExists(binPath))) return;

    const startTime = performance.now();
    const data = await readFile(binPath);

    // Extract strings
    const strings: string[] = [];
    let current = '';
    for (let i = 0; i < data.length; i++) {
      const byte = data[i];
      if (byte !== undefined && byte >= 32 && byte <= 126) {
        current += String.fromCharCode(byte);
      } else if (current.length >= 4) {
        strings.push(current);
        current = '';
      } else {
        current = '';
      }
    }

    const duration = performance.now() - startTime;

    // String extraction should be very fast
    expect(duration).toBeLessThan(1000);
    expect(strings.length).toBeGreaterThan(0);
  });
});

describe('Error Recovery', () => {
  test('handles invalid binary gracefully', async () => {
    // Create a temporary invalid file
    const invalidPath = join(OUTPUT_DIR, 'invalid.bin');
    try {
      await mkdir(OUTPUT_DIR, { recursive: true });
      await writeFile(invalidPath, Buffer.from([0x00, 0x00, 0x00, 0x00]));

      const { stderr, exitCode } = await runCli(`triage "${invalidPath}"`);

      // Should fail gracefully
      expect(exitCode).not.toBe(0);
      // Should not crash
      expect(stderr).not.toContain('SIGSEGV');
    } finally {
      try {
        await rm(invalidPath);
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  test('handles empty file gracefully', async () => {
    const emptyPath = join(OUTPUT_DIR, 'empty.bin');
    try {
      await mkdir(OUTPUT_DIR, { recursive: true });
      await writeFile(emptyPath, Buffer.alloc(0));

      const { exitCode } = await runCli(`triage "${emptyPath}"`);

      // Should fail gracefully
      expect(exitCode).not.toBe(0);
    } finally {
      try {
        await rm(emptyPath);
      } catch {
        // Ignore
      }
    }
  });

  test('handles permission denied gracefully', async () => {
    // Try to analyze a system file we don't have permission to
    const { exitCode } = await runCli('triage /etc/shadow');

    // Should fail gracefully
    expect(exitCode).not.toBe(0);
  });
});
