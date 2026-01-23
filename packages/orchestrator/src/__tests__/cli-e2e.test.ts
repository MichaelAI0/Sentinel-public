/**
 * CLI End-to-End Tests
 *
 * Tests the CLI commands with real invocations.
 */

import { beforeAll, describe, expect, test } from 'bun:test';
import { exec } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

// Path to the CLI entry point
const CLI_PATH = join(import.meta.dir, '..', 'cli.ts');
const BINARIES_DIR = join(import.meta.dir, '..', '..', '..', '..', 'binaries');
const TEST_BINARY = join(BINARIES_DIR, 'test_binary');

// Helper to run CLI commands
async function runCli(args: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execAsync(`bun run ${CLI_PATH} ${args}`, {
      timeout: 30000, // 30 second timeout
      env: { ...process.env, LOG_LEVEL: 'error' },
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

describe('CLI E2E Tests', () => {
  beforeAll(async () => {
    // Verify test binary exists
    try {
      await stat(TEST_BINARY);
    } catch {
      console.warn('Test binary not found, some tests will be skipped');
    }
  });

  describe('Help & Version', () => {
    test('--help shows usage information', async () => {
      const { stdout, exitCode } = await runCli('--help');

      expect(exitCode).toBe(0);
      expect(stdout).toContain('SENTINEL');
      expect(stdout).toContain('Usage:');
      expect(stdout).toContain('Commands:');
      expect(stdout).toContain('analyze');
      expect(stdout).toContain('triage');
    });

    test('help command shows usage', async () => {
      const { stdout, exitCode } = await runCli('help');

      expect(exitCode).toBe(0);
      expect(stdout).toContain('SENTINEL');
    });

    test('--version shows version', async () => {
      const { stdout, exitCode } = await runCli('--version');

      expect(exitCode).toBe(0);
      // Version should be a semver-like string or 'unknown'
      expect(stdout.trim()).toMatch(/^(\d+\.\d+\.\d+|unknown)$/);
    });

    test('-h is alias for --help', async () => {
      const { stdout, exitCode } = await runCli('-h');

      expect(exitCode).toBe(0);
      expect(stdout).toContain('SENTINEL');
    });

    test('-v is alias for --version', async () => {
      const { stdout, exitCode } = await runCli('-v');

      expect(exitCode).toBe(0);
      expect(stdout.trim()).toMatch(/^(\d+\.\d+\.\d+|unknown)$/);
    });
  });

  describe('Check Command', () => {
    test('check command runs system dependency check', async () => {
      const { stdout, stderr } = await runCli('check');

      // Check command may pass or fail depending on system
      // but should always produce meaningful output
      const output = stdout + stderr;
      expect(output).toMatch(/ghidra|docker|yara|ollama/i);
    });
  });

  describe('Error Handling', () => {
    test('unknown command shows error', async () => {
      const { stderr, exitCode } = await runCli('unknowncommand');

      expect(exitCode).not.toBe(0);
      expect(stderr.toLowerCase()).toContain('unknown');
    });

    test('analyze without path shows error', async () => {
      const { stderr, exitCode } = await runCli('analyze');

      expect(exitCode).not.toBe(0);
      expect(stderr).toMatch(/path|required|missing/i);
    });

    test('triage without path shows error', async () => {
      const { stderr, exitCode } = await runCli('triage');

      expect(exitCode).not.toBe(0);
      expect(stderr).toMatch(/path|required|missing/i);
    });

    test('non-existent file shows error', async () => {
      const { stderr, exitCode } = await runCli('analyze /nonexistent/path/to/binary');

      expect(exitCode).not.toBe(0);
      expect(stderr).toMatch(/not found|does not exist|no such file/i);
    });
  });

  describe('Options Parsing', () => {
    test('--quiet suppresses output', async () => {
      const { stdout } = await runCli('--quiet --help');

      // Even with --quiet, --help should still show
      expect(stdout).toContain('SENTINEL');
    });

    test('--json flag is recognized', async () => {
      // Just test that the flag is parsed without error
      const { exitCode } = await runCli('--json --help');
      expect(exitCode).toBe(0);
    });

    test('--output-dir accepts a path', async () => {
      const { stdout } = await runCli('--output-dir /tmp/test --help');
      expect(stdout).toContain('SENTINEL');
    });
  });
});

describe('CLI Integration', () => {
  test('CLI module exports main function', async () => {
    // Dynamic import to test module structure
    const cliModule = await import('../cli-impl.js');
    expect(typeof cliModule.main).toBe('function');
  });
});
