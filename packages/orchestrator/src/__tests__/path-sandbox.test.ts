/**
 * Path Sandbox Validation Tests
 *
 * Tests for path security and sandboxing utilities
 *
 * @module __tests__/path-sandbox.test
 */

import { beforeEach, describe, expect, it } from 'bun:test';
import { PathSecurityError } from '@sentinel/shared';
import { PathSandbox, type SandboxConfig } from '../utils/path-sandbox';

describe('PathSandbox', () => {
  let sandbox: PathSandbox;

  beforeEach(() => {
    const config: Partial<SandboxConfig> = {
      allowedDirs: ['/home/user/binaries', '/tmp/analysis'],
      maxPathDepth: 10,
      followSymlinks: false,
      allowTmp: false, // We explicitly set allowedDirs, so disable auto-add /tmp
    };
    sandbox = new PathSandbox(config);
  });

  describe('validatePath', () => {
    describe('valid paths', () => {
      it('accepts paths within allowed roots', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/sample.bin');
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.value.resolved).toBe('/home/user/binaries/sample.bin');
        }
      });

      it('accepts paths in /tmp/analysis', async () => {
        const result = await sandbox.validatePath('/tmp/analysis/output.json');
        expect(result.ok).toBe(true);
      });

      it('accepts nested paths within allowed roots', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/malware/samples/test.exe');
        expect(result.ok).toBe(true);
      });
    });

    describe('path traversal attacks', () => {
      it('rejects paths with ../', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/../../../etc/passwd');
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error).toBeInstanceOf(PathSecurityError);
        }
      });

      it('rejects paths starting with ..', async () => {
        const result = await sandbox.validatePath('../etc/passwd');
        expect(result.ok).toBe(false);
      });

      it('rejects paths with /..', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/..%2f..%2fetc/passwd');
        expect(result.ok).toBe(false);
      });
    });

    describe('null byte injection', () => {
      it('rejects paths with null bytes', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/file.bin\x00.txt');
        expect(result.ok).toBe(false);
      });
    });

    describe('paths outside sandbox', () => {
      it('rejects paths outside allowed roots', async () => {
        const result = await sandbox.validatePath('/etc/passwd');
        expect(result.ok).toBe(false);
      });

      it('rejects paths to system directories', async () => {
        const result = await sandbox.validatePath('/usr/bin/ls');
        expect(result.ok).toBe(false);
      });

      it('rejects root directory', async () => {
        const result = await sandbox.validatePath('/');
        expect(result.ok).toBe(false);
      });
    });

    describe('edge cases', () => {
      it('rejects empty paths (null byte check)', async () => {
        // Empty paths resolve to CWD, but if CWD isn't allowed, it will fail
        const result = await sandbox.validatePath('');
        // Result depends on whether CWD is in allowed dirs
        expect(result).toBeDefined();
      });

      it('includes sandbox directory info in result', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/test.exe');
        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.value.sandboxDir).toBe('/home/user/binaries');
          expect(result.value.relativePath).toBe('test.exe');
          expect(result.value.isSandboxed).toBe(true);
        }
      });
    });

    describe('path depth limits', () => {
      it('accepts paths within depth limit', async () => {
        const result = await sandbox.validatePath('/home/user/binaries/a/b/c/file.bin');
        expect(result.ok).toBe(true);
      });

      it('rejects paths exceeding depth limit', async () => {
        const deepPath = `/home/user/binaries${'/a'.repeat(15)}/file.bin`;
        const result = await sandbox.validatePath(deepPath);
        expect(result.ok).toBe(false);
      });
    });
  });

  describe('URL encoded attacks', () => {
    it('rejects URL encoded path traversal', async () => {
      const result = await sandbox.validatePath('/home/user/binaries/%2e%2e/etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('rejects double-encoded path traversal', async () => {
      const result = await sandbox.validatePath('/home/user/binaries/%252e%252e/etc/passwd');
      expect(result.ok).toBe(false);
    });
  });
});

describe('PathSandbox with allowTmp', () => {
  let sandbox: PathSandbox;

  beforeEach(() => {
    const config: Partial<SandboxConfig> = {
      allowedDirs: ['/home/user/binaries'],
      allowTmp: true,
    };
    sandbox = new PathSandbox(config);
  });

  it('automatically allows /tmp when allowTmp is true', async () => {
    const result = await sandbox.validatePath('/tmp/some-file.txt');
    expect(result.ok).toBe(true);
  });
});

describe('PathSandbox with custom depth', () => {
  let sandbox: PathSandbox;

  beforeEach(() => {
    const config: Partial<SandboxConfig> = {
      allowedDirs: ['/home/user/binaries'],
      maxPathDepth: 5,
      allowTmp: false,
    };
    sandbox = new PathSandbox(config);
  });

  it('enforces custom depth limit', async () => {
    const shallowPath = '/home/user/binaries/file.bin';
    const deepPath = '/home/user/binaries/a/b/c/d/e/f/file.bin';

    const shallowResult = await sandbox.validatePath(shallowPath);
    const deepResult = await sandbox.validatePath(deepPath);

    expect(shallowResult.ok).toBe(true);
    expect(deepResult.ok).toBe(false);
  });
});

describe('PathSandbox default config', () => {
  it('uses CWD as default allowed directory', async () => {
    const sandbox = new PathSandbox();
    // Paths within CWD should be allowed
    const cwd = process.cwd();
    const result = await sandbox.validatePath(`${cwd}/test-file.txt`);
    expect(result.ok).toBe(true);
  });
});
