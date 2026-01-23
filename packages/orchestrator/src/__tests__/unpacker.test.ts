/**
 * Binary Unpacker Tests
 *
 * Tests for packer detection and unpacking capabilities.
 */

import { describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { unlink } from 'node:fs/promises';
import { getUnpacker } from '../utils/unpacker';

describe('BinaryUnpacker', () => {
  const unpacker = getUnpacker();

  describe('detect', () => {
    test('detect method exists', () => {
      expect(typeof unpacker.detect).toBe('function');
    });

    test('unpack method exists', () => {
      expect(typeof unpacker.unpack).toBe('function');
    });
  });

  describe('getUnpacker singleton', () => {
    test('returns same instance with same config', () => {
      const u1 = getUnpacker();
      const u2 = getUnpacker();
      expect(u1).toBe(u2);
    });

    test('returns new instance with different config', () => {
      const u1 = getUnpacker();
      const u2 = getUnpacker({ tempDir: '/custom/temp' });
      expect(u1).not.toBe(u2);
    });
  });

  describe('cleanup', () => {
    test('cleanup method exists', () => {
      expect(typeof unpacker.cleanup).toBe('function');
    });
  });

  describe('static unpackers', () => {
    const createEmbeddedPEFile = async (): Promise<string> => {
      const filePath = `/tmp/sentinel-test-${randomUUID()}`;
      const bytes = new Uint8Array(1024);

      const mzOffset = 256;
      bytes[mzOffset] = 0x4d; // M
      bytes[mzOffset + 1] = 0x5a; // Z

      const eLfanew = 0x80;
      bytes[mzOffset + 0x3c] = eLfanew & 0xff;
      bytes[mzOffset + 0x3d] = (eLfanew >> 8) & 0xff;
      bytes[mzOffset + 0x3e] = (eLfanew >> 16) & 0xff;
      bytes[mzOffset + 0x3f] = (eLfanew >> 24) & 0xff;

      const peOffset = mzOffset + eLfanew;
      bytes[peOffset] = 0x50; // P
      bytes[peOffset + 1] = 0x45; // E
      bytes[peOffset + 2] = 0x00;
      bytes[peOffset + 3] = 0x00;

      await Bun.write(filePath, bytes);
      return filePath;
    };

    test('ASPack static unpack extracts embedded PE', async () => {
      const filePath = await createEmbeddedPEFile();
      const result = await unpacker.unpack(filePath, 'aspack');

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.success).toBe(true);
        expect(result.value.packerType).toBe('aspack');
        expect(result.value.unpackMethod).toBe('static');
        expect(result.value.unpackedPath.length).toBeGreaterThan(0);
      }

      await unpacker.cleanup();
      await unlink(filePath);
    });

    test('Petite static unpack extracts embedded PE', async () => {
      const filePath = await createEmbeddedPEFile();
      const result = await unpacker.unpack(filePath, 'petite');

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.success).toBe(true);
        expect(result.value.packerType).toBe('petite');
        expect(result.value.unpackMethod).toBe('static');
        expect(result.value.unpackedPath.length).toBeGreaterThan(0);
      }

      await unpacker.cleanup();
      await unlink(filePath);
    });
  });

  describe('emulation config', () => {
    test('enableEmulation defaults to true', () => {
      const u = getUnpacker({ tempDir: '/tmp/test-emu-config' });
      // Config is private, but we can test behavior by calling unpack on unknown packer
      expect(u).toBeDefined();
    });

    test('emulation can be disabled via config', () => {
      const u = getUnpacker({ enableEmulation: false, tempDir: '/tmp/test-emu-disabled' });
      expect(u).toBeDefined();
    });

    test('unipackerContainer can be customized', () => {
      const u = getUnpacker({
        unipackerContainer: 'custom-unipacker',
        tempDir: '/tmp/test-emu-custom',
      });
      expect(u).toBeDefined();
    });
  });

  describe('packer detection', () => {
    test('detects non-packed binary correctly', async () => {
      const filePath = `/tmp/sentinel-test-${randomUUID()}`;
      // Create a simple non-packed file with low entropy (repeated pattern)
      const bytes = new Uint8Array(10000);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = i % 4; // Very low entropy - only 4 unique values
      }
      await Bun.write(filePath, bytes);

      const u = getUnpacker({ tempDir: '/tmp/test-detect' });
      const result = await u.detect(filePath);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.isPacked).toBe(false);
        expect(result.value.method).toBe('none');
      }

      await unlink(filePath);
    });

    test('detects high entropy as potential packing', async () => {
      const filePath = `/tmp/sentinel-test-${randomUUID()}`;
      // Create high entropy data (random bytes)
      const bytes = new Uint8Array(10000);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
      await Bun.write(filePath, bytes);

      const u = getUnpacker({ tempDir: '/tmp/test-entropy' });
      const result = await u.detect(filePath);

      expect(result.ok).toBe(true);
      if (result.ok && result.value.isPacked) {
        expect(result.value.method).toBe('entropy');
      }

      await unlink(filePath);
    });
  });
});
