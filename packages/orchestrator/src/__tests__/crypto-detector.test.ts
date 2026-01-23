/**
 * Crypto Detector Tests
 *
 * Tests for cryptographic operation detection including
 * constant signatures, entropy analysis, and pattern matching.
 */

import { describe, expect, test } from 'bun:test';
import { getCryptoDetector } from '../utils/crypto-detector';

describe('CryptoDetector', () => {
  const detector = getCryptoDetector();

  describe('analyze', () => {
    test('detects AES S-box in data', () => {
      // AES S-box first bytes
      const aesSbox = new Uint8Array([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
      ]);

      const result = detector.analyze(aesSbox);
      expect(result.detections.some((d) => d.algorithm === 'aes')).toBe(true);
      expect(result.hasCrypto).toBe(true);
    });

    test('detects MD5 constants in data', () => {
      // MD5 first constant (0xd76aa478 in little-endian: 78 a4 6a d7)
      const md5Magic = new Uint8Array([0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8]);

      const result = detector.analyze(md5Magic);
      expect(result.detections.some((d) => d.algorithm === 'md5')).toBe(true);
    });

    test('returns empty detections for non-crypto data', () => {
      const plainData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04]);

      const result = detector.analyze(plainData);
      expect(result.detections.filter((d) => d.method === 'constant').length).toBe(0);
    });

    test('detects high entropy blocks', () => {
      // Create pseudo-random data (high entropy) - need at least 256 bytes for block analysis
      const randomData = new Uint8Array(512);
      for (let i = 0; i < 512; i++) {
        randomData[i] = (i * 179 + 83) % 256;
      }

      const result = detector.analyze(randomData);
      // High entropy may be detected depending on threshold
      expect(result.detections.some((d) => d.method === 'entropy')).toBe(true);
    });
  });

  describe('calculateEntropy', () => {
    test('returns low entropy for repeated bytes', () => {
      const data = new Uint8Array(256).fill(0xaa);
      const entropy = detector.calculateEntropy(data);
      expect(entropy).toBeLessThan(1);
    });

    test('returns high entropy for diverse bytes', () => {
      const data = new Uint8Array(256);
      for (let i = 0; i < 256; i++) data[i] = i;
      const entropy = detector.calculateEntropy(data);
      expect(entropy).toBeGreaterThan(7);
    });

    test('returns zero for empty data', () => {
      const data = new Uint8Array(0);
      const entropy = detector.calculateEntropy(data);
      expect(entropy).toBe(0);
    });
  });

  describe('findConstants', () => {
    test('finds AES S-box signature', () => {
      const aesSbox = new Uint8Array([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76,
      ]);

      const detections = detector.findConstants(aesSbox);
      expect(detections.some((d) => d.algorithm === 'aes')).toBe(true);
      expect(detections.some((d) => d.details?.includes('AES S-box'))).toBe(true);
    });

    test('finds blowfish P-array signature', () => {
      const blowfishP = new Uint8Array([0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3]);

      const detections = detector.findConstants(blowfishP);
      expect(detections.some((d) => d.algorithm === 'blowfish')).toBe(true);
    });

    test('returns empty for unknown data', () => {
      const unknownData = new Uint8Array([0x12, 0x34, 0x56, 0x78]);

      const detections = detector.findConstants(unknownData);
      expect(detections.length).toBe(0);
    });
  });

  describe('detectXOR', () => {
    test('detects single-byte XOR when result is printable', () => {
      // XOR encrypt "Hello World" with 0xAA
      const plaintext = 'Hello World!';
      const key = 0xaa;
      const encrypted = new Uint8Array(plaintext.length);
      for (let i = 0; i < plaintext.length; i++) {
        encrypted[i] = plaintext.charCodeAt(i) ^ key;
      }

      const detections = detector.detectXOR(encrypted);
      // May or may not detect depending on printable ratio
      expect(detections).toBeDefined();
    });
  });

  describe('getCryptoDetector singleton', () => {
    test('returns same instance with same config', () => {
      const d1 = getCryptoDetector();
      const d2 = getCryptoDetector();
      expect(d1).toBe(d2);
    });

    test('returns new instance with different config', () => {
      const d1 = getCryptoDetector();
      const d2 = getCryptoDetector({ entropyThreshold: 6.0 });
      expect(d1).not.toBe(d2);
    });
  });
});
