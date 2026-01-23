/**
 * SENTINEL Signature Updater Tests
 */

import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SignatureUpdater } from './signature-updater.js';

describe('SignatureUpdater', () => {
  const testRulesDir = './test-rules-temp';

  beforeEach(() => {
    // Clean up before each test
    if (existsSync(testRulesDir)) {
      rmSync(testRulesDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up after each test
    if (existsSync(testRulesDir)) {
      rmSync(testRulesDir, { recursive: true });
    }
  });

  describe('constructor', () => {
    it('should use default config when no options provided', () => {
      const updater = new SignatureUpdater();
      expect(updater.getRulesDir()).toContain('rules');
    });

    it('should accept custom rules directory', () => {
      const updater = new SignatureUpdater({ rulesDir: testRulesDir });
      expect(updater.getRulesDir()).toContain('test-rules-temp');
    });
  });

  describe('checkForUpdates', () => {
    it('should return needsUpdate=true when no previous update exists', () => {
      const updater = new SignatureUpdater({ rulesDir: testRulesDir });
      const result = updater.checkForUpdates();

      expect(result.needsUpdate).toBe(true);
      expect(result.lastUpdateTime).toBeNull();
      expect(result.hoursSinceUpdate).toBeNull();
    });

    it('should return needsUpdate=false when recently updated', () => {
      // Create rules directory and update file
      mkdirSync(testRulesDir, { recursive: true });
      writeFileSync(join(testRulesDir, '.last-update'), Date.now().toString());

      const updater = new SignatureUpdater({
        rulesDir: testRulesDir,
        updateIntervalHours: 24,
      });

      const result = updater.checkForUpdates();

      expect(result.needsUpdate).toBe(false);
      expect(result.lastUpdateTime).not.toBeNull();
      expect(result.hoursSinceUpdate).toBeLessThan(1);
    });

    it('should return needsUpdate=true when update interval exceeded', () => {
      // Create rules directory and old update file
      mkdirSync(testRulesDir, { recursive: true });
      const oldTime = Date.now() - 25 * 60 * 60 * 1000; // 25 hours ago
      writeFileSync(join(testRulesDir, '.last-update'), oldTime.toString());

      const updater = new SignatureUpdater({
        rulesDir: testRulesDir,
        updateIntervalHours: 24,
      });

      const result = updater.checkForUpdates();

      expect(result.needsUpdate).toBe(true);
      expect(result.hoursSinceUpdate).toBeGreaterThan(24);
    });
  });

  describe('listRuleFiles', () => {
    it('should return empty array when rules directory does not exist', () => {
      const updater = new SignatureUpdater({ rulesDir: testRulesDir });
      const files = updater.listRuleFiles();

      expect(files).toEqual([]);
    });

    it('should find .yar and .yara files', () => {
      // Create test structure
      mkdirSync(join(testRulesDir, 'subdir'), { recursive: true });
      writeFileSync(join(testRulesDir, 'test1.yar'), 'rule test1 { condition: true }');
      writeFileSync(join(testRulesDir, 'test2.yara'), 'rule test2 { condition: true }');
      writeFileSync(join(testRulesDir, 'subdir', 'test3.yar'), 'rule test3 { condition: true }');
      writeFileSync(join(testRulesDir, 'ignored.txt'), 'not a rule');

      const updater = new SignatureUpdater({ rulesDir: testRulesDir });
      const files = updater.listRuleFiles();

      expect(files.length).toBe(3);
      expect(files.some((f) => f.includes('test1.yar'))).toBe(true);
      expect(files.some((f) => f.includes('test2.yara'))).toBe(true);
      expect(files.some((f) => f.includes('test3.yar'))).toBe(true);
    });
  });

  describe('verifyRules', () => {
    it('should return zeros when no rules directory exists', () => {
      const updater = new SignatureUpdater({ rulesDir: testRulesDir });
      const result = updater.verifyRules();

      expect(result.valid).toBe(0);
      expect(result.invalid).toBe(0);
      expect(result.invalidFiles).toEqual([]);
    });
  });

  // Note: updateRules() is not tested directly as it requires network access
  // and git operations. Integration tests should cover this functionality.
});
