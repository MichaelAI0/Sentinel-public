/**
 * SENTINEL Signature Updater
 *
 * Automatically updates YARA rules from GitHub repositories.
 * Checks for updates periodically and downloads new rules.
 */

import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { logger } from './logger.js';

/**
 * Result of an update check
 */
export type UpdateCheckResult = {
  readonly needsUpdate: boolean;
  readonly lastUpdateTime: number | null;
  readonly hoursSinceUpdate: number | null;
};

/**
 * Result of a rules update
 */
export type UpdateResult = {
  readonly success: boolean;
  readonly rulesCount: number;
  readonly message: string;
};

/**
 * Result of rule verification
 */
export type VerificationResult = {
  readonly valid: number;
  readonly invalid: number;
  readonly invalidFiles: readonly string[];
};

/**
 * Configuration options for SignatureUpdater
 */
export type SignatureUpdaterConfig = {
  readonly rulesDir: string;
  readonly updateIntervalHours: number;
  readonly repositories: readonly string[];
};

const DEFAULT_CONFIG = {
  rulesDir: './rules',
  updateIntervalHours: 24,
  repositories: ['https://github.com/Yara-Rules/rules.git'],
} as const satisfies SignatureUpdaterConfig;

/**
 * Manages YARA rule updates from remote repositories.
 */
export class SignatureUpdater {
  private readonly config: SignatureUpdaterConfig;
  private readonly updateCheckFile: string;

  public constructor(config: Partial<SignatureUpdaterConfig> = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
    };
    this.updateCheckFile = join(this.config.rulesDir, '.last-update');
  }

  /**
   * Check if updates are needed based on the configured interval.
   */
  public checkForUpdates(): UpdateCheckResult {
    const lastUpdateTime = this.getLastUpdateTime();

    if (lastUpdateTime === null) {
      return {
        needsUpdate: true,
        lastUpdateTime: null,
        hoursSinceUpdate: null,
      };
    }

    const now = Date.now();
    const hoursSinceUpdate = (now - lastUpdateTime) / (1000 * 60 * 60);
    const needsUpdate = hoursSinceUpdate >= this.config.updateIntervalHours;

    return {
      needsUpdate,
      lastUpdateTime,
      hoursSinceUpdate: Math.round(hoursSinceUpdate * 10) / 10,
    };
  }

  /**
   * Update rules from all configured repositories.
   */
  public async updateRules(): Promise<UpdateResult> {
    logger.info('Updating YARA rules...');

    try {
      // Ensure rules directory exists
      const rulesDir = resolve(this.config.rulesDir);
      if (!existsSync(rulesDir)) {
        mkdirSync(rulesDir, { recursive: true });
      }

      let totalRulesCount = 0;

      for (const repoUrl of this.config.repositories) {
        const result = await this.updateFromRepository(repoUrl);
        totalRulesCount += result;
      }

      // Record update time
      this.recordUpdateTime();

      logger.info(`✅ YARA rules updated: ${totalRulesCount} rule files found`);

      return {
        success: true,
        rulesCount: totalRulesCount,
        message: `Successfully updated ${totalRulesCount} rule files`,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn(`Failed to update rules: ${message}`);

      return {
        success: false,
        rulesCount: 0,
        message: `Update failed: ${message}`,
      };
    }
  }

  /**
   * Update rules from a single repository.
   */
  private async updateFromRepository(repoUrl: string): Promise<number> {
    const repoName = this.extractRepoName(repoUrl);
    const targetDir = join(this.config.rulesDir, repoName);

    if (existsSync(targetDir)) {
      // Pull updates
      logger.debug(`Pulling updates for ${repoName}...`);
      this.runGitCommand(`cd "${targetDir}" && git pull --quiet`);
    } else {
      // Clone fresh
      logger.debug(`Cloning ${repoName}...`);
      this.runGitCommand(`git clone --depth 1 --quiet "${repoUrl}" "${targetDir}"`);
    }

    return this.countRuleFiles(targetDir);
  }

  /**
   * Extract repository name from URL.
   */
  private extractRepoName(repoUrl: string): string {
    const match = repoUrl.match(/\/([^/]+?)(?:\.git)?$/);
    return match?.[1] ?? 'rules';
  }

  /**
   * Run a git command safely.
   */
  private runGitCommand(command: string): void {
    try {
      execSync(command, {
        stdio: 'pipe',
        encoding: 'utf-8',
        timeout: 120000, // 2 minute timeout
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Git command failed: ${message}`);
    }
  }

  /**
   * Count .yar and .yara files in a directory.
   */
  private countRuleFiles(dir: string): number {
    let count = 0;

    const processDir = (currentDir: string): void => {
      const entries = readdirSync(currentDir);

      for (const entry of entries) {
        const fullPath = join(currentDir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory() && !entry.startsWith('.')) {
          processDir(fullPath);
        } else if (stat.isFile() && (entry.endsWith('.yar') || entry.endsWith('.yara'))) {
          count++;
        }
      }
    };

    processDir(dir);
    return count;
  }

  /**
   * Verify integrity of all rule files.
   * Note: Requires yara or yara-x to be installed.
   */
  public verifyRules(): VerificationResult {
    const invalidFiles: string[] = [];
    let valid = 0;
    let invalid = 0;

    const rulesDir = resolve(this.config.rulesDir);
    if (!existsSync(rulesDir)) {
      return { valid: 0, invalid: 0, invalidFiles: [] };
    }

    const processDir = (dir: string): void => {
      const entries = readdirSync(dir);

      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory() && !entry.startsWith('.')) {
          processDir(fullPath);
        } else if (stat.isFile() && (entry.endsWith('.yar') || entry.endsWith('.yara'))) {
          if (this.verifyRuleFile(fullPath)) {
            valid++;
          } else {
            invalid++;
            invalidFiles.push(fullPath);
          }
        }
      }
    };

    processDir(rulesDir);

    return { valid, invalid, invalidFiles };
  }

  /**
   * Verify a single rule file.
   */
  private verifyRuleFile(filePath: string): boolean {
    try {
      // Try yara first, then yara-x
      try {
        execSync(`yara --version`, { stdio: 'pipe' });
        execSync(`yara -w "${filePath}" /dev/null`, { stdio: 'pipe' });
        return true;
      } catch {
        // yara not available, try yara-x
        execSync(`yara-x check "${filePath}"`, { stdio: 'pipe' });
        return true;
      }
    } catch {
      return false;
    }
  }

  /**
   * Get the last update time from the checkpoint file.
   */
  private getLastUpdateTime(): number | null {
    try {
      if (!existsSync(this.updateCheckFile)) {
        return null;
      }
      // Use sync read for simplicity
      const data = require('node:fs').readFileSync(this.updateCheckFile, 'utf-8');
      const timestamp = parseInt(data.trim(), 10);
      return Number.isNaN(timestamp) ? null : timestamp;
    } catch {
      return null;
    }
  }

  /**
   * Record the current time as the last update time.
   */
  private recordUpdateTime(): void {
    const rulesDir = resolve(this.config.rulesDir);
    if (!existsSync(rulesDir)) {
      mkdirSync(rulesDir, { recursive: true });
    }
    writeFileSync(this.updateCheckFile, Date.now().toString());
  }

  /**
   * Get the rules directory path.
   */
  public getRulesDir(): string {
    return resolve(this.config.rulesDir);
  }

  /**
   * List all available rule files.
   */
  public listRuleFiles(): readonly string[] {
    const rulesDir = resolve(this.config.rulesDir);
    if (!existsSync(rulesDir)) {
      return [];
    }

    const files: string[] = [];

    const processDir = (dir: string): void => {
      const entries = readdirSync(dir);

      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory() && !entry.startsWith('.')) {
          processDir(fullPath);
        } else if (stat.isFile() && (entry.endsWith('.yar') || entry.endsWith('.yara'))) {
          files.push(fullPath);
        }
      }
    };

    processDir(rulesDir);
    return files;
  }
}
