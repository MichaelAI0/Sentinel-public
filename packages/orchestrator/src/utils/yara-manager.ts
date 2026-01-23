/**
 * YARA Manager
 *
 * Manages YARA rule loading, scanning, and result processing.
 * Provides integration with yara-x CLI for binary signature matching.
 * Supports hot-reloading of rules for continuous monitoring.
 * Supports synchronization with remote rule repositories.
 *
 * @module utils/yara-manager
 *
 * @todo Phase 4: Add custom rule editor integration
 * @todo Phase 4: Add YARA rule performance profiling
 */

import { exec } from 'node:child_process';
import {
  existsSync,
  type FSWatcher,
  mkdirSync,
  readdirSync,
  readFileSync,
  watch,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { getLogger } from '@logtape/logtape';
import type { YARAMatch, YARAScanResult, YARASeverity } from '@sentinel/shared';
import { err, ok, type Result } from '@sentinel/shared';

const execAsync = promisify(exec);
const logger = getLogger(['sentinel', 'yara-manager']);

// ============================================
// TYPES
// ============================================

/**
 * Remote repository configuration
 */
export type RemoteRuleRepository = {
  /** Unique identifier for the repository */
  id: string;
  /** Display name */
  name: string;
  /** Repository URL (git, http, or local path) */
  url: string;
  /** Repository type */
  type: 'git' | 'http' | 'local';
  /** Subdirectory containing rules (optional) */
  rulesPath?: string;
  /** Branch for git repositories */
  branch?: string;
  /** Auto-sync interval in milliseconds (0 = disabled) */
  syncIntervalMs?: number;
  /** Whether the repository is enabled */
  enabled?: boolean;
  /** Authentication token for private repositories */
  authToken?: string;
};

/**
 * Repository sync status
 */
export type RepositorySyncStatus = {
  id: string;
  name: string;
  lastSync: number;
  lastSyncSuccess: boolean;
  rulesCount: number;
  error?: string;
  nextSync?: number;
};

export type YARAManagerConfig = {
  /** Directory containing YARA rule files */
  rulesDir: string;
  /** Timeout for scans in milliseconds */
  timeoutMs: number;
  /** Maximum matches per rule */
  maxMatchesPerRule: number;
  /** Path to yara-x executable (auto-detect if not specified) */
  yaraExecutable?: string;
  /** Enable hot-reloading of rules when files change */
  enableHotReload?: boolean;
  /** Debounce interval for hot-reload in milliseconds */
  hotReloadDebounceMs?: number;
  /** Callback when rules are reloaded */
  onRulesReloaded?: (ruleCount: number) => void;
  /** Remote rule repositories to sync */
  remoteRepositories?: RemoteRuleRepository[];
  /** Directory to store synced remote rules */
  remoteCacheDir?: string;
  /** Enable automatic repository sync on initialization */
  autoSyncOnInit?: boolean;
};

export type RuleFile = {
  path: string;
  namespace: string;
  rulesCount: number;
};

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_CONFIG: YARAManagerConfig = {
  rulesDir: './rules',
  timeoutMs: 60_000,
  maxMatchesPerRule: 100,
  enableHotReload: false,
  hotReloadDebounceMs: 1000,
  remoteRepositories: [],
  remoteCacheDir: './rules/remote',
  autoSyncOnInit: false,
};

// ============================================
// YARA MANAGER CLASS
// ============================================

export class YARAManager {
  private readonly config: YARAManagerConfig;
  private yaraExecutable: string | null = null;
  private ruleFiles: RuleFile[] = [];
  private initialized = false;
  private fileWatcher: FSWatcher | null = null;
  private reloadTimeout: ReturnType<typeof setTimeout> | null = null;
  private isReloading = false;
  private lastReloadTime = 0;
  private repositoryStatus: Map<string, RepositorySyncStatus> = new Map();
  private syncTimers: Map<string, ReturnType<typeof setInterval>> = new Map();

  constructor(config: Partial<YARAManagerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }
  /**
   * Checks for yara-x installation and loads rules
   */
  async initialize(): Promise<Result<void, Error>> {
    if (this.initialized) {
      return ok(undefined);
    }

    // Find YARA binary
    const binaryResult = await this.findYARABinary();
    if (!binaryResult.ok) {
      return binaryResult;
    }
    this.yaraExecutable = binaryResult.value;

    // Load rule files
    const rulesResult = await this.discoverRules();
    if (!rulesResult.ok) {
      logger.warn`Failed to discover YARA rules: ${rulesResult.error.message}`;
      // Continue without rules - scanning will return empty results
    } else {
      this.ruleFiles = rulesResult.value;
      logger.info`Loaded ${this.ruleFiles.length} YARA rule files`;
    }

    this.initialized = true;

    // Start hot-reloading if enabled
    if (this.config.enableHotReload) {
      this.startWatching();
    }

    // Sync remote repositories if enabled
    if (this.config.autoSyncOnInit && this.config.remoteRepositories?.length) {
      await this.syncAllRepositories();
    }

    // Start auto-sync timers for repositories with intervals
    this.startAutoSync();

    return ok(undefined);
  }

  /**
   * Start watching for rule file changes (hot-reloading)
   */
  startWatching(): void {
    if (this.fileWatcher) {
      return; // Already watching
    }

    try {
      this.fileWatcher = watch(this.config.rulesDir, { recursive: true }, (eventType, filename) => {
        if (!filename) return;

        // Only react to .yar/.yara files
        if (!filename.endsWith('.yar') && !filename.endsWith('.yara')) {
          return;
        }

        logger.debug`Rule file change detected: ${eventType} ${filename}`;
        this.scheduleReload();
      });

      // FSWatcher extends EventEmitter but types may not reflect it
      (this.fileWatcher as unknown as NodeJS.EventEmitter).on('error', (error: Error) => {
        logger.error`File watcher error: ${error.message}`;
      });

      logger.info`Started watching ${this.config.rulesDir} for rule changes`;
    } catch (error) {
      logger.warn`Failed to start file watcher: ${error}`;
    }
  }

  /**
   * Stop watching for rule file changes
   */
  stopWatching(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
      this.fileWatcher = null;
      logger.info`Stopped watching for rule changes`;
    }

    if (this.reloadTimeout) {
      clearTimeout(this.reloadTimeout);
      this.reloadTimeout = null;
    }
  }

  /**
   * Schedule a debounced reload of rules
   */
  private scheduleReload(): void {
    // Clear any pending reload
    if (this.reloadTimeout) {
      clearTimeout(this.reloadTimeout);
    }

    // Schedule new reload
    this.reloadTimeout = setTimeout(async () => {
      await this.reloadRules();
    }, this.config.hotReloadDebounceMs ?? 1000);
  }

  /**
   * Reload all YARA rules
   */
  async reloadRules(): Promise<Result<number, Error>> {
    if (this.isReloading) {
      return ok(this.ruleFiles.length);
    }

    this.isReloading = true;
    const startTime = performance.now();

    try {
      const rulesResult = await this.discoverRules();

      if (!rulesResult.ok) {
        logger.error`Failed to reload YARA rules: ${rulesResult.error.message}`;
        return rulesResult;
      }

      const oldCount = this.ruleFiles.length;
      this.ruleFiles = rulesResult.value;
      this.lastReloadTime = Date.now();

      const durationMs = Math.round(performance.now() - startTime);
      const totalRules = this.ruleFiles.reduce((sum, r) => sum + r.rulesCount, 0);

      logger.info`Reloaded YARA rules: ${this.ruleFiles.length} files (${totalRules} rules) in ${durationMs}ms`;

      // Notify callback if provided
      if (this.config.onRulesReloaded) {
        this.config.onRulesReloaded(totalRules);
      }

      // Log changes
      if (this.ruleFiles.length !== oldCount) {
        logger.info`Rule file count changed: ${oldCount} -> ${this.ruleFiles.length}`;
      }

      return ok(totalRules);
    } finally {
      this.isReloading = false;
    }
  }

  /**
   * Get hot-reload status
   */
  getHotReloadStatus(): {
    enabled: boolean;
    watching: boolean;
    lastReloadTime: number;
    isReloading: boolean;
  } {
    return {
      enabled: this.config.enableHotReload ?? false,
      watching: this.fileWatcher !== null,
      lastReloadTime: this.lastReloadTime,
      isReloading: this.isReloading,
    };
  }

  /**
   * Clean up resources
   */
  dispose(): void {
    this.stopWatching();
    this.stopAutoSync();
    this.initialized = false;
    logger.info`YARA Manager disposed`;
  }

  /**
   * Scan a binary file against loaded YARA rules
   */
  async scan(filePath: string): Promise<Result<YARAScanResult, Error>> {
    if (!this.initialized) {
      const initResult = await this.initialize();
      if (!initResult.ok) {
        return initResult;
      }
    }

    if (this.ruleFiles.length === 0) {
      logger.warn`No YARA rules loaded, returning empty result`;
      return ok({
        scanned: true,
        matches: [],
        malwareFamilies: [],
        severity: 'unknown' as YARASeverity,
        timestamp: new Date(),
        rulesScanned: 0,
        errors: ['No YARA rules loaded'],
      });
    }

    const startTime = performance.now();

    try {
      // Build rule file arguments
      const ruleArgs = this.ruleFiles.map((r) => `"${r.path}"`).join(' ');

      // Run yara-x scan with JSON output
      const cmd = `${this.yaraExecutable} scan --output-format json ${ruleArgs} "${filePath}"`;

      logger.debug`Running YARA scan: ${cmd}`;

      const { stdout, stderr } = await execAsync(cmd, {
        timeout: this.config.timeoutMs,
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large results
      });

      if (stderr) {
        logger.warn`YARA scan stderr: ${stderr}`;
      }

      const durationMs = performance.now() - startTime;
      const result = this.parseYARAOutput(stdout);

      return ok({
        ...result,
        durationMs: Math.round(durationMs),
        rulesScanned: this.ruleFiles.reduce((sum, r) => sum + r.rulesCount, 0),
      });
    } catch (error) {
      const err_msg = error instanceof Error ? error.message : String(error);

      // Check for timeout
      if (err_msg.includes('ETIMEDOUT') || err_msg.includes('timed out')) {
        return err(new Error(`YARA scan timed out after ${this.config.timeoutMs}ms`));
      }

      logger.error`YARA scan failed: ${err_msg}`;
      return err(new Error(`YARA scan failed: ${err_msg}`));
    }
  }

  /**
   * Get list of loaded rule files
   */
  getRuleFiles(): RuleFile[] {
    return [...this.ruleFiles];
  }

  /**
   * Check if YARA is available on the system
   */
  async isAvailable(): Promise<boolean> {
    const result = await this.findYARABinary();
    return result.ok;
  }

  // ============================================
  // PRIVATE METHODS
  // ============================================

  /**
   * Find yara-x binary on system
   */
  private async findYARABinary(): Promise<Result<string, Error>> {
    // Check if explicitly configured
    if (this.config.yaraExecutable) {
      try {
        await execAsync(`${this.config.yaraExecutable} --version`);
        return ok(this.config.yaraExecutable);
      } catch {
        return err(
          new Error(`Configured YARA executable not found: ${this.config.yaraExecutable}`),
        );
      }
    }

    // Try common locations
    const candidates = ['yara-x', 'yr', 'yara', '/usr/local/bin/yara-x', '/usr/bin/yara'];

    for (const candidate of candidates) {
      try {
        await execAsync(`which ${candidate}`);
        const { stdout } = await execAsync(`${candidate} --version`);
        logger.debug`Found YARA binary: ${candidate} (${stdout.trim()})`;
        return ok(candidate);
      } catch {
        // Try next candidate
      }
    }

    return err(
      new Error(
        'yara-x not found. Install via: brew install yara-x (macOS), ' +
          'apt-get install yara (Linux), or cargo install yara-x-cli',
      ),
    );
  }

  /**
   * Discover YARA rule files in configured directory
   */
  private async discoverRules(): Promise<Result<RuleFile[], Error>> {
    const rules: RuleFile[] = [];

    try {
      // Check if rules directory exists
      const rulesDir = Bun.file(this.config.rulesDir);
      const stat = await rulesDir.stat();

      if (!stat) {
        logger.warn`Rules directory does not exist: ${this.config.rulesDir}`;
        return ok([]);
      }

      // Find all .yar and .yara files recursively
      const { stdout } = await execAsync(
        `find "${this.config.rulesDir}" -type f \\( -name "*.yar" -o -name "*.yara" \\) 2>/dev/null || true`,
      );

      const files = stdout
        .trim()
        .split('\n')
        .filter((f) => f.length > 0);

      for (const filePath of files) {
        try {
          // Extract namespace from directory structure
          const namespace =
            filePath.replace(this.config.rulesDir, '').replace(/^\//, '').split('/')[0] ||
            'default';

          // Count rules in file (rough estimate based on 'rule ' keyword)
          const content = await Bun.file(filePath).text();
          const rulesCount = (content.match(/^\s*rule\s+\w+/gm) || []).length;

          rules.push({
            path: filePath,
            namespace,
            rulesCount,
          });
        } catch (e) {
          logger.warn`Failed to process rule file ${filePath}: ${e}`;
        }
      }

      return ok(rules);
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  /**
   * Parse YARA JSON output
   */
  private parseYARAOutput(output: string): Omit<YARAScanResult, 'durationMs' | 'rulesScanned'> {
    if (!output.trim()) {
      return {
        scanned: true,
        matches: [],
        malwareFamilies: [],
        severity: 'unknown',
        timestamp: new Date(),
        errors: [],
      };
    }

    try {
      // yara-x outputs JSON array of matches
      const data = JSON.parse(output);

      const matches: YARAMatch[] = [];
      const errors: string[] = [];

      // Handle different output formats
      const entries = Array.isArray(data) ? data : [data];

      for (const entry of entries) {
        if (entry.error) {
          errors.push(entry.error);
          continue;
        }

        // Extract matches from entry
        const entryMatches = entry.matches || entry.rules || [entry];

        for (const match of entryMatches) {
          if (!match.rule && !match.identifier) continue;

          matches.push({
            rule: match.rule || match.identifier,
            namespace: match.namespace,
            tags: match.tags || [],
            metas: match.meta || match.metadata || {},
            strings:
              match.strings?.map((s: { identifier: string; instances?: unknown[] }) => ({
                identifier: s.identifier,
                instances: s.instances || [],
              })) || [],
          });
        }
      }

      // Calculate severity and extract malware families
      const severity = this.calculateSeverity(matches);
      const malwareFamilies = this.extractMalwareFamilies(matches);

      return {
        scanned: true,
        matches,
        malwareFamilies,
        severity,
        timestamp: new Date(),
        errors,
      };
    } catch (error) {
      logger.error`Failed to parse YARA output: ${error}`;
      return {
        scanned: true,
        matches: [],
        malwareFamilies: [],
        severity: 'unknown',
        timestamp: new Date(),
        errors: [`Failed to parse YARA output: ${error}`],
      };
    }
  }

  /**
   * Calculate severity based on matched rules
   */
  private calculateSeverity(matches: YARAMatch[]): YARASeverity {
    if (matches.length === 0) return 'unknown';

    const ruleNames = matches.map((m) => m.rule.toLowerCase());
    const tags = matches.flatMap((m) => m.tags.map((t) => t.toLowerCase()));
    const allIndicators = [...ruleNames, ...tags];

    // Critical indicators
    const criticalPatterns = ['ransomware', 'trojan', 'rootkit', 'bootkit', 'apt', 'zero-day'];
    if (criticalPatterns.some((p) => allIndicators.some((i) => i.includes(p)))) {
      return 'critical';
    }

    // High severity indicators
    const highPatterns = ['spyware', 'backdoor', 'keylogger', 'stealer', 'rat', 'c2', 'cnc'];
    if (highPatterns.some((p) => allIndicators.some((i) => i.includes(p)))) {
      return 'high';
    }

    // Medium severity indicators
    const mediumPatterns = ['suspicious', 'packed', 'obfuscated', 'dropper', 'downloader'];
    if (mediumPatterns.some((p) => allIndicators.some((i) => i.includes(p)))) {
      return 'medium';
    }

    // Low severity (generic matches)
    return 'low';
  }

  /**
   * Extract malware family names from matches
   */
  private extractMalwareFamilies(matches: YARAMatch[]): string[] {
    const families = new Set<string>();

    for (const match of matches) {
      // Check meta for family information
      if (typeof match.metas.malware_family === 'string') {
        families.add(match.metas.malware_family);
      }
      if (typeof match.metas.family === 'string') {
        families.add(match.metas.family);
      }

      // Parse rule name for family hints
      // Common formats: trojan_zeus, Zeus_variant, mal_Zeus
      const ruleName = match.rule;
      const familyMatch = ruleName.match(/(?:trojan|mal|malware|virus)[-_]?(\w+)/i);
      if (familyMatch?.[1]) {
        const family = this.normalizeFamily(familyMatch[1]);
        if (family.length > 2) {
          families.add(family);
        }
      }
    }

    return Array.from(families);
  }

  /**
   * Normalize malware family name
   */
  private normalizeFamily(name: string): string {
    return name
      .split(/[-_]/)
      .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('');
  }

  // ============================================
  // REMOTE REPOSITORY SYNC
  // ============================================

  /**
   * Sync all configured remote repositories
   */
  async syncAllRepositories(): Promise<Result<void, Error>> {
    const repos = this.config.remoteRepositories ?? [];
    const enabledRepos = repos.filter((r) => r.enabled !== false);

    if (enabledRepos.length === 0) {
      logger.debug`No remote repositories configured`;
      return ok(undefined);
    }

    logger.info`Syncing ${enabledRepos.length} remote repositories`;

    const errors: string[] = [];
    for (const repo of enabledRepos) {
      const result = await this.syncRepository(repo);
      if (!result.ok) {
        errors.push(`${repo.name}: ${result.error.message}`);
      }
    }

    // Reload rules after sync
    if (errors.length < enabledRepos.length) {
      await this.reloadRules();
    }

    if (errors.length > 0) {
      return err(new Error(`Failed to sync some repositories: ${errors.join('; ')}`));
    }

    return ok(undefined);
  }

  /**
   * Sync a single repository
   */
  async syncRepository(repo: RemoteRuleRepository): Promise<Result<number, Error>> {
    const status = this.getOrCreateStatus(repo);
    const cacheDir = this.getRepoCacheDir(repo);

    logger.info`Syncing repository: ${repo.name} (${repo.type})`;

    try {
      let rulesCount = 0;

      switch (repo.type) {
        case 'git':
          rulesCount = await this.syncGitRepository(repo, cacheDir);
          break;
        case 'http':
          rulesCount = await this.syncHttpRepository(repo, cacheDir);
          break;
        case 'local':
          rulesCount = await this.syncLocalRepository(repo, cacheDir);
          break;
        default:
          throw new Error(`Unknown repository type: ${repo.type}`);
      }

      status.lastSync = Date.now();
      status.lastSyncSuccess = true;
      status.rulesCount = rulesCount;
      status.error = undefined;

      logger.info`Successfully synced ${rulesCount} rules from ${repo.name}`;
      return ok(rulesCount);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      status.lastSync = Date.now();
      status.lastSyncSuccess = false;
      status.error = errorMsg;

      logger.error`Failed to sync ${repo.name}: ${errorMsg}`;
      return err(new Error(errorMsg));
    }
  }

  /**
   * Sync a git repository
   */
  private async syncGitRepository(repo: RemoteRuleRepository, cacheDir: string): Promise<number> {
    // Ensure cache directory exists
    if (!existsSync(cacheDir)) {
      mkdirSync(cacheDir, { recursive: true });
    }

    const gitDir = join(cacheDir, '.git');
    const branch = repo.branch ?? 'main';

    if (existsSync(gitDir)) {
      // Pull latest changes
      logger.debug`Pulling latest from ${repo.url}`;
      await execAsync(
        `git -C "${cacheDir}" fetch origin ${branch} && git -C "${cacheDir}" reset --hard origin/${branch}`,
        {
          timeout: 60_000,
        },
      );
    } else {
      // Clone repository
      logger.debug`Cloning ${repo.url}`;
      const authUrl = repo.authToken
        ? repo.url.replace('https://', `https://${repo.authToken}@`)
        : repo.url;
      await execAsync(`git clone --depth 1 --branch ${branch} "${authUrl}" "${cacheDir}"`, {
        timeout: 120_000,
      });
    }

    // Count rules in the sync'd directory
    const rulesPath = repo.rulesPath ? join(cacheDir, repo.rulesPath) : cacheDir;
    return this.countRulesInDirectory(rulesPath);
  }

  /**
   * Sync an HTTP repository (direct download of rules)
   */
  private async syncHttpRepository(repo: RemoteRuleRepository, cacheDir: string): Promise<number> {
    if (!existsSync(cacheDir)) {
      mkdirSync(cacheDir, { recursive: true });
    }

    const headers: Record<string, string> = {};
    if (repo.authToken) {
      headers.Authorization = `Bearer ${repo.authToken}`;
    }

    // Fetch the rule file or index
    const response = await fetch(repo.url, { headers });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const content = await response.text();

    // Check if it's a YARA rule file or a list of URLs
    if (content.includes('rule ') && content.includes('{')) {
      // Direct YARA rule content
      const filename = repo.url.split('/').pop() ?? 'rules.yar';
      const filepath = join(cacheDir, filename);
      writeFileSync(filepath, content, 'utf-8');
      return this.countRulesInFile(filepath);
    }

    // Assume it's a list of URLs to rule files
    const urls = content
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.startsWith('http') && (l.endsWith('.yar') || l.endsWith('.yara')));

    let totalRules = 0;
    for (const url of urls) {
      try {
        const ruleResponse = await fetch(url, { headers });
        if (ruleResponse.ok) {
          const ruleContent = await ruleResponse.text();
          const filename = url.split('/').pop() ?? `rule_${Date.now()}.yar`;
          const filepath = join(cacheDir, filename);
          writeFileSync(filepath, ruleContent, 'utf-8');
          totalRules += this.countRulesInFile(filepath);
        }
      } catch (e) {
        logger.warn`Failed to fetch rule from ${url}: ${e}`;
      }
    }

    return totalRules;
  }

  /**
   * Sync a local repository (copy from another directory)
   */
  private async syncLocalRepository(repo: RemoteRuleRepository, cacheDir: string): Promise<number> {
    const sourcePath = repo.rulesPath ? join(repo.url, repo.rulesPath) : repo.url;

    if (!existsSync(sourcePath)) {
      throw new Error(`Local repository path does not exist: ${sourcePath}`);
    }

    if (!existsSync(cacheDir)) {
      mkdirSync(cacheDir, { recursive: true });
    }

    // Copy rule files using rsync or cp
    try {
      await execAsync(
        `rsync -av --include='*.yar' --include='*.yara' --exclude='*' "${sourcePath}/" "${cacheDir}/"`,
        {
          timeout: 30_000,
        },
      );
    } catch {
      // Fallback to cp if rsync not available
      await execAsync(`cp -r "${sourcePath}"/*.yar "${cacheDir}/" 2>/dev/null || true`, {
        timeout: 30_000,
      });
      await execAsync(`cp -r "${sourcePath}"/*.yara "${cacheDir}/" 2>/dev/null || true`, {
        timeout: 30_000,
      });
    }

    return this.countRulesInDirectory(cacheDir);
  }

  /**
   * Count rules in a directory
   */
  private countRulesInDirectory(dir: string): number {
    if (!existsSync(dir)) return 0;

    let count = 0;
    const entries = readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        count += this.countRulesInDirectory(fullPath);
      } else if (entry.name.endsWith('.yar') || entry.name.endsWith('.yara')) {
        count += this.countRulesInFile(fullPath);
      }
    }

    return count;
  }

  /**
   * Count rules in a single file
   */
  private countRulesInFile(filepath: string): number {
    try {
      const content = readFileSync(filepath, 'utf-8');
      // Count "rule <name>" declarations
      const matches = content.match(/^\s*rule\s+\w+/gm);
      return matches?.length ?? 0;
    } catch {
      return 0;
    }
  }

  /**
   * Get cache directory for a repository
   */
  private getRepoCacheDir(repo: RemoteRuleRepository): string {
    const baseDir = this.config.remoteCacheDir ?? './rules/remote';
    return join(baseDir, repo.id);
  }

  /**
   * Get or create sync status for a repository
   */
  private getOrCreateStatus(repo: RemoteRuleRepository): RepositorySyncStatus {
    let status = this.repositoryStatus.get(repo.id);
    if (!status) {
      status = {
        id: repo.id,
        name: repo.name,
        lastSync: 0,
        lastSyncSuccess: false,
        rulesCount: 0,
      };
      this.repositoryStatus.set(repo.id, status);
    }
    return status;
  }

  /**
   * Start auto-sync timers for repositories
   */
  private startAutoSync(): void {
    const repos = this.config.remoteRepositories ?? [];

    for (const repo of repos) {
      if (repo.enabled !== false && repo.syncIntervalMs && repo.syncIntervalMs > 0) {
        // Clear existing timer if any
        const existingTimer = this.syncTimers.get(repo.id);
        if (existingTimer) {
          clearInterval(existingTimer);
        }

        // Set new timer
        const timer = setInterval(async () => {
          logger.debug`Auto-syncing repository: ${repo.name}`;
          await this.syncRepository(repo);
          await this.reloadRules();
        }, repo.syncIntervalMs);

        this.syncTimers.set(repo.id, timer);

        const status = this.getOrCreateStatus(repo);
        status.nextSync = Date.now() + repo.syncIntervalMs;

        logger.info`Scheduled auto-sync for ${repo.name} every ${repo.syncIntervalMs / 1000}s`;
      }
    }
  }

  /**
   * Stop all auto-sync timers
   */
  stopAutoSync(): void {
    for (const [id, timer] of this.syncTimers) {
      clearInterval(timer);
      logger.debug`Stopped auto-sync for repository: ${id}`;
    }
    this.syncTimers.clear();
  }

  /**
   * Get status of all repositories
   */
  getRepositoryStatus(): RepositorySyncStatus[] {
    return Array.from(this.repositoryStatus.values());
  }

  /**
   * Add a new remote repository
   */
  addRepository(repo: RemoteRuleRepository): void {
    const repos = this.config.remoteRepositories ?? [];
    const existing = repos.findIndex((r) => r.id === repo.id);

    if (existing >= 0) {
      repos[existing] = repo;
    } else {
      repos.push(repo);
    }

    this.config.remoteRepositories = repos;

    // Start auto-sync if configured
    if (repo.enabled !== false && repo.syncIntervalMs && repo.syncIntervalMs > 0) {
      this.startAutoSync();
    }
  }

  /**
   * Remove a remote repository
   */
  removeRepository(id: string): boolean {
    const repos = this.config.remoteRepositories ?? [];
    const index = repos.findIndex((r) => r.id === id);

    if (index >= 0) {
      repos.splice(index, 1);
      this.repositoryStatus.delete(id);

      // Stop auto-sync timer
      const timer = this.syncTimers.get(id);
      if (timer) {
        clearInterval(timer);
        this.syncTimers.delete(id);
      }

      return true;
    }

    return false;
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let defaultManager: YARAManager | null = null;

/**
 * Get or create the default YARA manager instance
 */
export function getYARAManager(config?: Partial<YARAManagerConfig>): YARAManager {
  if (!defaultManager || config) {
    defaultManager = new YARAManager(config);
  }
  return defaultManager;
}
