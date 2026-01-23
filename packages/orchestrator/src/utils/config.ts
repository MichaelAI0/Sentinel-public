/**
 * SENTINEL Configuration File Support
 *
 * Loads configuration from:
 * 1. sentinel.config.json (project root)
 * 2. .sentinelrc (project root)
 * 3. Environment variables (highest priority)
 *
 * Config file schema:
 * {
 *   "outputDir": "./outputs",
 *   "ollamaUrl": "http://localhost:11434",
 *   "mcpUrl": "http://localhost:3000",
 *   "logLevel": "info",
 *   "host": "0.0.0.0",
 *   "port": 8080,
 *   "verbose": false,
 *   "defaultCommand": "analyze"
 * }
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

export type SentinelConfig = {
  outputDir?: string;
  ollamaUrl?: string;
  mcpUrl?: string;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  host?: string;
  port?: number;
  verbose?: boolean;
  defaultCommand?: string;
};

const CONFIG_FILENAMES = ['sentinel.config.json', '.sentinelrc', '.sentinelrc.json'];

/**
 * Find the project root by looking for package.json
 */
function findProjectRoot(startDir: string = process.cwd()): string {
  let current = resolve(startDir);
  const root = dirname(current);

  while (current !== root) {
    if (existsSync(join(current, 'package.json'))) {
      return current;
    }
    current = dirname(current);
  }

  return process.cwd();
}

/**
 * Load configuration from a file
 */
function loadConfigFile(filePath: string): SentinelConfig | null {
  try {
    if (!existsSync(filePath)) return null;

    const content = readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(content) as SentinelConfig;

    // Basic validation
    if (typeof parsed !== 'object' || parsed === null) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

/**
 * Load configuration from the first found config file
 */
export function loadConfig(searchDir?: string): SentinelConfig {
  const projectRoot = findProjectRoot(searchDir);
  let config: SentinelConfig = {};

  // Try each config filename
  for (const filename of CONFIG_FILENAMES) {
    const filePath = join(projectRoot, filename);
    const loaded = loadConfigFile(filePath);
    if (loaded) {
      config = loaded;
      break;
    }
  }

  return config;
}

/**
 * Merge config file settings with CLI options and environment
 * Priority: CLI options > Environment > Config file > Defaults
 */
export function mergeConfig(
  cliOptions: Partial<SentinelConfig>,
  envOverrides: Partial<SentinelConfig> = {},
): SentinelConfig {
  const fileConfig = loadConfig();

  // Environment variable overrides
  const envConfig: SentinelConfig = {
    outputDir: process.env.OUTPUT_DIR,
    ollamaUrl: process.env.OLLAMA_BASE_URL,
    mcpUrl: process.env.MCP_SERVER_URL,
    logLevel: process.env.LOG_LEVEL as SentinelConfig['logLevel'],
    host: process.env.HOST,
    port: process.env.PORT ? Number.parseInt(process.env.PORT, 10) : undefined,
  };

  // Remove undefined values
  const cleanEnv = Object.fromEntries(
    Object.entries(envConfig).filter(([_, v]) => v !== undefined),
  );
  const cleanCli = Object.fromEntries(
    Object.entries(cliOptions).filter(([_, v]) => v !== undefined),
  );
  const cleanOverrides = Object.fromEntries(
    Object.entries(envOverrides).filter(([_, v]) => v !== undefined),
  );

  // Merge with priority: CLI > envOverrides > env > file
  return {
    ...fileConfig,
    ...cleanEnv,
    ...cleanOverrides,
    ...cleanCli,
  };
}

/**
 * Apply merged config to environment variables
 */
export function applyConfigToEnv(config: SentinelConfig): void {
  if (config.outputDir) process.env.OUTPUT_DIR = config.outputDir;
  if (config.ollamaUrl) process.env.OLLAMA_BASE_URL = config.ollamaUrl;
  if (config.mcpUrl) process.env.MCP_SERVER_URL = config.mcpUrl;
  if (config.logLevel) process.env.LOG_LEVEL = config.logLevel;
  if (config.host) process.env.HOST = config.host;
  if (config.port) process.env.PORT = String(config.port);
}

/**
 * Get the path where config would be saved
 */
export function getConfigPath(): string {
  const projectRoot = findProjectRoot();
  return join(projectRoot, 'sentinel.config.json');
}
