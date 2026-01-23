/**
 * SENTINEL CLI implementation
 *
 * This file is dynamically imported by `cli.ts` after LOG_LEVEL is set.
 */

import { exec } from 'node:child_process';
import { stat } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { promisify } from 'node:util';
import { getEditionName, getLicenseType, isPaidTier } from './config/features.js';
import type { AnalysisState } from './types.js';
import { applyConfigToEnv, loadConfig } from './utils/config.js';
import { initializeLicense } from './utils/license-validator.js';
import {
  createAnalyzeProgress,
  createTriageProgress,
  type ProgressOptions,
} from './utils/progress.js';

const execAsync = promisify(exec);

// ============================================================================
// Terminal Colors (ANSI escape codes)
// ============================================================================

const isColorSupported = process.stdout.isTTY && !process.env.NO_COLOR;

const colors = {
  reset: isColorSupported ? '\x1b[0m' : '',
  bold: isColorSupported ? '\x1b[1m' : '',
  dim: isColorSupported ? '\x1b[2m' : '',
  red: isColorSupported ? '\x1b[31m' : '',
  green: isColorSupported ? '\x1b[32m' : '',
  yellow: isColorSupported ? '\x1b[33m' : '',
  blue: isColorSupported ? '\x1b[34m' : '',
  magenta: isColorSupported ? '\x1b[35m' : '',
  cyan: isColorSupported ? '\x1b[36m' : '',
};

function colorize(text: string, color: keyof typeof colors): string {
  return `${colors[color]}${text}${colors.reset}`;
}

function riskColor(risk: string): string {
  switch (risk) {
    case 'CRITICAL':
      return colorize(risk, 'red');
    case 'HIGH':
      return colorize(risk, 'red');
    case 'MEDIUM':
      return colorize(risk, 'yellow');
    case 'LOW':
      return colorize(risk, 'green');
    default:
      return risk;
  }
}

type ExitCode = 0 | 1 | 2;

type GlobalOptions = {
  quiet: boolean;
  json: boolean;
  help: boolean;
  version: boolean;
  verbose: boolean;
  outputDir?: string;
  ollamaUrl?: string;
  mcpUrl?: string;
  port?: string;
  host?: string;
  config?: string;
};

type ParsedArgs = {
  options: GlobalOptions;
  command: string | null;
  commandArgs: string[];
};

function printHelp(): void {
  // Keep help text dependency-free and stable.
  // (No markdown; this is terminal output.)
  console.log(`SENTINEL - AI-driven static malware analysis

Usage:
  sentinel <command> [options]

Commands:
  analyze <binaryPath>        Full workflow (triage → analyze → report)
  triage <binaryPath>         Quick triage only (no deep analysis)
  server                      Start orchestrator HTTP server
  batch <dir>                 Run analysis on a directory of samples
  check                       Verify system dependencies (Ghidra, YARA, etc.)
  help                        Show this help

Global options:
  -h, --help                  Show help
  -v, --version               Show version
  -q, --quiet                 Suppress non-error logs
  -V, --verbose               Show detailed progress
  --json                      Print machine-readable JSON to stdout
  --config <file>             Path to config file
  --output-dir <dir>          Override OUTPUT_DIR for reports
  --ollama-url <url>          Override OLLAMA_BASE_URL
  --mcp-url <url>             Override MCP_SERVER_URL
  --host <host>               Server host (server command)
  --port <port>               Server port (server command)

Config file:
  Create sentinel.config.json or .sentinelrc in project root:
  {
    "outputDir": "./outputs",
    "ollamaUrl": "http://localhost:11434",
    "mcpUrl": "http://localhost:3000",
    "verbose": false
  }

Examples:
  sentinel triage ./binaries/suspicious_test
  sentinel analyze ./binaries/suspicious_test
  sentinel analyze ./binaries/test_binary --output-dir ./outputs
  sentinel server --port 8080
  sentinel check
  sentinel batch ./binaries --json > results.json
`);
}

function printVersion(): void {
  const version = process.env.npm_package_version ?? 'unknown';
  console.log(version);
}

function isFlag(token: string): boolean {
  return token.startsWith('-');
}

/** Flag definitions for argument parsing */
type FlagHandler = {
  requiresValue?: boolean;
  handler: (options: GlobalOptions, value?: string) => void;
};

const FLAG_HANDLERS: Record<string, FlagHandler> = {
  '-h': {
    handler: (o) => {
      o.help = true;
    },
  },
  '--help': {
    handler: (o) => {
      o.help = true;
    },
  },
  '-v': {
    handler: (o) => {
      o.version = true;
    },
  },
  '--version': {
    handler: (o) => {
      o.version = true;
    },
  },
  '-q': {
    handler: (o) => {
      o.quiet = true;
    },
  },
  '--quiet': {
    handler: (o) => {
      o.quiet = true;
    },
  },
  '-V': {
    handler: (o) => {
      o.verbose = true;
    },
  },
  '--verbose': {
    handler: (o) => {
      o.verbose = true;
    },
  },
  '--json': {
    handler: (o) => {
      o.json = true;
    },
  },
  '--config': {
    requiresValue: true,
    handler: (o, v) => {
      o.config = v;
    },
  },
  '--output-dir': {
    requiresValue: true,
    handler: (o, v) => {
      o.outputDir = v;
    },
  },
  '--ollama-url': {
    requiresValue: true,
    handler: (o, v) => {
      o.ollamaUrl = v;
    },
  },
  '--mcp-url': {
    requiresValue: true,
    handler: (o, v) => {
      o.mcpUrl = v;
    },
  },
  '--host': {
    requiresValue: true,
    handler: (o, v) => {
      o.host = v;
    },
  },
  '--port': {
    requiresValue: true,
    handler: (o, v) => {
      o.port = v;
    },
  },
};

function parseArgs(argv: string[]): ParsedArgs {
  const options: GlobalOptions = {
    quiet: false,
    json: false,
    help: false,
    version: false,
    verbose: false,
  };

  let command: string | null = null;
  const commandArgs: string[] = [];

  // Allow global flags anywhere; first non-flag token becomes the command.
  for (let idx = 0; idx < argv.length; idx += 1) {
    const token = argv[idx] ?? '';

    if (token === '--') {
      // Everything after `--` is treated as positional args.
      for (let j = idx + 1; j < argv.length; j += 1) {
        commandArgs.push(argv[j] as string);
      }
      break;
    }

    if (!isFlag(token) && command == null) {
      command = token;
      continue;
    }

    const handler = FLAG_HANDLERS[token];
    if (handler) {
      if (handler.requiresValue) {
        handler.handler(options, argv[idx + 1]);
        idx += 1;
      } else {
        handler.handler(options);
      }
      continue;
    }

    // Unknown token: positional for the command.
    commandArgs.push(token);
  }

  return { options, command, commandArgs };
}

async function ensureFileExists(path: string): Promise<void> {
  const st = await stat(path);
  if (!st.isFile()) {
    throw new Error(`Not a file: ${path}`);
  }
}

function applyEnvOverrides(options: GlobalOptions): void {
  // Load config file first (lowest priority)
  const fileConfig = loadConfig(options.config);
  applyConfigToEnv(fileConfig);

  // Apply verbose from config if not set on CLI
  if (fileConfig.verbose && !options.verbose) {
    options.verbose = true;
  }

  // CLI options override config file (highest priority)
  if (options.quiet || options.json) process.env.LOG_LEVEL = 'error';
  if (options.outputDir) process.env.OUTPUT_DIR = options.outputDir;
  if (options.ollamaUrl) process.env.OLLAMA_BASE_URL = options.ollamaUrl;
  if (options.mcpUrl) process.env.MCP_SERVER_URL = options.mcpUrl;
  if (options.host) process.env.HOST = options.host;
  if (options.port) process.env.PORT = options.port;
}

function getProgressOptions(options: GlobalOptions): ProgressOptions {
  return {
    quiet: options.quiet,
    json: options.json,
    verbose: options.verbose,
  };
}

function renderSummary(state: AnalysisState): object {
  return {
    status: state.status,
    filename: state.filename,
    binaryPath: state.binaryPath,
    triage: state.triageResults
      ? {
          riskLevel: state.triageResults.riskLevel,
          confidence: state.triageResults.confidence,
          recommendation: state.triageResults.recommendation,
          fileType: state.triageResults.fileType,
          sha256: state.triageResults.sha256,
          md5: state.triageResults.md5,
          entropy: state.triageResults.entropy,
          isPacked: state.triageResults.isPacked,
          packerName: state.triageResults.packerName ?? null,
          suspiciousStrings: state.triageResults.suspiciousStrings,
          suspiciousImports: state.triageResults.suspiciousImports,
          reasoning: state.triageResults.reasoning,
        }
      : null,
    analysis: state.analysisResults
      ? {
          malwareFamily: state.analysisResults.malwareFamily ?? null,
          familyConfidence: state.analysisResults.familyConfidence ?? null,
          sophistication: state.analysisResults.sophistication,
          capabilities: state.analysisResults.capabilities,
          antiAnalysis: state.analysisResults.antiAnalysis,
          mitreTechniques: state.analysisResults.mitreTechniques,
          iocs: state.analysisResults.iocs,
          keyFindings: state.analysisResults.keyFindings,
        }
      : null,
    reports: state.reportPaths ?? null,
    errors: state.errors,
    durationSeconds:
      state.endTime != null ? (state.endTime.getTime() - state.startTime.getTime()) / 1000 : null,
  };
}

/** Print verbose analysis details */
function printVerboseAnalysis(analysis: AnalysisState['analysisResults']): void {
  if (!analysis) return;

  console.log(`\n${colorize('Details:', 'bold')}`);
  if (analysis.malwareFamily) {
    console.log(
      `  Family: ${analysis.malwareFamily} (${Math.round((analysis.familyConfidence ?? 0) * 100)}%)`,
    );
  }
  console.log(`  Sophistication: ${analysis.sophistication}`);
  console.log(`  Capabilities: ${analysis.capabilities.length}`);
  console.log(`  MITRE Techniques: ${analysis.mitreTechniques.length}`);
  if (analysis.iocs) {
    const iocCount =
      (analysis.iocs.ipAddresses?.length ?? 0) +
      (analysis.iocs.domains?.length ?? 0) +
      (analysis.iocs.urls?.length ?? 0) +
      (analysis.iocs.filePaths?.length ?? 0) +
      (analysis.iocs.registryKeys?.length ?? 0);
    console.log(`  IOCs: ${iocCount}`);
  }

  printYaraMatches(analysis.yaraMatches);
  printCryptoFindings(analysis.cryptoFindings);
  printAssemblyPatterns(analysis.assemblyPatterns);
  printEnhancedStrings(analysis.enhancedStrings);

  if (analysis.wasUnpacked) {
    console.log(`\n${colorize('Unpacking:', 'green')}`);
    console.log(`  Was unpacked: Yes (${analysis.originalPacker ?? 'unknown packer'})`);
  }
}

function printYaraMatches(
  matches: NonNullable<AnalysisState['analysisResults']>['yaraMatches'],
): void {
  if (!matches || matches.length === 0) return;
  console.log(`\n${colorize('YARA Matches:', 'cyan')} ${matches.length}`);
  for (const match of matches.slice(0, 5)) {
    const tags = match.tags.length > 0 ? colorize(`[${match.tags.join(', ')}]`, 'dim') : '';
    console.log(`  - ${match.ruleName} ${tags}`);
  }
  if (matches.length > 5) {
    console.log(colorize(`    ...and ${matches.length - 5} more`, 'dim'));
  }
}

function printCryptoFindings(
  findings: NonNullable<AnalysisState['analysisResults']>['cryptoFindings'],
): void {
  if (!findings || findings.length === 0) return;
  console.log(`\n${colorize('Crypto Operations:', 'magenta')} ${findings.length}`);
  for (const finding of findings.slice(0, 5)) {
    const conf = colorize(`${Math.round(finding.confidence * 100)}%`, 'dim');
    console.log(`  - ${finding.algorithm} (${finding.type}) ${conf}`);
  }
}

function printAssemblyPatterns(
  patterns: NonNullable<AnalysisState['analysisResults']>['assemblyPatterns'],
): void {
  if (!patterns || patterns.length === 0) return;
  console.log(`\n${colorize('Assembly Patterns:', 'yellow')} ${patterns.length}`);
  const byCategory = patterns.reduce(
    (acc, p) => {
      acc[p.category] = (acc[p.category] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );
  for (const [cat, count] of Object.entries(byCategory)) {
    console.log(`  - ${cat}: ${count}`);
  }
}

function printEnhancedStrings(
  strings: NonNullable<AnalysisState['analysisResults']>['enhancedStrings'],
): void {
  if (!strings || strings.length === 0) return;
  const suspicious = strings.filter((s) => s.isSuspicious);
  console.log(`\n${colorize('String Analysis:', 'blue')}`);
  console.log(`  Total: ${strings.length}`);
  console.log(
    `  Suspicious: ${colorize(String(suspicious.length), suspicious.length > 0 ? 'yellow' : 'green')}`,
  );
}

async function cmdAnalyze(binaryPathRaw: string, options: GlobalOptions): Promise<ExitCode> {
  const binaryPath = resolve(binaryPathRaw);
  await ensureFileExists(binaryPath);

  const progress = createAnalyzeProgress(getProgressOptions(options));

  // Configure logger after LOG_LEVEL is set
  const { ensureLoggerConfigured } = await import('./utils/logger.js');
  await ensureLoggerConfigured();

  if (!options.json && !options.quiet) {
    console.log(`\nAnalyzing: ${basename(binaryPath)}\n`);
  }

  progress.start();

  const { analyzeWithWorkflow } = await import('./workflow/analysis-workflow.js');

  // Run the workflow - progress is tracked internally
  const result = await analyzeWithWorkflow(binaryPath, basename(binaryPath));

  // Mark all steps complete since workflow finished
  for (let i = 0; i < 9; i++) {
    progress.complete();
  }
  progress.finish(result.status === 'complete');

  if (options.json) {
    console.log(JSON.stringify(renderSummary(result), null, 2));
  } else {
    const triage = result.triageResults;
    console.log(
      `\nStatus: ${result.status === 'complete' ? colorize('complete', 'green') : colorize(result.status, 'yellow')}`,
    );
    if (triage) {
      console.log(`Risk: ${riskColor(triage.riskLevel)} (${Math.round(triage.confidence * 100)}%)`);
      console.log(`Recommendation: ${triage.recommendation}`);
      console.log(`SHA256: ${colorize(triage.sha256, 'dim')}`);
      if (result.reportPaths) {
        console.log(`\n${colorize('Reports:', 'bold')}`);
        console.log(`  Markdown: ${result.reportPaths.markdown}`);
        console.log(`  JSON:     ${result.reportPaths.json}`);
        console.log(`  STIX:     ${result.reportPaths.stix}`);
      }

      if (options.verbose && result.analysisResults) {
        printVerboseAnalysis(result.analysisResults);
      }
    }

    if (result.errors.length > 0) {
      console.error(`\nErrors: ${result.errors.join('; ')}`);
    }
  }

  return result.status === 'complete' ? 0 : 1;
}

/** Print verbose triage details */
function printVerboseTriage(triage: NonNullable<AnalysisState['triageResults']>): void {
  if (triage.suspiciousStrings.length > 0) {
    console.log(`\nSuspicious Strings (first 10):`);
    for (const s of triage.suspiciousStrings.slice(0, 10)) {
      console.log(`  - ${s}`);
    }
  }
  if (triage.suspiciousImports.length > 0) {
    console.log(`\nSuspicious Imports:`);
    for (const imp of triage.suspiciousImports.slice(0, 10)) {
      console.log(`  - ${imp}`);
    }
  }
  console.log(`\nReasoning: ${triage.reasoning}`);
}

/** Print triage results to console */
function printTriageResults(
  triage: NonNullable<AnalysisState['triageResults']>,
  verbose: boolean,
): void {
  console.log(`\nRisk: ${triage.riskLevel} (${Math.round(triage.confidence * 100)}%)`);
  console.log(`Recommendation: ${triage.recommendation}`);
  console.log(`FileType: ${triage.fileType}`);
  console.log(`SHA256: ${triage.sha256}`);
  console.log(`Entropy: ${triage.entropy.toFixed(2)}`);
  if (triage.isPacked) console.log(`Packed: yes (${triage.packerName ?? 'unknown'})`);
  if (triage.suspiciousStrings.length > 0) {
    console.log(`SuspiciousStrings: ${triage.suspiciousStrings.length}`);
  }
  if (triage.suspiciousImports.length > 0) {
    console.log(`SuspiciousImports: ${triage.suspiciousImports.length}`);
  }
  if (verbose) {
    printVerboseTriage(triage);
  }
}

/** Create initial analysis state for triage */
function createTriageState(binaryPath: string): AnalysisState {
  return {
    binaryPath,
    filename: basename(binaryPath),
    triageResults: null,
    triageComplete: false,
    analysisResults: null,
    analysisComplete: false,
    reportPaths: null,
    reportsComplete: false,
    startTime: new Date(),
    errors: [],
    status: 'triaging',
  };
}

/** Merge triage results into analysis state */
function mergeTriageResults(
  initialState: AnalysisState,
  partial: Partial<AnalysisState>,
): AnalysisState {
  return {
    ...initialState,
    ...partial,
    triageResults: partial.triageResults ?? null,
    triageComplete: partial.triageComplete ?? false,
    errors: partial.errors ?? initialState.errors,
    status: partial.status ?? initialState.status,
    endTime: partial.endTime,
  };
}

async function cmdTriage(binaryPathRaw: string, options: GlobalOptions): Promise<ExitCode> {
  const binaryPath = resolve(binaryPathRaw);
  await ensureFileExists(binaryPath);

  const progress = createTriageProgress(getProgressOptions(options));

  // Configure logger after LOG_LEVEL is set
  const { ensureLoggerConfigured } = await import('./utils/logger.js');
  await ensureLoggerConfigured();

  if (!options.json && !options.quiet) {
    console.log(`\nTriaging: ${basename(binaryPath)}\n`);
  }

  progress.start();

  const { runTriageAgent } = await import('./agents/triage-agent.js');
  const initialState = createTriageState(binaryPath);
  const partial = await runTriageAgent(initialState);

  // Mark all steps complete
  for (let i = 0; i < 4; i++) {
    progress.complete();
  }

  const merged = mergeTriageResults(initialState, partial);
  progress.finish(merged.triageResults !== null);

  if (options.json) {
    console.log(JSON.stringify(renderSummary(merged), null, 2));
    return merged.triageResults ? 0 : 1;
  }

  if (!merged.triageResults) {
    console.error('\nTriage failed: no results');
    if (merged.errors.length > 0) console.error(`Errors: ${merged.errors.join('; ')}`);
    return 1;
  }

  printTriageResults(merged.triageResults, options.verbose);
  if (merged.errors.length > 0) {
    console.error(`\nErrors: ${merged.errors.join('; ')}`);
  }

  return 0;
}

async function cmdServer(options: GlobalOptions): Promise<never> {
  // Configure logger after LOG_LEVEL is set
  const { ensureLoggerConfigured } = await import('./utils/logger.js');
  await ensureLoggerConfigured();

  // `index.ts` starts the server immediately at module load.
  await import('./index.js');

  if (options.json) {
    console.log(
      JSON.stringify(
        {
          status: 'running',
          host: process.env.HOST ?? '0.0.0.0',
          port: Number.parseInt(process.env.PORT ?? '8080', 10),
        },
        null,
        2,
      ),
    );
  } else {
    console.log(`Server running on ${process.env.HOST ?? '0.0.0.0'}:${process.env.PORT ?? '8080'}`);
  }

  // Keep process alive
  while (true) {
    await new Promise((r) => setTimeout(r, 60_000));
  }
}

async function cmdBatch(dirRaw: string, options: GlobalOptions): Promise<ExitCode> {
  const dirPath = resolve(dirRaw);
  const st = await stat(dirPath);
  if (!st.isDirectory()) throw new Error(`Not a directory: ${dirPath}`);

  // Configure logger after LOG_LEVEL is set
  const { ensureLoggerConfigured } = await import('./utils/logger.js');
  await ensureLoggerConfigured();

  const entries: string[] = [];
  for await (const entry of new Bun.Glob('**/*').scan({ cwd: dirPath, onlyFiles: true })) {
    entries.push(String(entry));
  }

  const results: Array<{ file: string; exitCode: number }> = [];

  for (const rel of entries) {
    const filePath = resolve(dirPath, rel);

    // Skip common non-binary artifacts
    if (rel.endsWith('.md') || rel.endsWith('.json') || rel.endsWith('.txt')) continue;

    try {
      const code = await cmdAnalyze(filePath, options);
      results.push({ file: filePath, exitCode: code });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      results.push({ file: filePath, exitCode: 1 });
      if (!options.json) console.error(`Batch error (${filePath}): ${msg}`);
    }
  }

  if (options.json) {
    console.log(JSON.stringify({ directory: dirPath, results }, null, 2));
  } else {
    const ok = results.filter((r) => r.exitCode === 0).length;
    const fail = results.length - ok;
    console.log(`Batch complete: ${ok} ok, ${fail} failed`);
  }

  return results.some((r) => r.exitCode !== 0) ? 1 : 0;
}

type DependencyCheck = {
  name: string;
  available: boolean;
  version?: string;
  path?: string;
  required: boolean;
  message?: string;
};

async function checkDependency(
  name: string,
  command: string,
  required: boolean,
): Promise<DependencyCheck> {
  try {
    const { stdout } = await execAsync(command);
    const version = stdout.trim().split('\n')[0] ?? 'unknown';
    return { name, available: true, version, required };
  } catch {
    return {
      name,
      available: false,
      required,
      message: required ? 'Required but not found' : 'Optional',
    };
  }
}

async function checkGhidraDocker(): Promise<DependencyCheck> {
  try {
    const { stdout } = await execAsync('docker images sentinel-ghidra --format "{{.Tag}}"');
    const tags = stdout.trim().split('\n').filter(Boolean);
    if (tags.length > 0) {
      return { name: 'Ghidra (Docker)', available: true, version: tags[0], required: true };
    }
    return {
      name: 'Ghidra (Docker)',
      available: false,
      required: true,
      message: 'Container image not found. Run: docker compose build ghidra',
    };
  } catch {
    return {
      name: 'Ghidra (Docker)',
      available: false,
      required: true,
      message: 'Could not check (Docker not running?)',
    };
  }
}

async function checkOllama(): Promise<DependencyCheck> {
  const ollamaUrl = process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434';
  try {
    const response = await fetch(`${ollamaUrl}/api/version`);
    if (response.ok) {
      const data = (await response.json()) as { version?: string };
      return {
        name: 'Ollama',
        available: true,
        version: data.version ?? 'unknown',
        path: ollamaUrl,
        required: true,
      };
    }
    return {
      name: 'Ollama',
      available: false,
      required: true,
      message: `Not responding at ${ollamaUrl}`,
    };
  } catch {
    return {
      name: 'Ollama',
      available: false,
      required: true,
      message: 'Connection failed. Is Ollama running?',
    };
  }
}

async function checkMcpServer(): Promise<DependencyCheck> {
  const mcpUrl = process.env.MCP_SERVER_URL ?? 'http://localhost:3000';
  try {
    const response = await fetch(`${mcpUrl}/health`);
    if (response.ok) {
      return { name: 'MCP Server', available: true, path: mcpUrl, required: true };
    }
    return {
      name: 'MCP Server',
      available: false,
      required: true,
      message: `Not responding at ${mcpUrl}`,
    };
  } catch {
    return {
      name: 'MCP Server',
      available: false,
      required: true,
      message: 'Not running. Start with: bun run --cwd packages/mcp-server start',
    };
  }
}

function printDependencyResult(check: DependencyCheck): void {
  const status = check.available
    ? colorize('✓', 'green')
    : check.required
      ? colorize('✗', 'red')
      : colorize('○', 'yellow');
  const name = check.required ? colorize(check.name, 'bold') : check.name;
  const version = check.version ? colorize(`v${check.version}`, 'dim') : '';
  const path = check.path ? colorize(`(${check.path})`, 'dim') : '';
  const message = !check.available && check.message ? colorize(check.message, 'dim') : '';
  console.log(`  ${status} ${name} ${version} ${path} ${message}`.trim());
}

async function cmdCheck(options: GlobalOptions): Promise<ExitCode> {
  const checks: DependencyCheck[] = [];

  if (!options.json && !options.quiet) {
    console.log(`\n${colorize('SENTINEL Dependency Check', 'bold')}\n`);
  }

  // Core runtime
  checks.push({
    name: 'Bun',
    available: true,
    version: Bun.version,
    required: true,
  });

  // Check YARA-X
  checks.push(await checkDependency('YARA-X', 'yr --version', false));

  // Check Ghidra (via Docker)
  checks.push(await checkDependency('Docker', 'docker --version', true));

  // Check Ghidra container, Ollama, and MCP Server in parallel
  const [ghidra, ollama, mcp] = await Promise.all([
    checkGhidraDocker(),
    checkOllama(),
    checkMcpServer(),
  ]);
  checks.push(ghidra, ollama, mcp);

  // Check UPX (optional)
  checks.push(await checkDependency('UPX', 'upx --version', false));

  // Check objdump (optional)
  checks.push(await checkDependency('objdump', 'objdump --version', false));

  if (options.json) {
    console.log(JSON.stringify({ dependencies: checks }, null, 2));
  } else {
    for (const check of checks) {
      printDependencyResult(check);
    }

    const requiredMissing = checks.filter((c) => c.required && !c.available);
    const optionalMissing = checks.filter((c) => !c.required && !c.available);

    console.log('');
    if (requiredMissing.length > 0) {
      console.log(colorize(`⚠ ${requiredMissing.length} required dependencies missing`, 'red'));
    } else {
      console.log(colorize('✓ All required dependencies available', 'green'));
    }

    if (optionalMissing.length > 0) {
      console.log(colorize(`  ${optionalMissing.length} optional dependencies not found`, 'dim'));
    }
    console.log('');
  }

  const requiredMissing = checks.filter((c) => c.required && !c.available);
  return requiredMissing.length > 0 ? 1 : 0;
}

export async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  const { options } = parsed;

  // Initialize license system
  initializeLicense();

  if (options.version) {
    printVersion();
    process.exit(0);
  }

  if (options.help || parsed.command === 'help' || parsed.command == null) {
    printHelp();
    process.exit(0);
  }

  // Display edition on non-quiet startup
  if (!options.quiet && !options.json) {
    const edition = getEditionName();
    const _tier = getLicenseType();
    const isPaid = isPaidTier();
    const editionColor = isPaid ? 'cyan' : 'dim';
    console.log(`${colorize('SENTINEL', 'bold')} ${colorize(edition, editionColor)}\n`);
  }

  applyEnvOverrides(options);

  // Command routing
  try {
    if (parsed.command === 'analyze') {
      const target = parsed.commandArgs[0];
      if (!target) throw new Error('Missing <binaryPath>');
      process.exit(await cmdAnalyze(target, options));
    }

    if (parsed.command === 'triage') {
      const target = parsed.commandArgs[0];
      if (!target) throw new Error('Missing <binaryPath>');
      process.exit(await cmdTriage(target, options));
    }

    if (parsed.command === 'server') {
      process.exit(await cmdServer(options));
    }

    if (parsed.command === 'batch') {
      const dir = parsed.commandArgs[0];
      if (!dir) throw new Error('Missing <dir>');
      process.exit(await cmdBatch(dir, options));
    }

    if (parsed.command === 'check') {
      process.exit(await cmdCheck(options));
    }

    if (parsed.command === 'help') {
      printHelp();
      process.exit(0);
    }

    throw new Error(`Unknown command: ${parsed.command}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (options.json) {
      console.log(JSON.stringify({ error: message }, null, 2));
    } else {
      console.error(`Error: ${message}`);
      console.error('Run `sentinel --help` for usage.');
    }

    process.exit(2);
  }
}
