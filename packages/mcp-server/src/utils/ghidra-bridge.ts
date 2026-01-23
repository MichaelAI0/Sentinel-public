/**
 * Ghidra Bridge - Spawns Ghidra container and runs analysis scripts
 *
 * This module handles communication between the MCP server and
 * the Ghidra headless container via Docker exec.
 */

import { spawn } from 'node:child_process';
import { basename } from 'node:path';
import { getLogger } from '@logtape/logtape';

const logger = getLogger(['sentinel', 'ghidra-bridge']);

export type GhidraExecOptions = {
  /** Path to binary file (host path or container path) */
  binaryPath: string;
  /** Script to run (without .js extension) */
  script:
    | 'analyze'
    | 'extract-functions'
    | 'detect-packers'
    | 'extract-cfg'
    | 'detect-crypto'
    | 'extract-api-calls';
  /** Additional script arguments */
  args?: string[];
  /** Timeout in milliseconds (default: 10 minutes) */
  timeout?: number;
};

export type GhidraExecResult<T> = {
  success: boolean;
  data?: T;
  error?: string;
  executionTime: number;
};

// Container name from docker-compose
const GHIDRA_CONTAINER = process.env.GHIDRA_CONTAINER ?? 'sentinel-ghidra';

// Path mappings: host path prefix → container path prefix
// Based on docker-compose.yml: ./binaries:/workspace/binaries:ro
const PATH_MAPPINGS = [
  { host: '/binaries/', container: '/workspace/binaries/' },
  { host: 'binaries/', container: '/workspace/binaries/' },
] as const;

/**
 * Map host path to container path
 */
function mapToContainerPath(hostPath: string): string {
  // If already using container path, return as-is
  if (hostPath.startsWith('/workspace/')) {
    return hostPath;
  }

  // Try each mapping
  for (const mapping of PATH_MAPPINGS) {
    if (hostPath.startsWith(mapping.host)) {
      return hostPath.replace(mapping.host, mapping.container);
    }
  }

  // Fallback: assume just the filename and place in /workspace/binaries/
  const filename = basename(hostPath);
  logger.warn`Unknown path format, assuming file is in /workspace/binaries/: ${hostPath}`;
  return `/workspace/binaries/${filename}`;
}

// Script output markers
const MARKERS = {
  analyze: {
    start: '---SENTINEL_ANALYSIS_START---',
    end: '---SENTINEL_ANALYSIS_END---',
  },
  'extract-functions': {
    start: '---SENTINEL_FUNCTIONS_START---',
    end: '---SENTINEL_FUNCTIONS_END---',
  },
  'detect-packers': {
    start: '---SENTINEL_PACKER_START---',
    end: '---SENTINEL_PACKER_END---',
  },
  'extract-cfg': {
    start: '---SENTINEL_CFG_START---',
    end: '---SENTINEL_CFG_END---',
  },
  'detect-crypto': {
    start: '---SENTINEL_CRYPTO_START---',
    end: '---SENTINEL_CRYPTO_END---',
  },
  'extract-api-calls': {
    start: '---SENTINEL_API_CALLS_START---',
    end: '---SENTINEL_API_CALLS_END---',
  },
} as const;

/**
 * Execute a Ghidra script in the container
 */
export async function executeGhidraScript<T>(
  options: GhidraExecOptions,
): Promise<GhidraExecResult<T>> {
  const startTime = Date.now();
  const timeout = options.timeout ?? 10 * 60 * 1000; // 10 minutes default

  // Map host path to container path
  const containerBinaryPath = mapToContainerPath(options.binaryPath);
  logger.debug`Path mapping: ${options.binaryPath} → ${containerBinaryPath}`;

  const projectPath = '/workspace/projects';
  const projectName = `temp_${Date.now()}`;

  // Script names map to compiled JavaScript files
  // TypeScript → JavaScript via tsc, executed by our GraalJS extension
  const SCRIPT_MAP: Record<string, string> = {
    analyze: 'analyze.js',
    'extract-functions': 'extract-functions.js',
    'detect-packers': 'detect-packers.js',
    'extract-cfg': 'extract-cfg.js',
    'detect-crypto': 'detect-crypto.js',
    'extract-api-calls': 'extract-api-calls.js',
  };
  const scriptFile = SCRIPT_MAP[options.script] ?? `${options.script}.js`;

  // Build analyzeHeadless command
  const ghidraArgs = [
    projectPath,
    projectName,
    '-import',
    containerBinaryPath,
    '-scriptPath',
    '/workspace/scripts',
    '-postScript',
    scriptFile,
    ...(options.args ?? []),
    '-deleteProject',
  ];

  const dockerArgs = [
    'exec',
    GHIDRA_CONTAINER,
    '/opt/ghidra/support/analyzeHeadless',
    ...ghidraArgs,
  ];

  logger.info`Executing Ghidra script: ${options.script}`;
  logger.debug`Docker command: docker ${dockerArgs.join(' ')}`;

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let killed = false;

    const proc = spawn('docker', dockerArgs);

    // Set timeout
    const timeoutId = setTimeout(() => {
      killed = true;
      proc.kill('SIGKILL');
      logger.error`Ghidra script timed out after ${timeout}ms`;
    }, timeout);

    // stdout/stderr are guaranteed non-null with stdio: ['ignore', 'pipe', 'pipe']
    proc.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on('close', (code: number | null) => {
      clearTimeout(timeoutId);
      const executionTime = Date.now() - startTime;

      if (killed) {
        resolve({
          success: false,
          error: `Ghidra analysis timed out after ${timeout}ms`,
          executionTime,
        });
        return;
      }

      if (code !== 0) {
        logger.error`Ghidra exited with code ${code}: ${stderr}`;
        resolve({
          success: false,
          error: `Ghidra exited with code ${code}: ${stderr.slice(0, 500)}`,
          executionTime,
        });
        return;
      }

      // Parse JSON output from script
      // The output includes Ghidra log prefixes that we need to strip
      const markers = MARKERS[options.script];
      const startIdx = stdout.indexOf(markers.start);
      const endIdx = stdout.indexOf(markers.end);

      if (startIdx === -1 || endIdx === -1) {
        logger.error`Could not find output markers in Ghidra output`;
        resolve({
          success: false,
          error: 'Could not parse Ghidra script output',
          executionTime,
        });
        return;
      }

      // Extract raw content between markers
      const rawContent = stdout.slice(startIdx + markers.start.length, endIdx);

      // Strip Ghidra log prefixes and suffixes from each line
      // Lines look like: "INFO  SentinelJSScript.class> {...json...} (GhidraScript)"
      const jsonLines = rawContent
        .split('\n')
        .map((line) => {
          // Remove common log prefixes
          const cleaned = line
            .replace(/^INFO\s+\S+>\s*/, '') // "INFO  SentinelJSScript.class> "
            .replace(/\s*\(GhidraScript\)\s*$/, ''); // " (GhidraScript)"
          return cleaned;
        })
        .join('');

      const jsonStr = jsonLines.trim();

      try {
        const data = JSON.parse(jsonStr) as T;
        logger.info`Ghidra script completed in ${executionTime}ms`;
        resolve({
          success: true,
          data,
          executionTime,
        });
      } catch (parseError) {
        logger.error`Failed to parse Ghidra JSON output: ${parseError}`;
        resolve({
          success: false,
          error: `Failed to parse Ghidra output: ${parseError}`,
          executionTime,
        });
      }
    });

    proc.on('error', (err: Error) => {
      clearTimeout(timeoutId);
      logger.error`Failed to spawn Ghidra process: ${err}`;
      resolve({
        success: false,
        error: `Failed to spawn Ghidra: ${err.message}`,
        executionTime: Date.now() - startTime,
      });
    });
  });
}

/**
 * Check if Ghidra container is running
 */
export async function isGhidraAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('docker', ['inspect', '-f', '{{.State.Running}}', GHIDRA_CONTAINER]);

    let output = '';
    // stdout is guaranteed non-null with stdio: ['ignore', 'pipe', 'pipe']
    proc.stdout?.on('data', (data: Buffer) => {
      output += data.toString();
    });

    proc.on('close', (code: number | null) => {
      resolve(code === 0 && output.trim() === 'true');
    });

    proc.on('error', (_err: Error) => {
      resolve(false);
    });
  });
}

/**
 * Get Ghidra container version
 */
export async function getGhidraVersion(): Promise<string | null> {
  return new Promise((resolve) => {
    const proc = spawn('docker', [
      'exec',
      GHIDRA_CONTAINER,
      'cat',
      '/opt/ghidra/Ghidra/application.properties',
    ]);

    let output = '';
    // stdout is guaranteed non-null with stdio: ['ignore', 'pipe', 'pipe']
    proc.stdout?.on('data', (data: Buffer) => {
      output += data.toString();
    });

    proc.on('close', (code: number | null) => {
      if (code !== 0) {
        resolve(null);
        return;
      }

      const versionMatch = output.match(/application\.version=(.+)/);
      resolve(versionMatch?.[1]?.trim() ?? null);
    });

    proc.on('error', (_err: Error) => {
      resolve(null);
    });
  });
}
