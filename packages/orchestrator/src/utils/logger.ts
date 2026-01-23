/**
 * SENTINEL Logger Configuration
 * Structured logging with LogTape - Lazy initialization to respect LOG_LEVEL set at runtime
 */

import { configure, getConsoleSink, getLogger, type Logger } from '@logtape/logtape';

let configured = false;
let configuring: Promise<void> | null = null;

/**
 * Ensure LogTape is configured exactly once.
 * Safe to call multiple times; subsequent calls return immediately.
 */
export async function ensureLoggerConfigured(): Promise<void> {
  if (configured) return;
  if (configuring) {
    await configuring;
    return;
  }

  configuring = (async () => {
    const logLevel = (process.env.LOG_LEVEL ?? 'info') as 'debug' | 'info' | 'warning' | 'error';
    // In quiet/json mode, disable meta logger entirely; otherwise set to error to minimize noise
    const metaSinks = logLevel === 'error' ? [] : ['console'];

    await configure({
      reset: true,
      sinks: {
        console: getConsoleSink(),
      },
      loggers: [
        {
          category: ['logtape', 'meta'],
          lowestLevel: 'fatal',
          sinks: metaSinks as 'console'[],
        },
        {
          category: ['sentinel', 'orchestrator'],
          lowestLevel: logLevel,
          sinks: ['console'],
        },
      ],
    });

    configured = true;
  })();

  await configuring;
}

// Lazy logger instances - only created after ensureLoggerConfigured() is called
let _logger: Logger | null = null;
let _triageLogger: Logger | null = null;
let _analyzerLogger: Logger | null = null;
let _reportLogger: Logger | null = null;

export const logger: Logger = new Proxy({} as Logger, {
  get(_, prop) {
    if (!_logger) _logger = getLogger(['sentinel', 'orchestrator']);
    return (_logger as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export const triageLogger: Logger = new Proxy({} as Logger, {
  get(_, prop) {
    if (!_triageLogger) _triageLogger = getLogger(['sentinel', 'orchestrator', 'triage']);
    return (_triageLogger as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export const analyzerLogger: Logger = new Proxy({} as Logger, {
  get(_, prop) {
    if (!_analyzerLogger) _analyzerLogger = getLogger(['sentinel', 'orchestrator', 'analyzer']);
    return (_analyzerLogger as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export const reportLogger: Logger = new Proxy({} as Logger, {
  get(_, prop) {
    if (!_reportLogger) _reportLogger = getLogger(['sentinel', 'orchestrator', 'report']);
    return (_reportLogger as unknown as Record<string | symbol, unknown>)[prop];
  },
});
