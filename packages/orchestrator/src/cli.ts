#!/usr/bin/env bun

/**
 * SENTINEL CLI Entry Point
 *
 * IMPORTANT: ES modules hoist all static imports before any code runs.
 * To set LOG_LEVEL before logger initialization, we must:
 * 1. Set LOG_LEVEL in this file with NO static imports that touch the logger
 * 2. Dynamically import the actual CLI code after LOG_LEVEL is set
 */

export {}; // Make this file a module for top-level await

// Set LOG_LEVEL BEFORE any imports to ensure logger respects quiet mode
const argv = process.argv;
if (argv.includes('--quiet') || argv.includes('-q') || argv.includes('--json')) {
  process.env.LOG_LEVEL = 'error';
}

// Now dynamically import the CLI implementation
const { main } = await import('./cli-impl.js');
await main();
