import { configure, getConsoleSink, getLogger } from '@logtape/logtape';

// Configure LogTape for the MCP server
await configure({
  sinks: {
    console: getConsoleSink(),
  },
  loggers: [
    {
      category: ['sentinel'],
      lowestLevel: process.env.LOG_LEVEL === 'debug' ? 'debug' : 'info',
      sinks: ['console'],
    },
    {
      category: ['sentinel', 'mcp'],
      lowestLevel: 'debug',
      sinks: ['console'],
    },
    {
      category: ['sentinel', 'tools'],
      lowestLevel: 'debug',
      sinks: ['console'],
    },
  ],
});

// Export pre-configured loggers for different components
export const logger = getLogger(['sentinel']);
export const mcpLogger = getLogger(['sentinel', 'mcp']);
export const toolLogger = getLogger(['sentinel', 'tools']);

// Log levels: debug, info, warning, error, fatal
export type LogLevel = 'debug' | 'info' | 'warning' | 'error' | 'fatal';

// Structured log helper for tool execution
export function logToolExecution(
  toolName: string,
  input: Record<string, unknown>,
  status: 'start' | 'success' | 'error',
  details?: Record<string, unknown>,
): void {
  const logData = {
    tool: toolName,
    input: JSON.stringify(input),
    status,
    ...details,
  };

  if (status === 'start') {
    toolLogger.info`Tool execution started: ${toolName}`;
  } else if (status === 'success') {
    toolLogger.info`Tool execution completed: ${toolName} ${JSON.stringify(logData)}`;
  } else {
    toolLogger.error`Tool execution failed: ${toolName} ${JSON.stringify(logData)}`;
  }
}
