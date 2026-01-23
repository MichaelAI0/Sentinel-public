/**
 * Custom Error Classes for SENTINEL
 *
 * Provides a hierarchy of typed errors with:
 * - Consistent error codes
 * - Structured metadata
 * - Proper stack traces
 * - Easy serialization for API responses
 *
 * @module types/errors
 */

/**
 * Base error class for all SENTINEL errors
 * Includes error code, cause chaining, and metadata
 */
export class SentinelError extends Error {
  public readonly code: string;
  public readonly timestamp: Date;
  public readonly metadata: Record<string, unknown>;

  constructor(
    message: string,
    code: string,
    options?: {
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(message, { cause: options?.cause });
    this.name = 'SentinelError';
    this.code = code;
    this.timestamp = new Date();
    this.metadata = options?.metadata ?? {};

    // Maintain proper prototype chain
    Object.setPrototypeOf(this, new.target.prototype);

    // Capture stack trace (if available)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Convert to JSON for API responses
   */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      timestamp: this.timestamp.toISOString(),
      metadata: this.metadata,
      ...(this.cause instanceof Error && {
        cause: {
          name: this.cause.name,
          message: this.cause.message,
        },
      }),
    };
  }

  /**
   * Create formatted string for logging
   */
  toLogString(): string {
    const parts = [`[${this.code}] ${this.message}`];

    if (Object.keys(this.metadata).length > 0) {
      parts.push(`Metadata: ${JSON.stringify(this.metadata)}`);
    }

    if (this.cause instanceof Error) {
      parts.push(`Caused by: ${this.cause.message}`);
    }

    return parts.join(' | ');
  }
}

/**
 * Input validation errors (bad user input)
 */
export class ValidationError extends SentinelError {
  public readonly field?: string;

  constructor(
    message: string,
    options?: {
      field?: string;
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(message, 'VALIDATION_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        ...(options?.field && { field: options.field }),
      },
    });
    this.name = 'ValidationError';
    this.field = options?.field;
  }
}

/**
 * File access errors (file not found, permission denied, etc.)
 */
export class FileAccessError extends SentinelError {
  public readonly filePath: string;
  public readonly operation: 'read' | 'write' | 'stat' | 'delete';

  constructor(
    filePath: string,
    operation: 'read' | 'write' | 'stat' | 'delete',
    options?: {
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    const message = `Cannot ${operation} file: ${filePath}`;
    super(message, 'FILE_ACCESS_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        filePath,
        operation,
      },
    });
    this.name = 'FileAccessError';
    this.filePath = filePath;
    this.operation = operation;
  }
}

/**
 * Path security errors (path traversal, escape sandbox, etc.)
 */
export class PathSecurityError extends SentinelError {
  public readonly attemptedPath: string;

  constructor(
    attemptedPath: string,
    reason: string,
    options?: {
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(`Path security violation: ${reason}`, 'PATH_SECURITY_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        attemptedPath,
        reason,
      },
    });
    this.name = 'PathSecurityError';
    this.attemptedPath = attemptedPath;
  }
}

/**
 * File size limit exceeded
 */
export class FileSizeError extends SentinelError {
  public readonly actualSize: number;
  public readonly maxSize: number;

  constructor(
    actualSize: number,
    maxSize: number,
    options?: {
      filePath?: string;
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    const actualMB = (actualSize / 1024 / 1024).toFixed(2);
    const maxMB = (maxSize / 1024 / 1024).toFixed(2);
    super(`File too large: ${actualMB}MB exceeds limit of ${maxMB}MB`, 'FILE_SIZE_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        actualSize,
        maxSize,
        ...(options?.filePath && { filePath: options.filePath }),
      },
    });
    this.name = 'FileSizeError';
    this.actualSize = actualSize;
    this.maxSize = maxSize;
  }
}

/**
 * Operation timeout errors
 */
export class TimeoutError extends SentinelError {
  public readonly operation: string;
  public readonly timeoutMs: number;

  constructor(
    operation: string,
    timeoutMs: number,
    options?: {
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    const timeoutSec = (timeoutMs / 1000).toFixed(1);
    super(`Operation "${operation}" timed out after ${timeoutSec}s`, 'TIMEOUT_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        operation,
        timeoutMs,
      },
    });
    this.name = 'TimeoutError';
    this.operation = operation;
    this.timeoutMs = timeoutMs;
  }
}

/**
 * Tool execution errors (MCP tools, analysis tools)
 */
export class ToolError extends SentinelError {
  public readonly toolName: string;

  constructor(
    toolName: string,
    message: string,
    options?: {
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(`Tool "${toolName}" failed: ${message}`, 'TOOL_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        toolName,
      },
    });
    this.name = 'ToolError';
    this.toolName = toolName;
  }
}

/**
 * Agent/workflow errors
 */
export class AgentError extends SentinelError {
  public readonly agentName: string;
  public readonly phase?: string;

  constructor(
    agentName: string,
    message: string,
    options?: {
      phase?: string;
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(`Agent "${agentName}" error: ${message}`, 'AGENT_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        agentName,
        ...(options?.phase && { phase: options.phase }),
      },
    });
    this.name = 'AgentError';
    this.agentName = agentName;
    this.phase = options?.phase;
  }
}

/**
 * Configuration errors
 */
export class ConfigError extends SentinelError {
  public readonly configKey?: string;

  constructor(
    message: string,
    options?: {
      configKey?: string;
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(message, 'CONFIG_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        ...(options?.configKey && { configKey: options.configKey }),
      },
    });
    this.name = 'ConfigError';
    this.configKey = options?.configKey;
  }
}

/**
 * External service errors (Ollama, Ghidra, etc.)
 */
export class ServiceError extends SentinelError {
  public readonly serviceName: string;

  constructor(
    serviceName: string,
    message: string,
    options?: {
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(`Service "${serviceName}" error: ${message}`, 'SERVICE_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        serviceName,
      },
    });
    this.name = 'ServiceError';
    this.serviceName = serviceName;
  }
}

/**
 * Analysis errors (during binary analysis)
 */
export class AnalysisError extends SentinelError {
  public readonly phase: string;
  public readonly filePath?: string;

  constructor(
    phase: string,
    message: string,
    options?: {
      filePath?: string;
      cause?: Error;
      metadata?: Record<string, unknown>;
    },
  ) {
    super(`Analysis failed at ${phase}: ${message}`, 'ANALYSIS_ERROR', {
      cause: options?.cause,
      metadata: {
        ...options?.metadata,
        phase,
        ...(options?.filePath && { filePath: options.filePath }),
      },
    });
    this.name = 'AnalysisError';
    this.phase = phase;
    this.filePath = options?.filePath;
  }
}

// ============================================
// ERROR UTILITIES
// ============================================

/**
 * Normalize any error to a SentinelError
 */
export function normalizeError(error: unknown): SentinelError {
  if (error instanceof SentinelError) {
    return error;
  }

  if (error instanceof Error) {
    return new SentinelError(error.message, 'UNKNOWN_ERROR', {
      cause: error,
      metadata: { originalName: error.name },
    });
  }

  if (typeof error === 'string') {
    return new SentinelError(error, 'UNKNOWN_ERROR');
  }

  return new SentinelError(`Unknown error: ${JSON.stringify(error)}`, 'UNKNOWN_ERROR', {
    metadata: { originalError: error },
  });
}

/**
 * Check if error is a specific SentinelError type
 */
export function isErrorType<T extends SentinelError>(
  error: unknown,
  ErrorClass: new (...args: never[]) => T,
): error is T {
  return error instanceof ErrorClass;
}

/**
 * Get HTTP status code for error
 */
export function getHttpStatusForError(error: SentinelError): number {
  const statusMap: Record<string, number> = {
    VALIDATION_ERROR: 400,
    FILE_ACCESS_ERROR: 404,
    PATH_SECURITY_ERROR: 403,
    FILE_SIZE_ERROR: 413,
    TIMEOUT_ERROR: 408,
    CONFIG_ERROR: 500,
    TOOL_ERROR: 500,
    AGENT_ERROR: 500,
    SERVICE_ERROR: 502,
    ANALYSIS_ERROR: 500,
    UNKNOWN_ERROR: 500,
  };

  return statusMap[error.code] ?? 500;
}
