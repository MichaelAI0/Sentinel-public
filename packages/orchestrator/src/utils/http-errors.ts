/**
 * HTTP Error Response Utilities
 *
 * Provides consistent HTTP error responses for API endpoints:
 * - Standardized error format
 * - Proper status codes
 * - Security-conscious error messages
 * - Request ID tracking
 *
 * @module utils/http-errors
 */

import { AnalysisError, SentinelError, TimeoutError, ValidationError } from '@sentinel/shared';
import { categorizeError, normalizeError } from './error-handler';

// ============================================
// TYPES
// ============================================

/**
 * Standard error response body
 */
export type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
    requestId?: string;
    timestamp: string;
    details?: Record<string, unknown>;
  };
};

/**
 * Options for error response generation
 */
export type ErrorResponseOptions = {
  /** Request ID for tracking */
  requestId?: string;
  /** Include detailed error information (dev mode only) */
  includeDetails?: boolean;
  /** Override HTTP status code */
  statusOverride?: number;
  /** Additional headers */
  headers?: Record<string, string>;
};

// ============================================
// ERROR CODE MAPPING
// ============================================

/**
 * Map error types to standardized error codes
 */
function getErrorCode(error: Error): string {
  if (error instanceof SentinelError) {
    return error.code;
  }

  // Map common error names to codes
  const nameToCode: Record<string, string> = {
    TypeError: 'TYPE_ERROR',
    RangeError: 'RANGE_ERROR',
    SyntaxError: 'SYNTAX_ERROR',
    ReferenceError: 'REFERENCE_ERROR',
    AggregateError: 'AGGREGATE_ERROR',
  };

  return nameToCode[error.name] ?? 'INTERNAL_ERROR';
}

/**
 * Get user-safe error message (no internal details)
 */
function getSafeMessage(error: Error): string {
  const category = categorizeError(error);

  // For user-facing errors, use the message
  if (error instanceof ValidationError) {
    return error.message;
  }

  // For other errors, use category's user message
  return category.userMessage;
}

// ============================================
// RESPONSE GENERATORS
// ============================================

/**
 * Generate a standardized error response
 *
 * @param error - Error to convert to response
 * @param options - Response options
 * @returns HTTP Response object
 *
 * @example
 * ```ts
 * try {
 *   await analyzeFile(path);
 * } catch (error) {
 *   return errorResponse(error, { requestId: req.id });
 * }
 * ```
 */
export function errorResponse(error: unknown, options: ErrorResponseOptions = {}): Response {
  const normalizedError = normalizeError(error);
  const category = categorizeError(normalizedError);
  const status = options.statusOverride ?? category.httpStatus;

  const body: ErrorResponseBody = {
    error: {
      code: getErrorCode(normalizedError),
      message: getSafeMessage(normalizedError),
      timestamp: new Date().toISOString(),
    },
  };

  // Add request ID if provided
  if (options.requestId) {
    body.error.requestId = options.requestId;
  }

  // Add details in development mode
  if (options.includeDetails && process.env.NODE_ENV !== 'production') {
    body.error.details = {
      errorName: normalizedError.name,
      originalMessage: normalizedError.message,
      stack: normalizedError.stack?.split('\n').slice(0, 5),
      ...(normalizedError instanceof SentinelError && {
        metadata: normalizedError.metadata,
      }),
    };
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options.headers,
  };

  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers,
  });
}

// ============================================
// SPECIFIC ERROR RESPONSES
// ============================================

/**
 * 400 Bad Request - Validation errors
 */
export function badRequest(
  message: string,
  details?: Record<string, unknown>,
  options?: ErrorResponseOptions,
): Response {
  const error = new ValidationError(message, { metadata: details });
  return errorResponse(error, { ...options, statusOverride: 400 });
}

/**
 * 401 Unauthorized
 */
export function unauthorized(
  message = 'Authentication required',
  options?: ErrorResponseOptions,
): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: 'UNAUTHORIZED',
        message,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        'WWW-Authenticate': 'Bearer',
        ...options?.headers,
      },
    },
  );
}

/**
 * 403 Forbidden
 */
export function forbidden(message = 'Access denied', options?: ErrorResponseOptions): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: 'FORBIDDEN',
        message,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    },
  );
}

/**
 * 404 Not Found
 */
export function notFound(
  resource = 'Resource',
  identifier?: string,
  options?: ErrorResponseOptions,
): Response {
  const message = identifier ? `${resource} '${identifier}' not found` : `${resource} not found`;

  return new Response(
    JSON.stringify({
      error: {
        code: 'NOT_FOUND',
        message,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 404,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    },
  );
}

/**
 * 405 Method Not Allowed
 */
export function methodNotAllowed(
  method: string,
  allowedMethods: string[],
  options?: ErrorResponseOptions,
): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: 'METHOD_NOT_ALLOWED',
        message: `Method ${method} not allowed`,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 405,
      headers: {
        'Content-Type': 'application/json',
        Allow: allowedMethods.join(', '),
        ...options?.headers,
      },
    },
  );
}

/**
 * 408 Request Timeout
 */
export function requestTimeout(operation?: string, options?: ErrorResponseOptions): Response {
  const error = new TimeoutError(operation ?? 'request', 0);
  return errorResponse(error, { ...options, statusOverride: 408 });
}

/**
 * 413 Payload Too Large
 */
export function payloadTooLarge(
  maxSize: number,
  actualSize?: number,
  options?: ErrorResponseOptions,
): Response {
  const message = actualSize
    ? `Payload size (${formatBytes(actualSize)}) exceeds limit (${formatBytes(maxSize)})`
    : `Payload exceeds maximum size of ${formatBytes(maxSize)}`;

  return new Response(
    JSON.stringify({
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 413,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    },
  );
}

/**
 * 422 Unprocessable Entity - Analysis errors
 */
export function unprocessableEntity(
  message: string,
  details?: Record<string, unknown>,
  options?: ErrorResponseOptions,
): Response {
  const error = new AnalysisError(message, 'analysis', { metadata: details });
  return errorResponse(error, { ...options, statusOverride: 422 });
}

/**
 * 429 Too Many Requests
 */
export function tooManyRequests(
  retryAfterSeconds?: number,
  options?: ErrorResponseOptions,
): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options?.headers,
  };

  if (retryAfterSeconds !== undefined) {
    headers['Retry-After'] = String(retryAfterSeconds);
  }

  return new Response(
    JSON.stringify({
      error: {
        code: 'TOO_MANY_REQUESTS',
        message: 'Rate limit exceeded. Please try again later.',
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
        ...(retryAfterSeconds !== undefined && { retryAfter: retryAfterSeconds }),
      },
    }),
    {
      status: 429,
      headers,
    },
  );
}

/**
 * 500 Internal Server Error
 */
export function internalError(error?: unknown, options?: ErrorResponseOptions): Response {
  if (error) {
    return errorResponse(error, { ...options, statusOverride: 500 });
  }

  return new Response(
    JSON.stringify({
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred.',
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    },
  );
}

/**
 * 502 Bad Gateway - External service errors
 */
export function badGateway(service: string, options?: ErrorResponseOptions): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: 'BAD_GATEWAY',
        message: `Error communicating with ${service}`,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 502,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    },
  );
}

/**
 * 503 Service Unavailable
 */
export function serviceUnavailable(
  reason?: string,
  retryAfterSeconds?: number,
  options?: ErrorResponseOptions,
): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options?.headers,
  };

  if (retryAfterSeconds !== undefined) {
    headers['Retry-After'] = String(retryAfterSeconds);
  }

  return new Response(
    JSON.stringify({
      error: {
        code: 'SERVICE_UNAVAILABLE',
        message: reason ?? 'Service temporarily unavailable. Please try again later.',
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
        ...(retryAfterSeconds !== undefined && { retryAfter: retryAfterSeconds }),
      },
    }),
    {
      status: 503,
      headers,
    },
  );
}

/**
 * 504 Gateway Timeout
 */
export function gatewayTimeout(service?: string, options?: ErrorResponseOptions): Response {
  const message = service
    ? `Timeout waiting for response from ${service}`
    : 'Upstream service timed out';

  return new Response(
    JSON.stringify({
      error: {
        code: 'GATEWAY_TIMEOUT',
        message,
        timestamp: new Date().toISOString(),
        ...(options?.requestId && { requestId: options.requestId }),
      },
    }),
    {
      status: 504,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    },
  );
}

// ============================================
// SUCCESS RESPONSES
// ============================================

/**
 * 200 OK with JSON body
 */
export function jsonResponse<T>(
  data: T,
  options?: { status?: number; headers?: Record<string, string> },
): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status: options?.status ?? 200,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });
}

/**
 * 201 Created
 */
export function created<T>(
  data: T,
  location?: string,
  options?: { headers?: Record<string, string> },
): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options?.headers,
  };

  if (location) {
    headers.Location = location;
  }

  return new Response(JSON.stringify(data, null, 2), {
    status: 201,
    headers,
  });
}

/**
 * 204 No Content
 */
export function noContent(options?: { headers?: Record<string, string> }): Response {
  return new Response(null, {
    status: 204,
    headers: options?.headers,
  });
}

/**
 * 202 Accepted (for async operations)
 */
export function accepted<T>(
  data: T,
  statusUrl?: string,
  options?: { headers?: Record<string, string> },
): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...options?.headers,
  };

  if (statusUrl) {
    headers.Location = statusUrl;
  }

  return new Response(JSON.stringify(data, null, 2), {
    status: 202,
    headers,
  });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/**
 * Generate a unique request ID
 */
export function generateRequestId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `req_${timestamp}_${random}`;
}

/**
 * Extract request ID from headers
 */
export function getRequestId(request: Request): string {
  return (
    request.headers.get('X-Request-ID') ??
    request.headers.get('X-Correlation-ID') ??
    generateRequestId()
  );
}

/**
 * Middleware wrapper for consistent error handling
 *
 * @param handler - Request handler function
 * @returns Wrapped handler with error catching
 *
 * @example
 * ```ts
 * const handler = withErrorHandling(async (req) => {
 *   const data = await processRequest(req);
 *   return jsonResponse(data);
 * });
 * ```
 */
export function withErrorHandling(
  handler: (request: Request) => Promise<Response>,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const requestId = getRequestId(request);

    try {
      return await handler(request);
    } catch (error) {
      return errorResponse(error, {
        requestId,
        includeDetails: process.env.NODE_ENV !== 'production',
      });
    }
  };
}
