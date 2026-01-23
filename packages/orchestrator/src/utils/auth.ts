/**
 * Authentication Module
 * Better Auth integration for SENTINEL API
 *
 * Uses Better Auth (https://www.better-auth.com) for:
 * - API key management with built-in rate limiting
 * - Stateless session management (no database required)
 * - Redis secondary storage support for multi-instance deployments
 *
 * SENTINEL is a local-first tool, so we use stateless mode by default.
 * API keys are the primary authentication mechanism for programmatic access.
 *
 * @module utils/auth
 * @see https://www.better-auth.com/docs/plugins/api-key
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { logger } from './logger.js';

// =============================================================================
// Types (using `type` per style guide, not `interface`)
// =============================================================================

/**
 * SENTINEL permission types for API access control
 */
export type Permission =
  | 'analyze' // Run binary analysis
  | 'triage' // Run triage operations
  | 'read' // Read analysis results
  | 'admin' // Administrative operations
  | 'metrics' // Access metrics endpoint
  | '*'; // Wildcard - all permissions

/**
 * Permission record for Better Auth API key plugin
 * Maps resource types to allowed actions
 */
export type PermissionRecord = {
  [resource: string]: string[];
};

/**
 * API key metadata stored in memory or secondary storage
 */
export type ApiKeyMetadata = {
  /** Unique key identifier (not the key itself) */
  id: string;
  /** Human-readable name */
  name: string;
  /** Hash of the API key (SHA-256) */
  keyHash: string;
  /** Key prefix for identification (first 8 chars) */
  prefix: string;
  /** Permissions granted to this key */
  permissions: Permission[];
  /** Creation timestamp */
  createdAt: Date;
  /** Expiration timestamp (optional) */
  expiresAt?: Date;
  /** Last used timestamp */
  lastUsedAt?: Date;
  /** Whether the key is active */
  active: boolean;
  /** Rate limit override (requests per minute) */
  rateLimit?: number;
};

/**
 * Authentication result from key validation
 */
export type AuthResult = {
  authenticated: boolean;
  keyId?: string;
  permissions?: Permission[];
  error?: string;
  rateLimit?: number;
};

/**
 * Better Auth configuration for SENTINEL
 */
export type BetterAuthConfig = {
  /** Secret for signing sessions/tokens (from BETTER_AUTH_SECRET env) */
  secret?: string;
  /** Base URL for auth endpoints (from BETTER_AUTH_URL env) */
  baseUrl?: string;
  /** Enable stateless mode (no database required) */
  stateless?: boolean;
  /** Redis configuration for secondary storage */
  redis?: {
    url: string;
    keyPrefix?: string;
  };
  /** Default rate limit for API keys (requests per day) */
  defaultRateLimit?: {
    enabled: boolean;
    timeWindow: number;
    maxRequests: number;
  };
};

/**
 * API key creation options
 */
export type CreateApiKeyOptions = {
  /** Expiration in days */
  expiresInDays?: number;
  /** Custom rate limit (requests per minute) */
  rateLimit?: number;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
};

// =============================================================================
// Configuration
// =============================================================================

/**
 * Default Better Auth configuration for SENTINEL
 * Uses stateless mode since SENTINEL is local-first
 */
const defaultConfig: BetterAuthConfig = {
  secret: process.env.BETTER_AUTH_SECRET ?? process.env.AUTH_SECRET,
  baseUrl: process.env.BETTER_AUTH_URL ?? 'http://localhost:8080',
  stateless: true,
  defaultRateLimit: {
    enabled: true,
    timeWindow: 60 * 1000, // 1 minute
    maxRequests: 100,
  },
};

let authConfig: BetterAuthConfig = { ...defaultConfig };

/**
 * Configure Better Auth settings
 */
export function configureBetterAuth(config: Partial<BetterAuthConfig>): void {
  authConfig = { ...authConfig, ...config };
  logger.info('Better Auth configured', { stateless: authConfig.stateless });
}

/**
 * Get current Better Auth configuration
 */
export function getBetterAuthConfig(): BetterAuthConfig {
  return { ...authConfig };
}

// =============================================================================
// API Key Storage (in-memory for local-first, Redis for multi-instance)
// =============================================================================

/**
 * In-memory API key store
 * In production multi-instance deployments, use Redis via secondaryStorage
 */
const apiKeyStore: Map<string, ApiKeyMetadata> = new Map();

/**
 * Secondary storage adapter for Redis (Better Auth compatible)
 */
export type SecondaryStorage = {
  get: (key: string) => Promise<string | null>;
  set: (key: string, value: string, ttl?: number) => Promise<void>;
  delete: (key: string) => Promise<void>;
};

let secondaryStorage: SecondaryStorage | null = null;

/**
 * Configure secondary storage (Redis) for API keys
 */
export function configureSecondaryStorage(storage: SecondaryStorage): void {
  secondaryStorage = storage;
  logger.info('Secondary storage configured for API keys');
}

// =============================================================================
// API Key Generation & Hashing
// =============================================================================

/**
 * Generate a secure API key
 * Format: sentinel_<32 random bytes in hex>
 */
export function generateApiKey(prefix = 'sentinel'): {
  key: string;
  hash: string;
  keyPrefix: string;
} {
  const randomPart = randomBytes(32).toString('hex');
  const key = `${prefix}_${randomPart}`;
  const hash = hashApiKey(key);
  const keyPrefix = key.substring(0, Math.min(16, key.length));

  return { key, hash, keyPrefix };
}

/**
 * Hash an API key using SHA-256
 */
export function hashApiKey(key: string): string {
  return createHash('sha256').update(key).digest('hex');
}

/**
 * Verify an API key hash in constant time (timing-safe)
 */
export function verifyApiKeyHash(key: string, expectedHash: string): boolean {
  const keyHash = hashApiKey(key);
  const keyBuffer = Buffer.from(keyHash, 'hex');
  const expectedBuffer = Buffer.from(expectedHash, 'hex');

  if (keyBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(keyBuffer, expectedBuffer);
}

// =============================================================================
// API Key CRUD Operations
// =============================================================================

/**
 * Create a new API key
 * Compatible with Better Auth API key plugin patterns
 */
export function createApiKey(
  name: string,
  permissions: Permission[] = ['analyze', 'triage', 'read'],
  options?: CreateApiKeyOptions,
): { key: string; metadata: ApiKeyMetadata } {
  const { key, hash, keyPrefix } = generateApiKey();
  const id = randomBytes(16).toString('hex');

  const metadata: ApiKeyMetadata = {
    id,
    name,
    keyHash: hash,
    prefix: keyPrefix,
    permissions,
    createdAt: new Date(),
    expiresAt: options?.expiresInDays
      ? new Date(Date.now() + options.expiresInDays * 24 * 60 * 60 * 1000)
      : undefined,
    active: true,
    rateLimit: options?.rateLimit,
  };

  apiKeyStore.set(id, metadata);

  // Also store in secondary storage if configured
  if (secondaryStorage) {
    const storageKey = `api-key:${hash}`;
    const ttl = metadata.expiresAt
      ? Math.floor((metadata.expiresAt.getTime() - Date.now()) / 1000)
      : undefined;
    secondaryStorage
      .set(storageKey, JSON.stringify(metadata), ttl)
      .catch((err) => logger.error('Failed to store API key in secondary storage', err));
  }

  logger.info('Created API key', { name, prefix: keyPrefix });

  return { key, metadata };
}

/**
 * Validate an API key and return authentication result
 */
export function validateApiKey(key: string): AuthResult {
  if (!key) {
    return { authenticated: false, error: 'No API key provided' };
  }

  // Find key by prefix
  const prefix = key.substring(0, Math.min(16, key.length));
  let foundMetadata: ApiKeyMetadata | undefined;

  for (const metadata of apiKeyStore.values()) {
    if (metadata.prefix === prefix) {
      foundMetadata = metadata;
      break;
    }
  }

  if (!foundMetadata) {
    return { authenticated: false, error: 'Invalid API key' };
  }

  // Verify hash in constant time
  if (!verifyApiKeyHash(key, foundMetadata.keyHash)) {
    return { authenticated: false, error: 'Invalid API key' };
  }

  // Check if active
  if (!foundMetadata.active) {
    return { authenticated: false, error: 'API key is disabled' };
  }

  // Check expiration
  if (foundMetadata.expiresAt && foundMetadata.expiresAt < new Date()) {
    return { authenticated: false, error: 'API key has expired' };
  }

  // Update last used timestamp
  foundMetadata.lastUsedAt = new Date();

  return {
    authenticated: true,
    keyId: foundMetadata.id,
    permissions: foundMetadata.permissions,
    rateLimit: foundMetadata.rateLimit,
  };
}

/**
 * Revoke an API key
 */
export function revokeApiKey(keyId: string): boolean {
  const metadata = apiKeyStore.get(keyId);
  if (metadata) {
    metadata.active = false;

    // Also update in secondary storage if configured
    if (secondaryStorage) {
      const storageKey = `api-key:${metadata.keyHash}`;
      secondaryStorage
        .set(storageKey, JSON.stringify(metadata))
        .catch((err) => logger.error('Failed to update API key in secondary storage', err));
    }

    logger.info('Revoked API key', { name: metadata.name });
    return true;
  }
  return false;
}

/**
 * Delete an API key
 */
export function deleteApiKey(keyId: string): boolean {
  const metadata = apiKeyStore.get(keyId);
  if (metadata) {
    apiKeyStore.delete(keyId);

    // Also delete from secondary storage if configured
    if (secondaryStorage) {
      const storageKey = `api-key:${metadata.keyHash}`;
      secondaryStorage
        .delete(storageKey)
        .catch((err) => logger.error('Failed to delete API key from secondary storage', err));
    }

    logger.info('Deleted API key', { name: metadata.name });
    return true;
  }
  return false;
}

/**
 * List all API keys (without sensitive data)
 */
export function listApiKeys(): Omit<ApiKeyMetadata, 'keyHash'>[] {
  return Array.from(apiKeyStore.values()).map(({ keyHash: _, ...rest }) => rest);
}

/**
 * Get API key by ID
 */
export function getApiKey(keyId: string): Omit<ApiKeyMetadata, 'keyHash'> | undefined {
  const metadata = apiKeyStore.get(keyId);
  if (metadata) {
    const { keyHash: _, ...rest } = metadata;
    return rest;
  }
  return undefined;
}

// =============================================================================
// JWT Support (for stateless session tokens)
// =============================================================================

/**
 * JWT payload structure (using `type` per style guide)
 */
export type JwtPayload = {
  /** Subject (user/key ID) */
  sub: string;
  /** Issued at (Unix timestamp) */
  iat: number;
  /** Expiration (Unix timestamp) */
  exp: number;
  /** Permissions */
  permissions: Permission[];
  /** Token type */
  type: 'api' | 'session';
};

/**
 * JWT configuration
 */
let jwtSecret: string | null = null;
const JWT_ALGORITHM = 'HS256';
const JWT_DEFAULT_EXPIRY = 24 * 60 * 60; // 24 hours in seconds

/**
 * Set JWT secret (must be at least 32 characters)
 */
export function setJwtSecret(secret: string): void {
  if (secret.length < 32) {
    throw new Error('JWT secret must be at least 32 characters');
  }
  jwtSecret = secret;
}

/**
 * Base64URL encode
 */
function base64UrlEncode(data: string): string {
  return Buffer.from(data)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64URL decode
 */
function base64UrlDecode(data: string): string {
  const padded = data + '='.repeat((4 - (data.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
}

/**
 * Create HMAC signature
 */
function createSignature(data: string, secret: string): string {
  const hmac = createHash('sha256');
  hmac.update(`${data}${secret}`);
  return base64UrlEncode(hmac.digest('hex'));
}

/**
 * Generate a JWT token
 */
export function generateJwt(
  subject: string,
  permissions: Permission[],
  options?: {
    expiresIn?: number; // seconds
    type?: 'api' | 'session';
  },
): string {
  if (!jwtSecret) {
    throw new Error('JWT secret not configured');
  }

  const now = Math.floor(Date.now() / 1000);
  const payload: JwtPayload = {
    sub: subject,
    iat: now,
    exp: now + (options?.expiresIn ?? JWT_DEFAULT_EXPIRY),
    permissions,
    type: options?.type ?? 'session',
  };

  const header = base64UrlEncode(JSON.stringify({ alg: JWT_ALGORITHM, typ: 'JWT' }));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const signature = createSignature(`${header}.${payloadB64}`, jwtSecret);

  return `${header}.${payloadB64}.${signature}`;
}

/**
 * Verify and decode a JWT token
 */
export function verifyJwt(token: string): AuthResult {
  if (!jwtSecret) {
    return { authenticated: false, error: 'JWT not configured' };
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { authenticated: false, error: 'Invalid token format' };
    }

    const [header, payloadB64, signature] = parts;

    // Verify all parts exist
    if (!header || !payloadB64 || !signature) {
      return { authenticated: false, error: 'Invalid token format' };
    }

    // Verify signature
    const expectedSignature = createSignature(`${header}.${payloadB64}`, jwtSecret);
    if (signature !== expectedSignature) {
      return { authenticated: false, error: 'Invalid signature' };
    }

    // Decode payload
    const payload = JSON.parse(base64UrlDecode(payloadB64)) as JwtPayload;

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) {
      return { authenticated: false, error: 'Token expired' };
    }

    return {
      authenticated: true,
      keyId: payload.sub,
      permissions: payload.permissions,
    };
  } catch {
    return { authenticated: false, error: 'Invalid token' };
  }
}

// =============================================================================
// Authentication Middleware
// =============================================================================

/**
 * Authentication configuration (using `type` per style guide)
 */
export type AuthConfig = {
  /** Enable authentication */
  enabled: boolean;
  /** Public endpoints (no auth required) */
  publicEndpoints?: string[];
  /** Allow API key auth */
  allowApiKey?: boolean;
  /** Allow JWT auth */
  allowJwt?: boolean;
  /** Header name for API key */
  apiKeyHeader?: string;
};

const defaultMiddlewareConfig: Required<AuthConfig> = {
  enabled: false,
  publicEndpoints: ['/', '/health', '/ready', '/api'],
  allowApiKey: true,
  allowJwt: true,
  apiKeyHeader: 'x-api-key',
};

let middlewareConfig: Required<AuthConfig> = { ...defaultMiddlewareConfig };

/**
 * Configure authentication middleware
 */
export function configureAuth(config: Partial<AuthConfig>): void {
  middlewareConfig = { ...defaultMiddlewareConfig, ...config };
  logger.info('Authentication middleware configured', { enabled: middlewareConfig.enabled });
}

/**
 * Extract authentication from request
 */
export function authenticateRequest(req: Request): AuthResult {
  // Check if auth is disabled
  if (!middlewareConfig.enabled) {
    return { authenticated: true, permissions: ['*'] };
  }

  // Check if endpoint is public
  const url = new URL(req.url);
  if (middlewareConfig.publicEndpoints.includes(url.pathname)) {
    return { authenticated: true, permissions: ['read'] };
  }

  // Try API key authentication
  if (middlewareConfig.allowApiKey) {
    const apiKey = req.headers.get(middlewareConfig.apiKeyHeader);
    if (apiKey) {
      return validateApiKey(apiKey);
    }
  }

  // Try JWT authentication (Bearer token)
  if (middlewareConfig.allowJwt) {
    const authHeader = req.headers.get('authorization');
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      return verifyJwt(token);
    }
  }

  return { authenticated: false, error: 'Authentication required' };
}

/**
 * Check if user has required permission
 */
export function hasPermission(authResult: AuthResult, required: Permission): boolean {
  if (!authResult.authenticated || !authResult.permissions) {
    return false;
  }

  return authResult.permissions.includes('*') || authResult.permissions.includes(required);
}

/**
 * Create 401 Unauthorized response
 */
export function createUnauthorizedResponse(error = 'Unauthorized'): Response {
  return new Response(JSON.stringify({ error }), {
    status: 401,
    headers: {
      'Content-Type': 'application/json',
      'WWW-Authenticate': 'Bearer, ApiKey',
    },
  });
}

/**
 * Create 403 Forbidden response
 */
export function createForbiddenResponse(error = 'Insufficient permissions'): Response {
  return new Response(JSON.stringify({ error }), {
    status: 403,
    headers: { 'Content-Type': 'application/json' },
  });
}

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize authentication from environment
 * Supports both Better Auth configuration and legacy JWT/API key setup
 */
export function initAuth(): void {
  // Check for Better Auth secret (preferred)
  const betterAuthSecret = process.env.BETTER_AUTH_SECRET ?? process.env.AUTH_SECRET;
  if (betterAuthSecret) {
    configureBetterAuth({
      secret: betterAuthSecret,
      baseUrl: process.env.BETTER_AUTH_URL,
    });
  }

  // Check for JWT secret in environment (legacy support)
  const jwtSecretEnv = process.env.SENTINEL_JWT_SECRET;
  if (jwtSecretEnv) {
    setJwtSecret(jwtSecretEnv);
  }

  // Check for auth config in environment
  const enabled = process.env.SENTINEL_AUTH_ENABLED === 'true';
  configureAuth({ enabled });

  // Create default admin key if none exists and auth is enabled
  if (enabled && apiKeyStore.size === 0) {
    const { key } = createApiKey('default-admin', ['*'], { rateLimit: 1000 });
    logger.warn('Created default admin API key - store this securely!', { key });
    logger.warn('This key will not be shown again');
  }

  logger.info('Authentication initialized', {
    enabled,
    betterAuthConfigured: !!betterAuthSecret,
    jwtConfigured: !!jwtSecretEnv,
  });
}

// =============================================================================
// Better Auth Integration Helpers
// =============================================================================

/**
 * Convert SENTINEL permissions to Better Auth permission record format
 */
export function toPermissionRecord(permissions: Permission[]): PermissionRecord {
  const record: PermissionRecord = {};

  for (const perm of permissions) {
    if (perm === '*') {
      // Wildcard grants all actions on all resources
      record['*'] = ['*'];
    } else if (perm === 'analyze') {
      record.analysis = ['execute', 'read'];
    } else if (perm === 'triage') {
      record.triage = ['execute', 'read'];
    } else if (perm === 'read') {
      record.results = ['read'];
    } else if (perm === 'admin') {
      record.admin = ['*'];
    } else if (perm === 'metrics') {
      record.metrics = ['read'];
    }
  }

  return record;
}

/**
 * Convert Better Auth permission record to SENTINEL permissions
 */
export function fromPermissionRecord(record: PermissionRecord): Permission[] {
  const permissions: Permission[] = [];

  if (record['*']?.includes('*')) {
    return ['*'];
  }

  if (record.analysis?.includes('execute')) {
    permissions.push('analyze');
  }
  if (record.triage?.includes('execute')) {
    permissions.push('triage');
  }
  if (record.results?.includes('read')) {
    permissions.push('read');
  }
  if (record.admin?.includes('*')) {
    permissions.push('admin');
  }
  if (record.metrics?.includes('read')) {
    permissions.push('metrics');
  }

  return permissions;
}

/**
 * Create a Redis secondary storage adapter for Better Auth
 * Usage:
 *   import { createClient } from 'redis';
 *   const redis = createClient();
 *   await redis.connect();
 *   configureSecondaryStorage(createRedisStorage(redis));
 */
export function createRedisStorageAdapter(
  redis: {
    get: (key: string) => Promise<string | null>;
    set: (key: string, value: string, options?: { EX?: number }) => Promise<unknown>;
    del: (key: string) => Promise<unknown>;
  },
  keyPrefix = 'sentinel:auth:',
): SecondaryStorage {
  return {
    get: async (key: string) => {
      return await redis.get(`${keyPrefix}${key}`);
    },
    set: async (key: string, value: string, ttl?: number) => {
      if (ttl) {
        await redis.set(`${keyPrefix}${key}`, value, { EX: ttl });
      } else {
        await redis.set(`${keyPrefix}${key}`, value);
      }
    },
    delete: async (key: string) => {
      await redis.del(`${keyPrefix}${key}`);
    },
  };
}

/**
 * Validate API key from request header
 * Compatible with Better Auth x-api-key header pattern
 */
export function validateApiKeyFromRequest(req: Request): AuthResult {
  const apiKey = req.headers.get('x-api-key');
  if (!apiKey) {
    return { authenticated: false, error: 'No API key provided' };
  }
  return validateApiKey(apiKey);
}
