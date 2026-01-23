/**
 * License Validation Module
 *
 * Handles loading, parsing, and validating SENTINEL licenses.
 * Supports offline validation with signature verification.
 *
 * @module utils/license-validator
 */

import { createVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { type LicenseType, setLicenseType } from '../config/features.js';
import { logger } from './logger.js';

// =============================================================================
// Types
// =============================================================================

/**
 * License data structure
 */
export type License = {
  /** Unique license identifier */
  id: string;
  /** License tier */
  type: LicenseType;
  /** Licensee email */
  email: string;
  /** Organization name (enterprise only) */
  organization?: string;
  /** Number of seats (enterprise only) */
  seats: number;
  /** ISO date when license was issued */
  issuedAt: string;
  /** ISO date when license expires */
  expiresAt: string;
  /** Cryptographic signature */
  signature: string;
};

/**
 * License validation result
 */
export type LicenseValidationResult = {
  valid: boolean;
  license: License | null;
  error?: string;
};

// =============================================================================
// Configuration
// =============================================================================

/**
 * Public key for license signature verification
 * This key is safe to distribute - it can only verify, not create signatures
 */
const PUBLIC_KEY = process.env.SENTINEL_LICENSE_PUBLIC_KEY ?? '';

/**
 * License server URL for online validation
 */
const LICENSE_SERVER_URL = process.env.SENTINEL_LICENSE_SERVER ?? 'https://api.example.com/sentinel';

// =============================================================================
// Parsing
// =============================================================================

/**
 * Parse a base64-encoded license string into a License object
 */
export function parseLicense(licenseString: string): License | null {
  try {
    const decoded = Buffer.from(licenseString.trim(), 'base64').toString('utf8');
    const license = JSON.parse(decoded) as License;

    // Validate required fields
    if (!license.id || !license.type || !license.email || !license.expiresAt) {
      logger.error('License missing required fields');
      return null;
    }

    // Validate type is known
    const validTypes: LicenseType[] = ['community', 'professional', 'enterprise', 'cloud'];
    if (!validTypes.includes(license.type)) {
      logger.error('Unknown license type', { type: license.type });
      return null;
    }

    return license;
  } catch (error) {
    logger.error('Failed to parse license', { error });
    return null;
  }
}

// =============================================================================
// Validation
// =============================================================================

/**
 * Verify license signature using public key
 */
export function verifyLicenseSignature(license: License): boolean {
  if (!PUBLIC_KEY) {
    logger.debug('No public key configured, skipping signature verification');
    return true; // Allow in development
  }

  try {
    const { signature, ...payload } = license;
    const message = JSON.stringify(payload);

    const verify = createVerify('sha256');
    verify.update(message);

    return verify.verify(PUBLIC_KEY, signature, 'base64');
  } catch (error) {
    logger.error('Signature verification failed', { error });
    return false;
  }
}

/**
 * Check if license has expired
 */
export function isLicenseExpired(license: License): boolean {
  const expiresAt = new Date(license.expiresAt);
  const now = new Date();
  return expiresAt < now;
}

/**
 * Calculate days until license expiration
 */
export function daysUntilExpiration(license: License): number {
  const expiresAt = new Date(license.expiresAt);
  const now = new Date();
  const diffMs = expiresAt.getTime() - now.getTime();
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Validate a license completely (parse, verify, check expiration)
 */
export function validateLicense(licenseString: string): LicenseValidationResult {
  // Parse the license
  const license = parseLicense(licenseString);
  if (!license) {
    return { valid: false, license: null, error: 'Invalid license format' };
  }

  // Verify signature
  if (!verifyLicenseSignature(license)) {
    return { valid: false, license: null, error: 'Invalid license signature' };
  }

  // Check expiration
  if (isLicenseExpired(license)) {
    return { valid: false, license, error: 'License has expired' };
  }

  // Warn if expiring soon
  const daysLeft = daysUntilExpiration(license);
  if (daysLeft <= 30) {
    logger.warn(`License expires in ${daysLeft} days`);
  }

  return { valid: true, license };
}

// =============================================================================
// Loading
// =============================================================================

/**
 * Load license from environment or file
 *
 * Priority:
 * 1. SENTINEL_LICENSE environment variable
 * 2. ~/.sentinel/license.key file
 * 3. ./.sentinel-license file (project local)
 * 4. None (community edition)
 */
export function loadLicense(): LicenseValidationResult {
  // Try environment variable first
  let licenseString = process.env.SENTINEL_LICENSE;

  // Try home directory
  if (!licenseString) {
    try {
      const homePath = join(homedir(), '.sentinel', 'license.key');
      licenseString = readFileSync(homePath, 'utf8').trim();
      logger.debug('Loaded license from ~/.sentinel/license.key');
    } catch {
      // File doesn't exist, continue
    }
  }

  // Try local project file
  if (!licenseString) {
    try {
      licenseString = readFileSync('.sentinel-license', 'utf8').trim();
      logger.debug('Loaded license from .sentinel-license');
    } catch {
      // File doesn't exist, continue
    }
  }

  // No license found - use community
  if (!licenseString) {
    logger.debug('No license found, using Community Edition');
    return {
      valid: true,
      license: {
        id: 'community',
        type: 'community',
        email: 'community@example.com',
        seats: 1,
        issuedAt: new Date().toISOString(),
        expiresAt: '2099-12-31T23:59:59Z',
        signature: '',
      },
    };
  }

  return validateLicense(licenseString);
}

/**
 * Initialize licensing system
 * Call this at application startup
 */
export function initializeLicense(): License | null {
  const result = loadLicense();

  if (!result.valid) {
    logger.error('License validation failed', { error: result.error });
    // Fall back to community
    setLicenseType('community');
    return null;
  }

  if (result.license) {
    setLicenseType(result.license.type);
    logger.info('License loaded', {
      type: result.license.type,
      email: result.license.email,
      expiresAt: result.license.expiresAt,
    });
  }

  return result.license;
}

// =============================================================================
// Remote Validation (Optional)
// =============================================================================

/**
 * Validate license against remote server
 * Falls back to offline validation if server unreachable
 */
export async function validateLicenseRemote(
  licenseString: string,
): Promise<LicenseValidationResult> {
  try {
    const response = await fetch(`${LICENSE_SERVER_URL}/api/licenses/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ licenseKey: licenseString }),
      signal: AbortSignal.timeout(5000), // 5 second timeout
    });

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const data = (await response.json()) as { valid: boolean; error?: string };

    if (!data.valid) {
      return { valid: false, license: null, error: data.error };
    }

    // Parse the license locally for full data
    const license = parseLicense(licenseString);
    return { valid: true, license };
  } catch (error) {
    logger.warn('Remote validation failed, using offline validation', { error });
    return validateLicense(licenseString);
  }
}
