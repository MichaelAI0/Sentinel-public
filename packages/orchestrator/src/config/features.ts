/**
 * Feature Flag System for Open Core Model
 *
 * Determines which features are available based on license type.
 * Community edition is free and open source.
 * Professional and Enterprise require commercial licenses.
 *
 * @module config/features
 */

import { logger } from '../utils/logger.js';

// =============================================================================
// Types (using `type` per style guide)
// =============================================================================

/**
 * License types available for SENTINEL
 */
export type LicenseType = 'community' | 'professional' | 'enterprise' | 'cloud';

/**
 * Feature flags for each license tier
 */
export type Features = {
  /** AI-powered 30-second triage */
  AI_TRIAGE: boolean;
  /** Deep analysis with MITRE ATT&CK mapping */
  AI_ANALYZER: boolean;
  /** Automated report generation */
  AI_REPORT: boolean;
  /** Cloud LLM providers (OpenAI, Anthropic, Google) */
  CLOUD_LLMS: boolean;
  /** Web dashboard access */
  WEB_DASHBOARD: boolean;
  /** Batch processing > 5 samples */
  BATCH_PROCESSING: boolean;
  /** STIX 2.1 threat intelligence export */
  STIX_EXPORT: boolean;
  /** SSO/SAML authentication */
  SSO_AUTH: boolean;
  /** Role-based access control */
  RBAC: boolean;
  /** Compliance audit logging */
  AUDIT_LOGGING: boolean;
  /** No rate limits on analysis */
  UNLIMITED_SAMPLES: boolean;
  /** Priority support access */
  PRIORITY_SUPPORT: boolean;
};

// =============================================================================
// Feature Matrix
// =============================================================================

/**
 * Feature availability by license type
 */
const FEATURE_MATRIX: Record<LicenseType, Features> = {
  community: {
    AI_TRIAGE: false,
    AI_ANALYZER: false,
    AI_REPORT: false,
    CLOUD_LLMS: false,
    WEB_DASHBOARD: false,
    BATCH_PROCESSING: false,
    STIX_EXPORT: false,
    SSO_AUTH: false,
    RBAC: false,
    AUDIT_LOGGING: false,
    UNLIMITED_SAMPLES: false,
    PRIORITY_SUPPORT: false,
  },
  professional: {
    AI_TRIAGE: true,
    AI_ANALYZER: true,
    AI_REPORT: true,
    CLOUD_LLMS: true,
    WEB_DASHBOARD: true,
    BATCH_PROCESSING: true,
    STIX_EXPORT: false,
    SSO_AUTH: false,
    RBAC: false,
    AUDIT_LOGGING: false,
    UNLIMITED_SAMPLES: false,
    PRIORITY_SUPPORT: false,
  },
  enterprise: {
    AI_TRIAGE: true,
    AI_ANALYZER: true,
    AI_REPORT: true,
    CLOUD_LLMS: true,
    WEB_DASHBOARD: true,
    BATCH_PROCESSING: true,
    STIX_EXPORT: true,
    SSO_AUTH: true,
    RBAC: true,
    AUDIT_LOGGING: true,
    UNLIMITED_SAMPLES: true,
    PRIORITY_SUPPORT: true,
  },
  cloud: {
    AI_TRIAGE: true,
    AI_ANALYZER: true,
    AI_REPORT: true,
    CLOUD_LLMS: true,
    WEB_DASHBOARD: true,
    BATCH_PROCESSING: true,
    STIX_EXPORT: true,
    SSO_AUTH: true,
    RBAC: false,
    AUDIT_LOGGING: true,
    UNLIMITED_SAMPLES: true,
    PRIORITY_SUPPORT: true,
  },
} as const;

// =============================================================================
// State
// =============================================================================

let currentLicense: LicenseType = 'community';
let currentFeatures: Features = { ...FEATURE_MATRIX.community };

// =============================================================================
// Functions
// =============================================================================

/**
 * Set the current license type and update available features
 */
export function setLicenseType(license: LicenseType): void {
  currentLicense = license;
  currentFeatures = { ...FEATURE_MATRIX[license] };
  logger.debug('License type set', { license });
}

/**
 * Get the current license type
 */
export function getLicenseType(): LicenseType {
  return currentLicense;
}

/**
 * Get all current feature flags
 */
export function getFeatures(): Features {
  return { ...currentFeatures };
}

/**
 * Check if a specific feature is enabled
 */
export function hasFeature(feature: keyof Features): boolean {
  return currentFeatures[feature];
}

/**
 * Require a feature or throw an error with upgrade message
 */
export function requireFeature(feature: keyof Features): void {
  if (!currentFeatures[feature]) {
    const featureName = feature.replace(/_/g, ' ').toLowerCase();
    const upgradeUrl = 'https://github.com/MichaelAI0/Sentinel-public';

    throw new Error(
      `Feature "${featureName}" requires a Professional or Enterprise license.\n` +
        `Current license: ${currentLicense}\n` +
        `Upgrade at: ${upgradeUrl}`,
    );
  }
}

/**
 * Get a human-readable edition name
 */
export function getEditionName(): string {
  switch (currentLicense) {
    case 'community':
      return 'Community Edition (Open Source)';
    case 'professional':
      return 'Professional Edition';
    case 'enterprise':
      return 'Enterprise Edition';
    case 'cloud':
      return 'Cloud Edition';
    default:
      return 'Unknown Edition';
  }
}

/**
 * Check if current license is paid tier
 */
export function isPaidTier(): boolean {
  return currentLicense !== 'community';
}

/**
 * Get list of features available in current license
 */
export function listEnabledFeatures(): string[] {
  return Object.entries(currentFeatures)
    .filter(([_, enabled]) => enabled)
    .map(([feature]) => feature);
}

/**
 * Get list of features NOT available in current license
 */
export function listDisabledFeatures(): string[] {
  return Object.entries(currentFeatures)
    .filter(([_, enabled]) => !enabled)
    .map(([feature]) => feature);
}
