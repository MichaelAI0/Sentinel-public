/**
 * Premium Module Loader
 *
 * Dynamically loads @sentinel/premium package when:
 * 1. A valid Professional/Enterprise license is present
 * 2. The premium package is installed
 *
 * This module provides graceful degradation - if premium isn't available,
 * the public agents use heuristic fallbacks.
 *
 * @module agents/premium-loader
 */

import { hasFeature, getLicenseType } from '../config/features.js';
import type { IPremiumModule, PremiumLoadResult } from './interfaces.js';

/** Cached premium module (singleton) */
let cachedPremium: IPremiumModule | null = null;
let loadAttempted = false;
let loadError: string | null = null;

/**
 * Attempt to load the premium module
 *
 * The premium module is distributed separately and installed via:
 * npm install @sentinel/premium (with license key in .npmrc)
 *
 * @returns Load result with module or error reason
 */
export async function loadPremiumModule(): Promise<PremiumLoadResult> {
  // Return cached result if already attempted
  if (loadAttempted) {
    if (cachedPremium) {
      return { loaded: true, module: cachedPremium };
    }
    return { loaded: false, reason: loadError ?? 'Premium module not available' };
  }

  loadAttempted = true;

  // Check license first
  const licenseType = getLicenseType();
  if (licenseType === 'community') {
    loadError = 'Community license - premium features not included';
    return { loaded: false, reason: loadError };
  }

  // Check if AI features are enabled
  if (!hasFeature('AI_TRIAGE') && !hasFeature('AI_ANALYZER')) {
    loadError = 'AI features not enabled for this license tier';
    return { loaded: false, reason: loadError };
  }

  try {
    // Attempt dynamic import of premium package
    // This package is NOT in the public repo - it's installed separately
    const premium = await import('@sentinel/premium');

    // Validate the module has expected exports
    if (!premium.TriageAgent || !premium.AnalyzerAgent || !premium.ReportAgent) {
      loadError = 'Invalid premium module structure';
      return { loaded: false, reason: loadError };
    }

    // Build the premium module from imports
    const premiumModule: IPremiumModule = {
      TriageAgent: premium.TriageAgent,
      AnalyzerAgent: premium.AnalyzerAgent,
      ReportAgent: premium.ReportAgent,
      version: premium.version ?? '1.0.0',
    };

    cachedPremium = premiumModule;
    return { loaded: true, module: cachedPremium };
  } catch (error) {
    // Premium package not installed - this is expected for open source users
    if (error instanceof Error && error.message.includes('Cannot find package')) {
      loadError = 'Premium package not installed. Install with: npm install @sentinel/premium';
    } else {
      loadError = `Failed to load premium module: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
    return { loaded: false, reason: loadError };
  }
}

/**
 * Check if premium module is available
 * (Non-blocking check using cached state)
 */
export function isPremiumAvailable(): boolean {
  return cachedPremium !== null;
}

/**
 * Get the cached premium module (if loaded)
 */
export function getPremiumModule(): IPremiumModule | null {
  return cachedPremium;
}

/**
 * Get the reason why premium failed to load
 */
export function getPremiumLoadError(): string | null {
  return loadError;
}

/**
 * Reset loader state (mainly for testing)
 */
export function resetPremiumLoader(): void {
  cachedPremium = null;
  loadAttempted = false;
  loadError = null;
}
