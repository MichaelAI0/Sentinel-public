/**
 * LLM Prompt Templates (Open Source Version)
 *
 * This module provides stub prompts for the Community Edition.
 * Professional/Enterprise users get enhanced prompts from @sentinel/premium.
 *
 * The actual proprietary prompts are distributed separately and loaded
 * dynamically when a valid license is present.
 *
 * @module prompts
 */

/**
 * Community Edition analyzer prompt.
 * Provides basic analysis capability.
 * Premium users get enhanced prompts with detailed MITRE mappings.
 */
export const ANALYZER_SYSTEM_PROMPT = `You are a binary analysis assistant.
Analyze the provided Ghidra data and output a JSON object with:
{
  "malwareFamily": "Family name or null",
  "familyConfidence": 0.0-1.0,
  "capabilities": ["List of capabilities"],
  "antiAnalysis": ["Anti-analysis techniques"],
  "sophistication": "Basic" | "Intermediate" | "Advanced" | "Expert",
  "mitreTechniques": [{"id": "TXXXX", "name": "...", "tactic": "...", "evidence": [], "confidence": 0.0}],
  "iocs": {"ipAddresses": [], "domains": [], "urls": [], "filePaths": [], "registryKeys": [], "mutexes": []},
  "keyFindings": ["Key findings"],
  "technicalNotes": "Analysis notes"
}

[Community Edition - Upgrade for enhanced analysis prompts]`;

/**
 * Community Edition triage prompt.
 * Provides basic risk assessment.
 * Premium users get enhanced prompts with detailed indicators.
 */
export const TRIAGE_SYSTEM_PROMPT = `You are a binary triage assistant.
Quickly assess the risk level of the provided binary data.

Output a JSON object with:
{
  "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation",
  "recommendation": "IGNORE" | "INVESTIGATE" | "ESCALATE",
  "keyIndicators": ["suspicious indicators"],
  "estimatedAnalysisTime": "X-Y minutes"
}

[Community Edition - Upgrade for enhanced triage prompts]`;

/**
 * Attempt to load premium prompts if available.
 * Returns null if @sentinel/premium is not installed.
 */
export async function loadPremiumPrompts(): Promise<{
  ANALYZER_SYSTEM_PROMPT: string;
  TRIAGE_SYSTEM_PROMPT: string;
} | null> {
  try {
    // Dynamic import of premium package
    const premium = await import('@sentinel/premium');
    if (premium.prompts) {
      return {
        ANALYZER_SYSTEM_PROMPT: premium.prompts.ANALYZER_SYSTEM_PROMPT,
        TRIAGE_SYSTEM_PROMPT: premium.prompts.TRIAGE_SYSTEM_PROMPT,
      };
    }
    return null;
  } catch {
    // Premium package not installed - expected for community users
    return null;
  }
}

