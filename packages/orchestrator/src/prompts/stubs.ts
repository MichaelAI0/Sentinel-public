/**
 * LLM Prompt Stubs (Open Source Version)
 *
 * The actual prompts are proprietary and distributed with @sentinel/premium.
 * These stubs provide minimal functionality for the community edition.
 *
 * Community Edition users get heuristic-based analysis without AI prompts.
 * Professional/Enterprise users get full AI-powered analysis from @sentinel/premium.
 *
 * @module prompts/stubs
 */

/**
 * Stub analyzer prompt for community edition
 * Real prompt is in @sentinel/premium
 */
export const ANALYZER_SYSTEM_PROMPT_STUB = `You are a binary analysis assistant.
Analyze the provided data and output a JSON object with your findings.
This is a limited community edition prompt.`;

/**
 * Stub triage prompt for community edition
 * Real prompt is in @sentinel/premium
 */
export const TRIAGE_SYSTEM_PROMPT_STUB = `You are a binary triage assistant.
Assess the risk level of the provided binary data.
This is a limited community edition prompt.`;

/**
 * Stub report prompt for community edition
 * Real prompt is in @sentinel/premium
 */
export const REPORT_SYSTEM_PROMPT_STUB = `You are a security report writer.
Generate a summary of the analysis findings.
This is a limited community edition prompt.`;

/**
 * Check if premium prompts are available
 */
export async function loadPremiumPrompts(): Promise<{
  ANALYZER_SYSTEM_PROMPT: string;
  TRIAGE_SYSTEM_PROMPT: string;
  REPORT_SYSTEM_PROMPT: string;
} | null> {
  try {
    const premium = await import('@sentinel/premium');
    if (premium.prompts) {
      return {
        ANALYZER_SYSTEM_PROMPT: premium.prompts.ANALYZER_SYSTEM_PROMPT,
        TRIAGE_SYSTEM_PROMPT: premium.prompts.TRIAGE_SYSTEM_PROMPT,
        REPORT_SYSTEM_PROMPT: premium.prompts.REPORT_SYSTEM_PROMPT,
      };
    }
    return null;
  } catch {
    return null;
  }
}
