import { z } from 'zod';
import {
  PRIORITY_LEVELS,
  RECOMMENDATIONS,
  RISK_LEVELS,
  SOPHISTICATION_LEVELS,
} from '../constants.js';

// ============================================
// AGENT CONFIGURATION
// ============================================

export const AgentConfigSchema = z.object({
  name: z.string(),
  role: z.string(),
  description: z.string(),
  temperature: z.number().min(0).max(2),
  maxTokens: z.number().int().positive(),
  systemPrompt: z.string(),
  authorizedTools: z.array(z.string()),
});

// ============================================
// TRIAGE AGENT
// ============================================

export const TriageAgentOutputSchema = z.object({
  riskLevel: z.enum(RISK_LEVELS),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
  recommendation: z.enum(RECOMMENDATIONS),
  estimatedAnalysisTime: z.string(),
  priority: z.enum(PRIORITY_LEVELS),
  quickIOCs: z.object({
    suspiciousStrings: z.array(z.string()),
    suspiciousImports: z.array(z.string()),
    networkIndicators: z.array(z.string()),
  }),
});

// ============================================
// ANALYZER AGENT
// ============================================

export const AnalyzerAgentOutputSchema = z.object({
  malwareFamily: z.string().nullable(),
  confidence: z.number().min(0).max(1),
  capabilities: z.array(z.string()),
  iocs: z.object({
    c2Servers: z.array(z.string()),
    filePaths: z.array(z.string()),
    registryKeys: z.array(z.string()),
    mutexes: z.array(z.string()),
  }),
  sophistication: z.enum(SOPHISTICATION_LEVELS),
  antiAnalysis: z.array(z.string()),
  keyFunctions: z.array(
    z.object({
      name: z.string(),
      address: z.string(),
      description: z.string(),
      techniques: z.array(z.string()),
    }),
  ),
  mitreTechniques: z.array(z.string()),
});

// ============================================
// REPORT AGENT
// ============================================

export const ReportAgentOutputSchema = z.object({
  executiveSummary: z.string(),
  technicalSummary: z.string(),
  reportPaths: z.object({
    markdown: z.string(),
    json: z.string(),
    stix: z.string(),
  }),
  generatedAt: z.string(), // ISO 8601
});

// ============================================
// TYPE EXPORTS
// ============================================

export type AgentConfig = z.infer<typeof AgentConfigSchema>;
export type TriageAgentOutput = z.infer<typeof TriageAgentOutputSchema>;
export type AnalyzerAgentOutput = z.infer<typeof AnalyzerAgentOutputSchema>;
export type ReportAgentOutput = z.infer<typeof ReportAgentOutputSchema>;
