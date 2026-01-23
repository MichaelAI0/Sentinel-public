/**
 * Multi-Model Orchestrator
 *
 * Routes analysis tasks to specialist AI models based on their strengths.
 * Enables parallel processing and efficient resource utilization.
 */

import type { LLMClient } from '../llm/llm-client.js';
import type { AnalysisResults, AssemblyPattern, EnhancedString, FunctionInfo } from '../types.js';

// ============================================================================
// Model Capabilities
// ============================================================================

export type ModelCapability = {
  name: string;
  model: string;
  contextSize: number;
  strengths: string[];
  cost: number; // Relative cost (1 = cheapest)
};

export const AVAILABLE_MODELS: Record<string, ModelCapability> = {
  gemma_2b: {
    name: 'Gemma 2B',
    model: 'gemma:2b',
    contextSize: 8192,
    strengths: ['fast', 'categorization', 'lightweight', 'string-analysis'],
    cost: 1,
  },
  phi3: {
    name: 'Phi-3',
    model: 'phi3:latest',
    contextSize: 4096,
    strengths: ['code-understanding', 'efficient', 'function-summary'],
    cost: 2,
  },
  codellama: {
    name: 'CodeLlama 13B',
    model: 'codellama:13b',
    contextSize: 16384,
    strengths: ['assembly', 'decompiled-code', 'detailed-analysis'],
    cost: 4,
  },
  qwen: {
    name: 'Qwen 2.5 7B',
    model: 'qwen2.5:7b-instruct',
    contextSize: 32768,
    strengths: ['general-analysis', 'synthesis', 'large-context', 'malware'],
    cost: 3,
  },
};

// ============================================================================
// Specialist Analysis Types
// ============================================================================

export type StringAnalysis = {
  categories: {
    urls: string[];
    ips: string[];
    paths: string[];
    apis: string[];
    suspicious: string[];
    other: string[];
  };
  summary: string;
};

export type FunctionAnalysis = {
  summaries: Array<{
    name: string;
    address: string;
    purpose: string;
    riskLevel: 'low' | 'medium' | 'high';
  }>;
  callGraph: string;
};

export type AssemblyAnalysis = {
  patterns: Array<{
    type: string;
    description: string;
    significance: string;
  }>;
  systemCalls: string[];
  memoryOperations: string[];
};

export type SynthesisResult = {
  overallAssessment: string;
  malwareLikelihood: number;
  keyFindings: string[];
  recommendations: string[];
};

export type SpecialistAnalysisResult = {
  strings?: StringAnalysis;
  functions?: FunctionAnalysis;
  assembly?: AssemblyAnalysis;
  synthesis?: SynthesisResult;
};

// ============================================================================
// Input Data Type
// ============================================================================

export type MultiModelInput = {
  binaryInfo?: {
    name: string;
    architecture?: string;
  };
  strings: EnhancedString[];
  functions: FunctionInfo[];
  assembly: AssemblyPattern[];
};

// ============================================================================
// Multi-Model Orchestrator
// ============================================================================

export class MultiModelOrchestrator {
  constructor(private llmClient: LLMClient) {}

  /**
   * Check which models are available on the Ollama server
   */
  async getAvailableModels(): Promise<string[]> {
    try {
      const response = await fetch('http://ollama:11434/api/tags');
      if (!response.ok) return [];

      const data = (await response.json()) as { models: Array<{ name: string }> };
      return data.models.map((m) => m.name);
    } catch {
      return [];
    }
  }

  /**
   * Route analysis to specialist models
   */
  async analyzeWithSpecialists(data: MultiModelInput): Promise<SpecialistAnalysisResult> {
    const available = await this.getAvailableModels();
    const result: SpecialistAnalysisResult = {};

    const gemmaModel = AVAILABLE_MODELS.gemma_2b;
    const phi3Model = AVAILABLE_MODELS.phi3;
    const codelamaModel = AVAILABLE_MODELS.codellama;
    const qwenModel = AVAILABLE_MODELS.qwen;

    // Use available models, fallback to qwen for missing specialists
    const tasks: Promise<void>[] = [];

    // String analysis with Gemma (fast categorization)
    if (gemmaModel && available.includes(gemmaModel.model)) {
      tasks.push(
        this.analyzeStringsWithGemma(data.strings, gemmaModel).then((r) => {
          result.strings = r;
        }),
      );
    }

    // Function analysis with Phi-3 (code understanding)
    if (phi3Model && available.includes(phi3Model.model)) {
      tasks.push(
        this.analyzeFunctionsWithPhi(data.functions, phi3Model).then((r) => {
          result.functions = r;
        }),
      );
    }

    // Assembly analysis with CodeLlama (assembly expert)
    if (codelamaModel && available.includes(codelamaModel.model)) {
      tasks.push(
        this.analyzeAssemblyWithCodeLlama(data.assembly, codelamaModel).then((r) => {
          result.assembly = r;
        }),
      );
    }

    // Wait for specialist analyses
    await Promise.all(tasks);

    // Final synthesis with Qwen (general + malware expertise)
    if (qwenModel && available.includes(qwenModel.model)) {
      result.synthesis = await this.synthesizeWithQwen(data, result, qwenModel);
    }

    return result;
  }

  /**
   * Fast string categorization with Gemma 2B
   */
  private async analyzeStringsWithGemma(
    strings: EnhancedString[],
    _model: ModelCapability,
  ): Promise<StringAnalysis> {
    const sampleStrings = strings.slice(0, 100).map((s) => s.value);

    const systemPrompt = 'You are a malware string analyzer. Categorize strings concisely.';
    const userMessage = `Categorize these strings from a binary. Be concise.
${sampleStrings.join('\n')}

Return JSON with categories:
- urls: HTTP/HTTPS URLs
- ips: IP addresses
- paths: File paths
- apis: API/function names
- suspicious: Suspicious or encoded strings
- other: Everything else

Also provide a brief summary.`;

    try {
      const response = await this.llmClient.generate(systemPrompt, userMessage, {
        temperature: 0.3,
      });
      const parsed = this.extractJSON<StringAnalysis>(response);

      return (
        parsed || {
          categories: { urls: [], ips: [], paths: [], apis: [], suspicious: [], other: [] },
          summary: 'Failed to parse categorization',
        }
      );
    } catch {
      return {
        categories: { urls: [], ips: [], paths: [], apis: [], suspicious: [], other: [] },
        summary: 'Error during analysis',
      };
    }
  }

  /**
   * Function summarization with Phi-3
   */
  private async analyzeFunctionsWithPhi(
    functions: FunctionInfo[],
    _model: ModelCapability,
  ): Promise<FunctionAnalysis> {
    const topFunctions = functions.slice(0, 15);

    const systemPrompt = 'You are a reverse engineering expert. Summarize functions.';
    const userMessage = `Analyze these functions from a binary. For each, provide:
1. A brief purpose (1 sentence)
2. Risk level (low/medium/high)

Functions:
${topFunctions.map((f) => `${f.name} @ ${f.address} (suspicious: ${f.isSuspicious})`).join('\n')}

Return JSON with: summaries array containing {name, address, purpose, riskLevel}`;

    try {
      const response = await this.llmClient.generate(systemPrompt, userMessage, {
        temperature: 0.4,
      });
      const parsed = this.extractJSON<{ summaries: FunctionAnalysis['summaries'] }>(response);

      return {
        summaries: parsed?.summaries || [],
        callGraph: this.generateCallGraphSummary(functions),
      };
    } catch {
      return {
        summaries: [],
        callGraph: 'Error during analysis',
      };
    }
  }

  /**
   * Assembly interpretation with CodeLlama
   */
  private async analyzeAssemblyWithCodeLlama(
    assembly: AssemblyPattern[],
    _model: ModelCapability,
  ): Promise<AssemblyAnalysis> {
    const samplePatterns = assembly.slice(0, 20);

    const systemPrompt = 'You are an assembly language expert. Analyze binary patterns.';
    const userMessage = `Analyze these assembly patterns from a binary.
Identify:
1. What each pattern does
2. System calls or dangerous operations
3. Memory manipulation techniques

Patterns:
${samplePatterns.map((p) => `${p.category}: ${p.name} - ${p.instructions.join('; ')}`).join('\n')}

Return JSON with: patterns[], systemCalls[], memoryOperations[]`;

    try {
      const response = await this.llmClient.generate(systemPrompt, userMessage, {
        temperature: 0.4,
      });
      const parsed = this.extractJSON<AssemblyAnalysis>(response);

      return (
        parsed || {
          patterns: [],
          systemCalls: [],
          memoryOperations: [],
        }
      );
    } catch {
      return {
        patterns: [],
        systemCalls: [],
        memoryOperations: [],
      };
    }
  }

  /**
   * Final synthesis with Qwen
   */
  private async synthesizeWithQwen(
    data: MultiModelInput,
    specialistResults: SpecialistAnalysisResult,
    _model: ModelCapability,
  ): Promise<SynthesisResult> {
    const systemPrompt = 'You are a senior malware analyst. Synthesize findings into assessments.';
    const userMessage = `You are analyzing a malware sample. Here's what specialists found:

Binary: ${data.binaryInfo?.name || 'unknown'}
Architecture: ${data.binaryInfo?.architecture || 'unknown'}

String Analysis:
${specialistResults.strings?.summary || 'Not available'}

Function Analysis:
${specialistResults.functions?.summaries.map((s) => `- ${s.name}: ${s.purpose} (${s.riskLevel})`).join('\n') || 'Not available'}

Assembly Patterns:
${specialistResults.assembly?.patterns.map((p) => `- ${p.type}: ${p.description}`).join('\n') || 'Not available'}

Provide JSON with:
- overallAssessment: string (2-3 sentences)
- malwareLikelihood: number (0.0-1.0)
- keyFindings: string[] (top 3-5 findings)
- recommendations: string[] (3-5 recommended actions)`;

    try {
      const response = await this.llmClient.generate(systemPrompt, userMessage, {
        temperature: 0.5,
      });
      const parsed = this.extractJSON<SynthesisResult>(response);

      return (
        parsed || {
          overallAssessment: 'Failed to generate assessment',
          malwareLikelihood: 0.5,
          keyFindings: [],
          recommendations: [],
        }
      );
    } catch {
      return {
        overallAssessment: 'Error during synthesis',
        malwareLikelihood: 0.5,
        keyFindings: [],
        recommendations: [],
      };
    }
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  /**
   * Extract JSON from model response
   */
  private extractJSON<T>(response: string): T | null {
    try {
      // Try direct parse
      return JSON.parse(response) as T;
    } catch {
      // Try to find JSON in markdown code blocks
      const jsonMatch = response.match(/```json?\s*(\{[\s\S]*?\})\s*```/);
      if (jsonMatch?.[1]) {
        try {
          return JSON.parse(jsonMatch[1]) as T;
        } catch {
          return null;
        }
      }

      // Try to find any JSON object
      const objectMatch = response.match(/\{[\s\S]*\}/);
      if (objectMatch?.[0]) {
        try {
          return JSON.parse(objectMatch[0]) as T;
        } catch {
          return null;
        }
      }

      return null;
    }
  }

  /**
   * Generate call graph summary
   */
  private generateCallGraphSummary(functions: FunctionInfo[]): string {
    const lines: string[] = [];
    lines.push('Function Summary:');

    for (const func of functions.slice(0, 10)) {
      const suspiciousMarker = func.isSuspicious ? ' [SUSPICIOUS]' : '';
      lines.push(`${func.name}${suspiciousMarker}`);
    }

    return lines.join('\n');
  }

  /**
   * Create input data from analysis results
   */
  static fromAnalysisResults(results: AnalysisResults, binaryName?: string): MultiModelInput {
    return {
      binaryInfo: binaryName ? { name: binaryName } : undefined,
      strings: results.enhancedStrings || [],
      functions: results.functions,
      assembly: results.assemblyPatterns || [],
    };
  }
}
