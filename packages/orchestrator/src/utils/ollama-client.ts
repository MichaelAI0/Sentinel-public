/**
 * Ollama LLM Client
 * Wrapper for local LLM inference via Ollama
 */

import type { OllamaConfig } from '../types.js';
import { logger } from './logger.js';

/**
 * Message format for Ollama chat API
 */
interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

/**
 * Ollama chat response
 */
interface ChatResponse {
  message: {
    role: string;
    content: string;
  };
  done: boolean;
  total_duration?: number;
  eval_count?: number;
}

/**
 * Ollama LLM Client for local inference
 */
export class OllamaClient {
  private config: OllamaConfig;

  constructor(config?: Partial<OllamaConfig>) {
    this.config = {
      baseUrl: config?.baseUrl ?? process.env.OLLAMA_BASE_URL ?? 'http://ollama:11434',
      model: config?.model ?? process.env.OLLAMA_MODEL ?? 'llama3.2',
      timeout: config?.timeout ?? 120000, // 2 minutes default
    };

    logger.info`Ollama client configured: model=${this.config.model}, url=${this.config.baseUrl}`;
  }

  /**
   * Check if Ollama is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * List available models
   */
  async listModels(): Promise<string[]> {
    try {
      const response = await fetch(`${this.config.baseUrl}/api/tags`);
      if (!response.ok) {
        throw new Error(`Failed to list models: ${response.status}`);
      }

      const data = (await response.json()) as { models: Array<{ name: string }> };
      return data.models.map((m) => m.name);
    } catch (error) {
      logger.error`Failed to list Ollama models: ${error}`;
      return [];
    }
  }

  /**
   * Pull a model if not available
   */
  async ensureModel(modelName?: string): Promise<boolean> {
    const model = modelName ?? this.config.model;
    const models = await this.listModels();

    if (models.some((m) => m.startsWith(model))) {
      logger.debug`Model ${model} is available`;
      return true;
    }

    logger.info`Pulling model ${model}...`;

    try {
      const response = await fetch(`${this.config.baseUrl}/api/pull`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: model, stream: false }),
      });

      if (!response.ok) {
        throw new Error(`Failed to pull model: ${response.status}`);
      }

      logger.info`Model ${model} pulled successfully`;
      return true;
    } catch (error) {
      logger.error`Failed to pull model ${model}: ${error}`;
      return false;
    }
  }

  /**
   * Generate a chat completion
   */
  async chat(
    messages: ChatMessage[],
    options?: {
      temperature?: number;
      maxTokens?: number;
      model?: string;
    },
  ): Promise<string> {
    const model = options?.model ?? this.config.model;

    logger.debug`Ollama chat request: model=${model}, messages=${messages.length}`;

    const response = await fetch(`${this.config.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        options: {
          temperature: options?.temperature ?? 0,
          num_predict: options?.maxTokens ?? 4096,
        },
      }),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Ollama chat failed: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as ChatResponse;

    if (data.eval_count) {
      logger.debug`Ollama response: ${data.eval_count} tokens generated`;
    }

    return data.message.content;
  }

  /**
   * Generate with a system prompt and user message
   */
  async generate(
    systemPrompt: string,
    userMessage: string,
    options?: { temperature?: number },
  ): Promise<string> {
    return this.chat(
      [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage },
      ],
      options,
    );
  }

  /**
   * Analyze with structured output expectation (JSON)
   */
  async analyzeJson<T>(
    systemPrompt: string,
    userMessage: string,
    options?: { temperature?: number },
  ): Promise<T | null> {
    const enhancedPrompt = `${systemPrompt}

IMPORTANT: Your response MUST be valid JSON only. No markdown, no explanations, just the JSON object.`;

    const response = await this.generate(enhancedPrompt, userMessage, options);

    try {
      // Try to extract JSON from the response
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as T;
      }

      // Try parsing the whole response
      return JSON.parse(response) as T;
    } catch (error) {
      logger.error`Failed to parse JSON from Ollama response: ${error}`;
      logger.debug`Raw response: ${response}`;
      return null;
    }
  }
}

// Singleton instance
let ollamaInstance: OllamaClient | null = null;

/**
 * Get or create the Ollama client singleton
 */
export function getOllamaClient(): OllamaClient {
  if (!ollamaInstance) {
    ollamaInstance = new OllamaClient();
  }
  return ollamaInstance;
}
