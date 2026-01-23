/**
 * LLM Client
 * Backward-compatible client that wraps LLMProvider for use in agents
 *
 * This adapter provides the same API as the legacy OllamaClient but uses
 * the new multi-provider LLMProviderRouter under the hood.
 */

import { logger } from '../utils/logger.js';
import type { RetryConfig } from './retry.js';
import { DEFAULT_RETRY_CONFIG, withRetry } from './retry.js';
import type { ProviderName } from './router.js';
import { getLLMRouter } from './router.js';
import type { ChatMessage, ChatOptions, LLMProvider } from './types.js';

/** LLM client configuration */
export type LLMClientConfig = {
  /** Provider to use (defaults to router's default) */
  provider?: ProviderName;
  /** Default model override */
  model?: string;
  /** Request timeout in ms */
  timeout?: number;
  /** Retry configuration */
  retry?: Partial<RetryConfig>;
  /** Whether to enable retries (default: true) */
  enableRetry?: boolean;
};

/**
 * LLM Client - Multi-provider wrapper with OllamaClient-compatible API
 *
 * Usage:
 * ```typescript
 * const client = getLLMClient();
 * const response = await client.generate(systemPrompt, userMessage);
 * const data = await client.analyzeJson<MyType>(systemPrompt, userMessage);
 * ```
 */
export class LLMClient {
  private provider: LLMProvider;
  private config: LLMClientConfig;
  private retryConfig: Partial<RetryConfig>;

  constructor(config?: LLMClientConfig) {
    this.config = {
      provider: config?.provider,
      model: config?.model,
      timeout: config?.timeout ?? 120000,
      enableRetry: config?.enableRetry ?? true,
    };
    this.retryConfig = config?.retry ?? DEFAULT_RETRY_CONFIG;

    const router = getLLMRouter();

    if (config?.provider) {
      this.provider = router.getProvider(config.provider);
    } else {
      // Use the best available provider for analysis
      this.provider = router.getBestForAnalysis();
    }

    logger.info`LLMClient using provider: ${this.provider.name}`;
  }

  /**
   * Get the underlying provider
   */
  getProvider(): LLMProvider {
    return this.provider;
  }

  /**
   * Get provider capabilities
   */
  getCapabilities(): ReturnType<LLMProvider['getCapabilities']> {
    return this.provider.getCapabilities();
  }

  /**
   * Check if provider is available
   */
  async isAvailable(): Promise<boolean> {
    return this.provider.isAvailable();
  }

  /**
   * Generate a chat completion (returns content string only)
   */
  async chat(
    messages: ChatMessage[],
    options?: {
      temperature?: number;
      maxTokens?: number;
      model?: string;
    },
  ): Promise<string> {
    const chatOptions: ChatOptions = {
      temperature: options?.temperature,
      maxTokens: options?.maxTokens,
      model: options?.model ?? this.config.model,
    };

    const executeChat = async (): Promise<string> => {
      const response = await this.provider.chat(messages, chatOptions);
      return response.content;
    };

    if (this.config.enableRetry) {
      const result = await withRetry(executeChat, this.retryConfig);
      if (result.ok) {
        if (result.attempts > 1) {
          logger.debug`Chat succeeded after ${result.attempts} attempts`;
        }
        return result.value;
      }
      throw result.error;
    }

    return executeChat();
  }

  /**
   * Generate with a system prompt and user message
   * Compatible with legacy OllamaClient.generate()
   */
  async generate(
    systemPrompt: string,
    userMessage: string,
    options?: { temperature?: number; maxTokens?: number },
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
   * Compatible with legacy OllamaClient.analyzeJson()
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
      logger.error`Failed to parse JSON from LLM response: ${error}`;
      logger.debug`Raw response: ${response}`;
      return null;
    }
  }

  /**
   * Estimate token count for text
   */
  estimateTokens(text: string): number {
    return this.provider.estimateTokens(text);
  }
}

// Singleton instance
let clientInstance: LLMClient | null = null;

/**
 * Get or create the LLM client singleton
 */
export function getLLMClient(config?: LLMClientConfig): LLMClient {
  if (!clientInstance) {
    clientInstance = new LLMClient(config);
  }
  return clientInstance;
}

/**
 * Reset the LLM client (for testing)
 */
export function resetLLMClient(): void {
  clientInstance = null;
}
