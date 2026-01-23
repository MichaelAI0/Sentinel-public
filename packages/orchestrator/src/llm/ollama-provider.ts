/**
 * Ollama Provider
 * LLM provider implementation for local Ollama inference
 */

import { logger } from '../utils/logger.js';
import type {
  ChatChunk,
  ChatMessage,
  ChatOptions,
  ChatResponse,
  LLMProvider,
  ProviderCapabilities,
  ProviderConfig,
} from './types.js';

/**
 * Ollama-specific response types
 */
interface OllamaChatResponse {
  message: {
    role: string;
    content: string;
  };
  done: boolean;
  total_duration?: number;
  eval_count?: number;
  prompt_eval_count?: number;
}

/**
 * Ollama LLM Provider
 */
export class OllamaProvider implements LLMProvider {
  readonly name = 'ollama';
  private config: Required<ProviderConfig>;

  constructor(config?: ProviderConfig) {
    this.config = {
      apiKey: config?.apiKey ?? '',
      baseUrl: config?.baseUrl ?? process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434',
      model: config?.model ?? process.env.OLLAMA_MODEL ?? 'qwen2.5-coder:7b',
      timeout: config?.timeout ?? 120000,
    };

    logger.info`OllamaProvider configured: model=${this.config.model}, url=${this.config.baseUrl}`;
  }

  getCapabilities(): ProviderCapabilities {
    return {
      streaming: true,
      toolCalling: false, // Ollama tool calling is model-dependent
      vision: false,
      maxContextTokens: 32768, // Varies by model
    };
  }

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

  async chat(messages: ChatMessage[], options?: ChatOptions): Promise<ChatResponse> {
    const model = options?.model ?? this.config.model;

    logger.debug`Ollama chat: model=${model}, messages=${messages.length}`;

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
          stop: options?.stop,
        },
      }),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Ollama chat failed: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as OllamaChatResponse;

    return {
      content: data.message.content,
      finishReason: 'stop',
      usage: data.eval_count
        ? {
            promptTokens: data.prompt_eval_count ?? 0,
            completionTokens: data.eval_count,
            totalTokens: (data.prompt_eval_count ?? 0) + data.eval_count,
          }
        : undefined,
    };
  }

  async *streamChat(messages: ChatMessage[], options?: ChatOptions): AsyncIterable<ChatChunk> {
    const model = options?.model ?? this.config.model;

    const response = await fetch(`${this.config.baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream: true,
        options: {
          temperature: options?.temperature ?? 0,
          num_predict: options?.maxTokens ?? 4096,
          stop: options?.stop,
        },
      }),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      throw new Error(`Ollama stream failed: ${response.status}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split('\n').filter((line) => line.trim());

      for (const line of lines) {
        try {
          const data = JSON.parse(line) as OllamaChatResponse;
          yield {
            content: data.message.content,
            done: data.done,
          };
        } catch {
          // Skip malformed lines
        }
      }
    }
  }

  estimateTokens(text: string): number {
    // Rough estimate: ~4 chars per token for English
    return Math.ceil(text.length / 4);
  }

  /**
   * List available models
   */
  async listModels(): Promise<string[]> {
    try {
      const response = await fetch(`${this.config.baseUrl}/api/tags`);
      if (!response.ok) return [];

      const data = (await response.json()) as { models: Array<{ name: string }> };
      return data.models.map((m) => m.name);
    } catch {
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
      return true;
    }

    logger.info`Pulling Ollama model ${model}...`;

    try {
      const response = await fetch(`${this.config.baseUrl}/api/pull`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: model, stream: false }),
      });

      return response.ok;
    } catch {
      return false;
    }
  }
}
