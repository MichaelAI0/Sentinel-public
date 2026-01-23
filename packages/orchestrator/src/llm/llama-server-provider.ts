/**
 * LlamaServer Provider
 * LLM provider implementation for local llama.cpp/llama-server inference
 *
 * Uses OpenAI-compatible API from llama-server which can run:
 * - GLM-4.7-Flash (30B MoE, best for agents/coding)
 * - Any GGUF model via llama.cpp
 *
 * Recommended for tool-calling use cases with parameters:
 * --temp 0.7 --top-p 1.0 --min-p 0.01 --jinja
 *
 * @see https://unsloth.ai/docs/models/glm-4.7-flash
 * @see https://github.com/ggml-org/llama.cpp/tree/master/examples/server
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
  ToolCall,
} from './types.js';

/**
 * llama-server health response
 */
type LlamaServerHealth = {
  status: 'ok' | 'loading model' | 'error';
  progress?: number;
};

/**
 * OpenAI-compatible request format (llama-server supports this)
 */
type OpenAIRequest = {
  model: string;
  messages: Array<{
    role: string;
    content: string;
  }>;
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
  stop?: string[];
  top_p?: number;
  min_p?: number;
  tools?: Array<{
    type: 'function';
    function: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
    };
  }>;
};

/**
 * OpenAI-compatible response format
 */
type OpenAIResponse = {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string | null;
      tool_calls?: Array<{
        id: string;
        type: 'function';
        function: {
          name: string;
          arguments: string;
        };
      }>;
    };
    finish_reason: string;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
};

/**
 * LlamaServer LLM Provider
 *
 * Connects to a local llama-server instance running GGUF models.
 * Perfect for running GLM-4.7-Flash locally with ~18GB RAM.
 *
 * Configuration via environment:
 * - LLAMA_SERVER_URL: Base URL (default: http://localhost:8081)
 * - LLAMA_MODEL: Model alias (default: local-model)
 *
 * Or via Docker:
 * ```yaml
 * llama-server:
 *   image: ghcr.io/ggml-org/llama.cpp:server
 *   environment:
 *     LLAMA_ARG_MODEL: /models/glm-4.7-flash-Q4_K_XL.gguf
 *     LLAMA_ARG_CTX_SIZE: 32768
 *     LLAMA_ARG_TEMP: 0.7
 *     LLAMA_ARG_TOP_P: 1.0
 *     LLAMA_ARG_MIN_P: 0.01
 *     LLAMA_ARG_JINJA: "true"
 * ```
 */
export class LlamaServerProvider implements LLMProvider {
  readonly name = 'llama-server';
  private config: Required<ProviderConfig>;

  constructor(config?: ProviderConfig) {
    this.config = {
      apiKey: config?.apiKey ?? 'no-key-required',
      baseUrl: config?.baseUrl ?? process.env.LLAMA_SERVER_URL ?? 'http://localhost:8081',
      model: config?.model ?? process.env.LLAMA_MODEL ?? 'local-model',
      timeout: config?.timeout ?? 300000, // 5 min for local inference
    };

    logger.info`LlamaServerProvider configured: url=${this.config.baseUrl}, model=${this.config.model}`;
  }

  getCapabilities(): ProviderCapabilities {
    return {
      streaming: true,
      toolCalling: true, // GLM-4.7-Flash supports function calling with --jinja
      vision: false,
      maxContextTokens: 32768, // Conservative default, GLM supports 200K
    };
  }

  /**
   * Check if llama-server is available and ready
   */
  async isAvailable(): Promise<boolean> {
    try {
      const healthUrl = `${this.config.baseUrl}/health`;
      const response = await fetch(healthUrl, {
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) return false;

      const data = (await response.json()) as LlamaServerHealth;
      return data.status === 'ok';
    } catch (error) {
      logger.debug`LlamaServer not available: ${error}`;
      return false;
    }
  }

  /**
   * Wait for llama-server to be ready (useful during startup)
   */
  async waitForReady(maxRetries = 30, intervalMs = 2000): Promise<boolean> {
    logger.info`Waiting for llama-server to be ready...`;

    for (let i = 0; i < maxRetries; i++) {
      try {
        const healthUrl = `${this.config.baseUrl}/health`;
        const response = await fetch(healthUrl, {
          signal: AbortSignal.timeout(5000),
        });

        if (response.ok) {
          const data = (await response.json()) as LlamaServerHealth;
          if (data.status === 'ok') {
            logger.info`llama-server is ready`;
            return true;
          }
          if (data.status === 'loading model' && data.progress !== undefined) {
            logger.debug`llama-server loading model: ${Math.round(data.progress * 100)}%`;
          }
        }
      } catch {
        // Server not yet available, continue retrying
      }

      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }

    logger.warn`llama-server did not become ready after ${maxRetries} retries`;
    return false;
  }

  async chat(messages: ChatMessage[], options?: ChatOptions): Promise<ChatResponse> {
    const model = options?.model ?? this.config.model;

    logger.debug`LlamaServer chat: model=${model}, messages=${messages.length}`;

    const request: OpenAIRequest = {
      model,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      temperature: options?.temperature ?? 0.7, // GLM recommended for tool-calling
      max_tokens: options?.maxTokens ?? 4096,
      stream: false,
      stop: options?.stop,
      top_p: 1.0, // GLM recommended for tool-calling
      min_p: 0.01, // llama.cpp recommendation
    };

    // Add tools if provided
    if (options?.tools && options.tools.length > 0) {
      request.tools = options.tools.map((tool) => ({
        type: 'function' as const,
        function: {
          name: tool.name,
          description: tool.description,
          parameters: tool.parameters,
        },
      }));
    }

    const chatUrl = `${this.config.baseUrl}/v1/chat/completions`;

    const response = await fetch(chatUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`llama-server chat failed: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as OpenAIResponse;
    const choice = data.choices[0];

    if (!choice) {
      throw new Error('llama-server returned empty response');
    }

    // Parse tool calls if present
    let toolCalls: ToolCall[] | undefined;
    if (choice.message.tool_calls) {
      toolCalls = choice.message.tool_calls.map((tc) => ({
        id: tc.id,
        name: tc.function.name,
        arguments: JSON.parse(tc.function.arguments) as Record<string, unknown>,
      }));
    }

    return {
      content: choice.message.content ?? '',
      toolCalls,
      finishReason: choice.finish_reason === 'tool_calls' ? 'tool_calls' : 'stop',
      usage: data.usage
        ? {
            promptTokens: data.usage.prompt_tokens,
            completionTokens: data.usage.completion_tokens,
            totalTokens: data.usage.total_tokens,
          }
        : undefined,
    };
  }

  /**
   * Parse a single SSE line and return content if valid
   */
  private parseSSELine(line: string): { content?: string; done?: boolean } {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith('data: ')) {
      return {};
    }

    const data = trimmed.slice(6);
    if (data === '[DONE]') {
      return { done: true };
    }

    try {
      const parsed = JSON.parse(data) as {
        choices: Array<{ delta: { content?: string } }>;
      };
      const content = parsed.choices[0]?.delta?.content;
      return content ? { content } : {};
    } catch {
      // Skip malformed SSE data
      return {};
    }
  }

  /**
   * Stream chat completion
   */
  async *streamChat(
    messages: ChatMessage[],
    options?: ChatOptions,
  ): AsyncGenerator<ChatChunk, void, unknown> {
    const model = options?.model ?? this.config.model;

    logger.debug`LlamaServer stream: model=${model}, messages=${messages.length}`;

    const request: OpenAIRequest = {
      model,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      temperature: options?.temperature ?? 0.7,
      max_tokens: options?.maxTokens ?? 4096,
      stream: true,
      stop: options?.stop,
      top_p: 1.0,
      min_p: 0.01,
    };

    const chatUrl = `${this.config.baseUrl}/v1/chat/completions`;

    const response = await fetch(chatUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`llama-server stream failed: ${response.status} - ${errorText}`);
    }

    if (!response.body) {
      throw new Error('llama-server returned no stream body');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          yield { content: '', done: true };
          break;
        }

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() ?? '';

        for (const line of lines) {
          const result = this.parseSSELine(line);
          if (result.done) {
            yield { content: '', done: true };
            return;
          }
          if (result.content) {
            yield { content: result.content, done: false };
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Get server properties (model info, settings)
   */
  async getServerProps(): Promise<Record<string, unknown> | null> {
    try {
      const response = await fetch(`${this.config.baseUrl}/props`, {
        signal: AbortSignal.timeout(5000),
      });
      if (response.ok) {
        return (await response.json()) as Record<string, unknown>;
      }
    } catch {
      // Props endpoint may not be available
    }
    return null;
  }

  /**
   * Estimate tokens for given text
   * Uses a simple heuristic of ~4 characters per token (GPT-style)
   */
  estimateTokens(text: string): number {
    if (!text) return 0;
    return Math.ceil(text.length / 4);
  }
}

/**
 * Create a LlamaServerProvider with default configuration
 */
export function createLlamaServerProvider(config?: ProviderConfig): LlamaServerProvider {
  return new LlamaServerProvider(config);
}
