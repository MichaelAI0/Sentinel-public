/**
 * OpenAI Provider
 * LLM provider implementation for OpenAI GPT models
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
 * OpenAI request format
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
 * OpenAI response format
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
 * OpenAI LLM Provider
 * Supports any OpenAI-compatible model via configuration
 */
export class OpenAIProvider implements LLMProvider {
  readonly name = 'openai';
  private config: Required<ProviderConfig>;

  constructor(config?: ProviderConfig) {
    this.config = {
      apiKey: config?.apiKey ?? process.env.OPENAI_API_KEY ?? '',
      baseUrl:
        config?.baseUrl ??
        process.env.OPENAI_BASE_URL ??
        'https://api.openai.com/v1/chat/completions',
      model: config?.model ?? process.env.OPENAI_MODEL ?? '',
      timeout: config?.timeout ?? 120000,
    };

    if (this.config.apiKey) {
      const modelInfo = this.config.model ? `model=${this.config.model}` : 'model=<per-request>';
      logger.info`OpenAIProvider configured: ${modelInfo}`;
    } else {
      logger.warn`OpenAIProvider: No API key configured`;
    }
  }

  getCapabilities(): ProviderCapabilities {
    return {
      streaming: true,
      toolCalling: true,
      vision: true,
      maxContextTokens: 128000, // Conservative default, varies by model
    };
  }

  async isAvailable(): Promise<boolean> {
    if (!this.config.apiKey) return false;

    try {
      // List models to verify API key works
      const response = await fetch('https://api.openai.com/v1/models', {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
        },
        signal: AbortSignal.timeout(10000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  async chat(messages: ChatMessage[], options?: ChatOptions): Promise<ChatResponse> {
    if (!this.config.apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    const model = options?.model ?? this.config.model;
    if (!model) {
      throw new Error('No model specified. Set OPENAI_MODEL env var or pass model in options.');
    }

    logger.debug`OpenAI chat: model=${model}, messages=${messages.length}`;

    const request: OpenAIRequest = {
      model,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      temperature: options?.temperature ?? 0,
      max_tokens: options?.maxTokens ?? 4096,
      stream: false,
      stop: options?.stop,
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

    const response = await fetch(this.config.baseUrl, {
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
      throw new Error(`OpenAI chat failed: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as OpenAIResponse;
    const choice = data.choices[0];

    if (!choice) {
      throw new Error('OpenAI returned empty response');
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

  async *streamChat(messages: ChatMessage[], options?: ChatOptions): AsyncIterable<ChatChunk> {
    if (!this.config.apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    const model = options?.model ?? this.config.model;
    if (!model) {
      throw new Error('No model specified. Set OPENAI_MODEL env var or pass model in options.');
    }

    const request: OpenAIRequest = {
      model,
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      temperature: options?.temperature ?? 0,
      max_tokens: options?.maxTokens ?? 4096,
      stream: true,
      stop: options?.stop,
    };

    const response = await fetch(this.config.baseUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      throw new Error(`OpenAI stream failed: ${response.status}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error('No response body');

    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = decoder.decode(value, { stream: true });
      const lines = chunk.split('\n').filter((line) => line.startsWith('data:'));

      for (const line of lines) {
        const data = line.slice(5).trim();
        if (data === '[DONE]') {
          yield { content: '', done: true };
          return;
        }

        try {
          const parsed = JSON.parse(data) as {
            choices: Array<{ delta: { content?: string } }>;
          };
          const content = parsed.choices[0]?.delta?.content ?? '';
          yield { content, done: false };
        } catch {
          // Skip malformed lines
        }
      }
    }
  }

  estimateTokens(text: string): number {
    // GPT uses ~4 chars per token for English
    return Math.ceil(text.length / 4);
  }
}
