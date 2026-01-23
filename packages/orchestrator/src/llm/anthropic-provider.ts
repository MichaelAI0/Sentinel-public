/**
 * Anthropic Provider
 * LLM provider implementation for Anthropic Claude models
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
 * Anthropic request format
 */
type AnthropicRequest = {
  model: string;
  messages: Array<{
    role: 'user' | 'assistant';
    content: string;
  }>;
  system?: string;
  max_tokens: number;
  temperature?: number;
  stream?: boolean;
  stop_sequences?: string[];
  tools?: Array<{
    name: string;
    description: string;
    input_schema: Record<string, unknown>;
  }>;
};

/**
 * Anthropic response format
 */
type AnthropicResponse = {
  id: string;
  type: 'message';
  role: 'assistant';
  content: Array<
    | { type: 'text'; text: string }
    | { type: 'tool_use'; id: string; name: string; input: Record<string, unknown> }
  >;
  model: string;
  stop_reason: 'end_turn' | 'max_tokens' | 'stop_sequence' | 'tool_use' | null;
  stop_sequence: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
};

/**
 * Anthropic streaming event types
 */
type AnthropicStreamEvent =
  | { type: 'message_start'; message: { id: string; model: string } }
  | { type: 'content_block_start'; index: number; content_block: { type: 'text'; text: string } }
  | { type: 'content_block_delta'; index: number; delta: { type: 'text_delta'; text: string } }
  | { type: 'content_block_stop'; index: number }
  | { type: 'message_delta'; delta: { stop_reason: string }; usage: { output_tokens: number } }
  | { type: 'message_stop' };

/**
 * Build Anthropic request from messages and options
 */
function buildAnthropicRequest(
  messages: ChatMessage[],
  model: string,
  options: ChatOptions | undefined,
  stream: boolean,
): AnthropicRequest {
  const systemMessage = messages.find((m) => m.role === 'system');
  const conversationMessages = messages
    .filter((m) => m.role !== 'system')
    .map((m) => ({
      role: m.role as 'user' | 'assistant',
      content: m.content,
    }));

  const request: AnthropicRequest = {
    model,
    messages: conversationMessages,
    max_tokens: options?.maxTokens ?? 4096,
    temperature: options?.temperature ?? 0,
    stream,
    stop_sequences: options?.stop,
  };

  if (systemMessage) {
    request.system = systemMessage.content;
  }

  if (options?.tools && options.tools.length > 0) {
    request.tools = options.tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.parameters,
    }));
  }

  return request;
}

/**
 * Parse SSE data line into a chat chunk
 */
function parseStreamEvent(data: string): ChatChunk | null {
  if (!data) return null;

  try {
    const event = JSON.parse(data) as AnthropicStreamEvent;

    if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
      return { content: event.delta.text, done: false };
    }
    if (event.type === 'message_stop') {
      return { content: '', done: true };
    }
  } catch {
    // Skip malformed lines
  }

  return null;
}

/**
 * Anthropic LLM Provider
 * Supports any Anthropic model via configuration
 */
export class AnthropicProvider implements LLMProvider {
  readonly name = 'anthropic';
  private config: Required<ProviderConfig>;

  constructor(config?: ProviderConfig) {
    this.config = {
      apiKey: config?.apiKey ?? process.env.ANTHROPIC_API_KEY ?? '',
      baseUrl:
        config?.baseUrl ??
        process.env.ANTHROPIC_BASE_URL ??
        'https://api.anthropic.com/v1/messages',
      model: config?.model ?? process.env.ANTHROPIC_MODEL ?? '',
      timeout: config?.timeout ?? 120000,
    };

    if (this.config.apiKey) {
      const modelInfo = this.config.model ? `model=${this.config.model}` : 'model=<per-request>';
      logger.info`AnthropicProvider configured: ${modelInfo}`;
    } else {
      logger.warn`AnthropicProvider: No API key configured`;
    }
  }

  getCapabilities(): ProviderCapabilities {
    return {
      streaming: true,
      toolCalling: true,
      vision: true,
      maxContextTokens: 200000, // Claude 3.5/4 context
    };
  }

  async isAvailable(): Promise<boolean> {
    return Boolean(this.config.apiKey);
  }

  async chat(messages: ChatMessage[], options?: ChatOptions): Promise<ChatResponse> {
    if (!this.config.apiKey) {
      throw new Error('Anthropic API key not configured');
    }

    const model = options?.model ?? this.config.model;
    if (!model) {
      throw new Error('No model specified. Set ANTHROPIC_MODEL env var or pass model in options.');
    }

    logger.debug`Anthropic chat: model=${model}, messages=${messages.length}`;

    const request = buildAnthropicRequest(messages, model, options, false);

    const response = await fetch(this.config.baseUrl, {
      method: 'POST',
      headers: {
        'x-api-key': this.config.apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Anthropic chat failed: ${response.status} - ${errorText}`);
    }

    const data = (await response.json()) as AnthropicResponse;

    // Extract text content and tool calls
    let textContent = '';
    const toolCalls: ToolCall[] = [];

    for (const block of data.content) {
      if (block.type === 'text') {
        textContent += block.text;
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id: block.id,
          name: block.name,
          arguments: block.input,
        });
      }
    }

    return {
      content: textContent,
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      finishReason: data.stop_reason === 'tool_use' ? 'tool_calls' : 'stop',
      usage: {
        promptTokens: data.usage.input_tokens,
        completionTokens: data.usage.output_tokens,
        totalTokens: data.usage.input_tokens + data.usage.output_tokens,
      },
    };
  }

  async *streamChat(messages: ChatMessage[], options?: ChatOptions): AsyncIterable<ChatChunk> {
    if (!this.config.apiKey) {
      throw new Error('Anthropic API key not configured');
    }

    const model = options?.model ?? this.config.model;
    if (!model) {
      throw new Error('No model specified. Set ANTHROPIC_MODEL env var or pass model in options.');
    }

    const request = buildAnthropicRequest(messages, model, options, true);

    const response = await fetch(this.config.baseUrl, {
      method: 'POST',
      headers: {
        'x-api-key': this.config.apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(this.config.timeout),
    });

    if (!response.ok) {
      throw new Error(`Anthropic stream failed: ${response.status}`);
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
        const parsed = parseStreamEvent(line.slice(5).trim());
        if (parsed) {
          yield parsed;
          if (parsed.done) return;
        }
      }
    }
  }

  estimateTokens(text: string): number {
    // Claude uses similar tokenization to GPT (~4 chars per token)
    return Math.ceil(text.length / 4);
  }
}
