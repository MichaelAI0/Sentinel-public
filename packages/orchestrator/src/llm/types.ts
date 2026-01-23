/**
 * LLM Provider Types
 * Shared types for multi-provider LLM abstraction
 */

/** Chat message roles */
export const MESSAGE_ROLES = ['system', 'user', 'assistant'] as const;
export type MessageRole = (typeof MESSAGE_ROLES)[number];

/** Chat message format (OpenAI-compatible) */
export type ChatMessage = {
  role: MessageRole;
  content: string;
};

/** Tool definition for function calling */
export type ToolDefinition = {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
};

/** Tool call from the LLM */
export type ToolCall = {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
};

/** Finish reasons for chat completion */
export const FINISH_REASONS = ['stop', 'tool_calls', 'length', 'error'] as const;
export type FinishReason = (typeof FINISH_REASONS)[number];

/** Chat completion options */
export type ChatOptions = {
  temperature?: number;
  maxTokens?: number;
  model?: string;
  tools?: ToolDefinition[];
  /** Stop sequences */
  stop?: string[];
};

/** Token usage statistics */
export type TokenUsage = {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
};

/** Chat completion response */
export type ChatResponse = {
  content: string;
  toolCalls?: ToolCall[];
  finishReason?: FinishReason;
  usage?: TokenUsage;
};

/** Streaming chunk */
export type ChatChunk = {
  content: string;
  done: boolean;
};

/** Provider capabilities */
export type ProviderCapabilities = {
  streaming: boolean;
  toolCalling: boolean;
  vision: boolean;
  maxContextTokens: number;
};

/** Provider configuration */
export type ProviderConfig = {
  /** API key (for cloud providers) */
  apiKey?: string;
  /** Base URL for API endpoint */
  baseUrl?: string;
  /** Default model to use */
  model?: string;
  /** Request timeout in ms */
  timeout?: number;
};

/**
 * LLM Provider type
 * All providers must implement this type
 */
export type LLMProvider = {
  /** Provider name (e.g., 'ollama', 'zai', 'openai') */
  readonly name: string;

  /** Get provider capabilities */
  getCapabilities(): ProviderCapabilities;

  /** Check if provider is available/configured */
  isAvailable(): Promise<boolean>;

  /** Generate a chat completion */
  chat(messages: ChatMessage[], options?: ChatOptions): Promise<ChatResponse>;

  /** Stream a chat completion */
  streamChat?(messages: ChatMessage[], options?: ChatOptions): AsyncIterable<ChatChunk>;

  /** Estimate token count for text */
  estimateTokens(text: string): number;
};

/** Provider registry entry */
export type ProviderEntry = {
  provider: LLMProvider;
  priority: number;
  config: ProviderConfig;
};
