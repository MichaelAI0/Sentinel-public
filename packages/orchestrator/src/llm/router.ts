/**
 * LLM Provider Router
 * Routes requests to the appropriate LLM provider based on configuration
 */

import { hasFeature } from '../config/features.js';
import { logger } from '../utils/logger.js';
import { AnthropicProvider } from './anthropic-provider.js';
import { LlamaServerProvider } from './llama-server-provider.js';
import { OllamaProvider } from './ollama-provider.js';
import { OpenAIProvider } from './openai-provider.js';
import type {
  ChatMessage,
  ChatOptions,
  ChatResponse,
  LLMProvider,
  ProviderCapabilities,
  ProviderConfig,
} from './types.js';

/** Provider type names */
export const PROVIDER_NAMES = ['ollama', 'openai', 'anthropic', 'llama-server'] as const;
export type ProviderName = (typeof PROVIDER_NAMES)[number];

/** Router configuration */
export type RouterConfig = {
  /** Default provider to use */
  defaultProvider: ProviderName;

  /** Provider-specific configurations */
  providers: {
    ollama?: ProviderConfig;
    openai?: ProviderConfig;
    anthropic?: ProviderConfig;
    'llama-server'?: ProviderConfig;
  };
};

/**
 * Load configuration from environment
 * Models are NOT hardcoded - set via env vars or pass in options
 */
function loadConfigFromEnv(): RouterConfig {
  const defaultProvider = (process.env.LLM_PROVIDER as ProviderName) ?? 'ollama';

  return {
    defaultProvider,
    providers: {
      ollama: {
        baseUrl: process.env.OLLAMA_BASE_URL,
        model: process.env.OLLAMA_MODEL,
      },
      openai: {
        apiKey: process.env.OPENAI_API_KEY,
        baseUrl: process.env.OPENAI_BASE_URL,
        model: process.env.OPENAI_MODEL,
      },
      anthropic: {
        apiKey: process.env.ANTHROPIC_API_KEY,
        baseUrl: process.env.ANTHROPIC_BASE_URL,
        model: process.env.ANTHROPIC_MODEL,
      },
      'llama-server': {
        baseUrl: process.env.LLAMA_SERVER_URL,
        model: process.env.LLAMA_MODEL,
      },
    },
  };
}

/**
 * LLM Provider Router
 */
export class LLMProviderRouter {
  private providers: Map<ProviderName, LLMProvider> = new Map();
  private config: RouterConfig;
  private defaultProvider: ProviderName;

  constructor(config?: Partial<RouterConfig>) {
    const envConfig = loadConfigFromEnv();

    this.config = {
      defaultProvider: config?.defaultProvider ?? envConfig.defaultProvider,
      providers: {
        ...envConfig.providers,
        ...config?.providers,
      },
    };

    this.defaultProvider = this.config.defaultProvider;
    this.initializeProviders();
  }

  private initializeProviders(): void {
    const { providers } = this.config;

    // Always initialize Ollama (local, no API key needed) - available in all editions
    this.providers.set('ollama', new OllamaProvider(providers.ollama));

    // Initialize llama-server if configured (local, no API key needed) - available in all editions
    if (providers['llama-server']?.baseUrl) {
      this.providers.set('llama-server', new LlamaServerProvider(providers['llama-server']));
    }

    // Cloud providers require Professional+ license
    if (hasFeature('CLOUD_LLMS')) {
      if (providers.openai?.apiKey) {
        this.providers.set('openai', new OpenAIProvider(providers.openai));
      }

      if (providers.anthropic?.apiKey) {
        this.providers.set('anthropic', new AnthropicProvider(providers.anthropic));
      }
    } else {
      // Log info about cloud providers being unavailable
      if (providers.openai?.apiKey || providers.anthropic?.apiKey) {
        logger.info`Cloud LLM providers (OpenAI, Anthropic) require Professional license. Using local providers only.`;
      }
    }

    logger.info`LLM Router initialized: default=${this.defaultProvider}, available=${[...this.providers.keys()].join(', ')}`;
  }

  /**
   * Get a specific provider by name
   */
  getProvider(name?: ProviderName): LLMProvider {
    const providerName = name ?? this.defaultProvider;
    const provider = this.providers.get(providerName);

    if (!provider) {
      throw new Error(
        `Provider '${providerName}' not available. Configured: ${[...this.providers.keys()].join(', ')}`,
      );
    }

    return provider;
  }

  /**
   * Get the default provider
   */
  getDefaultProvider(): LLMProvider {
    return this.getProvider(this.defaultProvider);
  }

  /**
   * Get the best available provider for analysis
   * Prefers providers with tool-calling and large context windows
   */
  getBestForAnalysis(): LLMProvider {
    // Priority: llama-server (local, tool-calling) > anthropic > openai > ollama
    const preference: ProviderName[] = ['llama-server', 'anthropic', 'openai', 'ollama'];

    for (const name of preference) {
      const provider = this.providers.get(name);
      if (provider) {
        return provider;
      }
    }

    throw new Error('No LLM provider available');
  }

  /**
   * Get capabilities of a provider
   */
  getCapabilities(name?: ProviderName): ProviderCapabilities {
    return this.getProvider(name).getCapabilities();
  }

  /**
   * Check if a provider is available
   */
  async isProviderAvailable(name: ProviderName): Promise<boolean> {
    const provider = this.providers.get(name);
    if (!provider) return false;
    return provider.isAvailable();
  }

  /**
   * List all configured providers
   */
  listProviders(): ProviderName[] {
    return [...this.providers.keys()];
  }

  /**
   * Chat using the default provider
   */
  async chat(
    messages: ChatMessage[],
    options?: ChatOptions & { provider?: ProviderName },
  ): Promise<ChatResponse> {
    const provider = this.getProvider(options?.provider);
    return provider.chat(messages, options);
  }

  /**
   * Set the default provider
   */
  setDefaultProvider(name: ProviderName): void {
    if (!this.providers.has(name)) {
      throw new Error(`Provider '${name}' not available`);
    }
    this.defaultProvider = name;
    logger.info`Default LLM provider changed to: ${name}`;
  }
}

// Singleton instance
let routerInstance: LLMProviderRouter | null = null;

/**
 * Get or create the router singleton
 */
export function getLLMRouter(config?: Partial<RouterConfig>): LLMProviderRouter {
  if (!routerInstance) {
    routerInstance = new LLMProviderRouter(config);
  }
  return routerInstance;
}

/**
 * Reset the router (for testing)
 */
export function resetLLMRouter(): void {
  routerInstance = null;
}
