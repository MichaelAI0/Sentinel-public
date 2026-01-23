/**
 * LLM Provider Tests
 */

import { beforeEach, describe, expect, test } from 'bun:test';
import { OllamaProvider } from './ollama-provider.js';
import { getLLMRouter, LLMProviderRouter, PROVIDER_NAMES, resetLLMRouter } from './router.js';
import { FINISH_REASONS, MESSAGE_ROLES } from './types.js';

describe('types', () => {
  describe('MESSAGE_ROLES', () => {
    test('has correct values', () => {
      expect(MESSAGE_ROLES).toEqual(['system', 'user', 'assistant']);
    });

    test('is readonly', () => {
      // TypeScript ensures this at compile time, but we can verify the array
      expect(Object.isFrozen(MESSAGE_ROLES)).toBe(false); // as const doesn't freeze
      expect(MESSAGE_ROLES.length).toBe(3);
    });
  });

  describe('FINISH_REASONS', () => {
    test('has correct values', () => {
      expect(FINISH_REASONS).toEqual(['stop', 'tool_calls', 'length', 'error']);
    });
  });

  describe('PROVIDER_NAMES', () => {
    test('has correct values', () => {
      expect(PROVIDER_NAMES).toEqual(['ollama', 'openai', 'anthropic', 'llama-server']);
    });
  });
});

describe('OllamaProvider', () => {
  test('has correct name', () => {
    const provider = new OllamaProvider();
    expect(provider.name).toBe('ollama');
  });

  test('uses default config when not provided', () => {
    const provider = new OllamaProvider();
    const caps = provider.getCapabilities();

    expect(caps.streaming).toBe(true);
    expect(caps.toolCalling).toBe(false);
    expect(caps.vision).toBe(false);
    expect(caps.maxContextTokens).toBe(32768);
  });

  test('accepts custom config', () => {
    const provider = new OllamaProvider({
      baseUrl: 'http://custom:11434',
      model: 'custom-model',
      timeout: 60000,
    });

    expect(provider.name).toBe('ollama');
  });

  test('estimateTokens returns reasonable estimate', () => {
    const provider = new OllamaProvider();

    // ~4 chars per token
    expect(provider.estimateTokens('hello')).toBe(2); // 5 / 4 = 1.25 -> ceil = 2
    expect(provider.estimateTokens('hello world')).toBe(3); // 11 / 4 = 2.75 -> ceil = 3
    expect(provider.estimateTokens('')).toBe(0);
  });
});

describe('LLMProviderRouter', () => {
  beforeEach(() => {
    resetLLMRouter();
  });

  test('initializes with ollama by default', () => {
    const router = new LLMProviderRouter();
    const providers = router.listProviders();

    expect(providers).toContain('ollama');
  });

  test('getProvider returns ollama', () => {
    const router = new LLMProviderRouter();
    const provider = router.getProvider('ollama');

    expect(provider.name).toBe('ollama');
  });

  test('getDefaultProvider returns configured default', () => {
    const router = new LLMProviderRouter({ defaultProvider: 'ollama' });
    const provider = router.getDefaultProvider();

    expect(provider.name).toBe('ollama');
  });

  test('getBestForAnalysis returns available provider', () => {
    const router = new LLMProviderRouter();
    const provider = router.getBestForAnalysis();

    // At minimum, ollama should be available
    expect(provider).toBeDefined();
    expect(typeof provider.name).toBe('string');
  });

  test('getCapabilities returns provider capabilities', () => {
    const router = new LLMProviderRouter();
    const caps = router.getCapabilities('ollama');

    expect(caps.streaming).toBe(true);
    expect(typeof caps.maxContextTokens).toBe('number');
  });

  test('throws on unknown provider', () => {
    const router = new LLMProviderRouter();

    expect(() => router.getProvider('unknown' as 'ollama')).toThrow(/not available/);
  });

  test('setDefaultProvider changes default', () => {
    const router = new LLMProviderRouter();

    // Ollama is always available
    router.setDefaultProvider('ollama');
    const provider = router.getDefaultProvider();

    expect(provider.name).toBe('ollama');
  });

  test('setDefaultProvider throws for unavailable provider', () => {
    const router = new LLMProviderRouter();

    // OpenAI requires API key, so it won't be available without env var
    expect(() => router.setDefaultProvider('openai')).toThrow(/not available/);
  });
});

describe('getLLMRouter singleton', () => {
  beforeEach(() => {
    resetLLMRouter();
  });

  test('returns same instance on multiple calls', () => {
    const router1 = getLLMRouter();
    const router2 = getLLMRouter();

    expect(router1).toBe(router2);
  });

  test('resetLLMRouter creates new instance', () => {
    const router1 = getLLMRouter();
    resetLLMRouter();
    const router2 = getLLMRouter();

    expect(router1).not.toBe(router2);
  });
});
