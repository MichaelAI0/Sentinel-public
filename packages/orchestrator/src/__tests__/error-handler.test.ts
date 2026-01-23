/**
 * Error Handler Utility Tests
 *
 * Tests for error normalization, categorization, and handling utilities
 *
 * @module __tests__/error-handler.test
 */

import { describe, expect, it, mock } from 'bun:test';
import {
  AgentError,
  AnalysisError,
  ConfigError,
  FileAccessError,
  SentinelError,
  ServiceError,
  TimeoutError,
  ToolError,
  ValidationError,
} from '@sentinel/shared';
import {
  assert,
  categorizeError,
  collectErrors,
  createErrorAggregator,
  handleAsyncOperation,
  isErrorOfType,
  normalizeError,
  withRetry,
} from '../utils/error-handler';

describe('normalizeError', () => {
  describe('Error instances', () => {
    it('returns Error instances unchanged', () => {
      const error = new Error('test error');
      expect(normalizeError(error)).toBe(error);
    });

    it('returns SentinelError instances unchanged', () => {
      const error = new ValidationError('validation failed');
      expect(normalizeError(error)).toBe(error);
    });
  });

  describe('string errors', () => {
    it('converts strings to Error', () => {
      const result = normalizeError('string error');
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('string error');
    });
  });

  describe('object errors', () => {
    it('converts objects with message to Error', () => {
      const result = normalizeError({ message: 'object error', name: 'CustomError' });
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toBe('object error');
      expect(result.name).toBe('CustomError');
    });
  });

  describe('other types', () => {
    it('converts numbers to Error', () => {
      const result = normalizeError(42);
      expect(result).toBeInstanceOf(Error);
      expect(result.message).toContain('42');
    });

    it('converts null to Error', () => {
      const result = normalizeError(null);
      expect(result).toBeInstanceOf(Error);
    });

    it('converts undefined to Error', () => {
      const result = normalizeError(undefined);
      expect(result).toBeInstanceOf(Error);
    });
  });
});

describe('categorizeError', () => {
  it('categorizes ValidationError as validation', () => {
    const error = new ValidationError('invalid input');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(400);
    expect(category.category).toBe('validation');
    expect(category.retryable).toBe(false);
  });

  it('categorizes FileAccessError as file', () => {
    const error = new FileAccessError('/path/to/file', 'read');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(404);
    expect(category.category).toBe('file');
    expect(category.retryable).toBe(false);
  });

  it('categorizes TimeoutError as timeout', () => {
    const error = new TimeoutError('api_call', 30000);
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(408);
    expect(category.category).toBe('timeout');
    expect(category.retryable).toBe(true);
  });

  it('categorizes ServiceError as network', () => {
    const error = new ServiceError('network', 'Connection failed');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(502);
    expect(category.category).toBe('network');
    expect(category.retryable).toBe(true);
  });

  it('categorizes ToolError as analysis', () => {
    const error = new ToolError('ghidra', 'Decompilation failed');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(503);
    expect(category.category).toBe('analysis');
    expect(category.retryable).toBe(true);
  });

  it('categorizes AgentError as analysis', () => {
    const error = new AgentError('triage', 'Agent crashed');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(503);
    expect(category.category).toBe('analysis');
    expect(category.retryable).toBe(true);
  });

  it('categorizes ConfigError as configuration', () => {
    const error = new ConfigError('Missing API key');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(500);
    expect(category.category).toBe('configuration');
    expect(category.retryable).toBe(false);
  });

  it('categorizes AnalysisError as analysis (non-retryable)', () => {
    const error = new AnalysisError('Malformed binary', 'static');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(422);
    expect(category.category).toBe('analysis');
    expect(category.retryable).toBe(false);
  });

  it('categorizes unknown errors as internal', () => {
    const error = new Error('Unknown error');
    const category = categorizeError(error);

    expect(category.httpStatus).toBe(500);
    expect(category.category).toBe('internal');
    expect(category.retryable).toBe(false);
  });
});

describe('handleAsyncOperation', () => {
  it('returns result on success', async () => {
    const result = await handleAsyncOperation(async () => 'success', { operation: 'test' });
    expect(result).toBe('success');
  });

  it('throws normalized error on failure', async () => {
    await expect(
      handleAsyncOperation(
        async () => {
          throw 'string error';
        },
        { operation: 'test' },
      ),
    ).rejects.toBeInstanceOf(Error);
  });

  it('preserves Error type on failure', async () => {
    const originalError = new ValidationError('test');

    await expect(
      handleAsyncOperation(
        async () => {
          throw originalError;
        },
        { operation: 'test' },
      ),
    ).rejects.toBeInstanceOf(ValidationError);
  });
});

describe('withRetry', () => {
  it('returns result on first success', async () => {
    const operation = mock(() => Promise.resolve('success'));

    const result = await withRetry(operation, { operation: 'test' }, { maxAttempts: 3 });

    expect(result).toBe('success');
    expect(operation).toHaveBeenCalledTimes(1);
  });

  it('retries on retryable errors', async () => {
    let attempts = 0;
    const operation = mock(async () => {
      attempts++;
      if (attempts < 3) {
        throw new TimeoutError('test', 1000);
      }
      return 'success';
    });

    const result = await withRetry(
      operation,
      { operation: 'test' },
      { maxAttempts: 3, initialDelayMs: 10 },
    );

    expect(result).toBe('success');
    expect(attempts).toBe(3);
  });

  it('does not retry non-retryable errors', async () => {
    const operation = mock(async () => {
      throw new ValidationError('invalid');
    });

    await expect(
      withRetry(operation, { operation: 'test' }, { maxAttempts: 3, initialDelayMs: 10 }),
    ).rejects.toBeInstanceOf(ValidationError);

    expect(operation).toHaveBeenCalledTimes(1);
  });

  it('throws after max attempts exhausted', async () => {
    const operation = mock(async () => {
      throw new TimeoutError('test', 1000);
    });

    await expect(
      withRetry(operation, { operation: 'test' }, { maxAttempts: 2, initialDelayMs: 10 }),
    ).rejects.toBeInstanceOf(TimeoutError);

    expect(operation).toHaveBeenCalledTimes(2);
  });

  it('calls onRetry callback', async () => {
    let attempts = 0;
    const onRetry = mock((attempt: number, _error: Error, _delay: number) => {
      expect(attempt).toBe(attempts);
    });

    const operation = mock(async () => {
      attempts++;
      if (attempts < 3) {
        throw new TimeoutError('test', 1000);
      }
      return 'success';
    });

    await withRetry(
      operation,
      { operation: 'test' },
      { maxAttempts: 3, initialDelayMs: 10, onRetry },
    );

    expect(onRetry).toHaveBeenCalledTimes(2);
  });
});

describe('collectErrors', () => {
  it('collects successful results', async () => {
    const operations = [Promise.resolve(1), Promise.resolve(2), Promise.resolve(3)];

    const { results, errors } = await collectErrors(operations, { operation: 'test' });

    expect(results).toEqual([1, 2, 3]);
    expect(errors).toHaveLength(0);
  });

  it('collects errors from failed operations', async () => {
    const operations = [
      Promise.resolve(1),
      Promise.reject(new Error('failed')),
      Promise.resolve(3),
    ];

    const { results, errors } = await collectErrors(operations, { operation: 'test' });

    expect(results).toEqual([1, 3]);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.message).toBe('failed');
  });

  it('handles all failures', async () => {
    const operations = [Promise.reject(new Error('error 1')), Promise.reject(new Error('error 2'))];

    const { results, errors } = await collectErrors(operations, { operation: 'test' });

    expect(results).toHaveLength(0);
    expect(errors).toHaveLength(2);
  });
});

describe('createErrorAggregator', () => {
  it('starts empty', () => {
    const aggregator = createErrorAggregator();
    expect(aggregator.hasErrors()).toBe(false);
    expect(aggregator.count()).toBe(0);
  });

  it('adds errors', () => {
    const aggregator = createErrorAggregator();
    aggregator.add(new Error('error 1'));
    aggregator.add(new Error('error 2'));

    expect(aggregator.hasErrors()).toBe(true);
    expect(aggregator.count()).toBe(2);
  });

  it('returns collected errors', () => {
    const aggregator = createErrorAggregator();
    const error1 = new Error('error 1');
    const error2 = new Error('error 2');

    aggregator.add(error1);
    aggregator.add(error2);

    const errors = aggregator.getErrors();
    expect(errors).toContain(error1);
    expect(errors).toContain(error2);
  });

  it('creates AggregateError', () => {
    const aggregator = createErrorAggregator();
    aggregator.add(new Error('error 1'));
    aggregator.add(new Error('error 2'));

    const aggregate = aggregator.toAggregateError('Multiple errors');
    expect(aggregate).toBeInstanceOf(AggregateError);
    expect(aggregate.message).toBe('Multiple errors');
    expect(aggregate.errors).toHaveLength(2);
  });

  it('throws if errors exist', () => {
    const aggregator = createErrorAggregator();
    aggregator.add(new Error('error'));

    expect(() => aggregator.throwIfErrors('Test')).toThrow(AggregateError);
  });

  it('does not throw if no errors', () => {
    const aggregator = createErrorAggregator();
    expect(() => aggregator.throwIfErrors('Test')).not.toThrow();
  });

  it('clears errors', () => {
    const aggregator = createErrorAggregator();
    aggregator.add(new Error('error'));
    aggregator.clear();

    expect(aggregator.hasErrors()).toBe(false);
  });
});

describe('isErrorOfType', () => {
  it('returns true for matching type', () => {
    const error = new ValidationError('test');
    expect(isErrorOfType(error, ValidationError)).toBe(true);
  });

  it('returns false for non-matching type', () => {
    const error = new ValidationError('test');
    expect(isErrorOfType(error, FileAccessError)).toBe(false);
  });

  it('returns false for non-Error values', () => {
    expect(isErrorOfType('string', Error)).toBe(false);
    expect(isErrorOfType(null, Error)).toBe(false);
    expect(isErrorOfType(undefined, Error)).toBe(false);
  });
});

describe('assert', () => {
  it('does not throw for truthy conditions', () => {
    expect(() => assert(true, 'should not throw')).not.toThrow();
    expect(() => assert(1, 'should not throw')).not.toThrow();
    expect(() => assert('string', 'should not throw')).not.toThrow();
  });

  it('throws for falsy conditions', () => {
    expect(() => assert(false, 'assertion failed')).toThrow('assertion failed');
    expect(() => assert(0, 'assertion failed')).toThrow();
    expect(() => assert('', 'assertion failed')).toThrow();
    expect(() => assert(null, 'assertion failed')).toThrow();
  });

  it('throws SentinelError by default', () => {
    expect(() => assert(false, 'test')).toThrow(SentinelError);
  });
});
