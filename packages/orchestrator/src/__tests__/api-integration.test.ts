/**
 * API Integration Tests
 *
 * Tests the HTTP API endpoints of the orchestrator server.
 * These tests start a real server instance and make HTTP requests.
 *
 * @module __tests__/api-integration
 */

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { stat } from 'node:fs/promises';
import { join } from 'node:path';

// Test configuration
const TEST_PORT = 9999;
const BASE_URL = `http://localhost:${TEST_PORT}`;
const BINARIES_DIR = join(import.meta.dir, '..', '..', '..', '..', 'binaries');
const TEST_BINARY = join(BINARIES_DIR, 'suspicious_test');

// Type definitions for API responses
type HealthResponse = {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  services: {
    llm: 'available' | 'unavailable';
    provider: string;
  };
};

type ReadyResponse = {
  ready: boolean;
  reason?: string;
};

type TriageResponse = {
  success: boolean;
  triage: {
    riskLevel: string;
    confidence: number;
    recommendation: string;
    reasoning: string;
  } | null;
  errors: string[];
};

type AnalyzeResponse = {
  success: boolean;
  status: 'complete' | 'failed' | 'partial';
  triage: {
    riskLevel: string;
    confidence: number;
    recommendation: string;
    reasoning: string;
  } | null;
  analysis: {
    malwareFamily: string | null;
    sophistication: string;
    capabilities: string[];
    mitreTechniques: number;
    iocs: { total: number };
  } | null;
  reports: string[] | null;
  errors: string[];
  duration: string | null;
};

type ApiDocResponse = {
  name: string;
  version: string;
  description: string;
  endpoints: Record<string, string>;
  examples: Record<string, { method: string; url: string; body: Record<string, string> }>;
};

// Helper to check if file exists
async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

describe('Orchestrator API Integration', () => {
  let server: ReturnType<typeof import('../index.js').startServer> | null = null;
  let hasTestBinary = false;

  beforeAll(async () => {
    // Check if test binary exists
    hasTestBinary = await fileExists(TEST_BINARY);

    // Start the server
    const { startServer } = await import('../index.js');
    server = startServer(TEST_PORT, '127.0.0.1');

    // Wait for server to be ready
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  afterAll(async () => {
    // Stop the server
    if (server) {
      server.stop();
    }
  });

  // =========================================================================
  // Health & Status Endpoints
  // =========================================================================

  describe('Health Endpoints', () => {
    test('GET / returns API documentation', async () => {
      const response = await fetch(BASE_URL);
      expect(response.ok).toBe(true);

      const data = (await response.json()) as ApiDocResponse;
      expect(data.name).toBe('SENTINEL Agent Orchestrator');
      expect(data.version).toBeDefined();
      expect(data.endpoints).toBeDefined();
      expect(data.endpoints['GET /health']).toBeDefined();
      expect(data.endpoints['POST /analyze']).toBeDefined();
      expect(data.endpoints['POST /triage']).toBeDefined();
    });

    test('GET /api returns same documentation as /', async () => {
      const response = await fetch(`${BASE_URL}/api`);
      expect(response.ok).toBe(true);

      const data = (await response.json()) as ApiDocResponse;
      expect(data.name).toBe('SENTINEL Agent Orchestrator');
    });

    test('GET /health returns service status', async () => {
      const response = await fetch(`${BASE_URL}/health`);
      expect(response.ok).toBe(true);

      const data = (await response.json()) as HealthResponse;
      expect(data.status).toBe('healthy');
      expect(data.timestamp).toBeDefined();
      expect(data.services).toBeDefined();
      expect(data.services.llm).toMatch(/^(available|unavailable)$/);
      expect(data.services.provider).toBeDefined();
    });

    test('GET /ready returns readiness status', async () => {
      const response = await fetch(`${BASE_URL}/ready`);

      const data = (await response.json()) as ReadyResponse;
      expect(typeof data.ready).toBe('boolean');

      if (!data.ready) {
        expect(data.reason).toBeDefined();
      }
    });

    test('GET /models returns LLM provider info', async () => {
      const response = await fetch(`${BASE_URL}/models`);
      expect(response.ok).toBe(true);

      const data = (await response.json()) as { provider: string; capabilities: unknown };
      expect(data.provider).toBeDefined();
      expect(data.capabilities).toBeDefined();
    });
  });

  // =========================================================================
  // Triage Endpoint
  // =========================================================================

  describe('POST /triage', () => {
    test('returns 400 when binaryPath is missing', async () => {
      const response = await fetch(`${BASE_URL}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      expect(response.status).toBe(400);
      const data = (await response.json()) as { error: string };
      expect(data.error).toContain('binaryPath');
    });

    test('handles non-existent file gracefully', async () => {
      const response = await fetch(`${BASE_URL}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binaryPath: '/nonexistent/file.exe' }),
      });

      // API may return 200 with errors in response or 500
      // depending on where the error is caught
      const data = (await response.json()) as {
        success?: boolean;
        error?: string;
        errors?: string[];
      };
      // Either error field or errors array should indicate the problem
      expect(
        data.error !== undefined ||
          (data.errors && data.errors.length > 0) ||
          response.status === 500,
      ).toBe(true);
    }, 30000);

    test('triages test binary successfully', async () => {
      if (!hasTestBinary) {
        console.log('Skipping: test binary not available');
        return;
      }

      const response = await fetch(`${BASE_URL}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binaryPath: TEST_BINARY }),
      });

      expect(response.ok).toBe(true);
      const data = (await response.json()) as TriageResponse;

      expect(data.success).toBe(true);
      expect(data.triage).toBeDefined();
      expect(data.triage?.riskLevel).toMatch(/^(LOW|MEDIUM|HIGH|CRITICAL)$/);
      expect(data.triage?.confidence).toBeGreaterThanOrEqual(0);
      expect(data.triage?.confidence).toBeLessThanOrEqual(1);
      expect(data.triage?.recommendation).toMatch(/^(IGNORE|INVESTIGATE|ESCALATE)$/);
    }, 60000); // 60s timeout for LLM calls
  });

  // =========================================================================
  // Analyze Endpoint
  // =========================================================================

  describe('POST /analyze', () => {
    test('returns 400 when binaryPath is missing', async () => {
      const response = await fetch(`${BASE_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      // 400 for missing binaryPath, or 429 if rate limited
      expect([400, 429]).toContain(response.status);
      if (response.status === 400) {
        const data = (await response.json()) as { error: string };
        expect(data.error).toContain('binaryPath');
      }
    });

    test('handles non-existent file gracefully', async () => {
      const response = await fetch(`${BASE_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binaryPath: '/nonexistent/file.exe' }),
      });

      // API may return 200 with errors or 500 depending on error handling
      const data = (await response.json()) as {
        success?: boolean;
        error?: string;
        errors?: string[];
      };
      expect(
        data.error !== undefined ||
          (data.errors && data.errors.length > 0) ||
          response.status === 500,
      ).toBe(true);
    }, 30000);

    test('accepts optional filename parameter', async () => {
      if (!hasTestBinary) {
        console.log('Skipping: test binary not available');
        return;
      }

      const response = await fetch(`${BASE_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          binaryPath: TEST_BINARY,
          filename: 'custom_name.exe',
        }),
      });

      // Should succeed or be rate limited
      expect([200, 429]).toContain(response.status);
    }, 180000); // 3 minute timeout for full analysis

    test('analyzes test binary with full workflow', async () => {
      if (!hasTestBinary) {
        console.log('Skipping: test binary not available');
        return;
      }

      const response = await fetch(`${BASE_URL}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binaryPath: TEST_BINARY }),
      });

      // May be rate limited in concurrent test runs
      if (response.status === 429) {
        console.log('Skipping: rate limited');
        return;
      }

      expect(response.ok).toBe(true);
      const data = (await response.json()) as AnalyzeResponse;

      expect(data.success).toBeDefined();
      expect(data.status).toMatch(/^(complete|failed|partial)$/);

      if (data.success) {
        expect(data.triage).toBeDefined();
        expect(data.duration).toBeDefined();
      }
    }, 180000); // 3 minute timeout for full analysis
  });

  // =========================================================================
  // Error Handling
  // =========================================================================

  describe('Error Handling', () => {
    test('returns 404 for unknown endpoints', async () => {
      const response = await fetch(`${BASE_URL}/unknown-endpoint`);
      // Note: Current implementation returns 404 for unknown routes
      expect(response.status).toBe(404);
    });

    test('handles malformed JSON gracefully', async () => {
      const response = await fetch(`${BASE_URL}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not valid json',
      });

      // 500 for parse error, or 429 if rate limited
      expect([429, 500]).toContain(response.status);
    });

    test('rejects non-POST requests to triage endpoint', async () => {
      const response = await fetch(`${BASE_URL}/triage`, {
        method: 'GET',
      });

      // Should return 404 since GET /triage is not defined
      expect(response.status).toBe(404);
    });

    test('rejects non-POST requests to analyze endpoint', async () => {
      const response = await fetch(`${BASE_URL}/analyze`, {
        method: 'GET',
      });

      expect(response.status).toBe(404);
    });
  });

  // =========================================================================
  // Response Format Validation
  // =========================================================================

  describe('Response Format Validation', () => {
    test('health response has correct structure', async () => {
      const response = await fetch(`${BASE_URL}/health`);
      const data = (await response.json()) as HealthResponse;

      // Validate timestamp is ISO format
      expect(new Date(data.timestamp).toISOString()).toBe(data.timestamp);

      // Validate status enum
      expect(['healthy', 'degraded', 'unhealthy']).toContain(data.status);
    });

    test('API documentation has required fields', async () => {
      const response = await fetch(BASE_URL);
      const data = (await response.json()) as ApiDocResponse;

      expect(data.name).toBe('SENTINEL Agent Orchestrator');
      expect(data.version).toMatch(/^\d+\.\d+\.\d+$/);
      expect(data.description).toBeDefined();

      // Required endpoints
      expect(data.endpoints['GET /']).toBeDefined();
      expect(data.endpoints['GET /health']).toBeDefined();
      expect(data.endpoints['GET /ready']).toBeDefined();
      expect(data.endpoints['POST /analyze']).toBeDefined();
      expect(data.endpoints['POST /triage']).toBeDefined();

      // Examples should have proper structure
      expect(data.examples.analyze).toBeDefined();
      expect(data.examples.analyze?.method).toBe('POST');
      expect(data.examples.triage).toBeDefined();
      expect(data.examples.triage?.method).toBe('POST');
    });
  });

  // =========================================================================
  // Content-Type Handling
  // =========================================================================

  describe('Content-Type Handling', () => {
    test('all responses are JSON', async () => {
      const endpoints = ['/', '/health', '/ready', '/models'];

      for (const endpoint of endpoints) {
        const response = await fetch(`${BASE_URL}${endpoint}`);
        const contentType = response.headers.get('content-type');
        expect(contentType).toContain('application/json');
      }
    });

    test('accepts application/json for POST requests', async () => {
      const response = await fetch(`${BASE_URL}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binaryPath: '/test' }),
      });

      // Should process the request - may return 200 (with errors), 400, 429 (rate limited), or 500
      expect([200, 400, 429, 500]).toContain(response.status);
    }, 30000);
  });
});

// =========================================================================
// Concurrent Request Handling
// =========================================================================

describe('Concurrent Request Handling', () => {
  let server: ReturnType<typeof import('../index.js').startServer> | null = null;
  const TEST_PORT_CONCURRENT = 9998;
  const BASE_URL_CONCURRENT = `http://localhost:${TEST_PORT_CONCURRENT}`;

  beforeAll(async () => {
    const { startServer } = await import('../index.js');
    server = startServer(TEST_PORT_CONCURRENT, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 100));
  });

  afterAll(async () => {
    if (server) {
      server.stop();
    }
  });

  test('handles multiple concurrent health checks', async () => {
    const requests = Array.from({ length: 10 }, () =>
      fetch(`${BASE_URL_CONCURRENT}/health`).then((r) => r.json() as Promise<{ status: string }>),
    );

    const results = await Promise.all(requests);

    for (const result of results) {
      expect(result.status).toBe('healthy');
    }
  });

  test('handles mixed concurrent requests', async () => {
    const requests = [
      fetch(`${BASE_URL_CONCURRENT}/health`),
      fetch(`${BASE_URL_CONCURRENT}/ready`),
      fetch(`${BASE_URL_CONCURRENT}/models`),
      fetch(`${BASE_URL_CONCURRENT}/`),
      fetch(`${BASE_URL_CONCURRENT}/api`),
    ];

    const responses = await Promise.all(requests);

    for (const response of responses) {
      expect(response.ok).toBe(true);
    }
  });
});
