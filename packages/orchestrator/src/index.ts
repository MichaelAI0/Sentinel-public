/**
 * SENTINEL Agent Orchestrator
 * Main entry point - HTTP server for binary analysis requests
 *
 * When imported as a library, only exports are available.
 * When run directly (bun run index.ts), starts the HTTP server.
 */

import { getLLMClient } from './llm/llm-client.js';
import type { AnalysisState } from './types.js';
import {
  authenticateRequest,
  createForbiddenResponse,
  createUnauthorizedResponse,
  hasPermission,
  initAuth,
} from './utils/auth.js';
import { logger } from './utils/logger.js';
import { getMcpBridge } from './utils/mcp-bridge.js';
import { createMetricsResponse, metrics } from './utils/metrics.js';
import {
  createRateLimitHeaders,
  createRateLimitResponse,
  getRateLimiter,
} from './utils/rate-limiter.js';
import { analyzeWithWorkflow } from './workflow/index.js';

// Export LLM provider abstraction
export * from './llm/index.js';
// Export types and workflow for library usage
export * from './types.js';
// Export authentication
export * from './utils/auth.js';
// Export Phase 1 utilities (security, file handling, context management)
export * from './utils/index.js';
export { getMcpBridge } from './utils/mcp-bridge.js';
// Export metrics and rate limiting
export { createMetricsResponse, exportMetrics, getRegistry, metrics } from './utils/metrics.js';
// Legacy export for backward compatibility (deprecated)
export { getOllamaClient } from './utils/ollama-client.js';
export {
  createRateLimitHeaders,
  createRateLimitResponse,
  getRateLimiter,
  RateLimiter,
} from './utils/rate-limiter.js';
// Export Redis rate limiter
export * from './utils/redis-rate-limiter.js';
export { analyzeWithWorkflow, buildAnalysisWorkflow } from './workflow/index.js';

// =============================================================================
// HTTP Server (only starts when run directly, not when imported as library)
// =============================================================================

// Rate limiters for different endpoint types
const apiRateLimiter = getRateLimiter('api', { maxRequests: 100, windowMs: 60_000 });
const analysisRateLimiter = getRateLimiter('analysis', { maxRequests: 10, windowMs: 60_000 });

/**
 * Extract client identifier from request
 */
function getClientId(req: Request): string {
  // Try X-Forwarded-For first (for proxied requests)
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0]?.trim() ?? forwarded;
  }
  // Fall back to X-Real-IP
  const realIp = req.headers.get('x-real-ip');
  if (realIp) {
    return realIp;
  }
  // Default to 'unknown' (in practice, Bun.serve doesn't expose client IP directly)
  return 'default';
}

/**
 * Start the orchestrator HTTP server
 */
export function startServer(port = 8080, host = '0.0.0.0'): ReturnType<typeof Bun.serve> {
  const server = Bun.serve({
    port,
    hostname: host,

    // biome-ignore lint/complexity/noExcessiveCognitiveComplexity: HTTP router requires multiple endpoint handlers
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);
      const startTime = Date.now();
      const clientId = getClientId(req);

      // Track request
      metrics.httpRequestsTotal.inc({ method: req.method, path: url.pathname });

      // Helper to add rate limit headers and track duration
      const respond = (
        response: Response,
        rateLimitResult?: ReturnType<typeof apiRateLimiter.check>,
      ): Response => {
        const duration = (Date.now() - startTime) / 1000;
        metrics.httpRequestDuration.observe(duration, { path: url.pathname });

        if (rateLimitResult) {
          const headers = new Headers(response.headers);
          for (const [key, value] of Object.entries(createRateLimitHeaders(rateLimitResult))) {
            headers.set(key, value);
          }
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers,
          });
        }
        return response;
      };

      // Metrics endpoint (auth required for 'metrics' permission)
      if (url.pathname === '/metrics') {
        const authResult = authenticateRequest(req);
        if (!authResult.authenticated) {
          return createUnauthorizedResponse(authResult.error);
        }
        if (!hasPermission(authResult, 'metrics')) {
          return createForbiddenResponse('metrics permission required');
        }
        return respond(createMetricsResponse());
      }

      // Health check endpoint (no rate limiting, public)
      if (url.pathname === '/health') {
        const llm = getLLMClient();
        const llmAvailable = await llm.isAvailable();
        metrics.llmAvailable.set(llmAvailable ? 1 : 0);

        return respond(
          Response.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            services: {
              llm: llmAvailable ? 'available' : 'unavailable',
              provider: llm.getProvider().name,
            },
          }),
        );
      }

      // Readiness check (no rate limiting)
      if (url.pathname === '/ready') {
        const llm = getLLMClient();
        const llmAvailable = await llm.isAvailable();

        if (!llmAvailable) {
          return respond(
            Response.json({ ready: false, reason: 'LLM provider not available' }, { status: 503 }),
          );
        }

        return respond(Response.json({ ready: true }));
      }

      // Analysis endpoint (rate limited, auth required)
      if (url.pathname === '/analyze' && req.method === 'POST') {
        // Check authentication
        const authResult = authenticateRequest(req);
        if (!authResult.authenticated) {
          return createUnauthorizedResponse(authResult.error);
        }
        if (!hasPermission(authResult, 'analyze')) {
          return createForbiddenResponse('analyze permission required');
        }

        // Check rate limit for analysis endpoint
        const rateLimit = analysisRateLimiter.consume(clientId);
        if (!rateLimit.allowed) {
          return createRateLimitResponse(rateLimit);
        }

        try {
          const body = (await req.json()) as { binaryPath: string; filename?: string };

          if (!body.binaryPath) {
            return respond(
              Response.json({ error: 'binaryPath is required' }, { status: 400 }),
              rateLimit,
            );
          }

          logger.info`Received analysis request for: ${body.binaryPath}`;

          // Track analysis
          metrics.analysisTotal.inc({ status: 'started' });
          metrics.analysisInProgress.inc();
          const analysisStart = Date.now();

          try {
            const result = await analyzeWithWorkflow(body.binaryPath, body.filename);

            // Track completion
            const analysisDuration = (Date.now() - analysisStart) / 1000;
            metrics.analysisDuration.observe(analysisDuration);
            metrics.analysisInProgress.dec();
            metrics.analysisTotal.inc({
              status: result.status === 'complete' ? 'success' : 'failed',
            });

            return respond(
              Response.json({
                success: result.status === 'complete',
                status: result.status,
                triage: result.triageResults
                  ? {
                      riskLevel: result.triageResults.riskLevel,
                      confidence: result.triageResults.confidence,
                      recommendation: result.triageResults.recommendation,
                      reasoning: result.triageResults.reasoning,
                    }
                  : null,
                analysis: result.analysisResults
                  ? {
                      malwareFamily: result.analysisResults.malwareFamily,
                      sophistication: result.analysisResults.sophistication,
                      capabilities: result.analysisResults.capabilities,
                      mitreTechniques: result.analysisResults.mitreTechniques.length,
                      iocs: {
                        total: Object.values(result.analysisResults.iocs).flat().length,
                      },
                    }
                  : null,
                reports: result.reportPaths,
                errors: result.errors,
                duration: result.endTime
                  ? `${((result.endTime.getTime() - result.startTime.getTime()) / 1000).toFixed(1)}s`
                  : null,
              }),
              rateLimit,
            );
          } catch (error) {
            metrics.analysisInProgress.dec();
            metrics.analysisTotal.inc({ status: 'error' });
            throw error;
          }
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          logger.error`Analysis request failed: ${errorMessage}`;
          return respond(Response.json({ error: errorMessage }, { status: 500 }));
        }
      }

      // Quick triage endpoint (rate limited, auth required)
      if (url.pathname === '/triage' && req.method === 'POST') {
        // Check authentication
        const authResult = authenticateRequest(req);
        if (!authResult.authenticated) {
          return createUnauthorizedResponse(authResult.error);
        }
        if (!hasPermission(authResult, 'triage')) {
          return createForbiddenResponse('triage permission required');
        }

        // Check rate limit for triage endpoint
        const rateLimit = analysisRateLimiter.consume(clientId);
        if (!rateLimit.allowed) {
          return createRateLimitResponse(rateLimit);
        }

        try {
          const body = (await req.json()) as { binaryPath: string };

          if (!body.binaryPath) {
            return respond(
              Response.json({ error: 'binaryPath is required' }, { status: 400 }),
              rateLimit,
            );
          }

          logger.info`Received triage request for: ${body.binaryPath}`;

          // Track triage
          metrics.triageTotal.inc({ status: 'started' });
          const triageStart = Date.now();

          // Import triage agent directly for quick triage
          const { runTriageAgent } = await import('./agents/triage-agent.js');

          const initialState: AnalysisState = {
            binaryPath: body.binaryPath,
            filename: body.binaryPath.split('/').pop() ?? 'unknown',
            triageResults: null,
            triageComplete: false,
            analysisResults: null,
            analysisComplete: false,
            reportPaths: null,
            reportsComplete: false,
            startTime: new Date(),
            errors: [],
            status: 'triaging',
          };

          const result = await runTriageAgent(initialState);

          // Track completion
          const triageDuration = (Date.now() - triageStart) / 1000;
          metrics.triageDuration.observe(triageDuration);
          metrics.triageTotal.inc({ status: 'success' });

          return respond(
            Response.json({
              success: true,
              triage: result.triageResults,
              errors: result.errors,
            }),
            rateLimit,
          );
        } catch (error) {
          metrics.triageTotal.inc({ status: 'error' });
          const errorMessage = error instanceof Error ? error.message : String(error);
          logger.error`Triage request failed: ${errorMessage}`;
          return respond(Response.json({ error: errorMessage }, { status: 500 }));
        }
      }

      // Models endpoint (rate limited)
      if (url.pathname === '/models') {
        const rateLimit = apiRateLimiter.consume(clientId);
        if (!rateLimit.allowed) {
          return createRateLimitResponse(rateLimit);
        }

        const llm = getLLMClient();
        const capabilities = llm.getCapabilities();
        return respond(
          Response.json({
            provider: llm.getProvider().name,
            capabilities,
          }),
          rateLimit,
        );
      }

      // API documentation (rate limited)
      if (url.pathname === '/' || url.pathname === '/api') {
        const rateLimit = apiRateLimiter.consume(clientId);
        if (!rateLimit.allowed) {
          return createRateLimitResponse(rateLimit);
        }

        return respond(
          Response.json({
            name: 'SENTINEL Agent Orchestrator',
            version: '1.0.0',
            description: 'Multi-agent malware analysis system',
            endpoints: {
              'GET /': 'This documentation',
              'GET /health': 'Health check (no rate limit)',
              'GET /ready': 'Readiness check (no rate limit)',
              'GET /metrics': 'Prometheus metrics (no rate limit)',
              'GET /models': 'List available LLM models',
              'POST /analyze': 'Full analysis workflow (triage → analyze → report)',
              'POST /triage': 'Quick triage only',
            },
            rateLimits: {
              api: '100 requests/minute',
              analysis: '10 requests/minute',
            },
            examples: {
              analyze: {
                method: 'POST',
                url: '/analyze',
                body: { binaryPath: '/binaries/malware.exe', filename: 'malware.exe' },
              },
              triage: {
                method: 'POST',
                url: '/triage',
                body: { binaryPath: '/binaries/suspicious.exe' },
              },
            },
          }),
          rateLimit,
        );
      }

      return respond(Response.json({ error: 'Not found' }, { status: 404 }));
    },

    error(error: Error): Response {
      logger.error`Server error: ${error.message}`;
      return Response.json({ error: 'Internal server error' }, { status: 500 });
    },
  });

  logger.info`SENTINEL Orchestrator listening on ${host}:${port}`;
  return server;
}

// Startup checks
async function startup(): Promise<void> {
  logger.info`Performing startup checks...`;

  // Check LLM provider
  const llm = getLLMClient();
  const llmAvailable = await llm.isAvailable();

  if (llmAvailable) {
    logger.info`LLM provider (${llm.getProvider().name}) is available`;
  } else {
    logger.warn`LLM provider (${llm.getProvider().name}) is not available - will retry on requests`;
  }

  // Initialize authentication
  initAuth();

  // Connect to MCP server
  const mcp = getMcpBridge();
  try {
    await mcp.connect();
    logger.info`MCP server connection established`;
  } catch (error) {
    logger.warn`Failed to connect to MCP server: ${error}`;
  }

  logger.info`Startup complete`;
}

// Only start the server when run directly (not when imported as library)
if (import.meta.main) {
  const PORT = Number.parseInt(process.env.PORT ?? '8080', 10);
  const HOST = process.env.HOST ?? '0.0.0.0';

  startServer(PORT, HOST);

  startup().catch((error) => {
    logger.error`Startup failed: ${error}`;
  });
}
