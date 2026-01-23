# =============================================================================
# SENTINEL Orchestrator Container
# =============================================================================
# Agent orchestration service for malware analysis workflow.
# Coordinates between LLM (Ollama), MCP tools, and report generation.
#
# Features:
#   - Multi-agent workflow (Triage → Analysis → Report)
#   - LangGraph-based state management
#   - HTTP API for external integration
#   - CLI for direct invocation
# =============================================================================

# -----------------------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------------------
FROM oven/bun:1.2-alpine AS builder

WORKDIR /build

# Copy root workspace files
COPY package.json bun.lock ./
COPY tsconfig.json ./

# Copy package.json files for all packages
COPY packages/shared/package.json ./packages/shared/
COPY packages/orchestrator/package.json ./packages/orchestrator/

# Install dependencies (workspace mode)
RUN bun install || bun install --no-frozen-lockfile

# Copy source code for shared package
COPY packages/shared/src ./packages/shared/src
COPY packages/shared/tsconfig.json ./packages/shared/

# Copy source code for orchestrator
COPY packages/orchestrator/src ./packages/orchestrator/src
COPY packages/orchestrator/tsconfig.json ./packages/orchestrator/

# Build shared package first
WORKDIR /build/packages/shared
RUN bun run build || bunx tsc

# Note: We run orchestrator from source (not bundled) because LangGraph
# has complex dynamic imports that don't bundle well with bun build.
# The node_modules are copied to runtime for dependencies.

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM oven/bun:1.2-alpine AS runtime

# Install runtime dependencies
RUN apk add --no-cache tini curl

# Create non-root user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Create directories
RUN mkdir -p /app /binaries /outputs /logs && \
    chown -R sentinel:sentinel /app /binaries /outputs /logs

WORKDIR /app

# Copy node_modules (for runtime dependencies like langchain)
COPY --from=builder --chown=sentinel:sentinel /build/node_modules ./node_modules

# Copy source code (running from source for LangGraph compatibility)
COPY --from=builder --chown=sentinel:sentinel /build/packages/orchestrator/src ./src
COPY --from=builder --chown=sentinel:sentinel /build/packages/orchestrator/package.json ./
COPY --from=builder --chown=sentinel:sentinel /build/packages/orchestrator/tsconfig.json ./
COPY --from=builder --chown=sentinel:sentinel /build/packages/shared/src ./node_modules/@sentinel/shared/src
COPY --from=builder --chown=sentinel:sentinel /build/packages/shared/package.json ./node_modules/@sentinel/shared/

# Switch to non-root user
USER sentinel

# Environment defaults
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV PORT=8080
ENV HOST=0.0.0.0
ENV OUTPUT_DIR=/outputs
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV MCP_SERVER_URL=http://mcp-server:3000
ENV OLLAMA_MODEL=qwen2.5:7b-instruct

# Health check - verify HTTP server responds
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose HTTP API port
EXPOSE 8080

# Use tini as init for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Default: run HTTP server
CMD ["bun", "run", "src/index.ts"]

# =============================================================================
# Usage:
# =============================================================================
#
# Build:
#   docker build -t sentinel-orchestrator -f packages/orchestrator/Dockerfile .
#
# Run standalone (requires Ollama and MCP-Server):
#   docker run -d --rm \
#     -p 8080:8080 \
#     -v /path/to/binaries:/binaries:ro \
#     -v /path/to/outputs:/outputs \
#     -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
#     -e MCP_SERVER_URL=http://host.docker.internal:3000 \
#     sentinel-orchestrator
#
# Run CLI command:
#   docker run --rm \
#     -v /path/to/binaries:/binaries:ro \
#     -v /path/to/outputs:/outputs \
#     sentinel-orchestrator \
#     bun run src/cli.ts triage /binaries/sample.exe
#
# Run in compose (see docker-compose.yml):
#   docker-compose --profile orchestrator up -d
# =============================================================================
