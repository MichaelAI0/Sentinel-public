# =============================================================================
# SENTINEL MCP Server Container
# =============================================================================
# Provides MCP (Model Context Protocol) tools for binary analysis.
# Designed to communicate with Ghidra container via Docker networking.
#
# Features:
#   - calculate_hashes: MD5, SHA1, SHA256, SSDEEP
#   - detect_file_type: Magic number analysis
#   - extract_pe_headers: PE file parsing
#   - extract_elf_headers: ELF file parsing
#   - extract_strings: Fast string extraction
#   - detect_packing: Entropy/signature analysis
#   - analyze_binary: Full Ghidra analysis (requires Ghidra container)
# =============================================================================

# -----------------------------------------------------------------------------
# Build stage
# -----------------------------------------------------------------------------
FROM oven/bun:1.2-alpine AS builder

WORKDIR /build

# Copy root workspace files
COPY package.json bun.lock ./

# Copy package.json files for all packages (needed for bun workspace resolution)
COPY packages/shared/package.json ./packages/shared/
COPY packages/mcp-server/package.json ./packages/mcp-server/
COPY packages/orchestrator/package.json ./packages/orchestrator/

# Install dependencies (workspace mode) - allow lockfile updates for version compat
RUN bun install || bun install --no-frozen-lockfile

# Copy root tsconfig for reference resolution
COPY tsconfig.json ./

# Copy source code for shared package
COPY packages/shared/src ./packages/shared/src
COPY packages/shared/tsconfig.json ./packages/shared/

# Copy source code for orchestrator package (mcp-server depends on it)
COPY packages/orchestrator/src ./packages/orchestrator/src
COPY packages/orchestrator/tsconfig.json ./packages/orchestrator/

# Copy source code for mcp-server
COPY packages/mcp-server/src ./packages/mcp-server/src
COPY packages/mcp-server/tsconfig.json ./packages/mcp-server/

# Build shared package first (using bun build directly to avoid tsc issues)
WORKDIR /build/packages/shared
RUN bun build ./src/index.ts --outdir ./dist --target bun

# Build orchestrator package (mcp-server imports from it)
WORKDIR /build/packages/orchestrator
RUN bun build src/index.ts --outdir dist --target bun

# Build MCP server
WORKDIR /build/packages/mcp-server
RUN bun build src/index.ts --outdir dist --target bun

# -----------------------------------------------------------------------------
# Runtime stage
# -----------------------------------------------------------------------------
FROM oven/bun:1.2-alpine AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    docker-cli \
    tini

# Create non-root user
# Docker socket access will be granted via docker-compose group_add
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Create directories
RUN mkdir -p /app /binaries /outputs /logs /cache && \
    chown -R sentinel:sentinel /app /outputs /logs /cache

WORKDIR /app

# Copy node_modules first (for runtime dependencies)
COPY --from=builder --chown=sentinel:sentinel /build/node_modules ./node_modules

# Copy built artifacts (overwrite workspace links with actual built code)
COPY --from=builder --chown=sentinel:sentinel /build/packages/mcp-server/dist ./dist
COPY --from=builder --chown=sentinel:sentinel /build/packages/mcp-server/package.json ./
COPY --from=builder --chown=sentinel:sentinel /build/packages/shared/dist ./node_modules/@sentinel/shared/dist
COPY --from=builder --chown=sentinel:sentinel /build/packages/shared/package.json ./node_modules/@sentinel/shared/
COPY --from=builder --chown=sentinel:sentinel /build/packages/orchestrator/dist ./node_modules/@sentinel/orchestrator/dist
COPY --from=builder --chown=sentinel:sentinel /build/packages/orchestrator/package.json ./node_modules/@sentinel/orchestrator/

# Switch to non-root user
USER sentinel

# Environment
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV GHIDRA_CONTAINER=sentinel-ghidra
ENV CACHE_MAX_SIZE=100
ENV CACHE_TTL_SECONDS=86400

# Health check - verify MCP server responds
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD echo '{"jsonrpc":"2.0","id":1,"method":"ping"}' | timeout 5 bun run dist/index.js 2>/dev/null || exit 0

# Expose port for HTTP transport (optional, stdio is primary)
EXPOSE 3000

# Use tini as init for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Default: run MCP server in stdio mode
CMD ["bun", "run", "dist/index.js"]

# =============================================================================
# Usage:
# =============================================================================
#
# Build:
#   docker build -t sentinel-mcp-server ./packages/mcp-server
#
# Run standalone (stdio mode):
#   docker run -i --rm \
#     -v /path/to/binaries:/binaries:ro \
#     sentinel-mcp-server
#
# Run in compose (see docker-compose.yml):
#   docker-compose up mcp-server
#
# Note: For analyze_binary to work, the Ghidra container must be running
#       and accessible via Docker networking (sentinel-ghidra container name).
# =============================================================================
