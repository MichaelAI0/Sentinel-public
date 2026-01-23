# =============================================================================
# SENTINEL Ghidra Headless Analysis Container
# =============================================================================
# Ghidra 12.0.1 (January 2026) + SENTINEL JavaScript Extension (GraalJS)
#
# This is a TypeScript-only solution:
#   1. Our TypeScript scripts compile to JavaScript
#   2. Our custom GraalJS extension enables JavaScript in Ghidra 12.x
#   3. No Python/Jython fallback needed
#
# Download:
#   ghidra_12.0.1_PUBLIC_20260114.zip (489 MB)
#   SHA-256: 85bd2990945f3a78df4d1e09f1bb1f40ab77be3bac62c6e7678900788c7f0f41
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build TypeScript scripts to JavaScript
# -----------------------------------------------------------------------------
FROM oven/bun:1.1-alpine AS ts-builder

WORKDIR /build

# Copy TypeScript source files
COPY scripts/tsconfig.json .
COPY scripts/ghidra-api.d.ts .
COPY scripts/*.ts ./

# Compile TypeScript to JavaScript
RUN bun install --no-save typescript && \
    bunx tsc -p tsconfig.json

# Verify output
RUN ls -la dist/ && \
    echo "Compiled scripts:" && \
    find dist -name "*.js" -type f

# -----------------------------------------------------------------------------
# Stage 2: Build SENTINEL GraalJS Extension for Ghidra
# -----------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk-jammy AS extension-builder

# Install Gradle
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Gradle
ARG GRADLE_VERSION=8.5
RUN curl -fsSL -o /tmp/gradle.zip \
    "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" && \
    unzip -q /tmp/gradle.zip -d /opt && \
    ln -s /opt/gradle-${GRADLE_VERSION}/bin/gradle /usr/local/bin/gradle && \
    rm /tmp/gradle.zip

# Download Ghidra (needed for API JARs during compilation)
ARG GHIDRA_VERSION=12.0.1
ARG GHIDRA_DATE=20260114
RUN curl -fsSL -o /tmp/ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Copy extension source
WORKDIR /extension
COPY extension/ .

# Build the extension
RUN gradle build --no-daemon -x test && \
    ls -la build/dist/ && \
    echo "Extension built successfully"

# -----------------------------------------------------------------------------
# Stage 3: Ghidra runtime with our extension
# -----------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk-jammy AS runtime

# Build arguments
ARG GHIDRA_VERSION=12.0.1
ARG GHIDRA_DATE=20260114
ARG GHIDRA_SHA256=85bd2990945f3a78df4d1e09f1bb1f40ab77be3bac62c6e7678900788c7f0f41

# Environment variables
ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="${GHIDRA_HOME}/support:${PATH}"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    fontconfig \
    libfreetype6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra with checksum verification
RUN echo "Downloading Ghidra ${GHIDRA_VERSION}..." && \
    curl -fsSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" && \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_HOME} && \
    rm /tmp/ghidra.zip && \
    echo "Ghidra ${GHIDRA_VERSION} installed successfully"

# Create non-root user for security with proper home directory
RUN groupadd -r sentinel && useradd -r -g sentinel -m -d /home/sentinel sentinel

# Install SENTINEL JavaScript Extension to USER SETTINGS directory
# IMPORTANT: Ghidra only loads extension JARs to classpath from:
#   1. {user settings}/Extensions (e.g., ~/.config/ghidra/.../Extensions)
#   2. NOT from {install dir}/Ghidra/Extensions (those are skipped as internal modules)
# See GhidraApplicationLayout.findExtensionInstallationDirectories()
ARG GHIDRA_SETTINGS_DIR=/home/sentinel/.config/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC
COPY --from=extension-builder /extension/build/dist/*.zip /tmp/sentinel-js.zip
RUN mkdir -p ${GHIDRA_SETTINGS_DIR}/Extensions && \
    unzip -q /tmp/sentinel-js.zip -d ${GHIDRA_SETTINGS_DIR}/Extensions/ && \
    rm /tmp/sentinel-js.zip && \
    chown -R sentinel:sentinel /home/sentinel && \
    echo "SENTINEL JavaScript Extension installed to user settings" && \
    ls -la ${GHIDRA_SETTINGS_DIR}/Extensions/

# Create workspace directories
RUN mkdir -p /workspace/binaries \
             /workspace/projects \
             /workspace/scripts \
             /workspace/output && \
    chown -R sentinel:sentinel /workspace

# Copy compiled JavaScript scripts
COPY --from=ts-builder --chown=sentinel:sentinel /build/dist/ /workspace/scripts/

# Copy analysis wrapper script
COPY --chown=sentinel:sentinel scripts/analyze.sh /workspace/analyze.sh
RUN chmod +x /workspace/analyze.sh

# Set working directory
WORKDIR /workspace

# Switch to non-root user
USER sentinel

# Health check - verify Ghidra headless responds
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 \
    CMD ${GHIDRA_HOME}/support/analyzeHeadless 2>&1 | head -1 | grep -q "Ghidra" || exit 1

# Default: keep container running for exec commands from MCP server
CMD ["bash", "-c", "echo 'SENTINEL Ghidra container ready with GraalJS JavaScript support.' && tail -f /dev/null"]

# =============================================================================
# Usage Examples:
# =============================================================================
#
# Build:
#   docker build -t sentinel-ghidra ./docker/ghidra
#
# Run container:
#   docker run -d --name sentinel-ghidra \
#     -v /path/to/samples:/workspace/binaries:ro \
#     sentinel-ghidra
#
# Execute analysis (uses TypeScript-compiled JavaScript):
#   docker exec sentinel-ghidra /workspace/analyze.sh \
#     /workspace/binaries/sample.exe analyze
#
# Direct headless command:
#   docker exec sentinel-ghidra analyzeHeadless \
#     /workspace/projects temp -import /workspace/binaries/sample.exe \
#     -scriptPath /workspace/scripts -postScript analyze.js -deleteProject
# =============================================================================
