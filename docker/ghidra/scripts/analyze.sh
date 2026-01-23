#!/bin/bash
# =============================================================================
# SENTINEL Ghidra Analysis Wrapper
# =============================================================================
# Usage: /workspace/analyze.sh <binary_path> <script_name> [script_args...]
#
# This script wraps Ghidra headless analysis for the MCP server.
# It uses our compiled JavaScript scripts (from TypeScript) via GraalJS.
# =============================================================================

set -e

BINARY_PATH="$1"
SCRIPT_NAME="$2"
shift 2 2>/dev/null || true
SCRIPT_ARGS="$@"

if [ -z "$BINARY_PATH" ] || [ -z "$SCRIPT_NAME" ]; then
  echo "Usage: analyze.sh <binary_path> <script_name> [script_args...]"
  echo ""
  echo "Available scripts:"
  echo "  analyze         - Full binary analysis (functions, strings, sections)"
  echo "  detect-packers  - Detect packing/obfuscation"
  echo "  extract-functions - Detailed function extraction with call graphs"
  exit 1
fi

# Create unique project name based on binary hash
BINARY_HASH=$(sha256sum "$BINARY_PATH" | cut -c1-12)
PROJECT_NAME="sentinel_${BINARY_HASH}"

echo "[SENTINEL] Analyzing: $BINARY_PATH"
echo "[SENTINEL] Script: $SCRIPT_NAME"
echo "[SENTINEL] Project: $PROJECT_NAME"

# Use JavaScript scripts directly (GraalJS extension handles .js files)
SCRIPT_FILE="${SCRIPT_NAME}.js"
echo "[SENTINEL] Using JavaScript script: $SCRIPT_FILE"

# Run Ghidra headless analysis
${GHIDRA_HOME}/support/analyzeHeadless \
  /workspace/projects "$PROJECT_NAME" \
  -import "$BINARY_PATH" \
  -scriptPath /workspace/scripts \
  -postScript "$SCRIPT_FILE" $SCRIPT_ARGS \
  -deleteProject \
  2>&1

echo "[SENTINEL] Analysis complete"
