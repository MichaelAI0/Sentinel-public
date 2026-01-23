#!/bin/bash
# Start orchestrator in background

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT/packages/orchestrator"
export OLLAMA_BASE_URL=http://localhost:11434
export MCP_SERVER_URL=http://localhost:3000
export OUTPUT_DIR="$PROJECT_ROOT/outputs"
export LOG_LEVEL=info
exec bun run ./src/index.ts
