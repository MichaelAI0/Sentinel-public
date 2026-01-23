#!/bin/bash
# SENTINEL Development Startup Script
# Starts MCP Server + Ghidra (Docker) and Orchestrator (Native)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 Starting SENTINEL Development Environment..."

# Check if Ollama is available locally
check_ollama() {
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "✅ Ollama is available locally"
        return 0
    else
        echo "⚠️  Local Ollama not available"
        return 1
    fi
}

# Start Docker services (MCP Server + Ghidra)
start_docker_services() {
    echo "📦 Starting Docker services (mcp-server, ghidra)..."
    cd "$PROJECT_ROOT"
    docker compose up -d mcp-server ghidra
    
    # Wait for MCP server to be healthy
    echo "⏳ Waiting for MCP server to be healthy..."
    for i in {1..30}; do
        if curl -s http://localhost:3000/health > /dev/null 2>&1; then
            echo "✅ MCP server is healthy"
            return 0
        fi
        sleep 1
    done
    echo "❌ MCP server failed to start"
    return 1
}

# Start Ollama in Docker if local not available
start_docker_ollama() {
    echo "🦙 Starting Ollama in Docker..."
    cd "$PROJECT_ROOT"
    docker compose --profile ollama up -d ollama
    
    echo "⏳ Waiting for Ollama to be ready..."
    for i in {1..60}; do
        if docker exec sentinel-ollama ollama list > /dev/null 2>&1; then
            echo "✅ Docker Ollama is ready"
            export OLLAMA_BASE_URL="http://localhost:11434"
            return 0
        fi
        sleep 2
    done
    echo "❌ Docker Ollama failed to start"
    return 1
}

# Start orchestrator natively
start_orchestrator() {
    local ollama_url="${OLLAMA_BASE_URL:-http://localhost:11434}"
    
    echo "🎯 Starting Orchestrator (native)..."
    echo "   Ollama URL: $ollama_url"
    echo "   MCP Server: http://localhost:3000"
    
    cd "$PROJECT_ROOT/packages/orchestrator"
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        echo "📥 Installing dependencies..."
        bun install
    fi
    
    # Run orchestrator
    OLLAMA_BASE_URL="$ollama_url" \
    MCP_SERVER_URL="http://localhost:3000" \
    LOG_LEVEL="${LOG_LEVEL:-info}" \
    exec bun run ./src/index.ts
}

# Main
main() {
    # Start Docker services first
    start_docker_services
    
    # Check for local Ollama, fall back to Docker if not available
    if ! check_ollama; then
        start_docker_ollama
    fi
    
    # Start orchestrator (this will block)
    start_orchestrator
}

# Handle cleanup
cleanup() {
    echo -e "\n🛑 Shutting down..."
    cd "$PROJECT_ROOT"
    docker compose down
    exit 0
}

trap cleanup SIGINT SIGTERM

main "$@"
