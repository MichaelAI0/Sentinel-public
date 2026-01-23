#!/bin/bash

# SENTINEL Executable Build Script
# Compiles the CLI into a single-file executable using Bun's compile feature.
#
# Usage:
#   ./scripts/build-executable.sh [--target <target>]
#
# Options:
#   --target <target>  Build for specific target (linux-x64, darwin-x64, windows-x64)
#                      Default: current platform
#
# Examples:
#   ./scripts/build-executable.sh                    # Build for current platform
#   ./scripts/build-executable.sh --target linux-x64 # Build for Linux x64
#   ./scripts/build-executable.sh --all              # Build for all platforms

set -euo pipefail

# Color output helpers
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

log_info() {
  echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
  echo -e "${GREEN}✅ $1${NC}"
}

log_warn() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
  echo -e "${RED}❌ $1${NC}"
}

# Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Build output directory
BUILD_DIR="$PROJECT_ROOT/dist"
mkdir -p "$BUILD_DIR"

# Parse arguments
TARGET=""
BUILD_ALL=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --all)
      BUILD_ALL=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [--target <target>] [--all]"
      echo ""
      echo "Options:"
      echo "  --target <target>  Build for specific target (linux-x64, darwin-x64, windows-x64)"
      echo "  --all              Build for all platforms"
      echo "  --help, -h         Show this help message"
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Ensure dependencies are installed
log_info "Installing dependencies..."
bun install --frozen-lockfile 2>/dev/null || bun install

# Run tests first
log_info "Running tests..."
if bun test; then
  log_success "All tests passed"
else
  log_error "Tests failed. Fix issues before building."
  exit 1
fi

# Run linter
log_info "Checking code quality..."
if bun run lint; then
  log_success "Lint check passed"
else
  log_warn "Lint issues found (continuing anyway)"
fi

# Run typecheck
log_info "Type checking..."
if bun run typecheck; then
  log_success "Type check passed"
else
  log_error "Type errors found. Fix issues before building."
  exit 1
fi

# Build function
build_for_target() {
  local target_platform="$1"
  local output_name="sentinel"
  
  case "$target_platform" in
    windows-x64)
      output_name="sentinel.exe"
      ;;
    linux-x64|darwin-x64|darwin-arm64)
      output_name="sentinel"
      ;;
    *)
      output_name="sentinel"
      ;;
  esac

  local output_path="$BUILD_DIR/$target_platform/$output_name"
  mkdir -p "$BUILD_DIR/$target_platform"

  log_info "Building for $target_platform..."

  # Bun compile command
  local compile_args=(
    build
    --compile
    "$PROJECT_ROOT/packages/orchestrator/src/cli.ts"
    --outfile "$output_path"
  )

  # Add target if cross-compiling
  if [[ -n "$target_platform" ]]; then
    compile_args+=(--target "bun-$target_platform")
  fi

  if bun "${compile_args[@]}"; then
    # Make executable (not needed on Windows)
    if [[ "$target_platform" != windows-x64 ]]; then
      chmod +x "$output_path"
    fi

    local size
    size=$(du -h "$output_path" | cut -f1)
    log_success "Built: $output_path ($size)"
  else
    log_error "Failed to build for $target_platform"
    return 1
  fi
}

# Main build logic
echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║         SENTINEL - Build Executable               ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

if [[ "$BUILD_ALL" == true ]]; then
  # Build for all platforms
  PLATFORMS=("linux-x64" "darwin-x64" "darwin-arm64" "windows-x64")
  
  for platform in "${PLATFORMS[@]}"; do
    build_for_target "$platform" || true
  done
else
  # Build for single target
  if [[ -n "$TARGET" ]]; then
    build_for_target "$TARGET"
  else
    # Detect current platform
    case "$(uname -s)-$(uname -m)" in
      Linux-x86_64)
        CURRENT_TARGET="linux-x64"
        ;;
      Darwin-x86_64)
        CURRENT_TARGET="darwin-x64"
        ;;
      Darwin-arm64)
        CURRENT_TARGET="darwin-arm64"
        ;;
      MINGW*|CYGWIN*|MSYS*)
        CURRENT_TARGET="windows-x64"
        ;;
      *)
        log_error "Unknown platform: $(uname -s)-$(uname -m)"
        exit 1
        ;;
    esac

    log_info "Detected platform: $CURRENT_TARGET"
    build_for_target "$CURRENT_TARGET"
  fi
fi

echo ""
log_success "Build complete!"
echo ""
echo "Usage:"
echo "  ./dist/<platform>/sentinel analyze <binary-file>"
echo ""
echo "Run with --help for all options:"
echo "  ./dist/<platform>/sentinel --help"
echo ""
