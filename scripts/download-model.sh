#!/usr/bin/env bash
# ============================================================================
# SENTINEL - GLM-4.7-Flash Model Downloader
# ============================================================================
# Downloads the GLM-4.7-Flash GGUF model for local inference via llama-server.
#
# Usage:
#   ./scripts/download-model.sh [quantization]
#
# Quantization options:
#   Q4_K_XL  - Recommended (~18GB RAM, best quality/speed balance)
#   Q6_K_L   - Higher quality (~24GB RAM)
#   Q8_0     - Highest quality (~30GB RAM)
#   IQ4_XS   - Smallest (~14GB RAM, slightly lower quality)
#
# Example:
#   ./scripts/download-model.sh Q4_K_XL
#
# Requirements:
#   - huggingface-cli: pip install huggingface_hub
#   - Sufficient disk space (~20GB for Q4_K_XL)
#
# See: https://huggingface.co/unsloth/GLM-4.7-Flash-GGUF
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MODEL_REPO="unsloth/GLM-4.7-Flash-GGUF"
MODELS_DIR="${MODELS_DIR:-./models}"
DEFAULT_QUANT="Q4_K_XL"

# Parse arguments
QUANTIZATION="${1:-$DEFAULT_QUANT}"

# Validate quantization
VALID_QUANTS=("Q4_K_XL" "Q6_K_L" "Q8_0" "IQ4_XS" "BF16")
if [[ ! " ${VALID_QUANTS[*]} " =~ " ${QUANTIZATION} " ]]; then
    echo -e "${RED}Error: Invalid quantization '${QUANTIZATION}'${NC}"
    echo "Valid options: ${VALID_QUANTS[*]}"
    exit 1
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      SENTINEL - GLM-4.7-Flash Model Downloader                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check for huggingface-cli
if ! command -v huggingface-cli &> /dev/null; then
    echo -e "${YELLOW}huggingface-cli not found. Installing...${NC}"
    pip install --upgrade huggingface_hub
fi

# Create models directory
mkdir -p "${MODELS_DIR}"

# Show model info
echo -e "${GREEN}Model Repository:${NC} ${MODEL_REPO}"
echo -e "${GREEN}Quantization:${NC}     ${QUANTIZATION}"
echo -e "${GREEN}Destination:${NC}      ${MODELS_DIR}"
echo ""

# Estimate sizes
case "${QUANTIZATION}" in
    "Q4_K_XL")
        SIZE="~18GB file, ~20GB RAM"
        ;;
    "Q6_K_L")
        SIZE="~24GB file, ~26GB RAM"
        ;;
    "Q8_0")
        SIZE="~30GB file, ~32GB RAM"
        ;;
    "IQ4_XS")
        SIZE="~14GB file, ~16GB RAM"
        ;;
    "BF16")
        SIZE="~55GB file, ~60GB RAM (requires ~60GB VRAM for GPU)"
        ;;
esac
echo -e "${YELLOW}Estimated:${NC}        ${SIZE}"
echo ""

# Check disk space
AVAILABLE=$(df -BG "${MODELS_DIR}" | awk 'NR==2 {print $4}' | tr -d 'G')
echo -e "${GREEN}Available space:${NC}  ${AVAILABLE}GB"

# Confirm download
read -p "$(echo -e ${YELLOW}"Proceed with download? (y/N): "${NC})" -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Download cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}Downloading GLM-4.7-Flash ${QUANTIZATION}...${NC}"
echo ""

# Download the model
huggingface-cli download "${MODEL_REPO}" \
    --local-dir "${MODELS_DIR}" \
    --include "*${QUANTIZATION}*" \
    --local-dir-use-symlinks False

# Find downloaded file
MODEL_FILE=$(find "${MODELS_DIR}" -name "*${QUANTIZATION}*.gguf" -type f | head -1)

if [[ -z "${MODEL_FILE}" ]]; then
    echo -e "${RED}Error: Model file not found after download${NC}"
    exit 1
fi

# Get file size
FILE_SIZE=$(du -h "${MODEL_FILE}" | cut -f1)
BASENAME=$(basename "${MODEL_FILE}")

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Download Complete!                          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Model file:${NC}  ${BASENAME}"
echo -e "${GREEN}Size:${NC}        ${FILE_SIZE}"
echo -e "${GREEN}Location:${NC}    ${MODEL_FILE}"
echo ""

# Create .env snippet
echo -e "${BLUE}Add to your .env file:${NC}"
echo ""
echo "# GLM-4.7-Flash Local Model Configuration"
echo "LLAMA_SERVER_URL=http://localhost:8081"
echo "LLAMA_MODEL_FILE=${BASENAME}"
echo "LLAMA_CTX_SIZE=32768"
echo ""

# Show usage
echo -e "${BLUE}To start the server:${NC}"
echo ""
echo "  # CPU mode (slower, ~18GB RAM required)"
echo "  docker compose --profile llama up -d"
echo ""
echo "  # GPU mode (fast, requires NVIDIA GPU with ~20GB VRAM)"
echo "  docker compose --profile llama-gpu up -d"
echo ""
echo -e "${BLUE}Test the server:${NC}"
echo ""
echo "  curl http://localhost:8081/v1/chat/completions \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{"
echo "      \"model\": \"glm-4.7-flash\","
echo "      \"messages\": [{\"role\": \"user\", \"content\": \"Hello!\"}]"
echo "    }'"
echo ""
echo -e "${GREEN}Happy hacking! 🎯${NC}"
